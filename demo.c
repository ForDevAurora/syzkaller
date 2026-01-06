// cat /sys/kernel/debug/kdfsan/post_boot
// echo "646 1 msg_iov[0].iov_base 40 4 dst" > /sys/kernel/debug/kdfsan/offset_rules
// echo "646 1 msg_iov[0].iov_base 72 4 priority_ip" > /sys/kernel/debug/kdfsan/offset_rules
// cat config > /sys/kernel/debug/kdfsan/offset_rules
// cat /sys/kernel/debug/kdfsan/offset_rules
// gcc demo-changed-kcov.c -o demo-changed-kcov

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>
#include <stdint.h>

/* KCOV related definitions */
#define KCOV_INIT_TRACE            _IOR('c', 1, unsigned long)
#define KCOV_ENABLE                _IO('c', 100)
#define KCOV_DISABLE               _IO('c', 101)
#define KCOV_MODE_TRACE_KDFSAN     2

/* KCOV buffer size (in u64 units) */
#define COVER_SIZE      (64 << 10)  /* 64K entries = 512KB */

struct {
    struct nlmsghdr nlh;
    struct rtmsg rtm;
    char attrbuf[512];
} req;

/* KCOV state */
static int kcov_fd = -1;
static uint64_t *kcov_area = NULL;

static void *addattr(struct nlmsghdr *n, int type, const void *data, int len)
{
    int rta_len = RTA_LENGTH(len);
    struct rtattr *rta;

    rta = (struct rtattr *)(((char *)n) + NLMSG_ALIGN(n->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = rta_len;
    memcpy(RTA_DATA(rta), data, len);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(rta_len);
    return RTA_DATA(rta);
}

static int kcov_init(void)
{
    kcov_fd = open("/sys/kernel/debug/kcov", O_RDWR);
    if (kcov_fd < 0) {
        perror("Failed to open /sys/kernel/debug/kcov");
        return -1;
    }

    if (ioctl(kcov_fd, KCOV_INIT_TRACE, COVER_SIZE) < 0) {
        perror("ioctl(KCOV_INIT_TRACE) failed");
        close(kcov_fd);
        kcov_fd = -1;
        return -1;
    }

    kcov_area = (uint64_t *)mmap(NULL, COVER_SIZE * sizeof(uint64_t),
                                  PROT_READ | PROT_WRITE, MAP_SHARED,
                                  kcov_fd, 0);
    if (kcov_area == MAP_FAILED) {
        perror("mmap() failed");
        close(kcov_fd);
        kcov_fd = -1;
        kcov_area = NULL;
        return -1;
    }

    if (ioctl(kcov_fd, KCOV_ENABLE, KCOV_MODE_TRACE_KDFSAN) < 0) {
        perror("ioctl(KCOV_ENABLE, KCOV_MODE_TRACE_KDFSAN) failed");
        munmap(kcov_area, COVER_SIZE * sizeof(uint64_t));
        close(kcov_fd);
        kcov_fd = -1;
        kcov_area = NULL;
        return -1;
    }

    printf("KCOV initialized successfully\n");
    return 0;
}

static void kcov_disable(void)
{
    if (kcov_fd >= 0) {
        ioctl(kcov_fd, KCOV_DISABLE, 0);
        if (kcov_area != NULL && kcov_area != MAP_FAILED)
            munmap(kcov_area, COVER_SIZE * sizeof(uint64_t));
        close(kcov_fd);
        printf("KCOV disabled\n");
    }
}

static void kcov_dump_data(const char *filename)
{
    FILE *fp;
    uint64_t count;
    uint64_t i;

    if (kcov_area == NULL) {
        fprintf(stderr, "KCOV not initialized\n");
        return;
    }

    count = kcov_area[0];
    printf("Collected %lu u64 values\n", (unsigned long)count);

    fp = fopen(filename, "w");
    if (fp == NULL) {
        perror("Failed to open output file");
        return;
    }

    if (count == 0) {
        fprintf(fp, "# No data collected\n");
        fclose(fp);
        return;
    }

    fprintf(fp, "# KCOV KDFSAN Taint Data\n");
    fprintf(fp, "# Total entries: %lu\n", (unsigned long)count);

    for (i = 1; i <= count; i++) {
        fprintf(fp, "0x%016lx", (unsigned long)kcov_area[i]);
        if (i % 5 == 0)
            fprintf(fp, "\n");
        else if (i < count)
            fprintf(fp, ",");
    }

    if (count % 5 != 0)
        fprintf(fp, "\n");

    fclose(fp);
    printf("Data written to %s\n", filename);
}

int main(void)
{
    int sock;
    struct sockaddr_nl local, nladdr;
    struct msghdr msg;
    struct iovec iov;
    __u32 priority = 100;
    __u32 table = 200;
    __u32 dst_addr = htonl(0xC0000200);  /* 192.0.2.0 in network byte order */

    /* Initialize KCOV */
    if (kcov_init() < 0) {
        fprintf(stderr, "Failed to initialize KCOV, continuing without it\n");
    }

    /* Create socket */
    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        kcov_disable();
        return 1;
    }

    /* Bind socket */
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_pid = 0;  /* Let kernel assign pid */

    if (bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
        syscall(__NR_close, sock);
        kcov_disable();
        return 1;
    }

    /* Build netlink message */
    memset(&req, 0, sizeof(req));

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type = RTM_NEWRULE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    req.nlh.nlmsg_seq = 1;
    req.nlh.nlmsg_pid = 0;

    req.rtm.rtm_family = AF_INET;
    req.rtm.rtm_dst_len = 24;
    req.rtm.rtm_table = RT_TABLE_UNSPEC;
    req.rtm.rtm_protocol = RTPROT_BOOT;
    req.rtm.rtm_scope = RT_SCOPE_UNIVERSE;
    req.rtm.rtm_type = RTN_BLACKHOLE;

    /* Add attributes */
    void *priority_ptr = addattr(&req.nlh, FRA_PRIORITY, &priority, sizeof(priority));
    void *table_ptr = addattr(&req.nlh, FRA_TABLE, &table, sizeof(table));
    void *dst_ptr = addattr(&req.nlh, FRA_DST, &dst_addr, sizeof(dst_addr));

    /* Calculate and print offsets relative to iov_base (&req.nlh) */
    void *base = &req.nlh;
    printf("=== Offsets relative to msg_iov[0].iov_base ===\n");
    printf("FRA_PRIORITY (priority): offset = %ld, size = %zu\n",
           (char*)priority_ptr - (char*)base, sizeof(priority));
    printf("FRA_TABLE (table):       offset = %ld, size = %zu\n",
           (char*)table_ptr - (char*)base, sizeof(table));
    printf("FRA_DST (dst_addr):      offset = %ld, size = %zu\n",
           (char*)dst_ptr - (char*)base, sizeof(dst_addr));
    printf("\n=== Config format ===\n");
    printf("646 1 msg_iov[0].iov_base %ld 4 priority\n", (char*)priority_ptr - (char*)base);
    printf("646 1 msg_iov[0].iov_base %ld 4 table\n", (char*)table_ptr - (char*)base);
    printf("646 1 msg_iov[0].iov_base %ld 4 dst\n", (char*)dst_ptr - (char*)base);

    /* Prepare message for sendmsg */
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &nladdr;
    msg.msg_namelen = sizeof(nladdr);

    iov.iov_base = &req.nlh;
    iov.iov_len = req.nlh.nlmsg_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    /* Reset KCOV counter before sendmsg */
    if (kcov_area != NULL)
        kcov_area[0] = 0;

    /* Target syscall for taint tracking */
    syscall(__NR_sendmsg+600, sock, &msg, 0);

    /* Dump collected KCOV data */
    if (kcov_area != NULL)
        kcov_dump_data("kcov_taint_data.csv");

    syscall(__NR_close, sock);
    kcov_disable();
    return 0;
}
