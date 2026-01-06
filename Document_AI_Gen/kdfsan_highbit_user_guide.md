# KDFSAN High-Bit Pointer Taint Mode User Guide

## Quick Start

### 1. Enable in Kernel Config
```bash
make menuconfig
# Navigate to: Memory Management -> KDFSAN -> Enable high-bit pointer taint marking
# Or add to .config:
CONFIG_KDFSAN_HIGH_POINTER=y
```

### 2. Encode Pointer in User Space

```c
#include <stdint.h>

/* Encode offset and size into pointer's high 16 bits */
void *encode_taint_ptr(void *ptr, uint16_t offset, uint8_t size) {
    uint64_t addr = (uint64_t)ptr;
    // offset: 12 bits (0-4095), size: 4 bits (1-15)
    uint16_t tag = (offset << 4) | (size & 0xF);
    addr = (addr & 0x0000FFFFFFFFFFFF) | ((uint64_t)tag << 48);
    return (void *)addr;
}
```

### 3. Pass to Kernel via Syscall

```c
char buffer[256] = "data with taint target here...";

// Taint bytes [16..23] (offset=16, size=8)
void *tagged_ptr = encode_taint_ptr(buffer, 16, 8);

// Use in syscall (e.g., sendmsg iov_base)
struct iovec iov = {
    .iov_base = tagged_ptr,
    .iov_len = sizeof(buffer)
};
```

---

## Bit Layout

```
63    52 51   48 47                                             0
+-------+-------+------------------------------------------------+
|offset | size  |              actual address                     |
|(12bit)|(4bit) |                 (48bit)                         |
+-------+-------+------------------------------------------------+
```

| Field | Bits | Range | Description |
|-------|------|-------|-------------|
| offset | [63:52] | 0-4095 | Byte offset within buffer to start taint |
| size | [51:48] | 1-15 | Number of bytes to taint |
| address | [47:0] | - | Actual user-space address |

---

## Rules

1. **size=0**: Pointer treated as normal (no taint applied)
2. **Detection**: High 16 bits must NOT be 0x0000 or 0xFFFF
3. **Auto-clean**: Kernel automatically cleans high bits before dereference
4. **Works with**: copy_from_user, get_user, strncpy_from_user

---

## Example: Taint IPv4 Address in Netlink Message

```c
#include <linux/rtnetlink.h>

struct {
    struct nlmsghdr nlh;
    struct rtmsg rtm;
    char attrbuf[512];
} req;

// Build netlink message...
void *dst_ptr = addattr(&req.nlh, FRA_DST, &dst_addr, 4);

// Calculate offset from iov_base
size_t offset = (char*)dst_ptr - (char*)&req.nlh;

// Encode: taint 4 bytes at calculated offset
struct iovec iov = {
    .iov_base = encode_taint_ptr(&req.nlh, offset, 4),
    .iov_len = req.nlh.nlmsg_len
};

// Send via sendmsg - KDFSAN will taint the dst_addr bytes
sendmsg(sock, &msg, 0);
```

---

## Verify Taint with KCOV

```c
// Enable KCOV in KDFSAN mode
ioctl(kcov_fd, KCOV_ENABLE, KCOV_MODE_TRACE_KDFSAN);

// Reset counter
kcov_area[0] = 0;

// Trigger syscall with tagged pointer
sendmsg(sock, &msg, 0);

// Check taint data
uint64_t count = kcov_area[0];
printf("Taint entries: %lu\n", count);
```

---

## Limitations

- Max offset: 4095 bytes
- Max size: 15 bytes (use multiple pointers for larger regions)
- Only works on x86-64 architecture
- Requires `CONFIG_KDFSAN` and `CONFIG_KDFSAN_HIGH_POINTER`
