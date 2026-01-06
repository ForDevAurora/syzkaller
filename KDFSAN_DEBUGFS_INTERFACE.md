# KDFSAN Debugfs Interface for Syzkaller Integration

## 1. Debugfs 接口路径

```
/sys/kernel/debug/kdfsan/offset_rules
```

权限：`0644` (可读可写)

## 2. 数据格式规范

### 写入格式

每行一条规则，格式如下：

```
<syscall_nr> <arg_idx> <base_addr> <offset> <size> <label>
```

| 字段 | 类型 | 描述 |
|------|------|------|
| `syscall_nr` | u16 | 系统调用号 (x86_64: sendmsg=46, sendto=44) |
| `arg_idx` | int | 参数索引 (0-based, 范围 0-5) |
| `base_addr` | string | 基地址路径字符串 (见下表) |
| `offset` | size_t | 相对基地址的字节偏移量 |
| `size` | size_t | 要标记污点的字节数 (1-1024) |
| `label` | string | 污点标签描述符 (无空格) |

### 读取格式

读取时返回带注释的当前规则列表：

```
# Format: <syscall_nr> <arg_idx> <base_addr> <offset> <size> <label>
46 1 msg_iov[0].iov_base 40 4 dst-ipv4
46 1 msg_iov[0].iov_base 48 4 gateway-ipv4
```

## 3. 基地址类型 (base_addr)

### 字符串到枚举对应关系

| 字符串格式 | 枚举值 | 数值 | 含义 |
|-----------|--------|------|------|
| `direct` | `KDF_BASE_DIRECT` | 0 | 直接使用参数指针作为基地址 |
| `msg_iov[N].iov_base` | `KDF_BASE_MSG_IOV_BASE` | 1 | msghdr.msg_iov[N].iov_base (N: 0-7) |
| `msg_control` | `KDF_BASE_MSG_CONTROL` | 2 | msghdr.msg_control |
| `msg_name` | `KDF_BASE_SOCKADDR` | 3 | msghdr.msg_name (sockaddr) |

### 内核结构体定义

```c
// include/linux/kdfsan_types.h

typedef enum {
    KDF_BASE_DIRECT = 0,
    KDF_BASE_MSG_IOV_BASE,
    KDF_BASE_MSG_CONTROL,
    KDF_BASE_SOCKADDR,
    KDF_BASE_TYPE_MAX
} kdf_base_type_t;

typedef struct {
    kdf_base_type_t type;
    union {
        struct {
            u8 iov_index;     // iov数组索引 (0-7)
            u8 reserved[3];
        } msg_iov;
        u32 raw;
    } params;
} kdf_base_addr_t;
```

## 4. Netlink Message 结构对应关系

### sendmsg 系统调用结构

```
sendmsg(fd, msg, flags)
        │
        └─► struct msghdr {
              void         *msg_name;       ← base_addr: "msg_name"
              socklen_t     msg_namelen;
              struct iovec *msg_iov;        ┐
              size_t        msg_iovlen;     │
              void         *msg_control;    ← base_addr: "msg_control"
              size_t        msg_controllen; │
              int           msg_flags;      │
            };                              │
                                            │
            msg_iov[0] ─────────────────────┘
              │
              └─► struct iovec {
                    void  *iov_base;  ← base_addr: "msg_iov[0].iov_base"
                    size_t iov_len;
                  };
```

### Netlink Route Message 布局 (iov_base 起始)

```
┌──────────────────────────────────────┐ offset 0
│ struct nlmsghdr (16 bytes)           │
│   nlmsg_len, nlmsg_type,             │
│   nlmsg_flags, nlmsg_seq, nlmsg_pid  │
├──────────────────────────────────────┤ offset 16
│ struct rtmsg (12 bytes)              │
│   rtm_family, rtm_dst_len,           │
│   rtm_src_len, rtm_tos, ...          │
├──────────────────────────────────────┤ offset 28
│ Netlink Attributes (rtattr)          │
│ ┌────────────────────────────────┐   │
│ │ RTA_TABLE (8 bytes)            │   │ offset 28-36
│ ├────────────────────────────────┤   │
│ │ RTA_DST (8 bytes)              │   │ offset 36-44
│ │   rta_len=8, rta_type=RTA_DST  │   │   (rta header: 4 bytes)
│ │   ipv4_addr (4 bytes)          │   │   offset 40: IPv4地址
│ ├────────────────────────────────┤   │
│ │ RTA_GATEWAY (8 bytes)          │   │ offset 44-52
│ │   rta_len=8, rta_type=RTA_GW   │   │   (rta header: 4 bytes)
│ │   ipv4_addr (4 bytes)          │   │   offset 48: 网关地址
│ ├────────────────────────────────┤   │
│ │ RTA_OIF (8 bytes)              │   │ offset 52-60
│ │   rta_len=8, rta_type=RTA_OIF  │   │   (rta header: 4 bytes)
│ │   ifindex (4 bytes)            │   │   offset 52: 出口接口
│ └────────────────────────────────┘   │
└──────────────────────────────────────┘
```

## 5. 使用示例

### 配置 RTM_DELROUTE 污点规则

```bash
# 清空现有规则
echo "" > /sys/kernel/debug/kdfsan/offset_rules

# 添加规则：标记目的IP、网关IP、出口接口
cat << 'EOF' > /sys/kernel/debug/kdfsan/offset_rules
46 1 msg_iov[0].iov_base 40 4 dst-ipv4
46 1 msg_iov[0].iov_base 48 4 gateway-ipv4
46 1 msg_iov[0].iov_base 52 4 oif-index
EOF

# 验证配置
cat /sys/kernel/debug/kdfsan/offset_rules
```

### Syzkaller Executor 集成伪代码

```c
// 在执行 sendmsg 前配置污点规则
void configure_taint_rules(int fd, struct msghdr *msg) {
    FILE *f = fopen("/sys/kernel/debug/kdfsan/offset_rules", "w");
    if (!f) return;

    // 根据程序分析结果写入规则
    // syscall_nr=46 (sendmsg), arg_idx=1 (msg指针)
    fprintf(f, "46 1 msg_iov[0].iov_base %lu %lu %s\n",
            calculated_offset, field_size, label);

    fclose(f);
}
```

## 6. 关键 Offset 计算公式

```
总 offset = nlmsghdr_size + payload_header_size + attr_header_offset + rta_header_size

对于标准 IPv4 路由消息:
- nlmsghdr: 16 bytes
- rtmsg:    12 bytes
- 每个 rtattr header: 4 bytes (rta_len + rta_type)
- IPv4 地址: 4 bytes
- NLMSG_ALIGN 对齐: 4 字节边界
```

## 7. 调试辅助

```bash
# 查看当前规则
cat /sys/kernel/debug/kdfsan/offset_rules

# 查看污点追踪日志
dmesg | grep -i kdfsan

# 查看帮助
cat /sys/kernel/debug/kdfsan/help  # (如果DEBUG模式启用)
```

## 8. 错误处理

| 错误码 | 原因 |
|--------|------|
| `-EINVAL` | 格式错误、参数超出范围、size=0 或 size>1024 |
| `-ENOMEM` | 内存分配失败 |
| `-EFAULT` | 用户空间地址无效 |

## 9. 注意事项

1. **系统调用号差异**: ARM64 与 x86_64 系统调用号不同
   - x86_64: sendmsg=46, sendto=44
   - ARM64: sendmsg=211, sendto=206

2. **动态规则模式**: 需确保 `KDFSAN_DYNAMIC_RULES` 宏已定义

3. **线程安全**: 规则更新使用 `mutex_lock` + RCU 同步保护

4. **规则替换**: 写入新规则会原子性替换所有现有规则
