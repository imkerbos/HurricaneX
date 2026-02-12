# IP/Ethernet 帧封装层实现计划

## Context

TCP 状态机目前只构建纯 TCP segment（20 字节 header + payload），没有 IP 和 Ethernet 帧头。DPDK 收发的是完整的 L2 帧（Ethernet + IP + TCP），缺少这层引擎无法真正上线。

当前 tcp.c 的注释也明确说了："Builds raw TCP segments (no IP/Ethernet framing — that's pktio's job)"。但实际上 pktio 层也没做这件事，需要在中间加一个网络层。

## 设计思路

新建 `net.h` / `net.c` 作为网络帧封装/解析层，提供：
- Ethernet + IPv4 header 结构体
- 帧构建函数（TCP segment → 完整 L2 帧）
- 帧解析函数（完整 L2 帧 → 剥离出 TCP segment）
- IP/TCP checksum 计算

然后修改 tcp.c 的发包路径，在 TCP segment 外面包上 IP + Ethernet header；收包路径从 raw packet 逐层剥离。

## 文件清单

| 操作 | 文件 | 说明 |
|------|------|------|
| 新建 | `engine/include/hurricane/net.h` | Ethernet/IPv4 结构体 + 帧封装/解析 API |
| 新建 | `engine/src/net.c` | 帧构建、解析、checksum 实现 |
| 新建 | `engine/tests/test_net.c` | 网络层单元测试 |
| 修改 | `engine/include/hurricane/tcp.h` | `hx_tcp_conn_t` 添加 MAC 地址字段 |
| 修改 | `engine/src/tcp.c` | 发包包 Eth+IP 帧头，收包剥离帧头 |
| 修改 | `engine/tests/test_tcp.c` | 适配新的包格式（带 Eth+IP 头） |
| 修改 | `engine/meson.build` | 添加 net.c 源文件 |
| 修改 | `engine/tests/meson.build` | 添加 test_net 测试 |

---

## 详细设计

### 1. `engine/include/hurricane/net.h`

```c
/* Ethernet header (14 bytes) */
typedef struct hx_ether_hdr {
    hx_u8  dst_mac[6];
    hx_u8  src_mac[6];
    hx_u16 ether_type;   /* 网络字节序: 0x0800 = IPv4 */
} hx_ether_hdr_t;

/* IPv4 header (20 bytes, no options) */
typedef struct hx_ipv4_hdr {
    hx_u8  ver_ihl;      /* version(4) + IHL(4) */
    hx_u8  tos;
    hx_u16 total_len;    /* 网络字节序 */
    hx_u16 id;           /* 网络字节序 */
    hx_u16 frag_off;     /* 网络字节序 */
    hx_u8  ttl;
    hx_u8  protocol;     /* 6 = TCP */
    hx_u16 checksum;     /* 网络字节序 */
    hx_u32 src_ip;       /* 网络字节序 */
    hx_u32 dst_ip;       /* 网络字节序 */
} hx_ipv4_hdr_t;

#define HX_ETHER_TYPE_IPV4  0x0800
#define HX_IP_PROTO_TCP     6
#define HX_IP_DEFAULT_TTL   64

/* 完整帧的总 header 开销 */
#define HX_FRAME_HDR_LEN  (HX_ETHER_HDR_LEN + HX_IPV4_HDR_LEN)

/* 网络字节序转换 */
hx_u16 hx_htons(hx_u16 x);
hx_u16 hx_ntohs(hx_u16 x);
hx_u32 hx_htonl(hx_u32 x);
hx_u32 hx_ntohl(hx_u32 x);

/* IP header checksum */
hx_u16 hx_ip_checksum(const void *data, hx_u32 len);

/* TCP checksum (with pseudo-header) */
hx_u16 hx_tcp_checksum(hx_u32 src_ip, hx_u32 dst_ip,
                        const hx_u8 *tcp_seg, hx_u32 tcp_len);

/*
 * 构建完整 L2 帧: Ethernet + IPv4 + TCP segment
 *
 * tcp_seg/tcp_len: 已构建好的 TCP segment（header + payload）
 * 写入 buf，返回总帧长度，失败返回 0
 */
hx_u32 hx_net_build_frame(const hx_u8 src_mac[6], const hx_u8 dst_mac[6],
                           hx_u32 src_ip, hx_u32 dst_ip,
                           const hx_u8 *tcp_seg, hx_u32 tcp_len,
                           hx_u8 *buf, hx_u32 buf_size);

/*
 * 解析 L2 帧，剥离 Ethernet + IPv4 头，返回 TCP segment 指针
 *
 * 输出: src_ip, dst_ip, tcp_seg 指针, tcp_len
 * 返回 HX_OK 成功，HX_ERR_PROTO 格式错误
 */
hx_result_t hx_net_parse_frame(const hx_u8 *frame, hx_u32 frame_len,
                                hx_u32 *src_ip, hx_u32 *dst_ip,
                                const hx_u8 **tcp_seg, hx_u32 *tcp_len);
```

### 2. `engine/src/net.c`

实现：
- `hx_htons/ntohs/htonl/ntohl` — 编译时检测字节序，条件 swap
- `hx_ip_checksum` — RFC 1071 one's complement 累加
- `hx_tcp_checksum` — 12 字节 pseudo-header + TCP segment
- `hx_net_build_frame` — 写 14 字节 Eth + 20 字节 IP + TCP segment，填 checksum
- `hx_net_parse_frame` — 校验 ether_type=0x0800, protocol=6, 提取 IP 地址和 TCP 段

### 3. 修改 `tcp.h` — 添加 MAC 地址

```c
typedef struct hx_tcp_conn {
    /* ... existing fields ... */

    /* L2/L3 addressing for frame construction */
    hx_u8   src_mac[6];
    hx_u8   dst_mac[6];   /* gateway/peer MAC */
} hx_tcp_conn_t;
```

### 4. 修改 `tcp.c` — 集成帧封装

**发包路径** (`hx_tcp_send_segment`):
- 先 `hx_tcp_build_segment()` 构建 TCP segment 到临时缓冲区
- 再 `hx_net_build_frame()` 包上 Eth+IP 头写入最终 pkt buffer
- MSS 计算要减去 Eth+IP 头的开销

**收包路径** (`hx_tcp_input`):
- 新增 `hx_tcp_input_frame()` 函数，接收完整 L2 帧
- 调用 `hx_net_parse_frame()` 剥离帧头
- 构造临时 `hx_pkt_t` 指向 TCP segment
- 调用现有 `hx_tcp_input()` 处理

保留现有 `hx_tcp_input()` 接口不变（接收纯 TCP segment），新增 `hx_tcp_input_frame()` 接收完整帧。这样现有测试可以继续用纯 TCP segment 测试状态机逻辑。

### 5. 测试

**test_net.c**:
- 字节序转换正确性
- IP checksum 已知向量验证
- TCP checksum 已知向量验证
- build_frame + parse_frame 往返一致性
- 畸形帧拒绝（短帧、错误 ether_type、错误 protocol）

**test_tcp.c 适配**:
- 现有测试不变（继续用纯 TCP segment 测试状态机）
- 新增 1-2 个测试用 `hx_tcp_input_frame()` 验证完整帧路径

---

## 验证

```bash
meson setup build && ninja -C build && ninja -C build test
```

预期：所有现有测试 + 新增 test_net 全部通过。
