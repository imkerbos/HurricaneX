# RX 包生命周期修复 — caller-frees 模型

## 问题

`hx_tcp_input()` 处理完 RX 包后不释放，DPDK 模式下 mbuf 泄漏。约 8191 个包后 mbuf pool 耗尽，RX 彻底停摆。

Mock 模式下测试没暴露问题，因为 mock loopback ring 存的是指针，mempool 在测试结束时整体销毁。

## 设计决策

采用 **caller-frees** 模型：
- `hx_tcp_input()` 保持 `const hx_pkt_t *` 只读语义，不负责释放
- 由上层 RX loop 在调用完协议栈后统一 `hx_pktio_free_pkt()`
- 理由：DPDK 范式一致、将来 HTTP/TLS 叠加时协议层只管解析不管生命周期、方便做包镜像/debug dump

## 改动清单

### 1. `engine/include/hurricane/pktio.h` — 添加所有权文档注释

在 `hx_pktio_rx_burst()` 和 `hx_pktio_free_pkt()` 声明上方补充所有权契约注释，明确 caller-frees 语义。

### 2. `engine/include/hurricane/tcp.h` — `hx_tcp_input()` 文档注释

补充注释说明：此函数不获取包的所有权，调用方负责释放。

### 3. `engine/tests/test_tcp.c` — 修复泄漏

当前有两个测试函数使用了 pktio（`test_three_way_handshake` 和 `test_data_transfer`），它们通过 `hx_pktio_rx_burst()` 取出 TCP 层发送的包，但从未释放。

修复方式：每次 `rx_burst` 取出的包，在使用完后调用 `hx_pktio_free_pkt()` 释放。

具体位置：
- `test_three_way_handshake()`: 两次 `rx_burst` 后各加 `free_pkt`（第 151 行、第 170 行之后）
- `test_data_transfer()`: 一次 `rx_burst` 后加 `free_pkt`（第 203 行之后）
- `test_mock_pktio_loopback()`: 已经手动 `hx_mempool_free`，改用 `hx_pktio_free_pkt` 保持一致

### 4. `engine/tests/test_pktio.c` — 改用 `hx_pktio_free_pkt()`

当前 `test_tx_rx_single`、`test_tx_rx_burst`、`test_fifo_order` 直接调 `hx_mempool_free()` 释放 RX 包的 data。改用 `hx_pktio_free_pkt()` 保持 API 一致性，确保 DPDK 模式下也正确。

### 5. 不改动的文件

- `engine/src/tcp.c` — `hx_tcp_input()` 不变，保持只读语义
- `engine/src/pktio_mock.c` — 不变
- `engine/src/pktio_dpdk.c` — 不变
- `engine/tests/smoke_dpdk.c` — 已经正确 free，不需要改

## 文件清单

| 操作 | 文件 | 改动 |
|------|------|------|
| 修改 | `engine/include/hurricane/pktio.h` | 所有权契约注释 |
| 修改 | `engine/include/hurricane/tcp.h` | `hx_tcp_input` 不获取所有权注释 |
| 修改 | `engine/tests/test_tcp.c` | RX 包用完后 `free_pkt` |
| 修改 | `engine/tests/test_pktio.c` | `mempool_free` → `free_pkt` |

## 验证

```bash
rm -rf build && meson setup build && ninja -C build && ninja -C build test
# 预期：全部通过，ASan 无泄漏报告
```
