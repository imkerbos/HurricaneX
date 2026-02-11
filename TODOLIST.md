# HurricaneX TODO List

## Phase 1：项目骨架搭建

### 已完成

- [x] 创建完整目录结构
- [x] C 引擎头文件：`common.h`, `config.h`, `mempool.h`, `pktio.h`, `tcp.h`, `http.h`, `tls.h`
- [x] C 引擎实现：`mempool.c`（free-list 内存池）, `common.c`, `config.c`, `pktio.c`（抽象层）
- [x] Mock 后端：`pktio_mock.c`（loopback 环形缓冲区）
- [x] HTTP 模块：`http.c`（请求构造 + 响应解析）
- [x] TCP 模块：`tcp.c`（状态机骨架 + 状态转换）
- [x] TLS 模块：`tls.c`（接口骨架）
- [x] Meson 构建系统（`meson setup build && ninja -C build` 编译通过）
- [x] C 单元测试：`test_http.c`（6 项）、`test_tcp.c`（6 项），全部通过
- [x] Go module 初始化（`github.com/kerbos/hurricanex`）
- [x] CLI 入口：`hurricane`（run / preflight）、`hurricane-ctl`（deploy / scale / monitor）
- [x] 配置加载：`internal/config/` YAML 解析 + 默认值
- [x] 预检框架：`internal/preflight/` 5 项检查骨架
- [x] 调度器骨架：`internal/scheduler/` 节点注册 / 确认 / 查询
- [x] gRPC Proto 定义：`api/proto/hurricane.proto`
- [x] 默认配置模板：`configs/hurricane.yaml`

### 待完成

- [ ] Meson 构建警告修复：Clang + ASan 与 `b_lundef` 冲突，需设置 `b_lundef=false`
- [ ] HTTP 响应解析补全：解析 `Content-Length`、`Connection` 头字段
- [ ] TCP 状态机核心实现：
  - [ ] SYN 包构造与发送
  - [ ] ISN（初始序列号）生成
  - [ ] 数据分段与发送
  - [ ] 输入包解析与状态转换（SYN-ACK → ESTABLISHED、FIN 处理等）
  - [ ] FIN 包构造与发送
- [ ] TLS 引擎集成 OpenSSL：
  - [ ] SSL_CTX 初始化
  - [ ] 自定义 BIO 对接 `hx_tcp_send` / `hx_tcp_input`
  - [ ] SSL_write / SSL_read 实现
- [ ] Preflight 各检查项实现（当前全部返回 "not implemented"）：
  - [ ] hugepage 检测
  - [ ] NIC 驱动检测
  - [ ] CPU/NUMA 拓扑检测
  - [ ] 权限检测（root / CAP_NET_ADMIN）
  - [ ] 依赖库检测（libdpdk / libnuma / OpenSSL）
- [ ] 补充更多单元测试：mempool 测试、pktio mock 独立测试
- [ ] Go 单元测试：config 加载测试、scheduler 测试
- [ ] Proto 生成 Go 代码（protoc + protoc-gen-go-grpc）
- [ ] gRPC server/client 骨架实现
- [ ] Prometheus 指标模块骨架（`metrics/`）
- [ ] CI 配置（GitHub Actions：C 构建 + 测试、Go 构建 + lint）

### Bug / 已知问题

- [x] `mempool.c` 缺少 `#include <stdio.h>` 导致 `snprintf` 编译失败（已修复）

---

## Phase 2：Linux DPDK 环境搭建与联调

### 1. 硬件准备

- [ ] 准备 Linux 裸金属服务器（建议：16核+、64GB+ 内存）
- [ ] 确认网卡型号支持 DPDK（Intel 82599/X710/E810、Mellanox CX-5/CX-6 等）
- [ ] 确认网卡支持 SR-IOV（可选，用于多队列隔离）
- [ ] 确认 NUMA 拓扑，网卡与 CPU socket 亲和关系

### 2. 操作系统配置

- [ ] 安装 Linux 发行版（推荐 Ubuntu 22.04 LTS 或 Rocky Linux 9）
- [ ] 内核启动参数配置：
  - `iommu=pt intel_iommu=on`（Intel 平台）
  - `default_hugepagesz=1G hugepagesz=1G hugepages=32`（根据内存调整）
  - `isolcpus=2-15`（隔离 CPU 核给 DPDK 使用，根据实际核数调整）
- [ ] 关闭 irqbalance 服务
- [ ] 配置 hugepage 挂载：`/dev/hugepages`

### 3. DPDK 编译安装

- [ ] 安装编译依赖：`gcc, make, meson, ninja, python3, pyelftools, libnuma-dev, libpcap-dev`
- [ ] 下载 DPDK 源码（建议 23.11 LTS 或更新的稳定版）
- [ ] 使用 meson + ninja 编译安装
- [ ] 验证安装：`pkg-config --modversion libdpdk`

### 4. 网卡绑定

- [ ] 加载 DPDK 驱动模块（推荐 `vfio-pci`，或 `igb_uio`）
- [ ] 使用 `dpdk-devbind.py` 查看网卡状态
- [ ] 将目标网卡从内核驱动解绑并绑定到 DPDK 驱动
- [ ] 确认绑定成功：`dpdk-devbind.py --status`

### 5. 验证 DPDK 环境

- [ ] 运行 `dpdk-testpmd` 确认收发包正常
- [ ] 运行 `dpdk-l2fwd` 验证转发性能
- [ ] 确认单核 PPS 达到预期基准

### 6. HurricaneX 引擎联调

- [ ] 将引擎代码迁移到 Linux 服务器
- [ ] 编译链接 DPDK 库（meson 配置 `pkg-config --cflags --libs libdpdk`）
- [ ] 实现真实 DPDK pktio 后端（替换 mock）
- [ ] 单核单队列基准测试
- [ ] 多核多队列扩展测试
- [ ] Preflight 模块在真实环境下的验证

### 7. 性能调优

- [ ] CPU 频率锁定（关闭 C-state、P-state）
- [ ] 内存大页调优（1G vs 2M hugepage 对比）
- [ ] 网卡 RSS 哈希配置
- [ ] burst size 调优
- [ ] 实测 HTTP CPS / HTTPS CPS 并记录基准数据
