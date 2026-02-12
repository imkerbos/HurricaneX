# 🌪 流量飓风（HurricaneX）

> 基于 AF_XDP 的分布式 L7 高性能流量仿真与攻防验证平台

---

## 📖 项目简介

流量飓风是一款面向 CDN / WAF / 高防系统 / 负载均衡设备的超高性能流量生成与攻防验证平台。

项目设计灵感来源于 dperf，在其高性能 L4 架构基础上扩展升级，构建面向 L7 场景的分布式攻防仿真系统。采用 AF_XDP 内核旁路技术，无需 DPDK 即可在普通云服务器上实现高性能收发包。

核心能力：

- 域名级 HTTP/HTTPS 测试
- TLS 握手压力模型
- CC 行为仿真
- 分布式节点池调度
- 超大规模并发连接模拟

---

## 🎯 设计目标

| 指标 | 目标值 | 备注 |
|------|--------|------|
| HTTP CPS | 待测试验证 | L7 层含协议解析开销，以实测为准 |
| HTTPS CPS | 待测试验证 | TLS 握手开销显著，需单独评估 |
| 单核 PPS | 5-8M | AF_XDP 零拷贝模式 |
| 单节点并发连接 | 100万+ | 取决于内存配置 |
| 延迟精度 | 微秒级 | |
| 分布式扩展 | 横向扩展 | 多节点线性叠加 |

---

## 🏗 系统架构

```
                   控制平面
           （调度 / API / 指标聚合）
                        |
------------------------------------------------------
|              |              |                    |
节点1         节点2         节点3               节点N
(AF_XDP引擎) (AF_XDP引擎) (AF_XDP引擎)       (AF_XDP引擎)
                        |
                  目标系统
        (CDN / WAF / 高防 / 负载均衡)
```

### 数据平面架构

```
┌─────────────────────────────────────────────┐
│  work_space (per-worker 主循环)              │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐ │
│  │ socket   │  │ mbuf     │  │ TX queue  │ │
│  │ table    │  │ cache    │  │ (4096)    │ │
│  │ O(1)查找 │  │ 3模板    │  │ batch-8   │ │
│  └──────────┘  └──────────┘  └───────────┘ │
│  ┌──────────────────────────────────────┐   │
│  │ TCP 状态机 + HTTP 内联处理           │   │
│  └──────────────────────────────────────┘   │
└──────────────────┬──────────────────────────┘
                   │ pktio vtable
┌──────────────────┴──────────────────────────┐
│  pktio_xdp (AF_XDP)                         │
│  UMEM 4096 frames × 2048 bytes              │
│  lock-free 四环: fill / comp / rx / tx      │
│  零拷贝 TX/RX                                │
└─────────────────────────────────────────────┘
```

---

## 🚀 快速开始

### 环境要求

- Linux 5.4+（AF_XDP 支持）
- GCC 或 Clang
- root 权限或 CAP_NET_RAW

### 1. 安装系统依赖

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install -y build-essential pkg-config python3-pip \
    meson ninja-build \
    libssl-dev libxdp-dev libbpf-dev

# CentOS / RHEL / Amazon Linux 2
sudo yum groupinstall -y "Development Tools"
sudo yum install -y pkg-config python3-pip \
    openssl-devel libxdp-devel libbpf-devel
pip3 install meson ninja

# 如果包管理器没有 meson/ninja，用 pip 安装
pip3 install meson ninja
```

### 2. 编译

```bash
# 首次编译
meson setup build
ninja -C build

# 运行测试
ninja -C build test
```

预期输出：
```
Message: libxdp + libbpf found — building with AF_XDP pktio backend
...
Ok:  10
Fail: 0
```

### 3. 运行 HTTP 压测

```bash
# 查看网关 MAC（目标的下一跳）
ip neigh show

# L7 HTTP 压测
sudo ./build/engine/tests/bench_http -- \
    -I eth0 \
    -M <网关MAC> \
    -U "http://目标地址/路径" \
    -C 1000 -D 30

# L4 TCP 握手压测
sudo ./build/engine/tests/bench_l4 -- \
    eth0 <网关MAC> <目标IP> 80 1000 30
```

### bench_http 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-I <ifname>` | 网卡接口（必填） | - |
| `-M <mac>` | 网关 MAC（必填） | - |
| `-U <url>` | 目标 URL（必填） | - |
| `-S <ip>` | 源 IP（可选，自动检测） | 网卡 IP |
| `-H <header>` | 额外 HTTP 头（可重复） | - |
| `-C <num>` | 并发连接数 | 10 |
| `-D <sec>` | 持续时间（秒） | 10 |
| `-K <num>` | 每连接请求数（0=无限） | 1 |
| `-B <num>` | 批量发起大小 | 64 |

### bench_l4 参数说明

```
sudo ./bench_l4 -- <网卡> <目标MAC> <目标IP> [端口] [连接数] [时长秒]
```

---

## 📂 目录结构

```
HurricaneX/
├── cmd/                  # CLI 入口（hurricane, hurricane-ctl）
├── engine/               # 流量引擎核心
│   ├── include/hurricane/  # 头文件
│   │   ├── pktio.h         # pktio vtable 抽象层
│   │   ├── socket.h        # 64字节 socket 结构
│   │   ├── socket_table.h  # O(1) 确定性查找表
│   │   ├── mbuf_cache.h    # 包模板缓存（SYN/DATA/ACK）
│   │   ├── work_space.h    # per-worker 上下文 + TX 队列
│   │   ├── tcp.h           # TCP 状态机
│   │   └── ...
│   ├── src/
│   │   ├── pktio_xdp.c    # AF_XDP 后端（零拷贝）
│   │   ├── pktio_mock.c   # Mock 后端（测试用）
│   │   ├── work_space.c   # 主循环 + TCP/HTTP 处理
│   │   └── ...
│   └── tests/
│       ├── test_*.c        # 单元测试（10个）
│       ├── bench_http.c    # L7 HTTP 压测
│       └── bench_l4.c      # L4 TCP 压测
├── scheduler/            # 分布式节点调度
├── metrics/              # Prometheus 指标采集与输出
├── configs/              # YAML 配置文件
└── docs/                 # 文档
```

---

## ⚙ 技术栈

| 组件 | 技术 | 说明 |
|------|------|------|
| 数据平面 | C + AF_XDP | 内核旁路、零拷贝、自定义 TCP 状态机 |
| 控制平面 | Go | 调度、API、指标聚合 |
| 通信 | gRPC + mTLS | 双向证书认证 |
| 指标 | Prometheus | Pull 模式 |
| 可观测 | eBPF | 扩展探针 |
| 配置 | YAML | 统一格式 |

---

## 🔬 典型应用场景

- CDN 高防能力验证
- WAF CC 拦截测试
- 云负载均衡容量验证
- 抗 DDoS 设备测试
- L7 攻防实验室环境验证
- 安全红蓝对抗演练

---

## ⚠ 合规与免责声明

本项目仅限以下用途：

- 经授权的安全测试与红蓝对抗演练
- CDN / WAF / 高防 / 负载均衡等防御系统的能力验证
- 实验室环境下的性能评估与压力测试

**使用限制：**

- 使用者必须在获得明确授权的目标环境中运行本工具
- 严禁将本工具用于未经授权的网络攻击或任何违反法律法规的行为
- 因使用本工具产生的一切法律责任由使用者自行承担
- 本项目作者及贡献者不对任何滥用行为承担责任

---

## 👨‍💻 作者

Kerbos
DevOps / 高性能网络 / 安全攻防工程师
