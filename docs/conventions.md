# HurricaneX 编码规范与最佳实践

本文档是 HurricaneX 项目的**唯一权威编码规范**，所有代码提交必须遵守。

---

## 1. 日志格式标准（Go + C 共用）

所有日志输出使用 **JSON ndjson 格式**（每行一个 JSON 对象），便于机器解析和日志聚合。

### 1.1 必填字段

```json
{"ts":"2026-02-12T03:14:15.926535Z","level":"info","component":"tcp","msg":"connection established"}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `ts` | string | ISO 8601 时间戳，UTC，微秒精度 |
| `level` | string | `debug`, `info`, `warn`, `error`, `fatal` |
| `component` | string | 子系统名称（见下方列表） |
| `msg` | string | 可读消息，小写，无结尾句号 |

### 1.2 可选字段

| 字段 | 类型 | 使用场景 |
|------|------|----------|
| `node_id` | string | 引擎节点上下文 |
| `task_id` | string | 流量任务上下文 |
| `conn_id` | uint64 | TCP 连接上下文 |
| `err` | string | 错误消息 |
| `latency_us` | float64 | 延迟度量 |
| `src_ip` | string | 网络操作 |
| `dst_ip` | string | 网络操作 |
| `dst_port` | int | 网络操作 |
| `cps` | int64 | 吞吐度量 |
| `bytes` | int64 | 数据传输量 |

### 1.3 Component 名称

`tcp`, `http`, `tls`, `pktio`, `mempool`, `config`, `engine`, `scheduler`, `grpc`, `metrics`, `preflight`, `cli`

### 1.4 日志级别指南

| 级别 | 用途 | 生产环境 |
|------|------|----------|
| `debug` | 内部状态细节，逐包/逐连接事件 | 关闭 |
| `info` | 正常运行事件——启动、关闭、节点注册、任务部署 | 开启 |
| `warn` | 意外但可恢复——重试、性能降级、配置回退 | 开启 |
| `error` | 操作失败——连接失败、TLS 错误、gRPC 调用失败 | 开启 |
| `fatal` | 不可恢复——端口绑定失败、hugepage 内存耗尽 | 开启 |

---

## 2. Go 日志规范（zap）

### 2.1 基本规则

- 使用 `internal/logger` 包（封装 `go.uber.org/zap`）
- **禁止** `fmt.Printf`、`log.Printf` 用于运行时日志
- 性能关键路径使用强类型 `*zap.Logger`
- CLI 命令和初始化代码可使用 `*zap.SugaredLogger`

### 2.2 结构化字段

```go
// 正确: 使用结构化字段
logger.Info("node registered",
    zap.String("node_id", nodeID),
    zap.String("addr", addr),
    zap.Int("workers", workers),
)

// 错误: 使用格式化字符串
logger.Info(fmt.Sprintf("node %s registered at %s", nodeID, addr))
```

### 2.3 子 Logger

在结构体初始化时创建子 logger，而非每次调用时创建：

```go
type Scheduler struct {
    logger *zap.Logger
    // ...
}

func New(logger *zap.Logger) *Scheduler {
    return &Scheduler{
        logger: logger.Named("scheduler"),
    }
}
```

### 2.4 错误日志

必须将 error 作为结构化字段传递：

```go
logger.Error("failed to deploy task",
    zap.String("task_id", taskID),
    zap.Error(err),
)
```

---

## 3. C 日志规范（rte_log 封装）

### 3.1 宏 API

```c
HX_LOG_DEBUG(component, fmt, ...)
HX_LOG_INFO(component, fmt, ...)
HX_LOG_WARN(component, fmt, ...)
HX_LOG_ERROR(component, fmt, ...)
HX_LOG_FATAL(component, fmt, ...)
```

### 3.2 Component 常量

```c
HX_LOG_COMP_TCP, HX_LOG_COMP_HTTP, HX_LOG_COMP_TLS,
HX_LOG_COMP_PKTIO, HX_LOG_COMP_MEMPOOL, HX_LOG_COMP_CONFIG, HX_LOG_COMP_ENGINE
```

### 3.3 使用示例

```c
HX_LOG_INFO(HX_LOG_COMP_TCP, "connection state changed, conn_id=%lu, old=%s, new=%s",
            conn_id, hx_tcp_state_str(old), hx_tcp_state_str(new));
```

### 3.4 设计约束

- 编译时级别过滤：`HX_LOG_LEVEL_MIN`（release: INFO，debug: DEBUG）
- DPDK 模式（`HX_USE_DPDK`）走 `rte_log()`，standalone 走 `fprintf(stderr)`
- 栈上缓冲区 1024 字节，截断不分配
- 线程安全：每次调用使用栈局部缓冲区
- **禁止** `printf` 用于运行时日志（测试文件输出 PASS/FAIL 除外）

---

## 4. gRPC 规范

### 4.1 Proto 风格

- 遵循 Google proto3 style guide
- Service 名称：PascalCase（`NodeService`）
- RPC 名称：PascalCase 动词（`Register`）
- Message 名称：PascalCase（`RegisterRequest`）
- Field 名称：snake_case（`node_id`）
- Enum 值：UPPER_SNAKE_CASE + 类型前缀（`NODE_ONLINE`）
- 每个 enum 必须有零值 `*_UNKNOWN` 或 `*_UNSPECIFIED`

### 4.2 mTLS 认证

```yaml
grpc:
  tls:
    ca_cert: "/etc/hurricanex/certs/ca.pem"
    server_cert: "/etc/hurricanex/certs/server.pem"
    server_key: "/etc/hurricanex/certs/server-key.pem"
    client_cert: "/etc/hurricanex/certs/client.pem"
    client_key: "/etc/hurricanex/certs/client-key.pem"
```

- Server 端：加载 CA 证书验证客户端，使用 `tls.RequireAndVerifyClientCert`
- Client 端：加载 CA 证书验证服务端，携带自身证书
- 最低 TLS 版本：TLS 1.2

### 4.3 Server 拦截器链（顺序固定）

1. **recovery** — 捕获 panic，返回 `codes.Internal`
2. **logging** — 记录每个 RPC 调用（method, duration, status）
3. **metrics** — Prometheus 计数（per method + status）

### 4.4 Client 拦截器

1. **logging** — 记录出站 RPC 调用
2. **retry** — `Unavailable` / `DeadlineExceeded` 时指数退避（初始 100ms，max 2s，max 3 次）

### 4.5 错误映射

| 内部错误 | gRPC Status Code |
|----------|------------------|
| 节点未找到 | `codes.NotFound` |
| 无效配置/请求 | `codes.InvalidArgument` |
| 节点已注册 | `codes.AlreadyExists` |
| 任务仍在运行 | `codes.FailedPrecondition` |
| 超时 | `codes.DeadlineExceeded` |
| 节点不可达 | `codes.Unavailable` |
| 认证失败 | `codes.Unauthenticated` |
| 权限不足 | `codes.PermissionDenied` |
| 未预期 panic | `codes.Internal` |

**禁止** 将 `codes.Internal` 作为万金油使用。每个错误必须映射到最具体的 status code。

### 4.6 超时策略

| 场景 | Deadline |
|------|----------|
| Unary 调用（默认） | 5 秒 |
| Heartbeat | 3 秒 |
| Deploy（多节点协调） | 30 秒 |
| Metrics 流 | 无 deadline + keepalive ping 10 秒 |

---

## 5. 错误处理

### 5.1 Go

- 始终包装错误上下文：`fmt.Errorf("register node %s: %w", id, err)`
- 永不忽略返回的 error。若有意忽略，赋值 `_` 并注释：`_ = conn.Close() // best-effort cleanup`
- 已知错误条件使用 sentinel error：`var ErrNodeNotFound = errors.New("node not found")`
- 使用 `errors.Is()` / `errors.As()` 检查，**永不**字符串比较
- gRPC handler 中将内部错误转为 `status.Errorf()` 后返回

### 5.2 C

- 所有可失败函数必须返回 `hx_result_t`
- 调用方必须检查每个返回值
- 函数开头先 NULL 检查参数
- 新增错误码时同步更新 `common.h` enum 和 `common.c` `hx_strerror()`

```c
hx_result_t hx_foo_init(hx_foo_t *foo, const char *name)
{
    if (!foo || !name)
        return HX_ERR_INVAL;

    /* ... */
    if (failed) {
        HX_LOG_ERROR(HX_LOG_COMP_FOO, "init failed: %s", hx_strerror(rc));
        return rc;
    }
    return HX_OK;
}
```

---

## 6. 代码组织与命名

### 6.1 Go

```
cmd/              CLI 入口
internal/         内部包（不可外部引用）
api/proto/        gRPC proto 定义 + 生成代码
configs/          配置模板
docs/             文档
```

- 包名小写单数：`config`, `logger`, `scheduler`
- 导出：CamelCase；非导出：camelCase
- 接口命名：`-er` 后缀（`Reader`, `Scheduler`）

### 6.2 C

```
engine/include/hurricane/*.h    公共头文件
engine/src/*.c                  实现文件
engine/tests/test_*.c           单元测试
```

- 公共符号：`hx_` 前缀
- 函数/变量：`snake_case`
- 类型：`_t` 后缀
- 宏/常量：`HX_` 前缀 + `UPPER_SNAKE_CASE`
- 不透明类型用于封装（`hx_mempool_t`、`hx_tls_ctx_t`）

### 6.3 Proto

- Service / Message / RPC：PascalCase
- Field：snake_case
- Enum 值：UPPER_SNAKE_CASE（带类型前缀）

### 6.4 配置

- YAML key：`snake_case`
- Go struct tag：`yaml:"snake_case"`

### 6.5 Metrics

- 前缀：`hurricanex_`
- 命名：`snake_case`

---

## 7. 测试规范

### 7.1 C 测试

- 每模块一个测试文件：`test_<module>.c`
- 每个测试函数：`static void test_<name>(void)`
- 使用 `assert()` 断言
- 成功输出：`"  PASS: test_<name>\n"`
- main 函数运行所有测试并打印总结
- 在 `engine/tests/meson.build` 中注册
- 测试使用 mock 后端，不依赖 DPDK

### 7.2 Go 测试

- Table-driven 测试 + `t.Run()` 子测试
- 测试文件：`*_test.go` 同包
- Mock 外部依赖的接口
- 集成测试使用 build tag：`//go:build integration`

```go
func TestScheduler_RegisterNode(t *testing.T) {
    tests := []struct {
        name    string
        nodeID  string
        wantErr bool
    }{
        {name: "valid", nodeID: "node-1", wantErr: false},
        {name: "empty id", nodeID: "", wantErr: true},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // ...
        })
    }
}
```

---

## 8. 配置规范

- 统一 YAML 格式，`configs/hurricane.yaml` 为模板
- 所有字段必须有默认值（`applyDefaults()`）
- 启动时调用 `Validate()` 校验，拒绝无效值
- 证书路径支持环境变量覆盖：`HX_GRPC_CA_CERT`, `HX_GRPC_SERVER_CERT` 等
- **永不**将证书或密钥提交到仓库

---

## 9. Prometheus 指标

### 9.1 架构

Pull 模式：Go 控制平面运行 HTTP server 在 `/metrics` 端点，Prometheus 主动拉取。引擎节点通过 `MetricsService.ReportMetrics()` gRPC 流式上报原始指标到控制平面，由控制平面聚合后暴露。

### 9.2 标准指标

| 指标名称 | 类型 | 标签 | 说明 |
|----------|------|------|------|
| `hurricanex_connections_active` | Gauge | `node_id` | 当前活跃连接 |
| `hurricanex_connections_total` | Counter | `node_id` | 总建立连接数 |
| `hurricanex_cps` | Gauge | `node_id` | 当前每秒连接数 |
| `hurricanex_bytes_sent_total` | Counter | `node_id` | 总发送字节 |
| `hurricanex_bytes_recv_total` | Counter | `node_id` | 总接收字节 |
| `hurricanex_errors_total` | Counter | `node_id`, `error_type` | 按类型统计的错误总数 |
| `hurricanex_latency_us` | Histogram | `node_id` | 连接延迟（微秒） |
| `hurricanex_grpc_requests_total` | Counter | `method`, `status` | gRPC 请求计数 |
| `hurricanex_grpc_request_duration_seconds` | Histogram | `method` | gRPC 请求延迟 |
| `hurricanex_nodes_active` | Gauge | — | 活跃引擎节点数 |
| `hurricanex_tasks_active` | Gauge | — | 活跃流量任务数 |

### 9.3 端点

- `/metrics` — Prometheus 指标
- `/healthz` — 健康检查（返回 200 OK）
