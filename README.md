# Vulpini

高性能代理服务器，支持 SOCKS5 与 HTTP 协议，具备智能流量分析、IP 池管理和实时监控能力。

项目分为两个部分：

- **Vulpini**（代理核心）— 纯 Rust 实现的代理后端，负责协议处理、流量路由与数据分析
- **Vulpini X**（管理界面）— 基于 Electron 的桌面端，提供可视化控制与实时监控

## 作者

- **zayoka**

本项目使用 [Claude Code](https://claude.ai/code) 辅助构建。

## 技术栈

### 代理核心（vulpini/）

| 技术 | 用途 |
|------|------|
| Rust | 主语言 |
| Tokio | 异步运行时 |
| DashMap | 无锁并发哈希表（IP 统计、行为记录） |
| parking_lot | 高性能 Mutex / RwLock |
| serde / serde_json | 序列化与 JSON 处理 |
| toml | 配置文件解析 |
| uuid | 异常事件唯一 ID |
| rand | IP 随机选择策略 |
| thiserror / anyhow | 错误处理 |

### 管理界面（vulpini-x/）

| 技术 | 用途 |
|------|------|
| Electron | 桌面应用框架 |
| TypeScript | 主语言（原生 DOM，无框架） |
| Vite | 构建工具 |

## 功能

- **双协议支持**：SOCKS5（含用户名/密码认证）与 HTTP/HTTPS 代理
- **IP 池管理**：多 IP 负载均衡，支持轮询、随机、最小连接数、性能优先等策略
- **智能路由**：基于延迟与可靠性动态选路，支持故障自动切换
- **流量分析**：实时统计请求量、字节数、平均延迟（含 p50/p95/p99）、错误率
- **异常检测**：自动识别流量突增、高延迟、高错误率、连接洪泛等异常
- **行为监控**：会话级流量行为分析
- **管理 API**：REST 接口（端口 9090），支持热重载配置
- **桌面 UI**：实时仪表盘、IP 池管理、日志查看、配置编辑

## 项目结构

```
vulpini/                        # 代理核心
├── src/
│   ├── main.rs                 # 启动入口（SOCKS5 + HTTP + 管理 API 三服务器）
│   ├── lib.rs                  # 库导出
│   ├── protocol/               # SOCKS5 / HTTP 协议实现
│   ├── traffic_analyzer/       # 流量统计与延迟分析
│   ├── ip_manager/             # IP 池增删查、健康检查、轮换策略
│   ├── smart_router/           # 动态路由决策与负载均衡
│   ├── behavior_monitor/       # 会话行为追踪
│   ├── anomaly_detector/       # 异常检测
│   ├── api/                    # HTTP 管理 API（端口 9090）
│   ├── config/                 # TOML 配置与热重载
│   └── logger/                 # 结构化日志
├── tests/                      # 集成测试
├── Cargo.toml
└── vulpini.example.toml        # 配置示例

vulpini-x/                      # 管理界面
├── electron/
│   ├── main/                   # Electron 主进程（启动后端、创建窗口）
│   └── renderer/               # 渲染进程
│       ├── src/
│       │   ├── App.ts          # 主界面（原生 TypeScript DOM）
│       │   ├── main.ts         # 入口
│       │   └── styles.css      # 样式
│       └── index.html
├── package.json
├── vite.config.ts
└── tsconfig.json

shared/
└── types.ts                    # 前后端共享 TypeScript 类型定义
```

## 快速开始

### 环境要求

- Rust 1.75+
- Node.js 18+

### 构建代理核心

```bash
cd vulpini
cargo build --release
```

### 构建管理界面

```bash
cd vulpini-x
npm install
npm run build
```

### 运行

**仅运行代理核心：**

```bash
cd vulpini
cargo run --release                  # 使用默认 vulpini.toml
cargo run --release -- config.toml  # 使用自定义配置
```

**开发模式（界面 + 后端）：**

```bash
cd vulpini-x
npm run dev
```

## 配置

复制示例配置并按需修改：

```bash
cp vulpini/vulpini.example.toml vulpini/vulpini.toml
```

配置分为以下几节：`socks5`、`http_proxy`、`ip_pool`、`routing`、`anomaly_detection`、`logging`。

## API 接口

管理 API 默认监听 `http://localhost:9090`：

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/stats` | 流量统计 |
| GET | `/api/ips` | IP 池列表 |
| POST | `/api/ips` | 添加 IP |
| DELETE | `/api/ips/{address}` | 删除 IP |
| GET | `/api/anomalies` | 异常事件 |
| GET | `/api/health` | 健康检查 |
| POST | `/api/config/reload` | 热重载配置 |

## 测试

```bash
cd vulpini
cargo test                      # 运行全部测试
cargo test --test config        # 运行指定集成测试
```

## 许可证

[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html)

---

## 免责声明

**本软件仅供学习、研究与合法用途。**

使用本软件即表示您同意：

1. 您将严格遵守所在国家/地区的法律法规，不将本软件用于任何违法活动。
2. 本软件作者及贡献者不对因使用或滥用本软件而产生的任何直接或间接损失承担责任，包括但不限于数据丢失、业务中断、法律纠纷等。
3. 在某些国家和地区，代理软件的使用可能受到法律限制，用户需自行承担合规责任。
4. 本软件不内置任何规避网络审查的功能，亦不对特定政治目的提供支持。

**请合法、负责任地使用本软件。**
