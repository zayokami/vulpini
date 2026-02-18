<div align="center">

<img src="assts/img/logo.jpeg" alt="Vulpini Logo" width="220" />

# Vulpini

**高性能代理服务器 · SOCKS5 & HTTP · 智能流量分析 · IP 池管理**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Electron](https://img.shields.io/badge/Electron-Latest-47848F.svg)](https://www.electronjs.org)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

</div>

---

Vulpini 分为两个独立部分：

| 组件 | 描述 |
|------|------|
| **Vulpini**（代理核心） | 纯 Rust 实现，负责协议处理、流量路由与数据分析 |
| **Vulpini X**（管理界面） | 基于 Electron 的桌面端，提供可视化控制与实时监控 |

> 本项目使用 [Claude Code](https://claude.ai/code) 辅助构建。
> 作者：**zayoka**

---

## 功能

- **双协议**：SOCKS5（含用户名/密码认证）与 HTTP/HTTPS 代理
- **IP 池管理**：多 IP 负载均衡，支持轮询、随机、最小连接数、性能优先等策略
- **智能路由**：基于延迟与可靠性动态选路，支持故障自动切换
- **流量分析**：实时统计请求量、字节数、平均延迟（p50 / p95 / p99）、错误率
- **异常检测**：自动识别流量突增、高延迟、高错误率、连接洪泛
- **行为监控**：会话级流量行为分析
- **管理 API**：REST 接口（`:9090`），支持热重载配置
- **桌面 UI**：实时仪表盘、IP 池管理、日志查看、配置编辑

---

## 技术栈

<table>
<tr><th>代理核心（vulpini/）</th><th>管理界面（vulpini-x/）</th></tr>
<tr><td>

| 依赖 | 用途 |
|------|------|
| Rust | 主语言 |
| Tokio | 异步运行时 |
| DashMap | 无锁并发哈希表 |
| parking_lot | 高性能互斥锁 |
| serde / serde_json | 序列化 |
| toml | 配置解析 |
| uuid | 事件唯一 ID |
| rand | 随机选路策略 |
| thiserror / anyhow | 错误处理 |

</td><td>

| 依赖 | 用途 |
|------|------|
| Electron | 桌面应用框架 |
| TypeScript | 主语言（原生 DOM） |
| Vite | 构建工具 |

</td></tr>
</table>

---

## 快速开始

### 环境要求

- Rust `1.75+`
- Node.js `18+`

### 构建

```bash
# 代理核心
cd vulpini
cargo build --release

# 管理界面
cd vulpini-x
npm install && npm run build
```

### 运行

```bash
# 仅运行代理核心
cd vulpini
cargo run --release                   # 默认读取 vulpini.toml
cargo run --release -- config.toml   # 指定配置文件

# 开发模式（界面 + 后端）
cd vulpini-x
npm run dev
```

### 测试

```bash
cd vulpini
cargo test                   # 全部测试
cargo test --test config     # 指定集成测试文件
```

---

## 配置

```bash
cp vulpini/vulpini.example.toml vulpini/vulpini.toml
```

配置文件分为以下几节：

| 节 | 说明 |
|----|------|
| `socks5` | SOCKS5 监听地址、端口、认证 |
| `http_proxy` | HTTP 代理监听地址、端口、认证 |
| `ip_pool` | IP 池列表、健康检查、轮换策略 |
| `routing` | 延迟阈值、可靠性阈值、负载均衡算法 |
| `anomaly_detection` | 异常检测阈值与检测间隔 |
| `logging` | 日志级别、文件/控制台输出 |

---

## 管理 API

默认监听 `http://localhost:9090`

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/stats` | 流量统计 |
| `GET` | `/api/ips` | IP 池列表 |
| `POST` | `/api/ips` | 添加 IP |
| `DELETE` | `/api/ips/{address}` | 删除 IP |
| `GET` | `/api/anomalies` | 异常事件 |
| `GET` | `/api/health` | 健康检查 |
| `POST` | `/api/config/reload` | 热重载配置 |

---

## 项目结构

```
vulpini/                        # 代理核心
├── src/
│   ├── main.rs                 # 启动入口（三服务器并发）
│   ├── protocol/               # SOCKS5 / HTTP 协议实现
│   ├── traffic_analyzer/       # 流量统计与延迟分析
│   ├── ip_manager/             # IP 池管理与轮换策略
│   ├── smart_router/           # 动态路由与负载均衡
│   ├── behavior_monitor/       # 会话行为追踪
│   ├── anomaly_detector/       # 异常检测
│   ├── api/                    # HTTP 管理 API
│   ├── config/                 # TOML 配置与热重载
│   └── logger/                 # 结构化日志
├── tests/
└── vulpini.example.toml

vulpini-x/                      # 管理界面
├── electron/
│   ├── main/                   # 主进程（启动后端、创建窗口）
│   └── renderer/src/
│       ├── App.ts              # 主界面（原生 TypeScript DOM）
│       └── styles.css
└── ...

shared/
└── types.ts                    # 前后端共享类型定义
```

---

## 许可证

[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html)

---

## 免责声明

> **本软件仅供学习、研究与合法用途。**

使用本软件即表示您同意以下条款：

1. **合法使用**：您将严格遵守所在国家/地区的法律法规，不将本软件用于任何违法活动，包括但不限于网络攻击、数据窃取、侵犯隐私等。
2. **免责**：本软件作者及贡献者不对因使用或滥用本软件而产生的任何直接或间接损失承担责任，包括但不限于数据丢失、业务中断、安全事故、法律纠纷等。
3. **合规责任**：在某些国家和地区，代理软件的使用可能受到法律限制，用户需自行了解并承担合规责任，作者不承担因用户违规使用而产生的任何法律后果。
4. **无政治立场**：本软件不内置任何规避网络审查的功能，亦不对任何特定政治目的、意识形态或组织提供支持。
5. **无捐赠**：本软件不接受任何形式的捐赠，包括但不限于法定货币、虚拟货币、加密货币、电子钱包转账等。任何以本项目名义发起的捐赠渠道均为诈骗，请提高警惕。
6. **无担保**：本软件按"现状"提供，不附带任何明示或暗示的担保，包括但不限于适销性、特定用途适用性及不侵权担保。

**请合法、负责任地使用本软件。**
