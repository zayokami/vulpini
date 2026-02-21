<div align="center">

<img src="assts/img/logo.jpeg" alt="Vulpini Logo" width="200" />

# Vulpini

A rule-based network utility built with Rust.

基于 Rust 的规则驱动网络工具平台。

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

</div>

---

## Overview · 概述

Vulpini consists of two independent components:

| Component | Description |
|-----------|-------------|
| **Vulpini** (Core) | Network kernel written in pure Rust — protocol handling, traffic routing, and analytics |
| **VulpiniX** (GUI) | Desktop application for visual management and real-time monitoring |

> Built with [Claude Code](https://claude.ai/code).
> Author: **zayoka**

---

## Vulpini Core

### Features · 特性

- Local SOCKS5 server with username/password authentication
- Local HTTP/HTTPS server with authentication support
- IP pool with multiple load-balancing strategies (round-robin, random, least-connections, performance-based)
- Rule-based routing with latency and reliability thresholds, automatic failover
- Real-time traffic analytics — request rate, throughput, latency percentiles (p50/p95/p99), error rate
- Anomaly detection — traffic spikes, high latency, error surges, connection floods
- Session-level behavior monitoring
- RESTful management API (`:9090`) with hot-reload configuration
- TOML-based configuration

### Tech Stack

| Dependency | Purpose |
|------------|---------|
| Tokio | Async runtime |
| Axum | API server framework |
| DashMap | Lock-free concurrent hashmap |
| parking_lot | High-performance mutexes |
| serde / serde_json | Serialization |
| toml | Configuration parsing |
| uuid | Event identification |
| rand | Random selection strategies |
| thiserror / anyhow | Error handling |

### Build & Run · 构建与运行

```bash
cd vulpini
cargo build --release

# Run with default config
cargo run --release

# Run with custom config
cargo run --release -- config.toml

# Run tests
cargo test
```

### Configuration · 配置

```bash
cp vulpini/vulpini.example.toml vulpini/vulpini.toml
```

| Section | Description |
|---------|-------------|
| `socks5` | SOCKS5 listen address, port, authentication |
| `http_proxy` | HTTP listen address, port, authentication |
| `ip_pool` | IP list, health check interval, rotation strategy |
| `routing` | Latency/reliability thresholds, load-balancing algorithm |
| `anomaly_detection` | Detection thresholds and check interval |
| `logging` | Log level, file/console output |

### API Endpoints

Default: `http://localhost:9090`

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/stats` | Traffic statistics |
| `GET` | `/api/ips` | List IPs |
| `POST` | `/api/ips` | Add IP |
| `PUT` | `/api/ips/{address}` | Update IP |
| `PATCH` | `/api/ips/{address}` | Toggle IP |
| `DELETE` | `/api/ips/{address}` | Remove IP |
| `POST` | `/api/ips/test-all` | Test all IPs |
| `GET` | `/api/anomalies` | Anomaly events |
| `GET` | `/api/health` | Health check |
| `POST` | `/api/config/reload` | Reload configuration |
| `GET` | `/pac` | PAC file |

### Project Structure · 项目结构

```
vulpini/
├── src/
│   ├── main.rs                 # Entry point (3 concurrent servers)
│   ├── protocol/               # SOCKS5 / HTTP protocol handlers
│   ├── traffic_analyzer/       # Traffic statistics & latency analysis
│   ├── ip_manager/             # IP pool management & rotation
│   ├── smart_router/           # Dynamic routing & load balancing
│   ├── behavior_monitor/       # Session behavior tracking
│   ├── anomaly_detector/       # Anomaly detection engine
│   ├── api/                    # RESTful management API (Axum)
│   ├── config/                 # TOML config with hot-reload
│   └── logger/                 # Structured logging
├── tests/
└── vulpini.example.toml
```

---

## VulpiniX

Desktop GUI for managing Vulpini Core. Currently built with Electron + TypeScript; **migrating to Tauri**.

```
vulpini-x/                      # Current (Electron)
shared/types.ts                 # Shared type definitions
```

---

## License · 许可证

[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html)

---

## Disclaimer · 免责声明

> **This software is provided for educational, research, and lawful purposes only.**

By using this software, you agree to the following:

1. **Lawful Use**: You shall comply with all applicable laws and regulations in your jurisdiction. This software must not be used for any illegal activity.
2. **No Liability**: The authors and contributors are not liable for any direct or indirect damages resulting from the use or misuse of this software.
3. **Compliance**: The use of network tools may be subject to legal restrictions in certain jurisdictions. Users are solely responsible for ensuring compliance.
4. **No Donations**: This project does not accept donations of any kind. Any donation channel claiming to represent this project is fraudulent.
5. **No Warranty**: This software is provided "as is" without warranty of any kind, express or implied.

**Please use this software responsibly.**
