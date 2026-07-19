<div align="center">

<img src="assts/img/logo.jpeg" alt="Vulpini Logo" width="200" />

# Vulpini

A proxy client with a self-contained Rust core.

基于纯 Rust 自研核心的代理客户端。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

</div>

---

## Overview · 概述

Vulpini is a desktop proxy client built around a hand-written Rust proxy engine —
no embedded third-party cores. The engine handles inbounds, outbound protocols,
rule routing, node/subscription management, and traffic stats; the desktop shell
is Tauri 2 + React.

Vulpini 围绕手写的 Rust 代理引擎构建，不嵌入任何第三方核心。引擎负责入站、
出站协议、规则路由、节点/订阅管理和流量统计；桌面端为 Tauri 2 + React。

> Built with [Claude Code](https://claude.ai/code).
> Author: **zayoka**

## Repository Layout · 仓库结构

```
crates/
├── vulpini-core/      # Proxy engine: inbounds, outbounds, router, nodes, stats
├── vulpini-rules/     # geosite.dat / geoip.dat (v2ray format) parsing + matchers
├── vulpini-sysproxy/  # Windows system proxy (registry + WinINet refresh)
└── vulpini-cli/       # Headless CLI shell for the core (dev & testing)
vulpini-x/             # Desktop app (Tauri 2 + React) — arrives at milestone M10
```

## Build & Test · 构建与测试

```bash
cargo build --workspace
cargo test --workspace
cargo run -p vulpini-cli -- --help
```

## Status · 状态

The project was rebuilt from scratch (the legacy IP-rotation server was removed).
Development proceeds milestone by milestone; every engine milestone is verifiable
through the CLI before the GUI arrives.

项目已推倒重做（旧的 IP 轮换服务器已删除）。按里程碑推进，引擎的每个
里程碑在 GUI 落地前都可以通过 CLI 验证。

| Milestone | Scope | Status |
|-----------|-------|--------|
| M0 | Workspace, CI, MIT license | Done |
| M1 | Core spine: mixed inbound, direct/block, relay | Planned |
| M2 | Node model, share-link parsers, config store | Planned |
| M3 | Shadowsocks outbound (AEAD) | Planned |
| M4 | Router + geosite/geoip rules | Planned |
| M5–M6 | Trojan, VLESS (+TLS/WS transports) | Planned |
| M7–M9 | Subscriptions, stats/logs/delay, system proxy | Planned |
| M10–M11 | Tauri + React GUI, packaging | Planned |

## License · 许可证

[MIT License](LICENSE)

---

## Disclaimer · 免责声明

> **This software is provided for educational, research, and lawful purposes only.**

By using this software, you agree to comply with all applicable laws and
regulations in your jurisdiction. The authors are not liable for any damages
resulting from the use or misuse of this software.

**Please use this software responsibly.**
