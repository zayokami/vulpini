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
Development proceeds milestone by milestone; every engine milestone was verified
through the CLI before the GUI arrived.

项目已推倒重做（旧的 IP 轮换服务器已删除）。按里程碑推进，引擎的每个
里程碑在 GUI 落地前都通过了 CLI 验证。

| Milestone | Scope | Status |
|-----------|-------|--------|
| M0 | Workspace, CI, MIT license | Done |
| M1 | Core spine: mixed inbound, direct/block, relay | Done |
| M2 | Node model, share-link parsers, config store | Done |
| M3 | Shadowsocks outbound (AEAD) | Done |
| M4 | Router + geosite/geoip rules | Done |
| M5 | TLS transport + Trojan outbound | Done |
| M6 | WS transport + VLESS outbound | Done |
| M7 | Subscriptions (fetch, sniffing, stable-key update) | Done |
| M8 | Stats, log bus, delay testing | Done |
| M9 | Windows system proxy (snapshot/restore) | Done |
| M10 | Tauri 2 + React GUI | Done |
| M11 | Packaging + release pipeline + license audit | Done |

Post-MVP roadmap: VMess outbound, UDP relay, TUN mode, Hysteria2/TUIC,
REALITY (documented limitations of the rustls TLS stack).

## Usage · 使用

### Desktop app (Vulpini X)

```bash
cd vulpini-x
pnpm install
pnpm tauri dev     # dev mode
pnpm tauri build   # produces NSIS/MSI installers in target/release/bundle/
```

### Headless CLI (engine test shell)

```bash
cargo run -p vulpini-cli -- run                    # serve 127.0.0.1:7890 (mixed socks5/http)
vulpini-cli import "ss://..." "trojan://..."       # import share links
vulpini-cli sub add my-sub https://example.com/sub # add a subscription
vulpini-cli list && vulpini-cli select <id>        # pick the active node
vulpini-cli delay --all                            # latency-test all nodes
vulpini-cli geo update                             # refresh geosite/geoip data
vulpini-cli sysproxy on|off|status                 # toggle Windows system proxy
```

## License · 许可证

[MIT License](LICENSE)

---

## Disclaimer · 免责声明

> **This software is provided for educational, research, and lawful purposes only.**

By using this software, you agree to comply with all applicable laws and
regulations in your jurisdiction. The authors are not liable for any damages
resulting from the use or misuse of this software.

**Please use this software responsibly.**
