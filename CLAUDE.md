# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vulpini is an advanced proxy server (SOCKS5 + HTTP) with intelligent traffic analysis, IP pool management, and a desktop UI. It consists of a Rust backend (`vulpini/`) and an Electron/TypeScript frontend (`vulpini-x/`), with shared types in `shared/types.ts`.

## Build & Run Commands

### Rust backend (`vulpini/`)
```bash
cargo build --release          # Build
cargo run --release             # Run with default vulpini.toml
cargo run --release config.toml # Run with custom config
cargo test                      # Run all tests
cargo test --test config        # Run a single integration test file
cargo test test_name            # Run a specific test by name
```

### Electron frontend (`vulpini-x/`)
```bash
npm install                     # Install dependencies
npm run build                   # TypeScript + Vite production build
npm run dev                     # Dev mode (Vite + Electron concurrently)
```

No top-level workspace scripts exist; commands must be run from within `vulpini/` or `vulpini-x/`.

## Architecture

### Three servers launched from `main.rs`
The Rust binary starts three async servers on Tokio:
- **SOCKS5 proxy** (default `:1080`) — `protocol::socks5::Socks5Protocol`
- **HTTP proxy** (default `:8080`) — `protocol::http::HttpProtocol`
- **Management API** (`:9090`) — `api::ApiServer`, JSON REST endpoints

### Core Rust modules (`vulpini/src/`)
Each module is a directory with `mod.rs`:
- `traffic_analyzer` — Real-time request stats, percentile latencies (p50/p95/p99)
- `ip_manager` — IP pool CRUD, health checks, rotation strategies, per-IP performance tracking
- `smart_router` — Routing decisions based on latency, reliability, and load balancing
- `behavior_monitor` — Session tracking and pattern analysis via DashMap
- `anomaly_detector` — Detects traffic spikes, latency anomalies, error rate surges, connection floods
- `config` — TOML-based configuration with hot-reload via watch channels
- `protocol` — SOCKS5 and HTTP proxy protocol handlers (with upstream SOCKS5 support)
- `api` — HTTP API server for management (stats, IP CRUD, anomalies, config reload, PAC file)
- `logger` — Structured logging with file and console output

### Concurrency model
Shared state uses `Arc<Mutex<T>>` for core components (TrafficAnalyzer, IPManager, etc.) and `DashMap` for high-throughput concurrent maps (IP stats, behavior records). Background tasks for health checks and anomaly detection run as spawned Tokio tasks.

### Frontend (`vulpini-x/`)
- **Native TypeScript** (no React) — recent refactor removed JSX; UI is built with DOM APIs in `App.ts`
- Electron main process (`electron/main/index.js`) spawns the Rust backend and creates a BrowserWindow
- Renderer polls the Rust API at `localhost:9090` every 2 seconds for real-time updates
- Tabbed interface: Dashboard, Config, IPs, Logs

### Shared types (`shared/types.ts`)
TypeScript interfaces mirroring the Rust API response shapes (TrafficStats, IPInfo, AnomalyEvent, ProxyConfig, etc.). Both frontend and any future TS tooling should reference these.

### API endpoints (port 9090)
- `GET /api/stats` — Traffic statistics
- `GET /api/ips` — List proxy IPs
- `POST /api/ips` — Add an IP
- `DELETE /api/ips/{address}` — Remove an IP
- `GET /api/anomalies` — Anomaly events
- `GET /api/health` — Health check
- `POST /api/config/reload` — Hot-reload configuration

### Configuration
TOML-based. Copy `vulpini.example.toml` to `vulpini.toml`. Sections: socks5, http_proxy, ip_pool (with per-IP metadata), routing, anomaly_detection, logging.

## Key Conventions

- Rust release profile uses LTO, single codegen unit, opt-level 3, stripped symbols
- Integration tests live in `vulpini/tests/` (one file per module)
- Dev dependencies include `criterion` (benchmarks), `proptest` (property testing), `tempfile`
- The README notes `App.tsx` but the UI was refactored to native TS (`App.ts`) — the README is outdated on this point
- License: GPL-3.0
