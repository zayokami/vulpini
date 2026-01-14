# Vulpini

Advanced proxy server with intelligent traffic analysis and IP management.

## Author

- **zayoka**

## Project Structure

```
vulpini/
├── src/
│   ├── main.rs                 # Entry point
│   ├── lib.rs                  # Library exports
│   ├── traffic_analyzer/       # Traffic statistics and analysis
│   ├── ip_manager/             # IP pool management
│   ├── behavior_monitor/       # User behavior tracking
│   ├── smart_router/           # Dynamic routing decisions
│   ├── anomaly_detector/       # Anomaly detection
│   ├── protocol/               # SOCKS5 and HTTP protocols
│   ├── config/                 # Configuration management
│   ├── logger/                 # Logging system
│   └── utils/                  # Utility functions
├── tests/
├── Cargo.toml
└── vulpini.example.toml        # Example configuration

vulpini-x/
├── electron/
│   ├── main/                   # Electron main process
│   └── renderer/               # Electron renderer process
│       ├── src/
│       │   ├── App.tsx         # Main UI component
│       │   ├── App.css         # Bauhaus-style styles
│       │   ├── main.tsx        # Entry point
│       │   └── styles.css      # Global styles
│       └── index.html
├── package.json
├── vite.config.ts
└── tsconfig.json
```

## Building

### Build Vulpini (Rust)

```bash
cd vulpini
cargo build --release
```

### Build Vulpini X (Electron)

```bash
cd vulpini-x
npm install
npm run build
```

## Running

### Run Vulpini Core

```bash
cd vulpini
cargo run --release [config_file.toml]
```

Default config file is `vulpini.toml`.

### Run Vulpini X (Development)

```bash
cd vulpini-x
npm run dev
```

## Features

- SOCKS5 proxy server
- HTTP proxy server
- Intelligent IP pool management
- Traffic analysis and monitoring
- User behavior tracking
- Dynamic routing with load balancing
- Anomaly detection and alerting

## Configuration

Copy `vulpini.example.toml` to `vulpini.toml` and modify as needed.

## License

GNU General Public License v3.0 (GPLv3)
