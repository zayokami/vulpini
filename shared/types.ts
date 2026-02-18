export interface ProxyConfig {
  socks5: Socks5Config;
  http_proxy: HttpProxyConfig;
  ip_pool: IPPoolConfig;
  routing: RoutingConfig;
  anomaly_detection: AnomalyDetectionConfig;
  logging: LoggingConfig;
}

export interface Socks5Config {
  enabled: boolean;
  listen_address: string;
  listen_port: number;
  auth_enabled: boolean;
  username: string | null;
  password: string | null;
  max_connections: number;
}

export interface HttpProxyConfig {
  enabled: boolean;
  listen_address: string;
  listen_port: number;
  auth_enabled: boolean;
  username: string | null;
  password: string | null;
  max_connections: number;
}

export interface IPPoolConfig {
  ips: IPConfig[];
  health_check_interval_secs: number;
  auto_rotate_interval_secs: number;
  strategy: string;
}

export interface IPConfig {
  address: string;
  port: number;
  country: string | null;
  isp: string | null;
}

export interface RoutingConfig {
  max_latency_threshold_ms: number;
  min_reliability_threshold: number;
  load_balancing: string;
  fallback_enabled: boolean;
}

export interface AnomalyDetectionConfig {
  enabled: boolean;
  spike_threshold: number;
  latency_threshold_ms: number;
  error_rate_threshold: number;
  connection_threshold: number;
  check_interval_secs: number;
}

export interface LoggingConfig {
  level: string;
  file_enabled: boolean;
  file_path: string;
  console_enabled: boolean;
}

export interface ProxyStatus {
  running: boolean;
  connections: number;
  requestsPerSecond: number;
  bytesPerSecond: number;
  avgLatency: string;
  errorRate: number;
}

export interface TrafficStats {
  total_requests: number;
  total_bytes_in: number;
  total_bytes_out: number;
  active_connections: number;
  requests_per_second: number;
  bytes_per_second: number;
  avg_latency_ms: number;
  error_rate: number;
}

export interface IPInfo {
  address: string;
  port: number;
  country: string | null;
  isp: string | null;
  latency_ms: number;
  avg_latency_ms: number;
  status: string;
  enabled: boolean;
  total_uses: number;
  success_count: number;
  failure_count: number;
  use_count: number;
}

export interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
}

export interface AnomalyEvent {
  id: string;
  timestamp: number;
  anomaly_type: string;
  value: number;
  threshold: number;
  description: string;
  severity: string;
}
