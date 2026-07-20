import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

export type Mode = 'global' | 'rule' | 'direct';

export interface CoreStatus {
  running: boolean;
  listen: string;
  mode: Mode;
  active_node: string | null;
}

export interface NodeView {
  id: string;
  name: string;
  proto: string;
  server: string;
  port: number;
  source: string;
  delay_ms: number | null;
  active: boolean;
}

export interface SubscriptionView {
  id: string;
  name: string;
  url: string;
  node_count: number;
  last_updated: number | null;
  last_error: string | null;
}

export interface StatsSnapshot {
  up_rate: number;
  down_rate: number;
  total_up: number;
  total_down: number;
  active_connections: number;
}

export interface ConfigView {
  listen: string;
  mode: Mode;
  rules: string[];
  system_proxy_enabled: boolean;
}

export interface SysProxyView {
  supported: boolean;
  enabled: boolean;
  server: string | null;
}

export interface LogEvent {
  level: string;
  target: string;
  message: string;
  ts: number;
}

export interface ImportResult {
  added: number;
  failed: { line: string; error: string }[];
}

export interface DelayResultPayload {
  node_id: string;
  delay_ms: number | null;
  error: string | null;
}

export interface SubscriptionUpdatedPayload {
  id: string;
  added: number;
  removed: number;
  error: string | null;
}

export const api = {
  coreStart: () => invoke<void>('core_start'),
  coreStop: () => invoke<void>('core_stop'),
  coreStatus: () => invoke<CoreStatus>('core_status'),
  setMode: (mode: Mode) => invoke<void>('set_mode', { mode }),
  listNodes: () => invoke<NodeView[]>('list_nodes'),
  importShareLinks: (text: string) => invoke<ImportResult>('import_share_links', { text }),
  deleteNode: (id: string) => invoke<void>('delete_node', { id }),
  setActiveNode: (id: string) => invoke<void>('set_active_node', { id }),
  addSubscription: (name: string, url: string) =>
    invoke<SubscriptionView>('add_subscription', { name, url }),
  listSubscriptions: () => invoke<SubscriptionView[]>('list_subscriptions'),
  deleteSubscription: (id: string) => invoke<void>('delete_subscription', { id }),
  updateSubscription: (id?: string) => invoke<void>('update_subscription', { id: id ?? null }),
  testNodeDelay: (id: string) => invoke<number>('test_node_delay', { id }),
  testAllDelays: () => invoke<void>('test_all_delays'),
  setSystemProxy: (enabled: boolean) => invoke<SysProxyView>('set_system_proxy', { enabled }),
  getSystemProxy: () => invoke<SysProxyView>('get_system_proxy'),
  getConfig: () => invoke<ConfigView>('get_config'),
  patchConfig: (patch: Partial<ConfigView>) => invoke<ConfigView>('patch_config', { patch }),
  getStatsSnapshot: () => invoke<StatsSnapshot | null>('get_stats_snapshot'),
  updateGeoData: () => invoke<[number, number]>('update_geo_data'),
};

export function onEvent<T>(name: string, handler: (payload: T) => void): Promise<UnlistenFn> {
  return listen<T>(name, (event) => handler(event.payload));
}
