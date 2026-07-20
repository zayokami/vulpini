import { create } from 'zustand';
import {
  api,
  onEvent,
  type ConfigView,
  type CoreStatus,
  type DelayResultPayload,
  type LogEvent,
  type Mode,
  type NodeView,
  type StatsSnapshot,
  type SubscriptionUpdatedPayload,
  type SubscriptionView,
  type SysProxyView,
} from './api';
import { useDelay } from './store/delay';

interface AppState {
  status: CoreStatus | null;
  nodes: NodeView[];
  subscriptions: SubscriptionView[];
  stats: StatsSnapshot | null;
  logs: LogEvent[];
  sysproxy: SysProxyView | null;
  config: ConfigView | null;
  notice: string | null;

  refreshAll: () => Promise<void>;
  refreshNodes: () => Promise<void>;
  refreshSubs: () => Promise<void>;
  refreshStatus: () => Promise<void>;
  refreshConfig: () => Promise<void>;
  refreshSysproxy: () => Promise<void>;

  startCore: () => Promise<void>;
  stopCore: () => Promise<void>;
  setMode: (mode: Mode) => Promise<void>;
  importLinks: (text: string) => Promise<string>;
  deleteNode: (id: string) => Promise<void>;
  selectNode: (id: string) => Promise<void>;
  addSub: (name: string, url: string) => Promise<void>;
  deleteSub: (id: string) => Promise<void>;
  updateSubs: (id?: string) => Promise<void>;
  testDelay: (id: string) => Promise<void>;
  testAllDelays: () => Promise<void>;
  toggleSysproxy: (enabled: boolean) => Promise<void>;
  patchConfig: (patch: Partial<ConfigView>) => Promise<void>;
  updateGeo: () => Promise<void>;
  clearNotice: () => void;

  /** Wires event listeners and returns an unlisten-all cleanup. */
  init: () => Promise<() => void>;
}

async function guarded(fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
  } catch (e) {
    console.error(e);
  }
}

export const useApp = create<AppState>((set, get) => {
  /** Unified fault channel: any failed action surfaces as a toast with
   * the real reason. Nothing fails silently. */
  const safely = async (label: string, fn: () => Promise<void>) => {
    try {
      await fn();
    } catch (e) {
      set({ notice: `${label}失败: ${e}` });
    }
  };

  // React StrictMode mounts effects twice in dev; wiring must be
  // idempotent or every event listener gets registered twice and each
  // log line appears duplicated.
  let wired = false;

  return {
    status: null,
    nodes: [],
    subscriptions: [],
    stats: null,
    logs: [],
    sysproxy: null,
    config: null,
    notice: null,

    refreshAll: async () => {
      const { refreshStatus, refreshNodes, refreshSubs, refreshConfig, refreshSysproxy } =
        get();
      await Promise.all([
        guarded(refreshStatus),
        guarded(refreshNodes),
        guarded(refreshSubs),
        guarded(refreshConfig),
        guarded(refreshSysproxy),
      ]);
      const snap = await api.getStatsSnapshot().catch(() => null);
      set({ stats: snap });
    },
    refreshNodes: async () => {
      const nodes = await api.listNodes();
      set({ nodes });
      useDelay.getState().reset(nodes.map((n) => ({ id: n.id, delay_ms: n.delay_ms })));
    },
    refreshSubs: async () => set({ subscriptions: await api.listSubscriptions() }),
    refreshStatus: async () => set({ status: await api.coreStatus() }),
    refreshConfig: async () => set({ config: await api.getConfig() }),
    refreshSysproxy: async () => set({ sysproxy: await api.getSystemProxy() }),

    startCore: () =>
      safely('启动核心', async () => {
        await api.coreStart();
        await get().refreshStatus();
      }),
    stopCore: () =>
      safely('停止核心', async () => {
        await api.coreStop();
        await get().refreshStatus();
        set({ stats: null });
      }),
    setMode: (mode) =>
      safely('切换模式', async () => {
        await api.setMode(mode);
        await get().refreshStatus();
        await get().refreshConfig();
      }),
    importLinks: async (text) => {
      try {
        const result = await api.importShareLinks(text);
        await get().refreshNodes();
        const failNote = result.failed.length > 0 ? `，${result.failed.length} 条失败` : '';
        return `已导入 ${result.added} 条${failNote}`;
      } catch (e) {
        set({ notice: `导入失败: ${e}` });
        return '导入失败';
      }
    },
    deleteNode: (id) =>
      safely('删除节点', async () => {
        await api.deleteNode(id);
        await get().refreshNodes();
      }),
    selectNode: (id) =>
      safely('选择节点', async () => {
        await api.setActiveNode(id);
        await get().refreshNodes();
      }),
    addSub: (name, url) =>
      safely('添加订阅', async () => {
        await api.addSubscription(name, url);
        // node arrival is signaled via subscription:updated / nodes:changed
        await get().refreshSubs();
      }),
    deleteSub: (id) =>
      safely('删除订阅', async () => {
        await api.deleteSubscription(id);
        await get().refreshSubs();
        await get().refreshNodes();
      }),
    updateSubs: (id) =>
      safely('更新订阅', async () => {
        await api.updateSubscription(id);
        await get().refreshSubs();
        await get().refreshNodes();
      }),
    testDelay: async (id) => {
      try {
        await api.testNodeDelay(id);
      } catch {
        // failure payload arrives via delay:result anyway
      }
    },
    testAllDelays: () =>
      safely('全部测速', async () => {
        await api.testAllDelays();
      }),
    toggleSysproxy: async (enabled) => {
      // Optimistic update with rollback (GuardState pattern).
      const previous = get().sysproxy;
      if (previous) set({ sysproxy: { ...previous, enabled } });
      try {
        const view = await api.setSystemProxy(enabled);
        set({ sysproxy: view });
      } catch (e) {
        if (previous) set({ sysproxy: previous });
        set({ notice: `系统代理切换失败: ${e}` });
      }
    },
    patchConfig: async (patch) => {
      const config = await api.patchConfig(patch);
      set({ config });
      await get().refreshStatus();
    },
    updateGeo: () =>
      safely('更新规则数据', async () => {
        const [site, ip] = await api.updateGeoData();
        set({
          notice: `规则数据已更新 (${(site / 1024).toFixed(0)}K / ${(ip / 1024).toFixed(0)}K)`,
        });
      }),
    clearNotice: () => set({ notice: null }),

    init: async () => {
      if (wired) return () => {};
      wired = true;
      await get().refreshAll();
      const unlisteners = await Promise.all([
        onEvent<StatsSnapshot>('stats:tick', (stats) => set({ stats })),
        onEvent<LogEvent>('log:line', (event) =>
          set((s) => ({ logs: [event, ...s.logs].slice(0, 500) })),
        ),
        onEvent<unknown>('core:status', () => void get().refreshStatus()),
        onEvent<unknown>('nodes:changed', () => void get().refreshNodes()),
        onEvent<DelayResultPayload>('delay:result', (payload) => {
          useDelay.getState().handleResult(payload);
          void get().refreshNodes();
        }),
        onEvent<SubscriptionUpdatedPayload>('subscription:updated', (payload) => {
          void get().refreshSubs();
          if (payload.error) {
            set({ notice: `订阅更新失败: ${payload.error}` });
          } else if (payload.skipped > 0) {
            set({
              notice: `已导入 ${payload.added} 个节点，${payload.skipped} 条因协议不支持被跳过（详见日志）`,
            });
          }
        }),
      ]);
      // Return an unlisten-all cleanup for the owning effect.
      return () => {
        wired = false;
        unlisteners.forEach((unlisten) => unlisten());
      };
    },
  };
});
