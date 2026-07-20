import { create } from 'zustand';
import { api, type DelayResultPayload } from '../api';
import type { DelayState } from '../components/DelayBadge';

const MIN_SPINNER_MS = 500;

export interface Entry {
  state: DelayState;
  testingSince: number | null;
}

interface DelayStore {
  entries: Record<string, Entry>;
  /** Mark one node as testing and fire its probe. */
  testNode: (id: string) => void;
  /** Mark every given node as testing and fire the batch probe. */
  testAll: (ids: string[]) => void;
  /** Feed a delay:result event payload. */
  handleResult: (payload: DelayResultPayload) => void;
  reset: (ids: { id: string; delay_ms: number | null }[]) => void;
}

function toState(ms: number | null, error: string | null): DelayState {
  if (ms != null) return { kind: 'ok', ms };
  if (error) return { kind: 'error' };
  return { kind: 'timeout' };
}

export const useDelay = create<DelayStore>((set, get) => ({
  entries: {},

  testNode: (id) => {
    set((s) => ({
      entries: {
        ...s.entries,
        [id]: { state: { kind: 'testing' }, testingSince: Date.now() },
      },
    }));
    // Result arrives via the delay:result event; errors surface as result too.
    void api.testNodeDelay(id).catch(() => undefined);
  },

  testAll: (ids) => {
    const now = Date.now();
    set((s) => {
      const entries = { ...s.entries };
      for (const id of ids) {
        entries[id] = { state: { kind: 'testing' }, testingSince: now };
      }
      return { entries };
    });
    void api.testAllDelays().catch(() => undefined);
  },

  handleResult: (payload) => {
    const apply = () =>
      set((s) => ({
        entries: {
          ...s.entries,
          [payload.node_id]: {
            state: toState(payload.delay_ms, payload.error),
            testingSince: null,
          },
        },
      }));
    const since = get().entries[payload.node_id]?.testingSince;
    // Keep the spinner visible for at least MIN_SPINNER_MS to avoid flicker.
    if (since && Date.now() - since < MIN_SPINNER_MS) {
      setTimeout(apply, MIN_SPINNER_MS - (Date.now() - since));
    } else {
      apply();
    }
  },

  reset: (ids) =>
    set((s) => {
      const entries: Record<string, Entry> = {};
      for (const n of ids) {
        const existing = s.entries[n.id];
        // Preserve in-flight testing states across node-list refreshes.
        entries[n.id] =
          existing?.state.kind === 'testing'
            ? existing
            : {
                state: n.delay_ms != null ? { kind: 'ok', ms: n.delay_ms } : { kind: 'none' },
                testingSince: null,
              };
      }
      return { entries };
    }),
}));

export function delayStateOf(entries: Record<string, Entry>, id: string): DelayState {
  return entries[id]?.state ?? { kind: 'none' };
}
