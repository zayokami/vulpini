export type DelayState =
  | { kind: 'none' }
  | { kind: 'testing' }
  | { kind: 'ok'; ms: number }
  | { kind: 'timeout' }
  | { kind: 'error' };

interface Props {
  state: DelayState;
}

/** Latency value with health colors: <250 green, <400 accent, else orange,
 * timeout/error red, untested "-", testing spinner. */
export default function DelayBadge({ state }: Props) {
  if (state.kind === 'testing') {
    return <span className="spinner" aria-label="testing" />;
  }
  if (state.kind === 'none') {
    return <span className="delay--none">-</span>;
  }
  if (state.kind === 'timeout') {
    return <span className="delay--timeout">超时</span>;
  }
  if (state.kind === 'error') {
    return <span className="delay--timeout">错误</span>;
  }
  const cls =
    state.ms < 250 ? 'delay--good' : state.ms < 400 ? 'delay--mid' : 'delay--bad';
  return <span className={cls}>{state.ms}ms</span>;
}
