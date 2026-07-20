import { useEffect, useRef, useState } from 'react';
import { useApp } from '../store';

const LEVELS = ['ALL', 'ERROR', 'WARN', 'INFO', 'DEBUG'] as const;

export default function Logs() {
  const logs = useApp((s) => s.logs);
  const [level, setLevel] = useState<(typeof LEVELS)[number]>('ALL');
  const bottomRef = useRef<HTMLDivElement>(null);

  const filtered = level === 'ALL' ? logs : logs.filter((l) => l.level === level);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ block: 'end' });
  }, [filtered.length]);

  return (
    <div className="page logs-page">
      <div className="row gap">
        {LEVELS.map((l) => (
          <button
            key={l}
            className={`btn sm ${level === l ? 'active' : ''}`}
            onClick={() => setLevel(l)}
          >
            {l}
          </button>
        ))}
        <span className="muted">{filtered.length} entries</span>
      </div>
      <div className="log-list">
        {filtered.length === 0 && <div className="muted">No log entries yet.</div>}
        {filtered.map((l, i) => (
          <div key={i} className={`log-entry lv-${l.level.toLowerCase()}`}>
            <span className="log-level">[{l.level}]</span>
            <span className="log-target">{l.target}</span>
            <span className="log-msg">{l.message}</span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
