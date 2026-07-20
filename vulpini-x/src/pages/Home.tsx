import { useApp } from '../store';
import type { Mode } from '../api';

const MODES: { id: Mode; label: string }[] = [
  { id: 'global', label: 'GLOBAL' },
  { id: 'rule', label: 'RULE' },
  { id: 'direct', label: 'DIRECT' },
];

function formatRate(bytesPerSec: number): string {
  if (bytesPerSec >= 1 << 20) return `${(bytesPerSec / (1 << 20)).toFixed(1)} MB/s`;
  if (bytesPerSec >= 1 << 10) return `${(bytesPerSec / (1 << 10)).toFixed(1)} KB/s`;
  return `${bytesPerSec} B/s`;
}

function formatTotal(bytes: number): string {
  if (bytes >= 1 << 30) return `${(bytes / (1 << 30)).toFixed(2)} GB`;
  if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1)} MB`;
  if (bytes >= 1 << 10) return `${(bytes / (1 << 10)).toFixed(1)} KB`;
  return `${bytes} B`;
}

export default function Home() {
  const status = useApp((s) => s.status);
  const stats = useApp((s) => s.stats);
  const sysproxy = useApp((s) => s.sysproxy);
  const startCore = useApp((s) => s.startCore);
  const stopCore = useApp((s) => s.stopCore);
  const setMode = useApp((s) => s.setMode);
  const toggleSysproxy = useApp((s) => s.toggleSysproxy);

  const running = status?.running ?? false;

  return (
    <div className="page">
      <div className="row gap">
        <button
          className={`btn big ${running ? 'btn-danger' : 'btn-primary'}`}
          onClick={() => void (running ? stopCore() : startCore())}
        >
          {running ? 'STOP' : 'START'}
        </button>
        <div className="mode-group">
          {MODES.map((m) => (
            <button
              key={m.id}
              className={`btn mode ${status?.mode === m.id ? 'active' : ''}`}
              onClick={() => void setMode(m.id)}
            >
              {m.label}
            </button>
          ))}
        </div>
        <label className="sysproxy-toggle">
          <input
            type="checkbox"
            checked={sysproxy?.enabled ?? false}
            disabled={!sysproxy?.supported}
            onChange={(e) => void toggleSysproxy(e.target.checked)}
          />
          <span>SYSTEM PROXY</span>
        </label>
      </div>

      <div className="card">
        <div className="card-title">STATUS</div>
        <div className="kv">
          <span>ENGINE</span>
          <span className={running ? 'ok' : 'muted'}>{running ? 'RUNNING' : 'STOPPED'}</span>
        </div>
        <div className="kv">
          <span>LISTEN</span>
          <span>{status?.listen ?? '-'}</span>
        </div>
        <div className="kv">
          <span>MODE</span>
          <span>{status?.mode?.toUpperCase() ?? '-'}</span>
        </div>
        <div className="kv">
          <span>SYSTEM PROXY</span>
          <span>{sysproxy?.enabled ? `ON (${sysproxy.server ?? ''})` : 'OFF'}</span>
        </div>
      </div>

      <div className="card">
        <div className="card-title">TRAFFIC</div>
        <div className="stats-grid">
          <div className="stat">
            <div className="stat-label">UP</div>
            <div className="stat-value up">{stats ? formatRate(stats.up_rate) : '-'}</div>
          </div>
          <div className="stat">
            <div className="stat-label">DOWN</div>
            <div className="stat-value down">{stats ? formatRate(stats.down_rate) : '-'}</div>
          </div>
          <div className="stat">
            <div className="stat-label">TOTAL UP</div>
            <div className="stat-value">{stats ? formatTotal(stats.total_up) : '-'}</div>
          </div>
          <div className="stat">
            <div className="stat-label">TOTAL DOWN</div>
            <div className="stat-value">{stats ? formatTotal(stats.total_down) : '-'}</div>
          </div>
          <div className="stat">
            <div className="stat-label">CONNECTIONS</div>
            <div className="stat-value">{stats?.active_connections ?? '-'}</div>
          </div>
        </div>
      </div>
    </div>
  );
}
