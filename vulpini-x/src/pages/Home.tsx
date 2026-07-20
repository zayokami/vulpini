import BasePage from '../components/BasePage';
import Switch from '../components/Switch';
import DelayBadge from '../components/DelayBadge';
import { useApp } from '../store';
import type { Mode } from '../api';
import { Activity, Globe, Network, Power, Server } from 'lucide-react';

const MODES: { id: Mode; label: string }[] = [
  { id: 'rule', label: '规则' },
  { id: 'global', label: '全局' },
  { id: 'direct', label: '直连' },
];

function formatRate(bps: number): string {
  if (bps >= 1 << 20) return `${(bps / (1 << 20)).toFixed(1)} MB/s`;
  if (bps >= 1 << 10) return `${(bps / (1 << 10)).toFixed(1)} KB/s`;
  return `${bps} B/s`;
}

function formatTotal(bytes: number): string {
  if (bytes >= 1 << 30) return `${(bytes / (1 << 30)).toFixed(2)} GB`;
  if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1)} MB`;
  if (bytes >= 1 << 10) return `${(bytes / (1 << 10)).toFixed(1)} KB`;
  return `${bytes} B`;
}

function IconBox({ children }: { children: React.ReactNode }) {
  return <div className="home-card__icon">{children}</div>;
}

export default function Home({ onNavigate }: { onNavigate: (page: 'nodes') => void }) {
  const status = useApp((s) => s.status);
  const stats = useApp((s) => s.stats);
  const sysproxy = useApp((s) => s.sysproxy);
  const nodes = useApp((s) => s.nodes);
  const startCore = useApp((s) => s.startCore);
  const stopCore = useApp((s) => s.stopCore);
  const setMode = useApp((s) => s.setMode);
  const toggleSysproxy = useApp((s) => s.toggleSysproxy);

  const running = status?.running ?? false;
  const activeNode = nodes.find((n) => n.active);

  return (
    <BasePage title="首页">
      <div className="home-grid">
        <div className="card">
          <div className="card__title">
            <IconBox>
              <Power size={19} />
            </IconBox>
            运行状态
          </div>
          <div className="home-card__row">
            <Switch
              checked={running}
              onChange={(on) => void (on ? startCore() : stopCore())}
              label="core"
            />
            <span className={running ? 'ok-text' : 'muted'}>
              {running ? '运行中' : '已停止'}
            </span>
          </div>
          <div className="muted small">监听 {status?.listen ?? '-'}</div>
        </div>

        <div className="card">
          <div className="card__title">
            <IconBox>
              <Globe size={19} />
            </IconBox>
            代理模式
          </div>
          <div className="btn-group">
            {MODES.map((m) => (
              <button
                key={m.id}
                className={`btn ${status?.mode === m.id ? 'btn--active' : ''}`}
                onClick={() => void setMode(m.id)}
              >
                {m.label}
              </button>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card__title">
            <IconBox>
              <Network size={19} />
            </IconBox>
            网络设置
          </div>
          <div className="home-card__row">
            <Switch
              checked={sysproxy?.enabled ?? false}
              disabled={!sysproxy?.supported}
              onChange={(on) => void toggleSysproxy(on)}
              label="system proxy"
            />
            <span className={sysproxy?.enabled ? 'ok-text' : 'muted'}>系统代理</span>
          </div>
          <div className="muted small">
            {sysproxy?.enabled ? sysproxy.server ?? '' : '未启用'}
          </div>
        </div>

        <div className="card card--clickable" onClick={() => onNavigate('nodes')}>
          <div className="card__title">
            <IconBox>
              <Server size={19} />
            </IconBox>
            当前节点
          </div>
          {activeNode ? (
            <>
              <div className="home-card__row">
                <span className="home-node-name">{activeNode.name}</span>
                <span className="badge">{activeNode.proto}</span>
              </div>
              <div className="muted small">
                {activeNode.server}:{activeNode.port} ·{' '}
                <DelayBadge
                  state={
                    activeNode.delay_ms != null
                      ? { kind: 'ok', ms: activeNode.delay_ms }
                      : { kind: 'none' }
                  }
                />
              </div>
            </>
          ) : (
            <div className="muted small">未选择节点，点击前往代理页</div>
          )}
        </div>

        <div className="card home-card--wide">
          <div className="card__title">
            <IconBox>
              <Activity size={19} />
            </IconBox>
            流量统计
          </div>
          <div className="home-stats">
            <div className="home-stat">
              <div className="muted small">上传速度</div>
              <div className="home-stat__value">{formatRate(stats?.up_rate ?? 0)}</div>
            </div>
            <div className="home-stat">
              <div className="muted small">下载速度</div>
              <div className="home-stat__value">{formatRate(stats?.down_rate ?? 0)}</div>
            </div>
            <div className="home-stat">
              <div className="muted small">总上传</div>
              <div className="home-stat__value">{formatTotal(stats?.total_up ?? 0)}</div>
            </div>
            <div className="home-stat">
              <div className="muted small">总下载</div>
              <div className="home-stat__value">{formatTotal(stats?.total_down ?? 0)}</div>
            </div>
            <div className="home-stat">
              <div className="muted small">活动连接</div>
              <div className="home-stat__value">{stats?.active_connections ?? '-'}</div>
            </div>
          </div>
        </div>
      </div>
    </BasePage>
  );
}
