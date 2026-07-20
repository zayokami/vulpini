import { useState } from 'react';
import { ClipboardPaste, RefreshCw, Trash2 } from 'lucide-react';
import BasePage from '../components/BasePage';
import { useApp } from '../store';

function formatRelative(ts: number | null): string {
  if (!ts) return '从未更新';
  const secs = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (secs < 60) return '刚刚';
  if (secs < 3600) return `${Math.floor(secs / 60)} 分钟前`;
  if (secs < 86400) return `${Math.floor(secs / 3600)} 小时前`;
  return `${Math.floor(secs / 86400)} 天前`;
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

export default function Subscriptions() {
  const subscriptions = useApp((s) => s.subscriptions);
  const addSub = useApp((s) => s.addSub);
  const deleteSub = useApp((s) => s.deleteSub);
  const updateSubs = useApp((s) => s.updateSubs);

  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [updating, setUpdating] = useState<Set<string>>(new Set());

  const doAdd = async () => {
    if (!name.trim() || !url.trim()) return;
    setBusy(true);
    setMessage(null);
    try {
      await addSub(name.trim(), url.trim());
      setName('');
      setUrl('');
      setMessage('已添加，正在获取节点…');
    } catch (e) {
      setMessage(`添加失败: ${e}`);
    } finally {
      setBusy(false);
    }
  };

  const pasteClipboard = async () => {
    try {
      setUrl(await navigator.clipboard.readText());
    } catch {
      setMessage('无法读取剪贴板');
    }
  };

  const doUpdate = async (id?: string) => {
    setUpdating((s) => new Set(s).add(id ?? '__all__'));
    try {
      await updateSubs(id);
    } finally {
      setUpdating((s) => {
        const next = new Set(s);
        next.delete(id ?? '__all__');
        return next;
      });
    }
  };

  return (
    <BasePage
      title="订阅"
      actions={
        subscriptions.length > 0 ? (
          <button
            className="btn"
            disabled={updating.has('__all__')}
            onClick={() => void doUpdate()}
          >
            <RefreshCw size={15} className={updating.has('__all__') ? 'spin' : undefined} />
            全部更新
          </button>
        ) : undefined
      }
    >
      <div className="card">
        <div className="row" style={{ gap: 8 }}>
          <input
            className="input"
            placeholder="名称"
            style={{ width: 140 }}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <input
            className="input"
            style={{ flex: 1 }}
            placeholder="https://provider.example/subscription"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void doAdd()}
          />
          <button className="btn" onClick={() => void pasteClipboard()} title="粘贴剪贴板">
            <ClipboardPaste size={15} />
          </button>
          <button className="btn btn--primary" disabled={busy} onClick={() => void doAdd()}>
            添加
          </button>
        </div>
        {message && <div className="muted small">{message}</div>}
      </div>

      {subscriptions.length === 0 && (
        <div className="empty">
          <span>暂无订阅 — 在上方粘贴订阅地址添加</span>
        </div>
      )}

      <div className="sub-grid">
        {subscriptions.map((s) => (
          <div key={s.id} className="card sub-card">
            <div className="sub-card__head">
              <span className="sub-card__name" title={s.name}>
                {s.name}
              </span>
              <button
                className="btn btn--sm"
                disabled={updating.has(s.id)}
                onClick={() => void doUpdate(s.id)}
                title="更新订阅"
              >
                <RefreshCw size={13} className={updating.has(s.id) ? 'spin' : undefined} />
              </button>
            </div>
            <div className="muted small sub-card__url" title={s.url}>
              {hostOf(s.url)}
            </div>
            <div className="muted small">
              {s.node_count} 个节点 · {formatRelative(s.last_updated)}
            </div>
            {s.last_error && <div className="error-text small">{s.last_error}</div>}
            <div className="sub-card__foot">
              <button className="btn btn--sm btn--danger" onClick={() => void deleteSub(s.id)}>
                <Trash2 size={13} />
                删除
              </button>
            </div>
          </div>
        ))}
      </div>
    </BasePage>
  );
}
