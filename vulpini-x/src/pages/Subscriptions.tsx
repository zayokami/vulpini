import { useState } from 'react';
import { useApp } from '../store';

function formatTime(ts: number | null): string {
  if (!ts) return 'never';
  return new Date(ts * 1000).toLocaleString();
}

export default function Subscriptions() {
  const subscriptions = useApp((s) => s.subscriptions);
  const addSub = useApp((s) => s.addSub);
  const deleteSub = useApp((s) => s.deleteSub);
  const updateSubs = useApp((s) => s.updateSubs);

  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [busy, setBusy] = useState(false);

  const doAdd = async () => {
    if (!name.trim() || !url.trim()) return;
    setBusy(true);
    try {
      await addSub(name.trim(), url.trim());
      setName('');
      setUrl('');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page">
      <div className="card">
        <div className="card-title">ADD SUBSCRIPTION</div>
        <div className="row gap">
          <input
            className="input"
            placeholder="name"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <input
            className="input grow"
            placeholder="https://provider.example/subscription"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <button className="btn btn-primary" disabled={busy} onClick={() => void doAdd()}>
            ADD
          </button>
        </div>
      </div>

      <div className="card">
        <div className="card-title row between">
          <span>SUBSCRIPTIONS ({subscriptions.length})</span>
          {subscriptions.length > 0 && (
            <button className="btn sm" onClick={() => void updateSubs()}>
              UPDATE ALL
            </button>
          )}
        </div>
        {subscriptions.length === 0 && <div className="muted">No subscriptions yet.</div>}
        {subscriptions.map((s) => (
          <div key={s.id} className="sub-row">
            <div className="sub-info">
              <div className="sub-name">{s.name}</div>
              <div className="muted sub-url">{s.url}</div>
              <div className="muted">
                {s.node_count} nodes · updated {formatTime(s.last_updated)}
                {s.last_error && <span className="err"> · {s.last_error}</span>}
              </div>
            </div>
            <div className="row gap-sm">
              <button className="btn sm" onClick={() => void updateSubs(s.id)}>
                UPDATE
              </button>
              <button className="btn sm btn-danger" onClick={() => void deleteSub(s.id)}>
                DEL
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
