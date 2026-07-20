import { useState } from 'react';
import { useApp } from '../store';

export default function Nodes() {
  const nodes = useApp((s) => s.nodes);
  const importLinks = useApp((s) => s.importLinks);
  const deleteNode = useApp((s) => s.deleteNode);
  const selectNode = useApp((s) => s.selectNode);
  const testDelay = useApp((s) => s.testDelay);
  const testAllDelays = useApp((s) => s.testAllDelays);

  const [text, setText] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);

  const doImport = async () => {
    if (!text.trim()) return;
    const result = await importLinks(text);
    setMessage(result);
    setText('');
  };

  return (
    <div className="page">
      <div className="card">
        <div className="card-title">IMPORT SHARE LINKS</div>
        <textarea
          className="input area"
          rows={3}
          placeholder={'ss://... vmess://... vless://... trojan://...\n(one per line)'}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <div className="row gap">
          <button className="btn btn-primary" onClick={() => void doImport()}>
            IMPORT
          </button>
          <button
            className="btn"
            disabled={testing}
            onClick={() => {
              setTesting(true);
              void testAllDelays().finally(() => setTesting(false));
            }}
          >
            {testing ? 'TESTING…' : 'TEST ALL'}
          </button>
          {message && <span className="muted">{message}</span>}
        </div>
      </div>

      <div className="card">
        <div className="card-title">NODES ({nodes.length})</div>
        {nodes.length === 0 && <div className="muted">No nodes yet — import share links or add a subscription.</div>}
        {nodes.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th></th>
                <th>NAME</th>
                <th>PROTO</th>
                <th>SERVER</th>
                <th>DELAY</th>
                <th>SRC</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {nodes.map((n) => (
                <tr key={n.id} className={n.active ? 'active-row' : ''}>
                  <td>
                    <input
                      type="radio"
                      name="active-node"
                      checked={n.active}
                      onChange={() => void selectNode(n.id)}
                    />
                  </td>
                  <td className="node-name">{n.name}</td>
                  <td className="proto">{n.proto}</td>
                  <td className="server">
                    {n.server}:{n.port}
                  </td>
                  <td className={n.delay_ms != null ? 'delay-ok' : 'muted'}>
                    {n.delay_ms != null ? `${n.delay_ms}ms` : '-'}
                  </td>
                  <td className="muted">{n.source === 'manual' ? 'M' : 'S'}</td>
                  <td className="row gap-sm">
                    <button className="btn sm" onClick={() => void testDelay(n.id)}>
                      PING
                    </button>
                    <button className="btn sm btn-danger" onClick={() => void deleteNode(n.id)}>
                      DEL
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
