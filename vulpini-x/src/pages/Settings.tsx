import { useState } from 'react';
import { useApp } from '../store';

export default function Settings() {
  const config = useApp((s) => s.config);
  const patchConfig = useApp((s) => s.patchConfig);
  const updateGeo = useApp((s) => s.updateGeo);

  const [listen, setListen] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [geoBusy, setGeoBusy] = useState(false);

  const currentListen = listen ?? config?.listen ?? '';

  const saveListen = async () => {
    try {
      await patchConfig({ listen: currentListen });
      setListen(null);
      setMessage('saved (engine restarts if the address changed)');
    } catch (e) {
      setMessage(`error: ${e}`);
    }
  };

  return (
    <div className="page">
      <div className="card">
        <div className="card-title">INBOUND</div>
        <div className="row gap">
          <span className="muted">LISTEN</span>
          <input
            className="input"
            value={currentListen}
            onChange={(e) => setListen(e.target.value)}
            placeholder="127.0.0.1:7890"
          />
          <button
            className="btn btn-primary"
            disabled={listen == null || listen === config?.listen}
            onClick={() => void saveListen()}
          >
            SAVE
          </button>
        </div>
        {message && <div className="muted">{message}</div>}
      </div>

      <div className="card">
        <div className="card-title">GEO DATA</div>
        <div className="muted help">
          geosite.dat / geoip.dat power the GEOSITE and GEOIP rules (Loyalsoldier v2ray-rules-dat).
        </div>
        <button
          className="btn"
          disabled={geoBusy}
          onClick={() => {
            setGeoBusy(true);
            void updateGeo().finally(() => setGeoBusy(false));
          }}
        >
          {geoBusy ? 'UPDATING…' : 'UPDATE GEO DATA'}
        </button>
      </div>

      <div className="card">
        <div className="card-title">ABOUT</div>
        <div className="kv">
          <span>APP</span>
          <span>Vulpini X 0.2.0</span>
        </div>
        <div className="kv">
          <span>CORE</span>
          <span>self-contained Rust proxy engine</span>
        </div>
        <div className="kv">
          <span>LICENSE</span>
          <span>MIT</span>
        </div>
      </div>
    </div>
  );
}
