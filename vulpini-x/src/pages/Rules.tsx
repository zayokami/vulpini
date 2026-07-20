import { useEffect, useState } from 'react';
import { useApp } from '../store';

export default function Rules() {
  const config = useApp((s) => s.config);
  const patchConfig = useApp((s) => s.patchConfig);

  const [text, setText] = useState('');
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    if (config) setText(config.rules.join('\n'));
    // Only populate from config on first load of this page.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const save = async () => {
    const rules = text
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith('#'));
    try {
      await patchConfig({ rules });
      setMessage('saved');
    } catch (e) {
      setMessage(`error: ${e}`);
    }
  };

  return (
    <div className="page">
      <div className="card">
        <div className="card-title">RULES (clash syntax, one per line)</div>
        <div className="muted help">
          DOMAIN,example.com,direct · DOMAIN-SUFFIX,google.com,proxy · DOMAIN-KEYWORD,ads,block ·
          IP-CIDR,10.0.0.0/8,direct · GEOIP,cn,direct · GEOSITE,cn,direct · PORT,53,block ·
          MATCH,proxy — evaluated in order; domains are never resolved locally, so IP rules only
          match literal IPs. The last rule is usually MATCH.
        </div>
        <textarea
          className="input area mono"
          rows={12}
          value={text}
          onChange={(e) => setText(e.target.value)}
          spellCheck={false}
        />
        <div className="row gap">
          <button className="btn btn-primary" onClick={() => void save()}>
            SAVE RULES
          </button>
          {message && <span className="muted">{message}</span>}
        </div>
      </div>
    </div>
  );
}
