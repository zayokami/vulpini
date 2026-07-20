import { useEffect, useState } from 'react';
import BasePage from '../components/BasePage';
import { useApp } from '../store';

export default function Rules() {
  const config = useApp((s) => s.config);
  const patchConfig = useApp((s) => s.patchConfig);

  const [text, setText] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    if (config && !dirty) setText(config.rules.join('\n'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [config]);

  const save = async () => {
    const rules = text
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith('#'));
    try {
      await patchConfig({ rules });
      setDirty(false);
      setMessage('已保存并生效');
    } catch (e) {
      setMessage(`保存失败: ${e}`);
    }
  };

  return (
    <BasePage
      title="规则"
      actions={
        <button className="btn btn--primary" disabled={!dirty} onClick={() => void save()}>
          保存规则
        </button>
      }
    >
      <div className="card">
        <div className="card__subtitle">
          每行一条，按顺序匹配。域名不会本地解析，IP 类规则只匹配字面 IP；最后一条通常是 MATCH。
        </div>
        <div className="rules-hints">
          {['DOMAIN,example.com,direct', 'DOMAIN-SUFFIX,google.com,proxy', 'DOMAIN-KEYWORD,ads,block', 'IP-CIDR,10.0.0.0/8,direct', 'GEOIP,cn,direct', 'GEOSITE,cn,direct', 'PORT,53,block', 'MATCH,proxy'].map(
            (hint) => (
              <code key={hint} className="rules-hint" onClick={() => {
                setText((t) => (t ? `${t}\n${hint}` : hint));
                setDirty(true);
              }}>
                {hint}
              </code>
            ),
          )}
        </div>
        <textarea
          className="input area mono rules-editor"
          rows={14}
          value={text}
          spellCheck={false}
          onChange={(e) => {
            setText(e.target.value);
            setDirty(true);
          }}
        />
        {message && <div className="muted small">{message}</div>}
      </div>
    </BasePage>
  );
}
