import { useState } from 'react';
import BasePage from '../components/BasePage';
import SettingItem from '../components/SettingItem';
import Switch from '../components/Switch';
import { useApp } from '../store';
import { useTheme, type Theme } from '../store/theme';

const THEMES: { id: Theme; label: string }[] = [
  { id: 'system', label: '跟随系统' },
  { id: 'light', label: '浅色' },
  { id: 'dark', label: '深色' },
];

interface Props {
  collapsed: boolean;
  onToggleCollapsed: (value: boolean) => void;
}

/** 代理 settings group: probe URL, timeout, subscription UA, bypass list. */
function ProxySettingsCard() {
  const config = useApp((s) => s.config);
  const patchConfig = useApp((s) => s.patchConfig);

  const [probeUrl, setProbeUrl] = useState<string | null>(null);
  const [timeout, setTimeout_] = useState<string | null>(null);
  const [ua, setUa] = useState<string | null>(null);
  const [bypass, setBypass] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const save = async (patch: Parameters<typeof patchConfig>[0]) => {
    try {
      await patchConfig(patch);
      setMsg('已保存');
      setProbeUrl(null);
      setTimeout_(null);
      setUa(null);
      setBypass(null);
    } catch (e) {
      setMsg(`保存失败: ${e}`);
    }
  };

  const dirtyTimeout = timeout != null && timeout !== String(config?.delay_timeout_secs ?? '');

  return (
    <div className="card">
      <div className="card__title">代理</div>
      <SettingItem label="测速地址" description="延迟测试使用的 HTTP 探测地址（必须 http://）">
        <input
          className="input settings-input"
          value={probeUrl ?? config?.probe_url ?? ''}
          onChange={(e) => setProbeUrl(e.target.value)}
          placeholder="http://www.gstatic.com/generate_204"
        />
        <button
          className="btn btn--primary btn--sm"
          disabled={probeUrl == null || probeUrl === config?.probe_url}
          onClick={() => void save({ probe_url: probeUrl ?? undefined })}
        >
          保存
        </button>
      </SettingItem>
      <SettingItem label="测速超时" description="单个节点测速的最长等待（1-60 秒）">
        <input
          className="input settings-input--sm"
          type="number"
          min={1}
          max={60}
          value={timeout ?? String(config?.delay_timeout_secs ?? 5)}
          onChange={(e) => setTimeout_(e.target.value)}
        />
        <button
          className="btn btn--primary btn--sm"
          disabled={!dirtyTimeout}
          onClick={() => void save({ delay_timeout_secs: Number(timeout) })}
        >
          保存
        </button>
      </SettingItem>
      <SettingItem
        label="订阅 User-Agent"
        description="留空使用内置 UA；部分机场只认 clash 系 UA，可填 clash.meta"
      >
        <input
          className="input settings-input"
          value={ua ?? config?.subscription_user_agent ?? ''}
          onChange={(e) => setUa(e.target.value)}
          placeholder="(默认 vulpini/x.y)"
        />
        <button
          className="btn btn--primary btn--sm"
          disabled={ua == null || ua === (config?.subscription_user_agent ?? '')}
          onClick={() => void save({ subscription_user_agent: ua ?? undefined })}
        >
          保存
        </button>
      </SettingItem>
      <SettingItem label="系统代理绕过列表" description="Windows ProxyOverride，分号分隔，更改后重开系统代理生效">
        <input
          className="input settings-input"
          value={bypass ?? config?.sysproxy_override ?? ''}
          onChange={(e) => setBypass(e.target.value)}
          placeholder="localhost;127.*;...;<local>"
        />
        <button
          className="btn btn--primary btn--sm"
          disabled={bypass == null || bypass === config?.sysproxy_override}
          onClick={() => void save({ sysproxy_override: bypass ?? undefined })}
        >
          保存
        </button>
      </SettingItem>
      {msg && <div className="muted small">{msg}</div>}
    </div>
  );
}

export default function Settings({ collapsed, onToggleCollapsed }: Props) {
  const config = useApp((s) => s.config);
  const patchConfig = useApp((s) => s.patchConfig);
  const updateGeo = useApp((s) => s.updateGeo);
  const { theme, setTheme } = useTheme();

  const [listen, setListen] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [geoBusy, setGeoBusy] = useState(false);

  const saveListen = async () => {
    try {
      await patchConfig({ listen: listen ?? undefined });
      setListen(null);
      setMessage('已保存（地址变更时引擎自动重启）');
    } catch (e) {
      setMessage(`保存失败: ${e}`);
    }
  };

  return (
    <BasePage title="设置">
      <div className="card">
        <div className="card__title">外观</div>
        <SettingItem label="主题" description="浅色 / 深色 / 跟随系统">
          <div className="btn-group">
            {THEMES.map((t) => (
              <button
                key={t.id}
                className={`btn ${theme === t.id ? 'btn--active' : ''}`}
                onClick={() => setTheme(t.id)}
              >
                {t.label}
              </button>
            ))}
          </div>
        </SettingItem>
        <SettingItem label="折叠侧栏" description="收起为纯图标导航">
          <Switch checked={collapsed} onChange={onToggleCollapsed} />
        </SettingItem>
      </div>

      <div className="card">
        <div className="card__title">入站</div>
        <SettingItem label="监听地址" description="混合 SOCKS5/HTTP 入站端口">
          <input
            className="input"
            value={listen ?? config?.listen ?? ''}
            onChange={(e) => setListen(e.target.value)}
            placeholder="127.0.0.1:7890"
          />
          <button
            className="btn btn--primary btn--sm"
            disabled={listen == null || listen === config?.listen}
            onClick={() => void saveListen()}
          >
            保存
          </button>
        </SettingItem>
        {message && <div className="muted small">{message}</div>}
      </div>

      <ProxySettingsCard />

      <div className="card">
        <div className="card__title">规则数据</div>
        <SettingItem
          label="geosite / geoip 数据"
          description="GEOSITE 和 GEOIP 规则依赖此数据（Loyalsoldier v2ray-rules-dat）"
        >
          <button
            className="btn btn--bordered btn--sm"
            disabled={geoBusy}
            onClick={() => {
              setGeoBusy(true);
              void updateGeo().finally(() => setGeoBusy(false));
            }}
          >
            {geoBusy ? '更新中…' : '立即更新'}
          </button>
        </SettingItem>
      </div>

      <div className="card">
        <div className="card__title">关于</div>
        <SettingItem label="版本">
          <span className="muted small">Vulpini X 0.2.0</span>
        </SettingItem>
        <SettingItem label="核心">
          <span className="muted small">自研 Rust 代理引擎</span>
        </SettingItem>
        <SettingItem label="许可证">
          <span className="muted small">MIT</span>
        </SettingItem>
      </div>
    </BasePage>
  );
}
