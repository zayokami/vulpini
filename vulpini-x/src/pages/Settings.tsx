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
