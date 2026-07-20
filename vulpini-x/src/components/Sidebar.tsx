import { Globe, Home, ListOrdered, Rss, ScrollText, Settings } from 'lucide-react';
import clsx from 'clsx';
import TrafficWidget from './TrafficWidget';

export type PageId = 'home' | 'nodes' | 'subs' | 'rules' | 'logs' | 'settings';

const NAV: { id: PageId; label: string; icon: React.ReactNode }[] = [
  { id: 'home', label: '首页', icon: <Home size={17} /> },
  { id: 'nodes', label: '代理', icon: <Globe size={17} /> },
  { id: 'subs', label: '订阅', icon: <Rss size={17} /> },
  { id: 'rules', label: '规则', icon: <ListOrdered size={17} /> },
  { id: 'logs', label: '日志', icon: <ScrollText size={17} /> },
  { id: 'settings', label: '设置', icon: <Settings size={17} /> },
];

interface Props {
  page: PageId;
  collapsed: boolean;
  onNavigate: (page: PageId) => void;
}

export default function Sidebar({ page, collapsed, onNavigate }: Props) {
  return (
    <aside className={clsx('sidebar', collapsed && 'sidebar--collapsed')}>
      <div className="sidebar__logo">
        <div className="sidebar__logo-icon">V</div>
        <span className="sidebar__logo-text">VULPINI</span>
      </div>
      <nav className="sidebar__nav">
        {NAV.map((item) => (
          <button
            key={item.id}
            className={clsx('sidebar__item', page === item.id && 'sidebar__item--active')}
            onClick={() => onNavigate(item.id)}
            title={item.label}
          >
            <span className="sidebar__item-icon">{item.icon}</span>
            <span className="sidebar__item-label">{item.label}</span>
          </button>
        ))}
      </nav>
      <TrafficWidget />
    </aside>
  );
}
