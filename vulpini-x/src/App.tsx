import { useEffect, useState } from 'react';
import { useApp } from './store';
import Home from './pages/Home';
import Nodes from './pages/Nodes';
import Subscriptions from './pages/Subscriptions';
import Rules from './pages/Rules';
import Logs from './pages/Logs';
import Settings from './pages/Settings';

const TABS = [
  { id: 'home', label: 'HOME' },
  { id: 'nodes', label: 'NODES' },
  { id: 'subs', label: 'SUBSCRIPTIONS' },
  { id: 'rules', label: 'RULES' },
  { id: 'logs', label: 'LOGS' },
  { id: 'settings', label: 'SETTINGS' },
] as const;

type TabId = (typeof TABS)[number]['id'];

export default function App() {
  const [tab, setTab] = useState<TabId>('home');
  const init = useApp((s) => s.init);
  const status = useApp((s) => s.status);
  const notice = useApp((s) => s.notice);
  const clearNotice = useApp((s) => s.clearNotice);

  useEffect(() => {
    void init();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!notice) return;
    const t = setTimeout(clearNotice, 4000);
    return () => clearTimeout(t);
  }, [notice, clearNotice]);

  return (
    <div className="app">
      <header className="header">
        <div className="logo">
          <span className="logo-text">VULPINI</span>
          <span className="logo-sub">X</span>
        </div>
        <div className={`status-pill ${status?.running ? 'on' : 'off'}`}>
          {status?.running ? 'RUNNING' : 'STOPPED'}
        </div>
      </header>
      <nav className="nav">
        {TABS.map((t) => (
          <button
            key={t.id}
            className={`nav-item ${tab === t.id ? 'active' : ''}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </nav>
      <main className="main">
        {tab === 'home' && <Home />}
        {tab === 'nodes' && <Nodes />}
        {tab === 'subs' && <Subscriptions />}
        {tab === 'rules' && <Rules />}
        {tab === 'logs' && <Logs />}
        {tab === 'settings' && <Settings />}
      </main>
      {notice && <div className="toast">{notice}</div>}
    </div>
  );
}
