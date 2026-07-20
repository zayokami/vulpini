import { useEffect, useState } from 'react';
import TitleBar from './components/TitleBar';
import Sidebar, { type PageId } from './components/Sidebar';
import { useApp } from './store';
import Home from './pages/Home';
import Nodes from './pages/Nodes';
import Subscriptions from './pages/Subscriptions';
import Rules from './pages/Rules';
import Logs from './pages/Logs';
import Settings from './pages/Settings';

const COLLAPSE_KEY = 'vulpini.sidebar_collapsed';

export default function App() {
  const [page, setPage] = useState<PageId>('home');
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem(COLLAPSE_KEY) === '1',
  );
  const init = useApp((s) => s.init);
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

  const toggleCollapsed = (value: boolean) => {
    setCollapsed(value);
    localStorage.setItem(COLLAPSE_KEY, value ? '1' : '0');
  };

  return (
    <div className="app">
      <TitleBar />
      <div className="app__body">
        <Sidebar page={page} collapsed={collapsed} onNavigate={setPage} />
        {page === 'home' && <Home onNavigate={setPage} />}
        {page === 'nodes' && <Nodes />}
        {page === 'subs' && <Subscriptions />}
        {page === 'rules' && <Rules />}
        {page === 'logs' && <Logs />}
        {page === 'settings' && <Settings collapsed={collapsed} onToggleCollapsed={toggleCollapsed} />}
      </div>
      {notice && <div className="toast">{notice}</div>}
    </div>
  );
}
