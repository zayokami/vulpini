import { useEffect, useRef, useState } from 'react';
import { ArrowDownUp, Pause, Play, Search } from 'lucide-react';
import BasePage from '../components/BasePage';
import { useApp } from '../store';
import type { LogEvent } from '../api';
import clsx from 'clsx';

const LEVELS = ['ALL', 'ERROR', 'WARN', 'INFO', 'DEBUG'] as const;

export default function Logs() {
  const storeLogs = useApp((s) => s.logs);
  const [level, setLevel] = useState<(typeof LEVELS)[number]>('ALL');
  const [query, setQuery] = useState('');
  const [paused, setPaused] = useState(false);
  const [newestFirst, setNewestFirst] = useState(false);
  const [frozen, setFrozen] = useState<LogEvent[]>([]);
  const listRef = useRef<HTMLDivElement>(null);
  const stickToBottom = useRef(true);

  const logs = paused ? frozen : storeLogs;

  const filtered = logs.filter((l) => {
    if (level !== 'ALL' && l.level !== level) return false;
    if (query && !`${l.target} ${l.message}`.toLowerCase().includes(query.toLowerCase()))
      return false;
    return true;
  });
  const shown = newestFirst ? filtered : [...filtered].reverse();

  const togglePause = () => {
    if (!paused) setFrozen(storeLogs);
    setPaused(!paused);
  };

  const onScroll = () => {
    const el = listRef.current;
    if (!el) return;
    stickToBottom.current =
      el.scrollHeight - el.scrollTop - el.clientHeight < 30;
  };

  useEffect(() => {
    if (!newestFirst && stickToBottom.current && !paused) {
      listRef.current?.scrollTo({ top: listRef.current.scrollHeight });
    }
  }, [shown.length, newestFirst, paused]);

  return (
    <BasePage
      title="日志"
      actions={
        <>
          <div className="log-search">
            <Search size={14} />
            <input
              className="input log-search__input"
              placeholder="搜索"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <button className="btn" onClick={() => setNewestFirst((v) => !v)} title="正序/倒序">
            <ArrowDownUp size={15} />
          </button>
          <button className="btn" onClick={togglePause} title={paused ? '继续' : '暂停'}>
            {paused ? <Play size={15} /> : <Pause size={15} />}
          </button>
        </>
      }
    >
      <div className="row" style={{ gap: 6 }}>
        {LEVELS.map((l) => (
          <button
            key={l}
            className={`btn btn--sm ${level === l ? 'btn--active' : ''}`}
            onClick={() => setLevel(l)}
          >
            {l}
          </button>
        ))}
        <span className="muted small">{shown.length} 条</span>
      </div>

      <div className="log-list" ref={listRef} onScroll={onScroll}>
        {shown.length === 0 && <div className="empty">暂无日志</div>}
        {shown.map((l, i) => (
          <div key={i} className={clsx('log-entry', `log-entry--${l.level.toLowerCase()}`)}>
            <span className="log-entry__level">{l.level}</span>
            <span className="log-entry__target">{l.target}</span>
            <span className="log-entry__msg">{l.message}</span>
          </div>
        ))}
      </div>
    </BasePage>
  );
}
