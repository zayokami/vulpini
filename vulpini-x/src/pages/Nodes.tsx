import { useMemo, useState } from 'react';
import {
  ArrowDownAZ,
  ArrowDownWideNarrow,
  ClipboardPaste,
  ListOrdered,
  LocateFixed,
  Trash2,
  Zap,
} from 'lucide-react';
import BasePage from '../components/BasePage';
import DelayBadge from '../components/DelayBadge';
import { useApp } from '../store';
import { delayStateOf, useDelay, type Entry } from '../store/delay';
import type { Mode, NodeView } from '../api';
import clsx from 'clsx';

const MODES: { id: Mode; label: string }[] = [
  { id: 'rule', label: '规则' },
  { id: 'global', label: '全局' },
  { id: 'direct', label: '直连' },
];

type SortMode = 'default' | 'delay' | 'name';

interface Group {
  key: string;
  title: string;
  nodes: NodeView[];
}

function sortNodes(
  nodes: NodeView[],
  mode: SortMode,
  delays: Record<string, Entry>,
): NodeView[] {
  if (mode === 'default') return nodes;
  return [...nodes].sort((a, b) => {
    if (mode === 'name') return a.name.localeCompare(b.name);
    const da = delayStateOf(delays, a.id);
    const db = delayStateOf(delays, b.id);
    const va = da.kind === 'ok' ? da.ms : Number.POSITIVE_INFINITY;
    const vb = db.kind === 'ok' ? db.ms : Number.POSITIVE_INFINITY;
    return va - vb;
  });
}

export default function Nodes() {
  const nodes = useApp((s) => s.nodes);
  const subscriptions = useApp((s) => s.subscriptions);
  const status = useApp((s) => s.status);
  const importLinks = useApp((s) => s.importLinks);
  const deleteNode = useApp((s) => s.deleteNode);
  const selectNode = useApp((s) => s.selectNode);
  const setMode = useApp((s) => s.setMode);
  const delayEntries = useDelay((s) => s.entries);
  const testNode = useDelay((s) => s.testNode);
  const testAll = useDelay((s) => s.testAll);

  const [text, setText] = useState('');
  const [filter, setFilter] = useState('');
  const [sort, setSort] = useState<SortMode>('default');
  const [message, setMessage] = useState<string | null>(null);

  const groups = useMemo<Group[]>(() => {
    const subName = new Map(subscriptions.map((s) => [s.id, s.name]));
    const byKey = new Map<string, Group>();
    const filtered = filter
      ? nodes.filter((n) => n.name.toLowerCase().includes(filter.toLowerCase()))
      : nodes;
    for (const n of filtered) {
      const key = n.source_id ?? 'manual';
      const title = n.source_id ? (subName.get(n.source_id) ?? '订阅') : '手动添加';
      if (!byKey.has(key)) byKey.set(key, { key, title, nodes: [] });
      byKey.get(key)!.nodes.push(n);
    }
    const result = [...byKey.values()];
    // Manual group first, then subscriptions by name.
    result.sort((a, b) =>
      a.key === 'manual' ? -1 : b.key === 'manual' ? 1 : a.title.localeCompare(b.title),
    );
    return result;
  }, [nodes, subscriptions, filter]);

  const doImport = async () => {
    if (!text.trim()) return;
    const result = await importLinks(text);
    setMessage(result);
    setText('');
  };

  const pasteClipboard = async () => {
    try {
      const clip = await navigator.clipboard.readText();
      setText(clip);
    } catch {
      setMessage('无法读取剪贴板');
    }
  };

  const cycleSort = () =>
    setSort((s) => (s === 'default' ? 'delay' : s === 'delay' ? 'name' : 'default'));

  const sortIcon =
    sort === 'default' ? <ListOrdered size={15} /> : sort === 'delay' ? <ArrowDownWideNarrow size={15} /> : <ArrowDownAZ size={15} />;

  const scrollToActive = () => {
    document.querySelector('.node-row--active')?.scrollIntoView({ block: 'center', behavior: 'smooth' });
  };

  return (
    <BasePage
      title="代理"
      actions={
        <>
          <div className="btn-group">
            {MODES.map((m) => (
              <button
                key={m.id}
                className={`btn ${status?.mode === m.id ? 'btn--active' : ''}`}
                onClick={() => void setMode(m.id)}
              >
                {m.label}
              </button>
            ))}
          </div>
          <input
            className="input"
            placeholder="搜索节点"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            style={{ width: 140 }}
          />
          <button className="btn" onClick={cycleSort} title={`排序: ${sort}`}>
            {sortIcon}
          </button>
          <button className="btn" onClick={scrollToActive} title="定位到当前节点">
            <LocateFixed size={15} />
          </button>
          <button
            className="btn btn--primary"
            onClick={() => testAll(nodes.map((n) => n.id))}
            disabled={nodes.length === 0}
          >
            <Zap size={15} />
            全部测速
          </button>
        </>
      }
    >
      <div className="card">
        <textarea
          className="input area"
          rows={2}
          placeholder={'粘贴分享链接导入（ss:// vmess:// vless:// trojan://），每行一条'}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <div className="row" style={{ gap: 8 }}>
          <button className="btn btn--primary" onClick={() => void doImport()}>
            导入
          </button>
          <button className="btn" onClick={() => void pasteClipboard()}>
            <ClipboardPaste size={15} />
            粘贴剪贴板
          </button>
          {message && <span className="muted small">{message}</span>}
        </div>
      </div>

      {groups.length === 0 && (
        <div className="empty">
          <span>暂无节点 — 导入分享链接或前往订阅页添加订阅</span>
        </div>
      )}

      {groups.map((group) => (
        <div key={group.key} className="node-group">
          <div className="node-group__header">
            <span className="node-group__title">{group.title}</span>
            <span className="badge badge--accent">{group.nodes.length}</span>
            <button
              className="btn btn--sm"
              onClick={() => testAll(group.nodes.map((n) => n.id))}
            >
              <Zap size={13} />
              测速
            </button>
          </div>
          <div className="node-group__list">
            {sortNodes(group.nodes, sort, delayEntries).map((n) => {
              const delay = delayStateOf(delayEntries, n.id);
              return (
                <div
                  key={n.id}
                  className={clsx('node-row', n.active && 'node-row--active')}
                  onClick={() => void selectNode(n.id)}
                >
                  <span className="node-row__name" title={n.name}>
                    {n.name}
                  </span>
                  <span className="badge">{n.proto}</span>
                  <span className="node-row__right">
                    <span className="node-row__delay">
                      <DelayBadge state={delay} />
                    </span>
                    <span className="node-row__hover-actions">
                      <button
                        className="btn btn--sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          testNode(n.id);
                        }}
                      >
                        测速
                      </button>
                      <button
                        className="btn btn--sm btn--danger"
                        onClick={(e) => {
                          e.stopPropagation();
                          void deleteNode(n.id);
                        }}
                      >
                        <Trash2 size={13} />
                      </button>
                    </span>
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </BasePage>
  );
}
