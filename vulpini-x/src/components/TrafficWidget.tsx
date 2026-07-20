import { useCallback, useEffect, useRef } from 'react';
import { ArrowDown, ArrowUp } from 'lucide-react';
import { useApp } from '../store';

const HISTORY = 60;

function formatRate(bytesPerSec: number): string {
  if (bytesPerSec >= 1 << 20) return `${(bytesPerSec / (1 << 20)).toFixed(1)} MB/s`;
  if (bytesPerSec >= 1 << 10) return `${(bytesPerSec / (1 << 10)).toFixed(1)} KB/s`;
  return `${bytesPerSec} B/s`;
}

/** Live traffic graph + rates, pinned to the sidebar bottom. */
export default function TrafficWidget() {
  const stats = useApp((s) => s.stats);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const historyRef = useRef<{ up: number[]; down: number[] }>({ up: [], down: [] });

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const h = historyRef.current;
    const dpr = window.devicePixelRatio || 1;
    const w = Math.max(1, Math.round(canvas.clientWidth * dpr));
    const hgt = Math.max(1, Math.round(canvas.clientHeight * dpr));
    if (canvas.width !== w || canvas.height !== hgt) {
      canvas.width = w;
      canvas.height = hgt;
    }
    ctx.clearRect(0, 0, w, hgt);

    const styles = getComputedStyle(document.documentElement);
    const accent = styles.getPropertyValue('--accent').trim() || '#007aff';
    const upColor = styles.getPropertyValue('--success').trim() || '#06943d';
    const max = Math.max(...h.up, ...h.down, 1024);

    const line = (data: number[], color: string) => {
      if (data.length < 2) return;
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.5 * dpr;
      ctx.lineJoin = 'round';
      ctx.beginPath();
      data.forEach((v, i) => {
        const x = (i / (HISTORY - 1)) * w;
        const y = hgt - (v / max) * (hgt - 4 * dpr) - 2 * dpr;
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      });
      ctx.stroke();
    };

    line(h.down, accent);
    line(h.up, upColor);
  }, []);

  // Feed new samples and repaint on every stats tick.
  useEffect(() => {
    const h = historyRef.current;
    h.up.push(stats?.up_rate ?? 0);
    h.down.push(stats?.down_rate ?? 0);
    if (h.up.length > HISTORY) h.up.shift();
    if (h.down.length > HISTORY) h.down.shift();
    draw();
  }, [stats, draw]);

  // Repaint when the widget itself changes size (window resize, theme
  // change, sidebar collapse) — even with no stats arriving.
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const observer = new ResizeObserver(() => draw());
    observer.observe(canvas);
    return () => observer.disconnect();
  }, [draw]);

  return (
    <div className="traffic">
      <canvas ref={canvasRef} className="traffic__graph" />
      <div className="traffic__row">
        <ArrowUp size={13} />
        <span className="traffic__value">{formatRate(stats?.up_rate ?? 0)}</span>
      </div>
      <div className="traffic__row">
        <ArrowDown size={13} />
        <span className="traffic__value">{formatRate(stats?.down_rate ?? 0)}</span>
      </div>
    </div>
  );
}
