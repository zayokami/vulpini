import './styles.css';

interface ApiStats {
  total_requests: number;
  total_bytes_in: number;
  total_bytes_out: number;
  active_connections: number;
  requests_per_second: number;
  bytes_per_second: number;
  avg_latency_ms: number;
  error_rate: number;
}

interface ApiIP {
  address: string;
  port: number;
  country: string | null;
  isp: string | null;
  latency_ms: number;
  status: string;
  enabled: boolean;
}

interface ApiAnomaly {
  id: string;
  timestamp: number;
  anomaly_type: string;
  value: number;
  threshold: number;
  description: string;
  severity: string;
}

const api = {
  async getStats(): Promise<ApiStats | null> {
    try {
      const res = await fetch('http://localhost:9090/api/stats');
      const json = await res.json();
      return json.success ? json.data : null;
    } catch {
      return null;
    }
  },

  async getIPs(): Promise<ApiIP[]> {
    try {
      const res = await fetch('http://localhost:9090/api/ips');
      const json = await res.json();
      return json.success ? json.data : [];
    } catch {
      return [];
    }
  },

  async getAnomalies(): Promise<ApiAnomaly[]> {
    try {
      const res = await fetch('http://localhost:9090/api/anomalies');
      const json = await res.json();
      return json.success ? json.data : [];
    } catch {
      return [];
    }
  },

  async getHealth(): Promise<{ success: boolean; status: string } | null> {
    try {
      const res = await fetch('http://localhost:9090/api/health');
      return await res.json();
    } catch {
      return null;
    }
  },

  async reloadConfig(): Promise<{ success: boolean; message?: string } | null> {
    try {
      const res = await fetch('http://localhost:9090/api/config/reload', { method: 'POST' });
      return await res.json();
    } catch {
      return null;
    }
  },

  async addIP(data: { address: string; port: number; country: string | null; isp: string | null }): Promise<{ success: boolean; message?: string } | null> {
    try {
      const res = await fetch('http://localhost:9090/api/ips', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      return await res.json();
    } catch {
      return null;
    }
  },

  async deleteIP(address: string): Promise<{ success: boolean; message?: string } | null> {
    try {
      const res = await fetch(`http://localhost:9090/api/ips/${address}`, { method: 'DELETE' });
      return await res.json();
    } catch {
      return null;
    }
  }
};

function create<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string> = {}, children: (string | Element)[] = []): HTMLElement {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    el.setAttribute(k, v);
  }
  for (const child of children) {
    if (typeof child === 'string') {
      el.appendChild(document.createTextNode(child));
    } else {
      el.appendChild(child);
    }
  }
  return el;
}

class VulpiniApp {
  private activeTab = 'dashboard';
  private isRunning = false;
  private darkMode = false;
  private stats: ApiStats = {
    total_requests: 0, total_bytes_in: 0, total_bytes_out: 0,
    active_connections: 0, requests_per_second: 0, bytes_per_second: 0,
    avg_latency_ms: 0, error_rate: 0
  };
  private ips: ApiIP[] = [];
  private anomalies: ApiAnomaly[] = [];
  private trafficHistory: { time: string; requests: number }[] = [];

  init(): void {
    this.render();
    this.bindEvents();
    this.startUpdateLoop();
  }

  render(): void {
    document.title = 'Vulpini X';
    document.body.innerHTML = '';
    document.body.appendChild(this.createApp());
  }

  createApp(): Element {
    return create('div', { class: `app ${this.darkMode ? 'dark' : 'light'}` }, [
      this.createHeader(),
      this.createNav(),
      this.createMain()
    ]);
  }

  createHeader(): Element {
    const header = create('header', { class: 'header' });
    const logo = create('div', { class: 'logo' });
    logo.appendChild(create('span', { class: 'logo-text' }, ['VULPINI']));
    logo.appendChild(create('span', { class: 'logo-subtitle' }, ['X']));
    header.appendChild(logo);

    const actions = create('div', { class: 'header-actions' });
    actions.appendChild(create('button', { class: 'btn-toggle' }, [this.darkMode ? 'LIGHT' : 'DARK']));
    actions.appendChild(create('button', { class: `btn ${this.isRunning ? 'btn-stop' : 'btn-start'}` }, [this.isRunning ? 'STOP' : 'START']));
    header.appendChild(actions);

    return header;
  }

  createNav(): Element {
    const nav = create('nav', { class: 'nav' });
    for (const tab of ['dashboard', 'config', 'ips', 'logs']) {
      nav.appendChild(create('button', {
        class: `nav-item ${this.activeTab === tab ? 'active' : ''}`,
        'data-tab': tab
      }, [tab.toUpperCase()]));
    }
    return nav;
  }

  createMain(): Element {
    const main = create('main', { class: 'main' });
    if (this.activeTab === 'dashboard') {
      main.appendChild(this.createDashboard());
    } else if (this.activeTab === 'config') {
      main.appendChild(this.createConfig());
    } else if (this.activeTab === 'ips') {
      main.appendChild(this.createIPs());
    } else if (this.activeTab === 'logs') {
      main.appendChild(this.createLogs());
    }
    return main;
  }

  createDashboard(): Element {
    const dashboard = create('div', { class: 'dashboard' });
    const statsGrid = create('div', { class: 'stats-grid' });

    const items = [
      { label: 'STATUS', value: this.isRunning ? 'RUNNING' : 'STOPPED', valueClass: this.isRunning ? 'running' : 'stopped' },
      { label: 'CONNECTIONS', value: String(this.stats.active_connections) },
      { label: 'REQUESTS/S', value: this.stats.requests_per_second.toFixed(1) },
      { label: 'BYTES/S', value: `${(this.stats.bytes_per_second / 1024).toFixed(1)} KB` },
      { label: 'AVG LATENCY', value: `${this.stats.avg_latency_ms.toFixed(1)}ms` },
      { label: 'ERROR RATE', value: `${(this.stats.error_rate * 100).toFixed(2)}%` }
    ];

    for (const item of items) {
      const card = create('div', { class: 'stat-card' });
      card.appendChild(create('div', { class: 'stat-label' }, [item.label]));
      card.appendChild(create('div', { class: `stat-value ${item.valueClass || ''}` }, [item.value]));
      statsGrid.appendChild(card);
    }
    dashboard.appendChild(statsGrid);

    const chartContainer = create('div', { class: 'chart-container' });
    chartContainer.appendChild(create('div', { class: 'chart-title' }, ['TRAFFIC OVERVIEW']));
    chartContainer.appendChild(create('canvas', { id: 'traffic-chart', width: '800', height: '250' }));
    dashboard.appendChild(chartContainer);

    return dashboard;
  }

  createConfig(): Element {
    const panel = create('div', { class: 'config-panel' });

    const socks5Section = create('div', { class: 'config-section' });
    socks5Section.appendChild(create('div', { class: 'section-title' }, ['SOCKS5 SETTINGS']));
    socks5Section.appendChild(this.createInput('LISTEN ADDRESS', 'text', '127.0.0.1', 'socks5-addr'));
    socks5Section.appendChild(this.createInput('LISTEN PORT', 'number', '1080', 'socks5-port'));
    socks5Section.appendChild(this.createInput('MAX CONNECTIONS', 'number', '1000', 'socks5-max'));
    panel.appendChild(socks5Section);

    const httpSection = create('div', { class: 'config-section' });
    httpSection.appendChild(create('div', { class: 'section-title' }, ['HTTP PROXY SETTINGS']));
    httpSection.appendChild(this.createInput('LISTEN ADDRESS', 'text', '127.0.0.1', 'http-addr'));
    httpSection.appendChild(this.createInput('LISTEN PORT', 'number', '8080', 'http-port'));
    panel.appendChild(httpSection);

    const btnGroup = create('div', { class: 'button-group' });
    btnGroup.appendChild(create('button', { class: 'btn btn-save' }, ['SAVE CONFIG']));
    btnGroup.appendChild(create('button', { class: 'btn btn-reload' }, ['RELOAD CONFIG']));
    panel.appendChild(btnGroup);

    return panel;
  }

  createInput(label: string, type: string, value: string, id: string): Element {
    const group = create('div', { class: 'form-group' });
    group.appendChild(create('label', { for: id }, [label]));
    group.appendChild(create('input', { type, id, value }));
    return group;
  }

  createIPs(): Element {
    const panel = create('div', { class: 'ip-panel' });
    panel.appendChild(create('div', { class: 'section-title' }, ['IP POOL']));

    const addForm = create('div', { class: 'add-ip-form' });
    const formRow = create('div', { class: 'form-row' });
    formRow.appendChild(create('input', { type: 'text', placeholder: 'IP Address', id: 'new-ip-address' }));
    formRow.appendChild(create('input', { type: 'number', placeholder: 'Port', value: '1080', id: 'new-ip-port' }));
    formRow.appendChild(create('input', { type: 'text', placeholder: 'Country (optional)', id: 'new-ip-country' }));
    formRow.appendChild(create('input', { type: 'text', placeholder: 'ISP (optional)', id: 'new-ip-isp' }));
    formRow.appendChild(create('button', { class: 'btn btn-add' }, ['ADD IP']));
    addForm.appendChild(formRow);
    panel.appendChild(addForm);

    const table = create('table', { class: 'ip-table' });
    table.appendChild(create('thead', {}, [create('tr', {}, [
      create('th', {}, ['ADDRESS']),
      create('th', {}, ['PORT']),
      create('th', {}, ['COUNTRY']),
      create('th', {}, ['LATENCY']),
      create('th', {}, ['STATUS']),
      create('th', {}, ['ACTIONS'])
    ])]));

    const tbody = create('tbody', { id: 'ip-list' });
    for (const ip of this.ips) {
      const tr = create('tr');
      tr.appendChild(create('td', {}, [ip.address]));
      tr.appendChild(create('td', {}, [String(ip.port)]));
      tr.appendChild(create('td', {}, [ip.country || '-']));
      tr.appendChild(create('td', {}, [`${ip.latency_ms.toFixed(1)}ms`]));
      tr.appendChild(create('td', {}, [create('span', { class: `status-badge ${ip.status}` }, [ip.status.toUpperCase()])]));
      tr.appendChild(create('td', {}, [create('button', { class: 'btn btn-delete', 'data-address': ip.address }, ['DELETE'])]));
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    panel.appendChild(table);

    return panel;
  }

  createLogs(): Element {
    const panel = create('div', { class: 'log-panel' });
    panel.appendChild(create('div', { class: 'section-title' }, ['SYSTEM LOGS']));

    const logContainer = create('div', { class: 'log-container', id: 'log-list' });
    for (const anomaly of this.anomalies.slice(0, 50)) {
      const entry = create('div', { class: `log-entry ${anomaly.severity}` });
      entry.appendChild(create('span', { class: 'log-time' }, [new Date(anomaly.timestamp * 1000).toLocaleTimeString()]));
      entry.appendChild(create('span', { class: 'log-level' }, [`[${anomaly.severity.toUpperCase()}]`]));
      entry.appendChild(create('span', { class: 'log-message' }, [anomaly.description]));
      logContainer.appendChild(entry);
    }
    panel.appendChild(logContainer);

    return panel;
  }

  bindEvents(): void {
    document.querySelectorAll('.nav-item').forEach(btn => {
      btn.addEventListener('click', () => {
        this.activeTab = (btn as HTMLElement).dataset.tab || 'dashboard';
        this.render();
        this.bindEvents();
      });
    });

    document.querySelector('.btn-toggle')?.addEventListener('click', () => {
      this.darkMode = !this.darkMode;
      this.render();
      this.bindEvents();
    });

    document.querySelector('.btn-start, .btn-stop')?.addEventListener('click', () => {
      this.isRunning = !this.isRunning;
      this.render();
      this.bindEvents();
    });

    document.querySelector('.btn-reload')?.addEventListener('click', async () => {
      const result = await api.reloadConfig();
      alert(result?.success ? 'Configuration reloaded successfully' : 'Failed to reload configuration');
    });

    document.querySelector('.btn-add')?.addEventListener('click', async () => {
      const address = (document.getElementById('new-ip-address') as HTMLInputElement)?.value;
      const port = parseInt((document.getElementById('new-ip-port') as HTMLInputElement)?.value || '1080');
      const country = (document.getElementById('new-ip-country') as HTMLInputElement)?.value || null;
      const isp = (document.getElementById('new-ip-isp') as HTMLInputElement)?.value || null;

      if (!address) {
        alert('IP address is required');
        return;
      }

      const result = await api.addIP({ address, port, country, isp });
      if (result?.success) {
        alert('IP added successfully');
        this.ips = await api.getIPs();
        this.render();
        this.bindEvents();
      } else {
        alert('Failed to add IP');
      }
    });

    document.querySelectorAll('.btn-delete').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const address = (e.target as HTMLElement).dataset.address;
        if (!address || !confirm(`Delete IP ${address}?`)) return;

        const result = await api.deleteIP(address);
        if (result?.success) {
          this.ips = await api.getIPs();
          this.render();
          this.bindEvents();
        } else {
          alert('Failed to delete IP');
        }
      });
    });
  }

  async startUpdateLoop(): Promise<void> {
    const update = async () => {
      const health = await api.getHealth();
      this.isRunning = health?.success === true;

      if (this.isRunning) {
        const statsData = await api.getStats();
        if (statsData) {
          this.stats = statsData;
          this.trafficHistory.push({
            time: new Date().toLocaleTimeString(),
            requests: Math.floor(statsData.requests_per_second)
          });
          if (this.trafficHistory.length > 30) {
            this.trafficHistory.shift();
          }
        }

        if (this.activeTab === 'ips') {
          this.ips = await api.getIPs();
          this.render();
          this.bindEvents();
        }

        if (this.activeTab === 'logs') {
          this.anomalies = await api.getAnomalies();
          this.render();
          this.bindEvents();
        }
      }

      if (this.activeTab === 'dashboard') {
        this.drawChart();
      }

      setTimeout(update, 2000);
    };

    update();
  }

  drawChart(): void {
    const canvas = document.getElementById('traffic-chart') as HTMLCanvasElement;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const w = canvas.width, h = canvas.height;
    const p = 40;
    const cw = w - p * 2, ch = h - p * 2;

    ctx.fillStyle = this.darkMode ? '#1a1a2e' : '#f5f5f5';
    ctx.fillRect(0, 0, w, h);

    if (this.trafficHistory.length < 2) return;

    const max = Math.max(...this.trafficHistory.map(d => d.requests), 10);
    const stepX = cw / (this.trafficHistory.length - 1);

    ctx.strokeStyle = this.darkMode ? '#333' : '#ddd';
    ctx.beginPath();
    for (let i = 0; i <= 4; i++) {
      const y = p + (ch / 4) * i;
      ctx.moveTo(p, y);
      ctx.lineTo(w - p, y);
    }
    ctx.stroke();

    ctx.strokeStyle = '#00ff88';
    ctx.lineWidth = 2;
    ctx.beginPath();
    for (let i = 0; i < this.trafficHistory.length; i++) {
      const x = p + i * stepX;
      const y = p + ch - (this.trafficHistory[i].requests / max) * ch;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    }
    ctx.stroke();

    ctx.fillStyle = this.darkMode ? '#888' : '#666';
    ctx.font = '10px monospace';
    ctx.fillText('0', p - 15, p + 10);
    ctx.fillText(String(max), p - 25, p);
  }
}

document.addEventListener('DOMContentLoaded', () => new VulpiniApp().init());
