import { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import './App.css';

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

declare global {
  interface Window {
    vulpiniAPI: {
      getStats: () => Promise<{ success: boolean; data: ApiStats } | null>;
      getIPs: () => Promise<{ success: boolean; data: ApiIP[] } | null>;
      getAnomalies: () => Promise<{ success: boolean; data: ApiAnomaly[] } | null>;
      getHealth: () => Promise<{ success: boolean; status: string } | null>;
      reloadConfig: () => Promise<{ success: boolean; message?: string } | null>;
      addIP: (data: { address: string; port: number; country: string | null; isp: string | null }) => Promise<{ success: boolean; message?: string } | null>;
      deleteIP: (address: string) => Promise<{ success: boolean; message?: string } | null>;
    };
  }
}

function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'config' | 'ips' | 'logs'>('dashboard');
  const [isRunning, setIsRunning] = useState(false);
  const [stats, setStats] = useState<ApiStats>({
    total_requests: 0,
    total_bytes_in: 0,
    total_bytes_out: 0,
    active_connections: 0,
    requests_per_second: 0,
    bytes_per_second: 0,
    avg_latency_ms: 0,
    error_rate: 0,
  });
  const [ips, setIPs] = useState<ApiIP[]>([]);
  const [anomalies, setAnomalies] = useState<ApiAnomaly[]>([]);
  const [trafficHistory, setTrafficHistory] = useState<{time: string, requests: number}[]>([]);
  const [darkMode, setDarkMode] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const health = await window.vulpiniAPI.getHealth();
        setIsRunning(health?.success === true);

        if (health?.success) {
          const statsData = await window.vulpiniAPI.getStats();
          const ipsData = await window.vulpiniAPI.getIPs();
          const anomaliesData = await window.vulpiniAPI.getAnomalies();

          if (statsData?.success && statsData.data) {
            setStats(statsData.data);
            setTrafficHistory(prev => {
              const now = new Date().toLocaleTimeString();
              const newData = [...prev, { time: now, requests: Math.floor(statsData.data!.requests_per_second) }];
              return newData.slice(-30);
            });
          }

          if (ipsData?.success && ipsData.data) {
            setIPs(ipsData.data);
          }

          if (anomaliesData?.success && anomaliesData.data) {
            setAnomalies(anomaliesData.data);
          }
        }
        setError(null);
      } catch (err) {
        setError('Failed to connect to backend');
        setIsRunning(false);
      }
    };

    const timer = setInterval(fetchData, 2000);
    fetchData();

    return () => clearInterval(timer);
  }, []);

  return (
    <div className={`app ${darkMode ? 'dark' : 'light'}`}>
      <header className="header">
        <div className="logo">
          <span className="logo-text">VULPINI</span>
          <span className="logo-subtitle">X</span>
        </div>
        <div className="header-actions">
          <button
            className="btn-toggle"
            onClick={() => setDarkMode(!darkMode)}
          >
            {darkMode ? 'LIGHT' : 'DARK'}
          </button>
          <button
            className={`btn ${isRunning ? 'btn-stop' : 'btn-start'}`}
            onClick={() => setIsRunning(!isRunning)}
          >
            {isRunning ? 'STOP' : 'START'}
          </button>
        </div>
      </header>

      <nav className="nav">
        {['dashboard', 'config', 'ips', 'logs'].map(tab => (
          <button
            key={tab}
            className={`nav-item ${activeTab === tab ? 'active' : ''}`}
            onClick={() => setActiveTab(tab as typeof activeTab)}
          >
            {tab.toUpperCase()}
          </button>
        ))}
      </nav>

      <main className="main">
        {error && (
          <div className="error-banner">
            {error}
          </div>
        )}

        {activeTab === 'dashboard' && (
          <div className="dashboard">
            <div className="stats-grid">
              <div className="stat-card">
                <div className="stat-label">STATUS</div>
                <div className={`stat-value ${isRunning ? 'running' : 'stopped'}`}>
                  {isRunning ? 'RUNNING' : 'STOPPED'}
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-label">CONNECTIONS</div>
                <div className="stat-value">{stats.active_connections}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">REQUESTS/S</div>
                <div className="stat-value">{stats.requests_per_second.toFixed(1)}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">BYTES/S</div>
                <div className="stat-value">{(stats.bytes_per_second / 1024).toFixed(1)} KB</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">AVG LATENCY</div>
                <div className="stat-value">{stats.avg_latency_ms.toFixed(1)}ms</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">ERROR RATE</div>
                <div className="stat-value">{(stats.error_rate * 100).toFixed(2)}%</div>
              </div>
            </div>

            <div className="chart-container">
              <div className="chart-title">TRAFFIC OVERVIEW</div>
              <ResponsiveContainer width="100%" height={250}>
                <LineChart data={trafficHistory}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#444" />
                  <XAxis dataKey="time" stroke="#888" fontSize={10} />
                  <YAxis stroke="#888" fontSize={10} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#222',
                      border: '1px solid #555',
                      fontSize: '12px'
                    }}
                  />
                  <Line
                    type="monotone"
                    dataKey="requests"
                    stroke="#00ff88"
                    strokeWidth={2}
                    dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {activeTab === 'config' && (
          <div className="config-panel">
            <div className="config-section">
              <div className="section-title">SOCKS5 SETTINGS</div>
              <div className="form-group">
                <label>LISTEN ADDRESS</label>
                <input type="text" defaultValue="127.0.0.1" />
              </div>
              <div className="form-group">
                <label>LISTEN PORT</label>
                <input type="number" defaultValue={1080} />
              </div>
              <div className="form-group">
                <label>MAX CONNECTIONS</label>
                <input type="number" defaultValue={1000} />
              </div>
            </div>

            <div className="config-section">
              <div className="section-title">HTTP PROXY SETTINGS</div>
              <div className="form-group">
                <label>LISTEN ADDRESS</label>
                <input type="text" defaultValue="127.0.0.1" />
              </div>
              <div className="form-group">
                <label>LISTEN PORT</label>
                <input type="number" defaultValue={8080} />
              </div>
            </div>

            <div className="config-section">
              <div className="section-title">ROUTING</div>
              <div className="form-group">
                <label>LOAD BALANCING</label>
                <select defaultValue="fastest">
                  <option value="roundrobin">ROUND ROBIN</option>
                  <option value="leastconnections">LEAST CONNECTIONS</option>
                  <option value="fastest">FASTEST RESPONSE</option>
                </select>
              </div>
              <div className="form-group">
                <label>MAX LATENCY (ms)</label>
                <input type="number" defaultValue={1000} />
              </div>
            </div>

            <div className="button-group">
              <button className="btn btn-save">SAVE CONFIG</button>
              <button className="btn btn-reload" onClick={async () => {
                const result = await window.vulpiniAPI.reloadConfig();
                if (result?.success) {
                  alert('Configuration reloaded successfully');
                } else {
                  alert('Failed to reload configuration');
                }
              }}>RELOAD CONFIG</button>
            </div>
          </div>
        )}

        {activeTab === 'ips' && (
          <div className="ip-panel">
            <div className="section-title">IP POOL</div>

            <div className="add-ip-form">
              <div className="form-row">
                <input
                  type="text"
                  placeholder="IP Address"
                  id="new-ip-address"
                />
                <input
                  type="number"
                  placeholder="Port"
                  defaultValue={1080}
                  id="new-ip-port"
                />
                <input
                  type="text"
                  placeholder="Country (optional)"
                  id="new-ip-country"
                />
                <input
                  type="text"
                  placeholder="ISP (optional)"
                  id="new-ip-isp"
                />
                <button
                  className="btn btn-add"
                  onClick={async () => {
                    const address = (document.getElementById('new-ip-address') as HTMLInputElement).value;
                    const port = parseInt((document.getElementById('new-ip-port') as HTMLInputElement).value);
                    const country = (document.getElementById('new-ip-country') as HTMLInputElement).value || null;
                    const isp = (document.getElementById('new-ip-isp') as HTMLInputElement).value || null;

                    if (!address) {
                      alert('IP address is required');
                      return;
                    }

                    const result = await window.vulpiniAPI.addIP({ address, port, country, isp });
                    if (result?.success) {
                      alert('IP added successfully');
                    } else {
                      alert('Failed to add IP');
                    }
                  }}
                >
                  ADD IP
                </button>
              </div>
            </div>

            <table className="ip-table">
              <thead>
                <tr>
                  <th>ADDRESS</th>
                  <th>PORT</th>
                  <th>COUNTRY</th>
                  <th>LATENCY</th>
                  <th>STATUS</th>
                  <th>ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {ips.map((ip, i) => (
                  <tr key={i}>
                    <td>{ip.address}</td>
                    <td>{ip.port}</td>
                    <td>{ip.country || '-'}</td>
                    <td>{ip.latency_ms.toFixed(1)}ms</td>
                    <td>
                      <span className={`status-badge ${ip.status}`}>
                        {ip.status.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <button
                        className="btn btn-delete"
                        onClick={async () => {
                          if (confirm(`Delete IP ${ip.address}?`)) {
                            const result = await window.vulpiniAPI.deleteIP(ip.address);
                            if (result?.success) {
                              alert('IP deleted successfully');
                            } else {
                              alert('Failed to delete IP');
                            }
                          }
                        }}
                      >
                        DELETE
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {activeTab === 'logs' && (
          <div className="log-panel">
            <div className="section-title">SYSTEM LOGS</div>
            <div className="log-container">
              {anomalies.slice(0, 50).map((anomaly, i) => (
                <div key={i} className={`log-entry ${anomaly.severity}`}>
                  <span className="log-time">{new Date(anomaly.timestamp * 1000).toLocaleTimeString()}</span>
                  <span className="log-level">[{anomaly.severity.toUpperCase()}]</span>
                  <span className="log-message">{anomaly.description}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
