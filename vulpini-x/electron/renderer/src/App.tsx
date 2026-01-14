import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import './App.css';

interface ProxyStatus {
  running: boolean;
  connections: number;
  requestsPerSecond: number;
  bytesPerSecond: number;
  avgLatency: string;
  errorRate: number;
}

interface IPInfo {
  address: string;
  port: number;
  country: string | null;
  latency: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
}

interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
}

function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'config' | 'ips' | 'logs'>('dashboard');
  const [status, setStatus] = useState<ProxyStatus>({
    running: false,
    connections: 0,
    requestsPerSecond: 0,
    bytesPerSecond: 0,
    avgLatency: '0ms',
    errorRate: 0,
  });
  const [ips, setIPs] = useState<IPInfo[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [trafficHistory, setTrafficHistory] = useState<{time: string, requests: number}[]>([]);
  const [darkMode, setDarkMode] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => {
      setStatus(prev => ({
        ...prev,
        running: Math.random() > 0.3,
        connections: Math.floor(Math.random() * 500) + 100,
        requestsPerSecond: Math.random() * 100 + 50,
        bytesPerSecond: Math.random() * 10000 + 5000,
        avgLatency: `${Math.floor(Math.random() * 100) + 20}ms`,
        errorRate: Math.random() * 0.05,
      }));
      
      setIPs([
        { address: '192.168.1.100', port: 1080, country: 'US', latency: '45ms', status: 'healthy' },
        { address: '10.0.0.50', port: 1080, country: 'DE', latency: '89ms', status: 'healthy' },
        { address: '172.16.0.25', port: 1080, country: 'JP', latency: '156ms', status: 'degraded' },
        { address: '192.168.5.10', port: 1080, country: 'GB', latency: '67ms', status: 'healthy' },
      ]);
      
      setLogs(prev => [
        { timestamp: new Date().toLocaleTimeString(), level: 'INFO', message: 'Connection established' },
        ...prev.slice(0, 99)
      ]);
      
      setTrafficHistory(prev => {
        const now = new Date().toLocaleTimeString();
        const newData = [...prev, { time: now, requests: Math.floor(Math.random() * 100) + 50 }];
        return newData.slice(-30);
      });
    }, 2000);
    
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
            className={`btn ${status.running ? 'btn-stop' : 'btn-start'}`}
            onClick={() => setStatus(prev => ({ ...prev, running: !prev.running }))}
          >
            {status.running ? 'STOP' : 'START'}
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
        {activeTab === 'dashboard' && (
          <div className="dashboard">
            <div className="stats-grid">
              <div className="stat-card">
                <div className="stat-label">STATUS</div>
                <div className={`stat-value ${status.running ? 'running' : 'stopped'}`}>
                  {status.running ? 'RUNNING' : 'STOPPED'}
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-label">CONNECTIONS</div>
                <div className="stat-value">{status.connections}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">REQUESTS/S</div>
                <div className="stat-value">{status.requestsPerSecond.toFixed(1)}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">BYTES/S</div>
                <div className="stat-value">{(status.bytesPerSecond / 1024).toFixed(1)} KB</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">AVG LATENCY</div>
                <div className="stat-value">{status.avgLatency}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">ERROR RATE</div>
                <div className="stat-value">{(status.errorRate * 100).toFixed(2)}%</div>
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
            
            <button className="btn btn-save">SAVE CONFIG</button>
          </div>
        )}
        
        {activeTab === 'ips' && (
          <div className="ip-panel">
            <div className="section-title">IP POOL</div>
            <table className="ip-table">
              <thead>
                <tr>
                  <th>ADDRESS</th>
                  <th>PORT</th>
                  <th>COUNTRY</th>
                  <th>LATENCY</th>
                  <th>STATUS</th>
                </tr>
              </thead>
              <tbody>
                {ips.map((ip, i) => (
                  <tr key={i}>
                    <td>{ip.address}</td>
                    <td>{ip.port}</td>
                    <td>{ip.country}</td>
                    <td>{ip.latency}</td>
                    <td>
                      <span className={`status-badge ${ip.status}`}>
                        {ip.status.toUpperCase()}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <button className="btn btn-add">ADD IP</button>
          </div>
        )}
        
        {activeTab === 'logs' && (
          <div className="log-panel">
            <div className="section-title">SYSTEM LOGS</div>
            <div className="log-container">
              {logs.map((log, i) => (
                <div key={i} className={`log-entry ${log.level.toLowerCase()}`}>
                  <span className="log-time">{log.timestamp}</span>
                  <span className="log-level">[{log.level}]</span>
                  <span className="log-message">{log.message}</span>
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
