import { useState, useEffect } from 'react'
import { AlertTriangle, Server, ShieldAlert, Cpu, Activity, Target } from 'lucide-react'
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar
} from 'recharts'
import { api } from '../api'
import type { Metrics, HoneypotEvent, Alert } from '../types'

import SHAPExplainer from '../components/SHAPExplainer'

export default function Dashboard() {
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [logs, setLogs] = useState<HoneypotEvent[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    setLoading(true)
    try {
      const [mRes, lRes, aRes] = await Promise.all([
        api.getMetrics().catch(() => null),
        api.getHoneypotLog().catch(() => []),
        api.getAlertHistory().catch(() => [])
      ])
      
      if (mRes) setMetrics(mRes)
      if (lRes) setLogs(lRes.slice(0, 10))
      if (aRes) setAlerts(aRes)
    } catch (error) {
      console.error('Failed to fetch dashboard data', error)
    } finally {
      setLoading(false)
    }
  }

  // Mock data for charts since FastAPI returns static logs
  const threatData = [
    { time: '00:00', alerts: 10,  },
    { time: '04:00', alerts: 15,  },
    { time: '08:00', alerts: 30,  },
    { time: '12:00', alerts: 20,  },
    { time: '16:00', alerts: 45,  },
    { time: '20:00', alerts: 25,  },
    { time: '23:59', alerts: 50,  },
  ]

  const attackTypes = [
    { name: 'RCE', count: 42, fill: '#ff6b6b' },
    { name: 'SQLi', count: 28, fill: '#ff9f43' },
    { name: 'XSS', count: 15, fill: '#feca57' },
    { name: 'Path', count: 10, fill: '#7b61ff' },
  ]

  return (
    <div className="page-body animate-in">
      <div className="page-header" style={{ marginLeft: '-32px', marginRight: '-32px', marginTop: '-28px', marginBottom: '28px' }}>
        <div className="page-header-left">
          <h2>Dashboard Overview</h2>
          <p>Real-time threat metrics and system activity</p>
        </div>
        <div className="page-header-right">
          <div className="header-badge">
            <span className="live-dot"></span> Live Monitoring
          </div>
          <button className="refresh-btn" onClick={fetchData} disabled={loading}>
            {loading ? 'Refreshing...' : 'Refresh Data'}
          </button>
        </div>
      </div>

      <div className="metrics-grid">
        <div className="metric-card red animate-in">
          <div className="metric-icon red"><ShieldAlert /></div>
          <div className="metric-label">Total Alerts</div>
          <div className="metric-value red">{metrics?.total_alerts || 0}</div>
          <div className="metric-change up">+12.5% vs yesterday</div>
        </div>
        
        <div className="metric-card cyan animate-in" style={{ animationDelay: '0.1s' }}>
          <div className="metric-icon cyan"><AlertTriangle /></div>
          <div className="metric-label">Honeypot Events</div>
          <div className="metric-value cyan">{metrics?.honeypot_events || 0}</div>
          <div className="metric-change down">-5.2% vs yesterday</div>
        </div>
        
        <div className="metric-card purple animate-in" style={{ animationDelay: '0.2s' }}>
          <div className="metric-icon purple"><Server /></div>
          <div className="metric-label">Unique IP Addresses</div>
          <div className="metric-value purple">{metrics?.honeypot_ip_count || 0}</div>
          <div className="metric-change up">+3.1% vs yesterday</div>
        </div>
        
        <div className="metric-card blue animate-in" style={{ animationDelay: '0.3s' }}>
          <div className="metric-icon blue"><Cpu /></div>
          <div className="metric-label">Model Retrains</div>
          <div className="metric-value blue">{metrics?.retrain_events || 0}</div>
          <div className="metric-change down">Stable</div>
        </div>
      </div>

      <div className="dashboard-grid">
        <div className="panel animate-in" style={{ animationDelay: '0.4s' }}>
          <div className="panel-header">
            <div className="panel-title">
              <Activity /> Threat Activity Timeline
            </div>
          </div>
          <div className="panel-body">
            <div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={threatData}>
                  <defs>
                    <linearGradient id="colorAlerts" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ff6b6b" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#ff6b6b" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="time" />
                  <YAxis />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#111827', borderColor: '#ff6b6b', borderRadius: '8px' }}
                    itemStyle={{ color: '#e8eaf6' }}
                  />
                  <Area type="monotone" dataKey="alerts" stroke="#ff6b6b" strokeWidth={3} fillOpacity={1} fill="url(#colorAlerts)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        <div className="panel animate-in" style={{ animationDelay: '0.5s' }}>
          <div className="panel-header">
            <div className="panel-title">
              <Target /> Attack Vectors
            </div>
          </div>
          <div className="panel-body">
            <div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={attackTypes} layout="vertical" margin={{ left: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                  <XAxis type="number" />
                  <YAxis dataKey="name" type="category" />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#111827', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px' }}
                    itemStyle={{ color: '#e8eaf6' }}
                    cursor={{fill: 'rgba(255,255,255,0.05)'}}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>
      
      <div className="panel animate-in" style={{ animationDelay: '0.6s', marginBottom: '28px' }}>
        <div className="panel-header">
          <div className="panel-title">
            <ShieldAlert /> Recent ML Alerts
          </div>
          <span className="panel-badge danger">AI Detected</span>
        </div>
        <div className="panel-body" style={{ padding: 0 }}>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Entity ID</th>
                  <th>Final Score</th>
                  <th>Threat Level</th>
                  <th>XAI Analysis</th>
                </tr>
              </thead>
              <tbody>
                {alerts.length > 0 ? alerts.slice(0, 10).map((alert, i) => (
                  <tr key={i} className={selectedAlert?.id === alert.id ? 'active' : ''}>
                    <td>{new Date(alert.timestamp * 1000).toLocaleString()}</td>
                    <td><span className="path-badge">{alert.entity_id}</span></td>
                    <td>{(alert.final_score * 100).toFixed(1)}%</td>
                    <td>
                      <span className={`event-type-badge ${alert.threat_level === 'CRITICAL' || alert.threat_level === 'HIGH' ? 'critical' : 'warning'}`}>
                        {alert.threat_level}
                      </span>
                    </td>
                    <td>
                      <button 
                        className="refresh-btn" 
                        style={{ padding: '4px 10px', fontSize: '0.7rem' }}
                        onClick={() => setSelectedAlert(alert)}
                      >
                        Evaluate Why
                      </button>
                    </td>
                  </tr>
                )) : (
                  <tr>
                    <td colSpan={5} style={{ textAlign: 'center', padding: '30px' }}>No ML alerts found</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {selectedAlert && (
        <div className="panel animate-in" style={{ marginBottom: '28px', border: '1px solid var(--accent-cyan)' }}>
          <div className="panel-header">
            <div className="panel-title">
              <Activity /> SHAP Explainability: Alert {selectedAlert.id}
            </div>
            <button className="refresh-btn red" onClick={() => setSelectedAlert(null)}>Close</button>
          </div>
          <div className="panel-body">
            <div className="dashboard-grid">
              <SHAPExplainer 
                data={selectedAlert.shap_host || []} 
                title="Host Features Attribution" 
              />
              <SHAPExplainer 
                data={selectedAlert.shap_network || []} 
                title="Network Features Attribution" 
              />
            </div>
            <div style={{ marginTop: '20px', padding: '15px', background: 'rgba(0,0,0,0.2)', borderRadius: '8px' }}>
              <h4 style={{ fontSize: '0.9rem', marginBottom: '10px' }}>Meta-Classifier Composition</h4>
              <div style={{ display: 'flex', gap: '20px' }}>
                {selectedAlert.shap_meta?.map((m, i) => (
                  <div key={i} style={{ flex: 1 }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{m.feature}</div>
                    <div style={{ height: '8px', background: 'var(--bg-primary)', borderRadius: '4px', marginTop: '6px', overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${m.contribution * 100}%`, background: 'var(--accent-purple)' }}></div>
                    </div>
                    <div style={{ fontSize: '0.8rem', marginTop: '4px', fontWeight: 'bold' }}>{(m.contribution * 100).toFixed(1)}% weight</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
      
      <div className="panel animate-in" style={{ animationDelay: '0.7s' }}>
        <div className="panel-header">
          <div className="panel-title">
            <Server /> Recent Honeypot Interactions
          </div>
          <span className="panel-badge">Log</span>
        </div>
        <div className="panel-body" style={{ padding: 0 }}>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Event Type</th>
                  <th>Path</th>
                </tr>
              </thead>
              <tbody>
                {logs.length > 0 ? logs.map((log, i) => (
                  <tr key={i}>
                    <td>{new Date(log.timestamp * 1000).toLocaleString()}</td>
                    <td><span className="event-type-badge warning">{log.event_type}</span></td>
                    <td><span className="path-badge">{log.path}</span></td>
                  </tr>
                )) : (
                  <tr>
                    <td colSpan={3} style={{ textAlign: 'center', padding: '20px' }}>No honeypot activity</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}
