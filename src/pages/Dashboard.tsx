import { useState, useEffect } from 'react'
import { AlertTriangle, Server, ShieldAlert, Cpu, Activity, Target } from 'lucide-react'
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar
} from 'recharts'
import { api } from '../api'
import type { Metrics, HoneypotEvent, Alert } from '../types'

export default function Dashboard() {
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [logs, setLogs] = useState<HoneypotEvent[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    setLoading(true)
    try {
      const [mRes, lRes] = await Promise.all([
        api.getMetrics().catch(() => null),
        api.getHoneypotLog().catch(() => [])
      ])
      
      if (mRes) setMetrics(mRes)
      if (lRes) setLogs(lRes.slice(0, 10)) // show last 10
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
      
      <div className="panel animate-in" style={{ animationDelay: '0.6s' }}>
        <div className="panel-header">
          <div className="panel-title">
            <ShieldAlert /> Recent High-Risk Events
          </div>
          <span className="panel-badge danger">Live Events</span>
        </div>
        <div className="panel-body" style={{ padding: 0 }}>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Event Type</th>
                  <th>Path / Target</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {logs.length > 0 ? logs.slice(0, 5).map((log, i) => (
                  <tr key={i}>
                    <td>{new Date(log.timestamp * 1000).toLocaleString() || 'N/A'}</td>
                    <td>
                      <span className={`event-type-badge ${log.event_type.includes('rce') ? 'critical' : 'warning'}`}>
                        {log.event_type}
                      </span>
                    </td>
                    <td>
                      <span className="path-badge">{log.path}</span>
                    </td>
                    <td>
                      <div className="severity-bar" style={{ width: '80px', marginTop: 0 }}>
                        <div className={`severity-fill ${log.event_type.includes('rce') ? 'critical' : 'medium'}`} style={{ width: log.event_type.includes('rce') ? '90%' : '60%' }}></div>
                      </div>
                    </td>
                  </tr>
                )) : (
                  <tr>
                    <td colSpan={4} style={{ textAlign: 'center', padding: '30px' }}>No recent events found</td>
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
