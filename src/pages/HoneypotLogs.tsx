import { useState, useEffect } from 'react'
import { Database, Download, Filter } from 'lucide-react'
import { api } from '../api'
import type { HoneypotEvent } from '../types'

export default function HoneypotLogs() {
  const [logs, setLogs] = useState<HoneypotEvent[]>([])
  const [flaggedIps, setFlaggedIps] = useState<string[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 10000) // 10s refresh
    return () => clearInterval(interval)
  }, [])

  const fetchData = async () => {
    try {
      const [lRes, iRes] = await Promise.all([
        api.getHoneypotLog().catch(() => []),
        api.getHoneypotIPs().catch(() => ({ flagged_ips: [] }))
      ])
      setLogs(lRes)
      setFlaggedIps(iRes.flagged_ips)
    } catch (error) {
      console.error('Failed to fetch honeypot data', error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="page-body animate-in">
      <div className="page-header" style={{ marginLeft: '-32px', marginRight: '-32px', marginTop: '-28px', marginBottom: '28px' }}>
        <div className="page-header-left">
          <h2>Honeypot Event Logs</h2>
          <p>Complete record of all attacks caught by the deception layer</p>
        </div>
        <div className="page-header-right">
          <button className="refresh-btn" onClick={fetchData} disabled={loading}>
            <Filter size={16} /> Filter
          </button>
          <button className="refresh-btn" onClick={fetchData} disabled={loading}>
             {loading ? '...' : 'Refresh'}
          </button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: '28px' }}>
        <div className="panel animate-in full" style={{ margin: 0 }}>
          <div className="panel-header">
            <div className="panel-title">
              <Database /> Raw Event Data
            </div>
            <span className="panel-badge">{logs.length} Events Logged</span>
          </div>
          <div className="panel-body" style={{ padding: 0 }}>
            <div style={{ overflowX: 'auto', maxHeight: '600px', overflowY: 'auto' }}>
              <table className="data-table">
                <thead style={{ position: 'sticky', top: 0, background: 'var(--bg-card)', zIndex: 10 }}>
                  <tr>
                    <th>Timestamp</th>
                    <th>Event Type</th>
                    <th>Target Path</th>
                    <th>Threat Level</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.length > 0 ? logs.map((log, i) => {
                    const isRce = log.event_type.includes('rce')
                    return (
                      <tr key={i}>
                        <td style={{ fontFamily: 'var(--font-mono)' }}>{new Date(log.timestamp * 1000).toISOString().replace('T', ' ').substring(0, 19)}</td>
                        <td>
                          <span className={`event-type-badge ${isRce ? 'critical' : 'warning'}`}>
                            {log.event_type}
                          </span>
                        </td>
                        <td>
                          <span className="path-badge">{log.path}</span>
                        </td>
                        <td>
                          <div className="severity-bar" style={{ width: '80px', marginTop: 0 }}>
                            <div className={`severity-fill ${isRce ? 'critical' : 'medium'}`} style={{ width: isRce ? '90%' : '50%' }}></div>
                          </div>
                        </td>
                      </tr>
                    )
                  }) : (
                    <tr>
                      <td colSpan={4} style={{ textAlign: 'center', padding: '40px' }}>
                        No events recorded yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="panel animate-in" style={{ margin: 0, border: '1px solid var(--accent-red)' }}>
          <div className="panel-header">
            <div className="panel-title">
              <Download /> IP Registry
            </div>
            <span className="panel-badge danger">{flaggedIps.length} Flagged</span>
          </div>
          <div className="panel-body">
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '16px' }}>
              Entities in this registry are transparently proxied to the deception layer.
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {flaggedIps.length > 0 ? flaggedIps.map((ip, i) => (
                <div key={i} className="glass-card" style={{ padding: '10px 15px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(255, 107, 107, 0.05)' }}>
                  <span className="font-mono" style={{ fontSize: '0.9rem', color: 'var(--accent-red)' }}>{ip}</span>
                  <div className="health-dot danger" />
                </div>
              )) : (
                <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '20px', fontSize: '0.8rem' }}>
                  No entities currently flagged.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
