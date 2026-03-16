import { useState, useEffect } from 'react'
import { Database, Download, Filter } from 'lucide-react'
import { api } from '../api'
import type { HoneypotEvent } from '../types'

export default function HoneypotLogs() {
  const [logs, setLogs] = useState<HoneypotEvent[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchLogs = async () => {
      setLoading(true)
      try {
        const data = await api.getHoneypotLog()
        setLogs(data)
      } catch (error) {
        console.error('Failed to fetch logs', error)
      } finally {
        setLoading(false)
      }
    }
    fetchLogs()
  }, [])

  return (
    <div className="page-body animate-in">
      <div className="page-header" style={{ marginLeft: '-32px', marginRight: '-32px', marginTop: '-28px', marginBottom: '28px' }}>
        <div className="page-header-left">
          <h2>Honeypot Event Logs</h2>
          <p>Complete record of all attacks caught by the deception layer</p>
        </div>
        <div className="page-header-right">
          <button className="refresh-btn">
            <Filter size={16} /> Filter
          </button>
          <button className="refresh-btn">
            <Download size={16} /> Export CSV
          </button>
        </div>
      </div>

      <div className="panel animate-in full">
        <div className="panel-header">
          <div className="panel-title">
            <Database /> Raw Event Data
          </div>
          <span className="panel-badge">{logs.length} Events Logged</span>
        </div>
        <div className="panel-body" style={{ padding: 0 }}>
          {loading ? (
             <div style={{ padding: '30px' }}>
               <div className="skeleton skeleton-text" style={{ marginBottom: '15px' }}></div>
               <div className="skeleton skeleton-text" style={{ marginBottom: '15px' }}></div>
               <div className="skeleton skeleton-text" style={{ marginBottom: '15px' }}></div>
             </div>
          ) : (
            <div style={{ overflowX: 'auto', maxHeight: '600px', overflowY: 'auto' }}>
              <table className="data-table">
                <thead style={{ position: 'sticky', top: 0, background: 'var(--bg-card)', zIndex: 10 }}>
                  <tr>
                    <th>Timestamp</th>
                    <th>Event Type</th>
                    <th>Target Path</th>
                    <th>Threat Level</th>
                    <th>Action Taken</th>
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
                        <td>
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>Isolated</span>
                        </td>
                      </tr>
                    )
                  }) : (
                    <tr>
                      <td colSpan={5} style={{ textAlign: 'center', padding: '40px' }}>
                        <div className="empty-state" style={{ padding: 0 }}>
                          <Database size={32} />
                          <p>No honeypot events recorded yet.</p>
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
