import { useState, useEffect } from 'react'
import { Play, CheckCircle2, AlertCircle, Info } from 'lucide-react'
import { api } from '../api'
import type { Alert } from '../types'

const SCENARIOS = [
  { id: 'scenario_01_portScan', name: 'Port Scan', expected: 'MEDIUM', icon: '🔍', story: 'Attacker mapping 48,000 ports.' },
  { id: 'scenario_02_meterpreter', name: 'Meterpreter', expected: 'CRITICAL', icon: '💀', story: 'Web shell beaconing to C2.' },
  { id: 'scenario_03_c2_beaconing', name: 'C2 Beaconing', expected: 'HIGH', icon: '📡', story: 'Stealthy beaconing to port 6667.' },
  { id: 'scenario_04_benign_admin', name: 'Benign Admin', expected: 'LOW', icon: '👤', story: 'IT admin running apt upgrade with sudo.' },
  { id: 'scenario_05_hydra_brute', name: 'Hydra Brute', expected: 'HIGH', icon: '🔨', story: 'SSH brute-forcing attempt.' }
]

export default function DemoScenarios() {
  const [results, setResults] = useState<Record<string, Alert>>({})
  const [loading, setLoading] = useState<Record<string, boolean>>({})
  const [runningAll, setRunningAll] = useState(false)

  const runScenario = async (id: string) => {
    console.log(`[DemoScenarios] Running scenario: ${id}`)
    setLoading(prev => ({ ...prev, [id]: true }))
    try {
      const data = await api.getScenario(id + '.json')
      console.log(`[DemoScenarios] Scenario data fetched for ${id}:`, data)
      const res = await api.runScenario(data)
      console.log(`[DemoScenarios] Prediction result for ${id}:`, res)
      setResults(prev => ({ ...prev, [id]: res }))
    } catch (error) {
      console.error(`[DemoScenarios] Failed to run scenario ${id}:`, error)
      alert(`Error running scenario ${id}: ${error instanceof Error ? error.message : String(error)}`)
    } finally {
      setLoading(prev => ({ ...prev, [id]: false }))
    }
  }

  const runAllScenarios = async () => {
    setRunningAll(true)
    for (const sc of SCENARIOS) {
      await runScenario(sc.id)
      await new Promise(r => setTimeout(r, 1000))
    }
    setRunningAll(false)
  }

  return (
    <div className="page-body animate-in">
      <div className="page-header" style={{ marginBottom: '32px' }}>
        <div className="page-header-left">
          <h2 style={{ background: 'var(--gradient-primary)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', fontSize: '1.8rem' }}>
            Scenario Engine
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '4px' }}>
            Execute pre-configured attack vectors to validate system behavioral response.
          </p>
        </div>
        <div className="page-header-right">
          <button 
            className="btn-premium" 
            onClick={runAllScenarios} 
            disabled={runningAll}
            style={{ minWidth: '220px' }}
          >
            {runningAll ? (
              <div className="flex items-center gap-2">
                <div className="health-dot" style={{ width: '10px', height: '10px' }} />
                Sequencing vectors...
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <Play size={16} fill="currentColor" />
                Run Full Sequence
              </div>
            )}
          </button>
        </div>
      </div>

      <div className="flex flex-col gap-6">
        {SCENARIOS.map((sc) => (
          <div key={sc.id} className={`glass-card scenario-card ${loading[sc.id] ? 'running' : ''}`}>
            <div className="panel-header" style={{ borderBottom: '1px solid var(--border-color)', marginBottom: '0', padding: '24px' }}>
              <div className="flex items-center gap-5">
                <div className="sidebar-brand-icon" style={{ 
                  width: '56px', 
                  height: '56px', 
                  fontSize: '1.8rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(255,255,255,0.03)',
                  border: '1px solid var(--border-color)'
                }}>
                  {sc.icon}
                </div>
                <div>
                  <div className="flex items-center gap-3">
                    <h3 style={{ fontSize: '1.2rem', fontWeight: '800', color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>{sc.name}</h3>
                    <span className="badge-premium" style={{ 
                      background: 'rgba(255,255,255,0.05)', 
                      color: 'var(--text-muted)',
                      border: '1px solid var(--border-color)',
                      fontSize: '0.6rem'
                    }}>
                      Expect: {sc.expected}
                    </span>
                  </div>
                  <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', marginTop: '6px', opacity: 0.8 }}>{sc.story}</p>
                </div>
              </div>
              <button 
                className="btn-premium"
                style={{ 
                  background: loading[sc.id] ? 'var(--bg-card)' : 'var(--gradient-primary)',
                  color: loading[sc.id] ? 'var(--text-muted)' : 'var(--bg-primary)'
                }}
                onClick={() => runScenario(sc.id)}
                disabled={loading[sc.id]}
              >
                {loading[sc.id] ? 'Analyzing...' : 'Execute Vector'}
              </button>
            </div>

            {results[sc.id] && (
              <div className="panel-body animate-in" style={{ padding: '32px' }}>
                <div className="flex items-center gap-12 mb-10">
                  <div className="flex flex-col">
                    <span className="metric-label" style={{ marginBottom: '8px' }}>Threat Magnitude</span>
                    <span className={`metric-value ${
                      results[sc.id].final_score > 0.7 ? 'red' : 
                      results[sc.id].final_score > 0.4 ? 'orange' : 'cyan'
                    }`} style={{ fontSize: '2.5rem' }}>
                      {(results[sc.id].final_score * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="flex flex-col">
                    <span className="metric-label" style={{ marginBottom: '8px' }}>AI Verdict</span>
                    <span className={`badge-premium ${results[sc.id].threat_level.toLowerCase()}`} style={{ padding: '6px 16px', fontSize: '0.8rem' }}>
                      {results[sc.id].threat_level}
                    </span>
                  </div>
                  <div className="ml-auto flex flex-col items-end gap-2">
                    <span className="metric-label">Validation Status</span>
                    {results[sc.id].threat_level === sc.expected ? (
                      <div className="header-badge" style={{ borderColor: 'var(--accent-cyan)', color: 'var(--accent-cyan)', background: 'var(--accent-cyan-dim)', padding: '8px 16px' }}>
                        <CheckCircle2 size={16} /> Precision Match
                      </div>
                    ) : (
                      <div className="header-badge" style={{ borderColor: 'var(--accent-yellow)', color: 'var(--accent-yellow)', background: 'var(--accent-yellow-dim)', padding: '8px 16px' }}>
                        <Info size={16} /> Threshold Variance
                      </div>
                    )}
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '64px' }}>
                  <div className="flex flex-col gap-8">
                    <h4 className="metric-label" style={{ opacity: 0.5, borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>Ensemble Pipeline Intelligence</h4>
                    
                    <div className="flex flex-col gap-6">
                      <div>
                        <div className="flex justify-between items-end mb-2">
                          <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', fontWeight: '600' }}>Host Behavior Pulse</span>
                          <span className="font-mono" style={{ fontSize: '1rem', color: 'var(--accent-blue)' }}>{results[sc.id].p_host.toFixed(3)}</span>
                        </div>
                        <div className="progress-bar-container" style={{ height: '10px' }}>
                          <div 
                            className="progress-bar-fill" 
                            style={{ 
                              width: `${results[sc.id].p_host * 100}%`,
                              background: 'var(--accent-blue)',
                              boxShadow: '0 0 10px rgba(76, 201, 240, 0.4)'
                            }}
                          />
                        </div>
                      </div>

                      <div>
                        <div className="flex justify-between items-end mb-2">
                          <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', fontWeight: '600' }}>Network Traffic Signature</span>
                          <span className="font-mono" style={{ fontSize: '1rem', color: 'var(--accent-purple)' }}>{results[sc.id].p_net.toFixed(3)}</span>
                        </div>
                        <div className="progress-bar-container" style={{ height: '10px' }}>
                          <div 
                            className="progress-bar-fill" 
                            style={{ 
                              width: `${results[sc.id].p_net * 100}%`,
                              background: 'var(--accent-purple)',
                              boxShadow: '0 0 10px rgba(123, 97, 255, 0.4)'
                            }}
                          />
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-col gap-6">
                    <h4 className="metric-label" style={{ opacity: 0.5, borderBottom: '1px solid var(--border-color)', paddingBottom: '12px' }}>Neural Attribution (SHAP)</h4>
                    <div className="flex flex-col gap-3">
                      {results[sc.id].shap_host?.slice(0, 3).map((f, i) => (
                        <div key={i} className="glass-card" style={{ padding: '14px 20px', background: 'rgba(255,255,255,0.02)', borderRadius: 'var(--radius-md)', border: '1px solid rgba(255,255,255,0.03)' }}>
                          <div className="flex items-center justify-between">
                            <span style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{f.feature}</span>
                            <div className="flex items-center gap-3">
                              <div style={{ 
                                width: '40px', 
                                height: '4px', 
                                background: 'rgba(255,255,255,0.05)',
                                borderRadius: '2px',
                                overflow: 'hidden'
                              }}>
                                <div style={{ 
                                  width: `${Math.min(Math.abs(f.shap_value) * 200, 100)}%`,
                                  height: '100%',
                                  background: f.shap_value > 0 ? 'var(--accent-red)' : 'var(--accent-cyan)'
                                }} />
                              </div>
                              <span style={{ 
                                fontSize: '0.85rem', 
                                fontWeight: '700',
                                color: f.shap_value > 0 ? 'var(--accent-red)' : 'var(--accent-cyan)',
                                minWidth: '60px',
                                textAlign: 'right'
                              }}>
                                {f.shap_value > 0 ? '+' : ''}{f.shap_value.toFixed(4)}
                              </span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
