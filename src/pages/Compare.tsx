import { useState } from 'react'
import { GitCompare, ArrowRightLeft, ShieldAlert, ShieldCheck } from 'lucide-react'
import { api } from '../api'
import type { Alert } from '../types'
import SHAPExplainer from '../components/SHAPExplainer'

const SCENARIOS = [
  { id: 'scenario_01_portScan', name: 'Port Scan' },
  { id: 'scenario_02_meterpreter', name: 'Meterpreter' },
  { id: 'scenario_03_c2_beaconing', name: 'C2 Beaconing' },
  { id: 'scenario_04_benign_admin', name: 'Benign Admin' },
  { id: 'scenario_05_hydra_brute', name: 'Hydra Brute' }
]

export default function Compare() {
  const [leftId, setLeftId] = useState('scenario_02_meterpreter')
  const [rightId, setRightId] = useState('scenario_04_benign_admin')
  const [leftResult, setLeftResult] = useState<Alert | null>(null)
  const [rightResult, setRightResult] = useState<Alert | null>(null)
  const [loading, setLoading] = useState(false)

  const runComparison = async () => {
    setLoading(true)
    try {
      const [leftData, rightData] = await Promise.all([
        api.getScenario(leftId + '.json'),
        api.getScenario(rightId + '.json')
      ])
      const [lRes, rRes] = await Promise.all([
        api.runScenario(leftData),
        api.runScenario(rightData)
      ])
      setLeftResult(lRes)
      setRightResult(rRes)
    } catch (error) {
      console.error('Comparison failed', error)
    } finally {
      setLoading(false)
    }
  }

  const getGap = () => {
    if (!leftResult || !rightResult) return null
    return Math.abs(leftResult.final_score - rightResult.final_score).toFixed(3)
  }

  const diff = getGap()
  const success = diff ? parseFloat(diff) >= 0.3 : false

  return (
    <div className="page-body animate-in">
      <div className="page-header" style={{ marginBottom: '32px' }}>
        <div className="page-header-left">
          <h2 style={{ background: 'var(--gradient-primary)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', fontSize: '1.8rem' }}>
            Behavioral Comparator
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '4px' }}>
            Contrast AI response across diverse telemetry fingerprints.
          </p>
        </div>
        <div className="page-header-right">
          <button 
            className="btn-premium" 
            onClick={runComparison} 
            disabled={loading || leftId === rightId}
            style={{ minWidth: '240px' }}
          >
            {loading ? (
              <div className="flex items-center gap-2">
                <div className="health-dot" style={{ width: '10px', height: '10px' }} />
                Contrasting Vectors...
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <ArrowRightLeft size={16} />
                Execute Comparison
              </div>
            )}
          </button>
        </div>
      </div>

      <div className="flex items-center gap-6 mb-8">
        <div className="flex-1 glass-card" style={{ padding: '16px 20px', background: 'rgba(255,255,255,0.02)' }}>
          <label className="metric-label" style={{ marginBottom: '10px', display: 'block' }}>Primary Vector</label>
          <select 
            value={leftId} 
            onChange={(e) => setLeftId(e.target.value)}
            className="form-select"
            style={{ width: '100%', padding: '12px' }}
          >
            {SCENARIOS.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
          </select>
        </div>
        <div style={{ color: 'var(--text-muted)', fontWeight: '800', fontSize: '0.8rem' }}>VS</div>
        <div className="flex-1 glass-card" style={{ padding: '16px 20px', background: 'rgba(255,255,255,0.02)' }}>
          <label className="metric-label" style={{ marginBottom: '10px', display: 'block' }}>Control Vector</label>
          <select 
            value={rightId} 
            onChange={(e) => setRightId(e.target.value)}
            className="form-select"
            style={{ width: '100%', padding: '12px' }}
          >
            {SCENARIOS.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
          </select>
        </div>
      </div>

      {leftResult && rightResult && (
        <div className={` glass-card animate-in mb-8 ${
          success ? 'border-cyan-500/30' : 'border-red-500/30'
        }`} style={{ 
          padding: '24px', 
          background: success ? 'rgba(6, 214, 160, 0.03)' : 'rgba(255, 107, 107, 0.03)',
          display: 'flex',
          alignItems: 'center',
          gap: '20px'
        }}>
          <div style={{ 
            width: '48px', 
            height: '48px', 
            borderRadius: 'var(--radius-md)', 
            background: success ? 'var(--accent-cyan-dim)' : 'var(--accent-red-dim)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: success ? 'var(--accent-cyan)' : 'var(--accent-red)'
          }}>
            {success ? <ShieldCheck size={24} /> : <ShieldAlert size={24} />}
          </div>
          <div>
            <div style={{ fontSize: '1.1rem', fontWeight: '800', color: success ? 'var(--accent-cyan)' : 'var(--accent-red)', marginBottom: '4px' }}>
              Pattern Differentiation: {(parseFloat(diff || '0') * 100).toFixed(1)}% Gap
            </div>
            <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
              {success ? 
                'The ensemble exhibits high precision in isolating malicious entropy from administrative noise.' : 
                'Warning: High behavioral overlap detected between selected fingerprints. Threshold tuning recommended.'}
            </p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 gap-8">
        <ComparisonCard title="Target Analysis" result={leftResult} side="left" />
        <ComparisonCard title="Baseline Analysis" result={rightResult} side="right" />
      </div>

      <div className="mt-12 glass-card" style={{ padding: '32px', background: 'var(--accent-blue-dim)', border: '1px solid rgba(76, 201, 240, 0.1)' }}>
        <h3 style={{ fontSize: '1.2rem', fontWeight: '800', color: 'var(--accent-blue)', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <GitCompare size={24} /> Behavioral Intelligence
        </h3>
        <p style={{ fontSize: '0.95rem', color: 'var(--text-primary)', lineHeight: '1.8', opacity: 0.9 }}>
          Unlike static signatures, CyberShield's neural ensemble analyzes the <strong>latent syscall intent</strong>. 
          By contrasting these vectors, you can see how the system distinguishes between an attacker executing a 
          meterpreter shell and an admin performing system updates—even when both use similar privilege levels.
        </p>
      </div>
    </div>
  )
}

function ComparisonCard({ title, result, side }: { title: string, result: Alert | null, side: 'left' | 'right' }) {
  const accent = side === 'left' ? 'var(--accent-red)' : 'var(--accent-cyan)'
  const accentDim = side === 'left' ? 'var(--accent-red-dim)' : 'var(--accent-cyan-dim)'

  return (
    <div className="glass-card" style={{ overflow: 'hidden' }}>
      <div className="panel-header" style={{ padding: '20px 24px', borderBottom: '1px solid var(--border-color)', background: 'rgba(255,255,255,0.01)' }}>
        <h3 className="metric-label" style={{ marginBottom: '0', opacity: 0.7 }}>{title}</h3>
      </div>
      
      {!result ? (
        <div style={{ height: '240px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: '0.9rem', fontStyle: 'italic' }}>
          Awaiting Vector Execution...
        </div>
      ) : (
        <div className="panel-body animate-in" style={{ padding: '32px' }}>
          <div className="flex items-end justify-between mb-10">
            <div className="flex flex-col">
              <span className="metric-label" style={{ marginBottom: '8px' }}>Threat Score</span>
              <span className="metric-value font-mono" style={{ fontSize: '3rem', color: accent }}>
                {result.final_score.toFixed(4)}
              </span>
            </div>
            <span className={`badge-premium ${result.threat_level?.toLowerCase() || 'low'}`} style={{ padding: '6px 16px' }}>
              {result.threat_level || 'LOW'}
            </span>
          </div>

          <div className="flex flex-col gap-8">
            <div>
              <div className="flex justify-between items-end mb-2">
                <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', fontWeight: '600' }}>Host Behavior Pulse</span>
                <span className="font-mono" style={{ fontSize: '1rem', color: accent }}>{result.p_host.toFixed(3)}</span>
              </div>
              <div className="progress-bar-container" style={{ height: '10px' }}>
                <div 
                  className="progress-bar-fill" 
                  style={{ 
                    width: `${result.p_host * 100}%`,
                    background: accent,
                    boxShadow: `0 0 10px ${accentDim}`
                  }}
                />
              </div>
              <div style={{ marginTop: '16px' }}>
                <SHAPExplainer 
                  data={result.shap_host || []} 
                  title="Critical Host Attributions" 
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between items-end mb-2">
                <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', fontWeight: '600' }}>Network Traffic Signature</span>
                <span className="font-mono" style={{ fontSize: '1rem', color: accent }}>{result.p_net.toFixed(3)}</span>
              </div>
              <div className="progress-bar-container" style={{ height: '10px' }}>
                <div 
                  className="progress-bar-fill" 
                  style={{ 
                    width: `${result.p_net * 100}%`,
                    background: accent,
                    boxShadow: `0 0 10px ${accentDim}`
                  }}
                />
              </div>
              <div style={{ marginTop: '16px' }}>
                <SHAPExplainer 
                  data={result.shap_network || []} 
                  title="Malicious Network Patterns" 
                />
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
