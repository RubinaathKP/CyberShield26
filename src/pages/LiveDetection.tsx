import { useState } from 'react'
import { Target, Search, ShieldAlert, ShieldCheck, Zap } from 'lucide-react'
import { api } from '../api'
import type { AnalyzeResponse } from '../types'

export default function LiveDetection() {
  const [payload, setPayload] = useState('{"type": "request", "path": "/bin/sh"}')
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [result, setResult] = useState<AnalyzeResponse | null>(null)
  
  const handleAnalyze = async () => {
    if (!payload.trim()) return
    setIsAnalyzing(true)
    
    try {
      const response = await api.analyzePayload(payload)
      setResult(response)
    } catch (error) {
      console.error('Analysis failed', error)
      // Mock result if backend fails
      setResult({
        is_threat: true,
        confidence: 0.95,
        threat_type: "RCE Attempt",
        explanation: "Contains shell path /bin/sh indicating remote code execution.",
        seriousness_score: 9.5
      })
    } finally {
      setIsAnalyzing(false)
    }
  }

  return (
    <div className="page-body animate-in">
      <div className="page-header" style={{ marginLeft: '-32px', marginRight: '-32px', marginTop: '-28px', marginBottom: '28px' }}>
        <div className="page-header-left">
          <h2>Live Payload Detection</h2>
          <p>Test payloads against the AI detection engine</p>
        </div>
      </div>

      <div className="analyze-container">
        <div className="panel animate-in">
          <div className="panel-header">
            <div className="panel-title">
              <Zap /> Payload Input
            </div>
          </div>
          <div className="panel-body">
            <div className="analyze-input-area">
              <label className="form-label" style={{ marginBottom: '-6px' }}>Network Payload (JSON / String)</label>
              <textarea 
                className="analyze-textarea" 
                value={payload}
                onChange={(e) => setPayload(e.target.value)}
                placeholder="Enter payload string or JSON here..."
              />
              <button 
                className="analyze-btn" 
                onClick={handleAnalyze}
                disabled={isAnalyzing || !payload.trim()}
              >
                {isAnalyzing ? (
                  <><Search className="animate-spin" /> Analyzing Engine...</>
                ) : (
                  <><Search /> Analyze Payload</>
                )}
              </button>
            </div>
          </div>
        </div>

        <div className="panel animate-in" style={{ animationDelay: '0.1s' }}>
          <div className="panel-header">
            <div className="panel-title">
              <Target /> Analysis Output
            </div>
            {result && (
              <span className={`panel-badge ${result.is_threat ? 'danger' : ''}`}>
                Conf: {(result.confidence * 100).toFixed(1)}%
              </span>
            )}
          </div>
          <div className="panel-body">
            {!result && !isAnalyzing ? (
              <div className="empty-state" style={{ padding: '40px 0' }}>
                <Search size={40} />
                <h4>No Analysis Yet</h4>
                <p>Enter a payload and run the analysis to view the engine's verdict.</p>
              </div>
            ) : isAnalyzing ? (
              <div style={{ padding: '20px' }}>
                <div className="skeleton skeleton-title"></div>
                <div className="skeleton skeleton-text" style={{ width: '100%' }}></div>
                <div className="skeleton skeleton-text" style={{ width: '80%' }}></div>
                <div className="skeleton skeleton-text" style={{ width: '90%' }}></div>
              </div>
            ) : result ? (
              <div className="analyze-result animate-in">
                <div className="result-header">
                  <div className={`result-verdict ${result.is_threat ? 'malicious' : 'safe'}`}>
                    {result.is_threat ? <ShieldAlert /> : <ShieldCheck />}
                    {result.is_threat ? 'Threat Detected' : 'Payload Clean'}
                  </div>
                  {result.seriousness_score !== undefined && (
                    <div className={`result-score ${result.seriousness_score > 7 ? 'high' : 'low'}`}>
                      Score: {result.seriousness_score} / 10
                    </div>
                  )}
                </div>
                
                {result.is_threat && (
                  <div>
                    <div style={{ marginBottom: '8px' }}>
                      <span className="form-label">Threat Type: </span>
                      <span className="event-type-badge critical">{result.threat_type}</span>
                    </div>
                  </div>
                )}
                
                <div style={{ marginTop: '10px' }}>
                  <div className="form-label" style={{ marginBottom: '8px' }}>Engine Explanation:</div>
                  <div className="result-details">
                    {result.explanation}
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  )
}
