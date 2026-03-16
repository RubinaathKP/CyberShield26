import { useState } from 'react'
import { MessageSquare, ThumbsUp, ThumbsDown, Send } from 'lucide-react'
import { api } from '../api'

export default function Feedback() {
  const [alertId, setAlertId] = useState('')
  const [accurate, setAccurate] = useState<boolean | null>(null)
  const [comments, setComments] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [toast, setToast] = useState<{ message: string, type: 'success' | 'error' } | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!alertId || accurate === null) return

    setIsSubmitting(true)
    try {
      await api.submitFeedback(Number(alertId), accurate, comments)
      setToast({ message: 'Feedback submitted successfully. The AI model will be retrained with this data.', type: 'success' })
      setAlertId('')
      setAccurate(null)
      setComments('')
    } catch (error) {
      console.error('Failed to submit feedback', error)
      setToast({ message: 'Error submitting feedback. Please try again.', type: 'error' })
    } finally {
      setIsSubmitting(false)
      setTimeout(() => setToast(null), 3000)
    }
  }

  return (
    <div className="page-body animate-in">
      {toast && (
        <div className={`toast ${toast.type}`}>
          {toast.type === 'success' ? <ThumbsUp size={16} /> : <MessageSquare size={16} />}
          {toast.message}
        </div>
      )}

      <div className="page-header" style={{ marginLeft: '-32px', marginRight: '-32px', marginTop: '-28px', marginBottom: '28px' }}>
        <div className="page-header-left">
          <h2>AI Model Feedback</h2>
          <p>Improve the threat detection engine by reporting false positives</p>
        </div>
      </div>

      <div className="panel animate-in" style={{ maxWidth: '600px' }}>
        <div className="panel-header">
          <div className="panel-title">
            <MessageSquare /> Report Alert Accuracy
          </div>
        </div>
        <div className="panel-body">
          <form className="feedback-form" onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label" htmlFor="alertId">Alert ID</label>
              <input 
                id="alertId"
                type="number" 
                className="form-input" 
                placeholder="Enter alert ID (e.g., 42)" 
                value={alertId}
                onChange={(e) => setAlertId(e.target.value)}
                required
              />
            </div>

            <div className="form-group" style={{ marginTop: '10px' }}>
              <label className="form-label">Was this alert accurate?</label>
              <div style={{ display: 'flex', gap: '12px', marginTop: '6px' }}>
                <button 
                  type="button"
                  className={`refresh-btn ${accurate === true ? 'spinning' : ''}`}
                  style={{ 
                    background: accurate === true ? 'var(--accent-cyan-dim)' : 'transparent',
                    borderColor: accurate === true ? 'var(--accent-cyan)' : 'var(--border-color)',
                    flex: 1, 
                    justifyContent: 'center',
                    animation: 'none'
                  }}
                  onClick={() => setAccurate(true)}
                >
                  <ThumbsUp size={16} /> Yes, it was a threat
                </button>
                <button 
                  type="button"
                  className={`refresh-btn ${accurate === false ? 'spinning' : ''}`}
                  style={{ 
                    background: accurate === false ? 'var(--accent-red-dim)' : 'transparent',
                    borderColor: accurate === false ? 'var(--accent-red)' : 'var(--border-color)',
                    color: accurate === false ? 'var(--accent-red)' : 'var(--accent-cyan)',
                    flex: 1, 
                    justifyContent: 'center',
                    animation: 'none'
                  }}
                  onClick={() => setAccurate(false)}
                >
                  <ThumbsDown size={16} /> No, False Positive
                </button>
              </div>
            </div>

            <div className="form-group" style={{ marginTop: '10px' }}>
              <label className="form-label" htmlFor="comments">Additional Context (Optional)</label>
              <textarea 
                id="comments"
                className="analyze-textarea" 
                style={{ minHeight: '120px' }}
                placeholder="Details about the activity..."
                value={comments}
                onChange={(e) => setComments(e.target.value)}
              />
            </div>

            <button 
              type="submit" 
              className="submit-btn" 
              style={{ marginTop: '10px', width: '100% '}}
              disabled={isSubmitting || !alertId || accurate === null}
            >
              {isSubmitting ? (
                <><Send className="animate-spin" /> Submitting...</>
              ) : (
                <><Send /> Send Feedback to ML Engine</>
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
