import type {
  Metrics,
  HoneypotEvent,
  Alert,
  AnalyzeResponse,
  HealthStatus,
  AlertExplanation,
} from './types'

const BASE_URL = '/api'

async function fetchJSON<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${url}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    throw new Error(`API Error: ${res.status} ${res.statusText}`)
  }
  return res.json()
}

export const api = {
  getHealth: () => fetchJSON<HealthStatus>('/dashboard/health'),

  getMetrics: () => fetchJSON<Metrics>('/metrics'),

  getAlertHistory: () => fetchJSON<Alert[]>('/alerts/history'),

  getHoneypotLog: () => fetchJSON<HoneypotEvent[]>('/honeypot/log'),

  analyzePayload: (payload: string) =>
    fetchJSON<AnalyzeResponse>('/demo/analyze', {
      method: 'POST',
      body: JSON.stringify({ payload }),
    }),

  getAlertExplanation: (id: number) =>
    fetchJSON<AlertExplanation>(`/alerts/${id}/explain`),

  submitFeedback: (alertId: number, accurate: boolean, comments?: string) =>
    fetchJSON<{ message: string }>('/feedback', {
      method: 'POST',
      body: JSON.stringify({ alert_id: alertId, accurate, comments }),
    }),
}
