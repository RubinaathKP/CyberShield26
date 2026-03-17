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
  console.log(`[API Request] ${options?.method || 'GET'} ${BASE_URL}${url}`, options?.body)
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

  submitFeedback: (alertId: string, accurate: boolean, comments?: string) =>
    fetchJSON<{ message: string }>('/feedback', {
      method: 'POST',
      body: JSON.stringify({ alert_id: alertId, accurate, comments }),
    }),

  getScenarios: () =>
    fetch(`${BASE_URL}/scenarios`).then((res) => {
      if (!res.ok) throw new Error('Failed to list scenarios')
      return res.json()
    }),

  getScenario: (name: string) =>
    fetch(`${BASE_URL}/scenarios/${name}`).then((res) => {
      if (!res.ok) throw new Error('Failed to fetch scenario')
      return res.json()
    }),

  runScenario: (scenarioData: any) =>
    fetchJSON<Alert>('/predict', {
      method: 'POST',
      body: JSON.stringify(scenarioData),
    }),
}
