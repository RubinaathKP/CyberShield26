// API Types matching FastAPI backend responses

export interface Metrics {
  total_alerts: number
  honeypot_events: number
  honeypot_ip_count: number
  retrain_events: number
}

export interface HoneypotEvent {
  timestamp: number
  event_type: string
  path: string
}

export interface Alert {
  id: number
  timestamp: number
  event_type: string
  severity: string
  source_ip?: string
  path?: string
  description?: string
}

export interface AnalyzeRequest {
  payload: string
}

export interface AnalyzeResponse {
  is_threat: boolean
  confidence: number
  threat_type: string
  explanation: string
  seriousness_score?: number
}

export interface FeedbackRequest {
  alert_id: number
  accurate: boolean
  comments?: string
}

export interface HealthStatus {
  status: string
  uptime?: number
  version?: string
}

export interface AlertExplanation {
  alert_id: number
  explanation: string
  severity: string
  recommendation: string
}
