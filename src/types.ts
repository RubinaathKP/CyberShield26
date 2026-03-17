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

export interface SHAPValue {
  feature: string
  shap_value: number
  feature_value: number
}

export interface SHAPMeta {
  feature: string
  contribution: number
}

export interface Alert {
  id: string
  timestamp: number
  p_host: number
  p_net: number
  final_score: number
  threat_level: string
  detected_at: number
  mttd_seconds?: number
  shap_host?: SHAPValue[]
  shap_network?: SHAPValue[]
  shap_meta?: SHAPMeta[]
  entity_id?: string
}

export interface AnalyzeRequest {
  payload: string
}

export interface AnalyzeResponse {
  score: number
  threat_level: string
  findings: string[]
  shap_host?: SHAPValue[]
  shap_network?: SHAPValue[]
  shap_meta?: SHAPMeta[]
}

export interface FeedbackRequest {
  alert_id: string
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
