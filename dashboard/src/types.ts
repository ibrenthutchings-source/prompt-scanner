export type Severity = "none" | "low" | "medium" | "high" | "critical";
export type Action = "allow" | "warn" | "redact" | "block";
export type Category = "pii" | "phi" | "pci" | "secret" | "ip" | "regulated" | "other";
export type Stage = "fast_gate" | "council";

export interface FindingOut {
  id: string;
  stage: Stage;
  category: Category;
  detector: string;
  severity: Severity;
  confidence: number;
  score: number;
  title: string;
  detail: string | null;
  evidence: string | null;
  regulations: string[];
}

export interface VoteOut {
  id: string;
  agent: string;
  model: string;
  severity: Severity;
  confidence: number;
  rationale: string | null;
  latency_ms: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  error: string | null;
}

export interface EventOut {
  id: string;
  created_at: string;
  source: string;
  client_app: string | null;
  provider: string | null;
  model: string | null;
  actor: string | null;
  actor_department: string | null;
  session_id: string | null;
  prompt_chars: number;
  risk_score: number;
  severity: Severity;
  action: Action;
  action_reason: string | null;
  council_status: string;
  council_summary: string | null;
  retro_escalated: boolean;
  fast_gate_ms: number;
  council_ms: number;
  council_cost_usd: number;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  analyst_note: string | null;
}

export interface EventDetailOut extends EventOut {
  findings: FindingOut[];
  votes: VoteOut[];
}

export interface Summary {
  window_hours: number;
  generated_at: string;
  totals: {
    events: number;
    prior_events: number;
    change_pct: number | null;
    blocked: number;
    redacted: number;
    warned: number;
    allowed: number;
    open_criticals: number;
    retro_escalations: number;
  };
  by_severity: Record<Severity, number>;
  by_action: Record<Action, number>;
  by_category: Record<Category, number>;
  by_source: Record<string, number>;
  top_detectors: { detector: string; title: string; count: number; peak_score: number }[];
  top_actors: {
    actor: string;
    department: string | null;
    events: number;
    blocked: number;
    max_score: number;
  }[];
  performance: {
    fast_gate_avg_ms: number;
    fast_gate_max_ms: number;
    council_avg_ms: number;
    council_cost_usd: number;
  };
}

export interface TimeseriesPoint {
  t: string;
  allow: number;
  warn: number;
  redact: number;
  block: number;
  critical: number;
}

export interface Timeseries {
  since: string;
  bucket_seconds: number;
  series: TimeseriesPoint[];
}

export interface RegulationExposure {
  window_hours: number;
  regulations: { regulation: string; events: number; max_severity: Severity }[];
}

export interface CouncilDetail {
  event_id: string;
  status: string;
  summary: string | null;
  elapsed_ms: number;
  cost_usd: number;
  votes: {
    agent: string;
    model: string;
    severity: Severity;
    confidence: number;
    rationale: string;
    findings: Record<string, unknown>[];
    latency_ms: number;
    tokens: { input: number; output: number; cache_read: number };
    error: string | null;
  }[];
  council_findings: {
    category: Category;
    severity: Severity;
    title: string;
    detail: string | null;
    regulations: string[];
  }[];
}

export interface LiveMessage {
  type: "backfill" | "event.created" | "event.updated" | "event.escalated" | "heartbeat";
  data?: EventOut[] | EventOut;
}
