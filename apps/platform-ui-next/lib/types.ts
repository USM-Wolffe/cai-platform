// Core platform types matching platform-api contracts

export type CaseStatus = "open" | "closed" | "archived";
export type RunStatus = "pending" | "running" | "completed" | "failed";
export type Severity = "critical" | "high" | "medium" | "low" | "clean" | "unknown";

export interface Case {
  case_id: string;
  client_id: string;
  title: string;
  status: CaseStatus;
  created_at: string;
  updated_at: string;
  metadata?: Record<string, unknown>;
}

export interface Artifact {
  artifact_id: string;
  case_id: string;
  artifact_type: string;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface Run {
  run_id: string;
  case_id: string;
  status: RunStatus;
  created_at: string;
  updated_at: string;
  metadata?: Record<string, unknown>;
}

export interface ObservationResult {
  status: "succeeded" | "failed" | "skipped";
  message?: string;
}

export interface ObservationResponse {
  observation_result: ObservationResult;
  artifacts: Artifact[];
}

// WatchGuard investigation synthesis output (from cai-orchestrator)
export interface WatchGuardResult {
  case_id: string;
  run_id: string;
  workspace_id: string;
  overall_severity: Severity;
  confidence: number;
  incident_detected: boolean;
  incident_categories: string[];
  multi_stage_attack: boolean;
  top_attacker_ip: string | null;
  top_targeted_user: string | null;
  nist_phase: string;
  recommended_actions: string[];
  evidence_summary: string;
}

// Phishing analysis result
export interface PhishingResult {
  verdict: Severity;
  score: number;
  action: string;
  rules_triggered: PhishingRule[];
  suspicious_urls: SuspiciousURL[];
  summary: string;
}

export interface PhishingRule {
  rule_id: string;
  name: string;
  severity: Severity;
  description: string;
}

export interface SuspiciousURL {
  url: string;
  reasons: string[];
}

// Dashboard metrics
export interface DashboardMetrics {
  total_cases: number;
  active_runs: number;
  highest_severity: Severity;
  phishing_cases: number;
}

// API response wrappers
export interface CaseResponse {
  case: Case;
}

export interface RunResponse {
  run: Run;
}

export interface ArtifactResponse {
  artifact: Artifact;
}

export interface CasesListResponse {
  cases: Case[];
}

// Investigation states
export type InvestigationPhase = "idle" | "staging" | "detecting" | "synthesizing" | "done" | "error";

export interface InvestigationProgress {
  phase: InvestigationPhase;
  step_label: string;
  steps_done: number;
  steps_total: number;
}
