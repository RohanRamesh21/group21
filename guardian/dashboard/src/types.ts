export type Risk = "critical" | "high" | "medium" | "low" | "info";
export type Agent = "lead" | "hunter" | "forensics" | "skeptic" | "fixer" | "human" | "system";

export interface FeedMessage {
  seq: number; ts: number; type: "message";
  id: string; sender: Agent; recipient: string; kind: string; claim?: string;
  evidence_ids: string[]; kind_of_claim?: "verified" | "inferred"; confidence?: number;
  proposed_risk?: Risk; finding_id?: string; case_id?: string; task_id?: string; in_reply_to?: string;
}
export interface FeedAudit {
  seq: number; ts: number; type: "audit"; event: string; agent?: Agent; tool?: string;
  args?: Record<string, unknown>; [k: string]: unknown;
}
export type FeedItem = FeedMessage | FeedAudit;

export interface Finding {
  type: string; component: string; summary: string; hard_signal: boolean; floor: Risk; risk: Risk;
  label?: string; status: "candidate" | "needs_review" | "corroborated" | "cleared" | "disputed"; evidence_ids: string[];
}
export interface Case {
  title: string; finding_ids: string[]; verdict: string; risk: Risk; resolved: boolean;
  confidence: number; rationale?: string; evidence_ids: string[];
}
export interface RunTarget { project: string | null; app: string; base?: string; head?: string; base_ref?: string; head_ref?: string;
  compare?: boolean; verdict?: string; recorded?: boolean }
export interface RunState {
  run_id: string; status: "starting" | "running" | "done" | "error"; error?: string; mode: string; world: string; target?: RunTarget;
  pending_human?: { id: string; question: string; options: string[]; timeout: number } | null; elapsed: number;
  plan?: string[]; tasks?: Record<string, { assignee: string; goal: string; scope: string[]; status: string }>;
  findings?: Record<string, Finding>; cases?: Record<string, Case>;
  coverage?: { required: string[]; done: string[] }; coverage_gaps?: string[];
  verdict?: { decision: "block" | "safe_to_merge" | "inconclusive"; rationale: string; case_ids: string[]; evidence_ids: string[] } | null;
}
export interface Evidence { id: string; kind: string; source: string; path?: string; untrusted: boolean; content: string }
