export type OracleMode = "single" | "sast" | "exec" | "dual" | "auto";

export const MODES: { id: OracleMode; code: string; label: string; hint: string }[] = [
  { id: "single", code: "C0", label: "Single prompt", hint: "One repair attempt, no feedback loop" },
  { id: "sast", code: "C1", label: "SAST only", hint: "Retry until the Bandit re-scan is clean" },
  { id: "exec", code: "C2", label: "Tests only", hint: "Retry until generated tests pass" },
  { id: "dual", code: "C3", label: "Dual oracle", hint: "Both must pass" },
  { id: "auto", code: "C4", label: "Autonomous", hint: "Both oracles + a critic agent; a supervisor agent picks each next step: VOID's default" },
];

export interface BanditFinding {
  test_id: string;
  test_name?: string;
  issue_text: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | string;
  confidence?: string;
  line_number?: number | null;
  cwe?: number | string | null;
  filename?: string;
}

export interface PackageCheck {
  import: string;
  package: string;
  status: "ok" | "suspicious" | "not_found" | "unknown";
  reasons: string[];
  lookalike_of?: string | null;
  first_release?: string | null;
  releases?: number;
}

export interface AuditFinding {
  title: string;
  cwe: string;
  owasp?: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  line?: number | null;
  explanation: string;
  fix: string;
}

export interface ExecOracle {
  passed: boolean;
  status: "passed" | "failed" | "no_tests" | "timeout" | "error";
  error_kind?: string | null;
  logs?: string;
  backend?: string;
  duration_s?: number;
  tests_collected?: number;
}

export interface SastOracle {
  passed: boolean;
  resolved: number;
  remaining: BanditFinding[];
  remaining_low?: BanditFinding[];
  introduced: BanditFinding[];
  before_count: number;
  after_count: number;
}

export interface Attempt {
  n: number;
  patched_code?: string;
  tests?: string;
  notes?: string;
  exec?: ExecOracle;
  sast?: SastOracle;
  accepted?: boolean;
  feedback?: string;
  action?: string;
  critic?: { approved: boolean; issues: string[]; summary?: string };
  decision?: { action: string; reason: string; guidance?: string };
}

export type StageId = "ast_parser" | "security_audit" | "refactor" | "sandbox" | "presentation";
export type StageStatus = "pending" | "active" | "done" | "skipped" | "failed";

export interface RunResult {
  verdict: "verified" | "unverified" | "clean" | "invalid_input" | string;
  oracle_mode?: OracleMode;
  diff?: string;
  refactored_code?: string | null;
  generated_tests?: string | null;
  test_status?: string;
  sast_status?: string;
  retries?: number;
  usage?: Record<string, unknown>;
  merged_file?: string;
  focus?: { name: string; kind: string; start_line: number; end_line: number };
  replay_id?: string;
  error_logs?: string | null;
}

export interface RunState {
  status: "idle" | "running" | "done" | "error";
  code: string;
  stages: Record<StageId, StageStatus>;
  ast?: { valid_syntax: boolean; imports: string[]; functions: { name: string }[]; syntax_error?: string | null };
  sastBefore: BanditFinding[];
  packages: PackageCheck[];
  audit?: { summary: string; findings: AuditFinding[] };
  attempts: Attempt[];
  result?: RunResult;
  error?: string;
  replayId?: string;
  focus?: { name: string; kind: string; start_line: number; end_line: number; snippet: string };
}

export interface RepoTarget {
  id: string;
  file: string;
  name: string;
  kind: string;
  start_line: number;
  end_line: number;
  snippet: string;
  findings: BanditFinding[];
  score: number;
}

export interface RepoScan {
  repo: string;
  url: string;
  python_files: number;
  total_findings: number;
  by_severity: Record<string, number>;
  targets: RepoTarget[];
  selected?: string[];
}

export interface StreamEvent {
  event: string;
  data: any; // eslint-disable-line @typescript-eslint/no-explicit-any
}

export interface Health {
  status: string;
  model: string;
  stub_llm?: boolean;
  api_key_configured: boolean;
  oracle_mode: OracleMode;
  max_retries: number;
  sandbox: string;
  docker_image_ready: boolean;
}

export interface ReplayMeta {
  id: string;
  kind: "snippet" | "repo";
  title: string;
  created: string;
  duration_s: number;
  meta?: Record<string, unknown>;
}

export interface ReplayDoc extends ReplayMeta {
  events: { t: number; event: string; data: any }[]; // eslint-disable-line @typescript-eslint/no-explicit-any
}
