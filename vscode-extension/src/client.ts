import * as vscode from "vscode";

export interface BanditFinding {
  test_id: string;
  issue_text: string;
  severity: string;
  confidence?: string;
  line_number?: number | null;
  line_range?: number[];
  cwe?: number | null;
}

export interface PackageCheck {
  import: string;
  package: string;
  status: "ok" | "suspicious" | "not_found" | "unknown";
  reasons: string[];
}

export interface ScanResult {
  valid_syntax: boolean;
  syntax_error?: string;
  findings: BanditFinding[];
  packages: PackageCheck[];
}

export interface AuditResult {
  verdict: string;
  oracle_mode?: string;
  audit?: { summary: string; findings: { title: string; cwe: string; severity: string; line?: number; explanation: string; fix: string }[] };
  refactored_code?: string | null;
  merged_file?: string | null;
  focus?: { name: string; kind: string; start_line: number; end_line: number };
  test_status?: string;
  sast_status?: string;
  retries?: number;
  attempts?: { n: number; accepted: boolean; exec: { status: string; error_kind?: string; passed: boolean }; sast: { passed: boolean; resolved: number; remaining: unknown[]; introduced: unknown[] } }[];
  replay_id?: string;
  usage?: { llm_calls?: number; model?: string };
}

function cfg() {
  const c = vscode.workspace.getConfiguration("void");
  return {
    url: (c.get<string>("backendUrl") || "http://localhost:8000").replace(/\/$/, ""),
    mode: c.get<string>("oracleMode") || "auto",
    timeout: (c.get<number>("timeoutSeconds") || 300) * 1000,
  };
}

export function dashboardUrl() {
  return (vscode.workspace.getConfiguration("void").get<string>("dashboardUrl") || "http://localhost:5173").replace(/\/$/, "");
}

export function backendUrl() {
  return cfg().url;
}

async function post<T>(path: string, body: unknown, timeoutMs = 30000): Promise<T> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(cfg().url + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    return (await res.json()) as T;
  } finally {
    clearTimeout(t);
  }
}

export async function health(): Promise<{ model: string; sandbox: string; api_key_configured: boolean; stub_llm?: boolean } | null> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 3000);
    const res = await fetch(cfg().url + "/health", { signal: ctrl.signal });
    clearTimeout(t);
    return res.ok ? ((await res.json()) as never) : null;
  } catch {
    return null;
  }
}

export function scan(code: string): Promise<ScanResult> {
  return post<ScanResult>("/api/v1/scan", { code });
}

const STAGE_TEXT: Record<string, string> = {
  ast_parser: "Pre-checks done (AST, Bandit, PyPI)",
  security_audit: "Audit done",
  refactor: "Patch written, verifying",
  sandbox: "Verification finished",
  presentation: "Preparing result",
};

/** Streams /audit/stream and reports progress; resolves with the final result. */
export async function auditStream(
  code: string,
  focusLine: number | undefined,
  onProgress: (msg: string) => void,
  token: vscode.CancellationToken,
): Promise<AuditResult> {
  const { url, mode, timeout } = cfg();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  token.onCancellationRequested(() => ctrl.abort());
  try {
    const res = await fetch(url + "/api/v1/audit/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
      body: JSON.stringify({ code, language: "python", oracle_mode: mode, focus_line: focusLine }),
      signal: ctrl.signal,
    });
    if (!res.ok || !res.body) throw new Error(`${res.status} ${await res.text()}`);
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let result: AuditResult | undefined;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let idx: number;
      while ((idx = buffer.indexOf("\n\n")) >= 0) {
        const block = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 2);
        let event = "";
        let data = "";
        for (const line of block.split("\n")) {
          if (line.startsWith("event:")) event = line.slice(6).trim();
          else if (line.startsWith("data:")) data += line.slice(5).trimStart();
        }
        if (!data) continue;
        const d = JSON.parse(data);
        if (event === "focus") onProgress(`Focusing on ${d.name} (lines ${d.start_line}-${d.end_line})`);
        else if (event === "node") {
          if (d.node === "refactor") onProgress(`Attempt ${d.attempt}: patch written, running oracles…`);
          else if (d.node === "sandbox")
            onProgress(
              `Attempt ${d.attempt}: Bandit ${d.sast?.passed ? "clean" : "still flags issues"} · tests ${d.exec?.status}` +
                (d.accepted ? " → accepted" : " → retrying"),
            );
          else onProgress(STAGE_TEXT[d.node] || d.node);
        } else if (event === "done") result = d as AuditResult;
        else if (event === "error") throw new Error(d.message);
      }
    }
    if (!result) throw new Error("The stream ended without a result.");
    return result;
  } finally {
    clearTimeout(timer);
  }
}
