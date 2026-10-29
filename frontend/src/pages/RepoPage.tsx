import { useEffect, useReducer, useRef, useState } from "react";
import { RunResults } from "../components/RunView";
import { api, repoRunStream } from "../lib/api";
import { applyRepoEvent, emptyRepo, type RepoState } from "../lib/repoReducer";
import { MODES, type OracleMode, type RepoScan, type RunState, type StreamEvent } from "../lib/types";

type Action = { type: "reset" } | { type: "scanning" } | { type: "scanned"; scan: RepoScan } | { type: "fail"; msg: string } | { type: "event"; ev: StreamEvent };

function reducer(s: RepoState, a: Action): RepoState {
  switch (a.type) {
    case "reset":
      return emptyRepo();
    case "scanning":
      return { ...emptyRepo(), status: "scanning" };
    case "scanned":
      return { ...emptyRepo(), status: "scanned", scan: a.scan };
    case "fail":
      return { ...s, status: "error", error: a.msg };
    case "event":
      return applyRepoEvent(s, a.ev);
  }
}

export function statusCell(run?: RunState) {
  if (!run) return <span className="muted tiny">-</span>;
  if (run.status === "idle") return <span className="muted tiny">queued</span>;
  if (run.status === "error") return <span className="badge bad">ERROR</span>;
  if (run.status === "running") {
    const stage = Object.entries(run.stages).find(([, v]) => v === "active")?.[0] || "";
    const label: Record<string, string> = { ast_parser: "pre-checks", security_audit: "auditing", refactor: `repairing #${run.attempts.length + 1}`, sandbox: `verifying #${run.attempts.length}`, presentation: "finishing" };
    return (
      <span className="status" style={{ color: "var(--orange-deep)" }}>
        <span className="spinner" /> {label[stage] || "running"}
      </span>
    );
  }
  const v = run.result?.verdict || "";
  const cls = v === "verified" ? "good" : v === "unverified" ? "warn" : v === "clean" ? "" : "bad";
  return (
    <span className={`badge ${cls}`}>
      {v.toUpperCase()} {run.attempts.length ? `· ${run.attempts.length} att.` : ""}
    </span>
  );
}

export function RepoSummary({ state, selectedCount }: { state: RepoState; selectedCount?: number }) {
  const scan = state.scan;
  if (!scan) return null;
  const sev = scan.by_severity || {};
  return (
    <div className="stats">
      <div className="stat"><b>{scan.python_files}</b><span>Python files</span></div>
      <div className="stat"><b>{scan.total_findings}</b><span>Bandit findings ({sev.HIGH || 0} high · {sev.MEDIUM || 0} med)</span></div>
      <div className="stat"><b>{scan.targets.length}</b><span>risky code blocks ranked</span></div>
      <div className="stat">
        <b>{state.summary ? `${state.summary.verified || 0}/${Object.keys(state.runs).length}` : Object.keys(state.runs).length || selectedCount || "-"}</b>
        <span>{state.summary ? "verified fixes" : "selected for repair"}</span>
      </div>
    </div>
  );
}

export function TargetsTable({ state, selected, onToggle, viewing, onView, selectable }: {
  state: RepoState; selected?: Set<string>; onToggle?: (id: string) => void; viewing?: string; onView: (id: string) => void; selectable: boolean;
}) {
  const targets = state.scan?.targets || [];
  const shown = selectable ? targets : targets.filter((t) => state.runs[t.id]);
  return (
    <table className="targets">
      <thead>
        <tr>
          {selectable && <th />}
          <th>Block</th>
          <th>Findings</th>
          <th>Risk</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {shown.map((t) => (
          <tr key={t.id} className={`clickable ${viewing === t.id ? "selected" : ""}`} onClick={() => onView(t.id)}>
            {selectable && (
              <td onClick={(e) => e.stopPropagation()}>
                <input type="checkbox" checked={selected?.has(t.id)} onChange={() => onToggle?.(t.id)} />
              </td>
            )}
            <td>
              <div className="mono small">{t.file}</div>
              <div className="tiny muted">
                {t.kind.replace("Def", "").toLowerCase()} <b>{t.name}</b> · L{t.start_line}-{t.end_line}
              </div>
            </td>
            <td>
              <div className="row" style={{ gap: 4 }}>
                {t.findings.slice(0, 5).map((f, i) => (
                  <span key={i} className={`badge ${f.severity}`} title={f.issue_text}>{f.test_id}</span>
                ))}
                {t.findings.length > 5 && <span className="tiny muted">+{t.findings.length - 5}</span>}
              </div>
            </td>
            <td className="mono">{t.score}</td>
            <td>{statusCell(state.runs[t.id])}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function RepoPage({ defaultMode }: { defaultMode: OracleMode }) {
  const [url, setUrl] = useState("");
  const [user, setUser] = useState("");
  const [mode, setMode] = useState<OracleMode>(defaultMode);
  const [demos, setDemos] = useState<string[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [viewing, setViewing] = useState<string>();
  const [state, dispatch] = useReducer(reducer, emptyRepo());
  const abort = useRef<AbortController | null>(null);

  useEffect(() => setMode(defaultMode), [defaultMode]);
  useEffect(() => {
    api.demos().then((r) => setDemos(r.repos)).catch(() => undefined);
  }, []);
  useEffect(() => {
    if (state.current) setViewing(state.current);
  }, [state.current]);

  async function scan(target = url) {
    if (!target) return;
    setUrl(target);
    setViewing(undefined);
    dispatch({ type: "scanning" });
    try {
      const s = await api.scanRepo(target);
      dispatch({ type: "scanned", scan: s });
      setSelected(new Set(s.targets.slice(0, 3).map((t) => t.id)));
    } catch (e) {
      dispatch({ type: "fail", msg: (e as Error).message });
    }
  }

  async function random(fromUser: boolean) {
    try {
      const r = await api.randomRepo(fromUser ? user : "");
      await scan(r.url);
    } catch (e) {
      dispatch({ type: "fail", msg: (e as Error).message });
    }
  }

  async function runSelected() {
    if (!state.scan || !selected.size) return;
    const ctrl = new AbortController();
    abort.current = ctrl;
    try {
      await repoRunStream(state.scan.url, [...selected], mode, (ev) => dispatch({ type: "event", ev }), ctrl.signal);
    } catch (e) {
      if ((e as Error).name !== "AbortError") dispatch({ type: "fail", msg: (e as Error).message });
    }
  }

  const toggle = (id: string) =>
    setSelected((prev) => {
      const n = new Set(prev);
      if (n.has(id)) n.delete(id);
      else if (n.size < 10) n.add(id);
      return n;
    });

  const running = state.status === "running" || state.status === "scanning";
  const viewRun = viewing ? state.runs[viewing] : undefined;
  const viewTarget = state.scan?.targets.find((t) => t.id === viewing);

  return (
    <div className="stack">
      <div className="card">
        <h2>Pick a repository</h2>
        <div className="row">
          <input className="input" style={{ flex: 1, minWidth: 280 }} placeholder="https://github.com/owner/repo" value={url} onChange={(e) => setUrl(e.target.value)} onKeyDown={(e) => e.key === "Enter" && scan()} />
          <button className="btn dark" onClick={() => scan()} disabled={running || !url}>Scan</button>
          <button className="btn" onClick={() => random(false)} disabled={running}>Random vulnerable demo</button>
          <input className="input" style={{ width: 170 }} placeholder="GitHub username" value={user} onChange={(e) => setUser(e.target.value)} />
          <button className="btn" onClick={() => random(true)} disabled={running || !user}>Random from user</button>
        </div>
        {demos.length > 0 && (
          <div className="row tiny muted" style={{ marginTop: 10 }}>
            Demo repos:
            {demos.map((d) => (
              <button key={d} className="badge orange" style={{ border: 0, cursor: "pointer" }} onClick={() => scan(d)} disabled={running}>
                {d.replace("https://github.com/", "")}
              </button>
            ))}
          </div>
        )}
      </div>

      {state.status === "scanning" && (
        <div className="verdict running"><span className="spinner" /><div><div className="big" style={{ fontSize: 16 }}>Cloning and scanning…</div><p>Shallow clone, Bandit across every Python file, then ranking the riskiest code blocks.</p></div></div>
      )}
      {state.status === "error" && <div className="error-box">{state.error}</div>}

      {state.scan && (
        <>
          <div className="card">
            <div className="row" style={{ marginBottom: 12 }}>
              <h2 style={{ margin: 0 }}>{state.scan.repo}</h2>
              <span className="spacer" />
              {state.replayId && <span className="tiny muted">replay {state.replayId}</span>}
            </div>
            <RepoSummary state={state} selectedCount={selected.size} />
          </div>
          <div className="grid">
            <div className="stack">
              <div className="card">
                <div className="row" style={{ marginBottom: 10 }}>
                  <h2 style={{ margin: 0 }}>Ranked blocks</h2>
                  <span className="spacer" />
                  <select className="input" value={mode} onChange={(e) => setMode(e.target.value as OracleMode)}>
                    {MODES.map((m) => <option key={m.id} value={m.id}>{m.code} · {m.label}</option>)}
                  </select>
                  <button className="btn primary" onClick={runSelected} disabled={running || !selected.size}>
                    {state.status === "running" ? "Running…" : `Repair ${selected.size} selected`}
                  </button>
                </div>
                {state.scan.targets.length ? (
                  <TargetsTable state={state} selected={selected} onToggle={toggle} viewing={viewing} onView={setViewing} selectable={state.status !== "running"} />
                ) : (
                  <div className="empty">No MEDIUM/HIGH findings inside functions or classes. Try another repo.</div>
                )}
              </div>
            </div>
            <div className="stack">
              {viewRun && viewRun.status !== "idle" ? (
                <>
                  <div className="card small">
                    <b className="mono">{viewTarget?.file}</b> · {viewTarget?.name} (lines {viewTarget?.start_line}-{viewTarget?.end_line})
                  </div>
                  <RunResults run={viewRun} />
                </>
              ) : viewTarget ? (
                <div className="card">
                  <h2>{viewTarget.file} · {viewTarget.name}</h2>
                  <pre className="block">{viewTarget.snippet}</pre>
                </div>
              ) : (
                <div className="card empty">Select a block to preview it, then run the repair to watch VOID work through each one.</div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
