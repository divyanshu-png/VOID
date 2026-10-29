import ReactDiffViewer, { DiffMethod } from "react-diff-viewer-continued";
import { STAGES } from "../lib/runReducer";
import type { Attempt, RunState } from "../lib/types";

export function Pipeline({ run }: { run: RunState }) {
  return (
    <div className="pipeline">
      {STAGES.map((s, i) => (
        <div key={s.id} className={`stage ${run.stages[s.id]}`}>
          <div className="num">{run.stages[s.id] === "done" ? "✓" : i + 1}</div>
          <b>{s.label}</b>
          <span>{s.id === "refactor" && run.attempts.length ? `attempt ${run.attempts.length}` : s.detail}</span>
        </div>
      ))}
    </div>
  );
}

const VERDICT_COPY: Record<string, [string, string]> = {
  verified: ["VERIFIED", "The patch removed the flagged weaknesses and passed its tests. Every check agrees."],
  unverified: ["UNVERIFIED", "The best patch is shown, but at least one oracle still rejects it. Review before using."],
  clean: ["CLEAN", "No exploitable issues were found, so no patch was needed."],
  invalid_input: ["INVALID INPUT", "The code does not parse, so it was not reviewed."],
};

export function Verdict({ run }: { run: RunState }) {
  if (run.status === "idle") return null;
  if (run.status === "error")
    return (
      <div className="verdict error">
        <div className="big">ERROR</div>
        <p>{run.error}</p>
      </div>
    );
  if (run.status === "running" || !run.result)
    return (
      <div className="verdict running">
        <span className="spinner" />
        <div>
          <div className="big" style={{ fontSize: 16 }}>Reviewing…</div>
          <p>{runningText(run)}</p>
        </div>
      </div>
    );
  const v = run.result.verdict;
  const [title, text] = VERDICT_COPY[v] || [v.toUpperCase(), ""];
  const usage = run.result.usage as { llm_calls?: number; model?: string } | undefined;
  return (
    <div className={`verdict ${v}`}>
      <div className="big">{title}</div>
      <div style={{ flex: 1 }}>
        <p>{text}</p>
        <p className="tiny muted">
          {run.attempts.length} attempt{run.attempts.length === 1 ? "" : "s"}
          {usage?.llm_calls ? ` · ${usage.llm_calls} model calls` : ""}
          {usage?.model ? ` · ${usage.model}` : ""}
          {run.result.oracle_mode ? ` · mode: ${run.result.oracle_mode}` : ""}
        </p>
      </div>
    </div>
  );
}

function runningText(run: RunState): string {
  if (run.stages.ast_parser === "active") return "Parsing the code, running Bandit and checking packages on PyPI…";
  if (run.stages.security_audit === "active") return "The auditor is reviewing the code against the OWASP Top 10…";
  const last = run.attempts[run.attempts.length - 1];
  if (run.stages.sandbox === "active" && last?.exec && !last.critic) return `The critic agent is reviewing attempt ${run.attempts.length}…`;
  if (run.stages.sandbox === "active" && last?.critic) return "The supervisor agent is choosing the next step…";
  if (run.stages.sandbox === "active") return `Verifying attempt ${run.attempts.length}: Bandit re-scan + sandboxed tests…`;
  if (run.stages.refactor === "active")
    return run.attempts.length ? `Attempt ${run.attempts.length} was rejected; repairing again with the feedback…` : "Writing a patch and tests…";
  return "Finishing up…";
}

export function Findings({ run }: { run: RunState }) {
  const flagged = run.packages.filter((p) => p.status !== "ok");
  return (
    <div className="card">
      <h2>What was found</h2>
      {run.audit?.summary && <p style={{ marginTop: 0 }}>{run.audit.summary}</p>}
      {run.audit?.findings?.length ? (
        <div className="findings">
          {run.audit.findings.map((f, i) => (
            <div className="finding" key={i}>
              <div className="row">
                <span className={`badge ${f.severity}`}>{f.severity}</span>
                <span className="badge">{f.cwe}</span>
                {f.line ? <span className="tiny muted">line {f.line}</span> : null}
              </div>
              <h4>{f.title}</h4>
              <p>{f.explanation}</p>
              <div className="fix">→ {f.fix}</div>
            </div>
          ))}
        </div>
      ) : (
        <div className="empty">{run.stages.security_audit === "done" ? "The auditor reported no issues." : "Waiting for the audit…"}</div>
      )}
      <div className="row" style={{ marginTop: 14, alignItems: "flex-start", gap: 24 }}>
        <div style={{ flex: 1, minWidth: 240 }}>
          <h3 className="small">Bandit (before)</h3>
          <div className="list">
            {run.sastBefore.length ? (
              run.sastBefore.map((f, i) => (
                <div className="list-item" key={i}>
                  <span className={`badge ${f.severity}`}>{f.test_id}</span>
                  <span>{f.issue_text}</span>
                  {f.line_number ? <span className="muted tiny">L{f.line_number}</span> : null}
                </div>
              ))
            ) : (
              <span className="muted small">{run.ast ? "No Bandit findings." : "-"}</span>
            )}
          </div>
        </div>
        <div style={{ flex: 1, minWidth: 220 }}>
          <h3 className="small">Packages</h3>
          <div className="list">
            {run.packages.length === 0 && <span className="muted small">{run.ast ? "No third-party imports." : "-"}</span>}
            {run.packages.map((p, i) => (
              <div className="list-item" key={i}>
                <span className={`badge ${p.status === "ok" ? "good" : p.status === "unknown" ? "" : "bad"}`}>
                  {p.status === "not_found" ? "NOT ON PYPI" : p.status.toUpperCase()}
                </span>
                <span className="mono">{p.package}</span>
                {p.reasons[0] && <span className="muted tiny">{p.reasons.join("; ")}</span>}
              </div>
            ))}
            {flagged.length > 0 && <span className="tiny" style={{ color: "var(--red)" }}>Possible slopsquatting risk.</span>}
          </div>
        </div>
      </div>
    </div>
  );
}

function OracleBadges({ a }: { a: Attempt }) {
  if (!a.exec || !a.sast)
    return (
      <span className="badge orange">
        <span className="spinner" /> verifying
      </span>
    );
  const execLabel =
    a.exec.status === "passed"
      ? `tests pass (${a.exec.tests_collected ?? "?"})`
      : a.exec.status === "no_tests"
        ? "no tests"
        : a.exec.status === "timeout"
          ? "timeout"
          : `tests fail · ${a.exec.error_kind ?? "error"}`;
  const sastLabel = a.sast.passed
    ? `bandit clean (${a.sast.resolved} fixed)`
    : `bandit: ${a.sast.remaining.length} left${a.sast.introduced.length ? `, ${a.sast.introduced.length} new` : ""}`;
  return (
    <>
      <span className={`badge ${a.sast.passed ? "good" : "bad"}`}>SAST · {sastLabel}</span>
      <span className={`badge ${a.exec.passed ? "good" : "bad"}`}>EXEC · {execLabel}</span>
      {a.critic && <span className={`badge ${a.critic.approved ? "good" : "bad"}`}>CRITIC · {a.critic.approved ? "approved" : "rejected"}</span>}
      {a.exec.backend && <span className="tiny muted">{a.exec.backend}</span>}
    </>
  );
}

export function Attempts({ run }: { run: RunState }) {
  return (
    <div className="card">
      <h2>Self-correction loop</h2>
      {!run.attempts.length && <div className="empty">No repair attempts yet.</div>}
      <div className="attempts">
        {run.attempts.map((a) => (
          <div key={a.n} className={`attempt ${a.accepted === undefined ? "" : a.accepted ? "accepted" : "rejected"}`}>
            <div className="attempt-head">
              <b>Attempt {a.n}</b>
              <OracleBadges a={a} />
              <span className="spacer" />
              {a.accepted !== undefined && (
                <span className={`badge ${a.accepted ? "good" : "warn"}`}>{a.accepted ? "ACCEPTED" : "REJECTED"}</span>
              )}
            </div>
            {a.action === "repair_tests" && <p className="tiny muted" style={{ margin: "6px 0 0" }}>Tests rewritten, code kept</p>}
            {a.notes && <p className="small muted" style={{ margin: "6px 0 0" }}>{a.notes}</p>}
            {a.critic && !a.critic.approved && a.critic.issues.length > 0 && (
              <ul className="small" style={{ margin: "6px 0 0", paddingLeft: 18 }}>
                {a.critic.issues.map((i, k) => <li key={k}>{i}</li>)}
              </ul>
            )}
            {a.decision && (
              <p className="small" style={{ margin: "6px 0 0" }}>
                <b>Supervisor → {a.decision.action.replace("_", " ")}</b>: {a.decision.reason}
              </p>
            )}
            {a.feedback && (
              <details>
                <summary>Feedback sent back to the repair agent</summary>
                <pre className="block">{a.feedback}</pre>
              </details>
            )}
            {a.tests && (
              <details>
                <summary>Generated tests</summary>
                <pre className="block">{a.tests}</pre>
              </details>
            )}
            {a.exec?.logs && !a.exec.passed && (
              <details>
                <summary>Sandbox output</summary>
                <pre className="block">{a.exec.logs}</pre>
              </details>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

export function Diff({ original, patched, title }: { original: string; patched: string; title?: string }) {
  return (
    <div className="card">
      <h2>{title || "Patch"}</h2>
      {original.trim() === patched.trim() ? (
        <div className="empty">The final candidate is identical to the original: the repair agent made no change.</div>
      ) : (
      <div className="diff-wrap">
        <ReactDiffViewer
          oldValue={original}
          newValue={patched}
          splitView
          compareMethod={DiffMethod.WORDS}
          leftTitle="original"
          rightTitle="patched"
          styles={{
            variables: {
              light: {
                diffViewerBackground: "#ffffff",
                addedBackground: "#e3f1e9",
                addedGutterBackground: "#d2eadc",
                wordAddedBackground: "#b9dcc8",
                removedBackground: "#fbe4e2",
                removedGutterBackground: "#f6d2ce",
                wordRemovedBackground: "#f0bdb8",
                gutterBackground: "#faf8f5",
                gutterColor: "#9a948d",
                diffViewerTitleBackground: "#faf8f5",
                diffViewerTitleColor: "#6b6661",
                diffViewerTitleBorderColor: "#e6dfd6",
                emptyLineBackground: "#fbfaf8",
              },
            },
            contentText: { fontFamily: "var(--mono)", fontSize: 12 },
          }}
        />
      </div>
      )}
    </div>
  );
}

/** Full results column for one run. */
export function RunResults({ run, showPipeline = true }: { run: RunState; showPipeline?: boolean }) {
  const patched = run.result?.refactored_code ?? run.attempts[run.attempts.length - 1]?.patched_code;
  const original = run.focus?.snippet ?? run.code;
  return (
    <div className="stack">
      {showPipeline && (
        <div className="card">
          <h2>Pipeline</h2>
          <Pipeline run={run} />
        </div>
      )}
      <Verdict run={run} />
      {run.focus && (
        <div className="card small">
          Focused on <b>{run.focus.kind.replace("Def", "").toLowerCase()} {run.focus.name}</b> (lines {run.focus.start_line}-
          {run.focus.end_line})
        </div>
      )}
      {(run.ast || run.audit) && <Findings run={run} />}
      {(run.attempts.length > 0 || run.status === "running") && <Attempts run={run} />}
      {patched && original && <Diff original={original} patched={patched} />}
    </div>
  );
}
