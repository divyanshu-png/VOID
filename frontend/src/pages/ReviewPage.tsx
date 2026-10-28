import { useEffect, useReducer, useRef, useState } from "react";
import { RunResults } from "../components/RunView";
import { api, auditStream } from "../lib/api";
import { applyEvent, emptyRun, startRun } from "../lib/runReducer";
import { MODES, type OracleMode, type RunState, type StreamEvent } from "../lib/types";

const DEFAULT_CODE = `import sqlite3
import subprocess
import yaml


def get_user(conn, username):
    cur = conn.cursor()
    cur.execute(f"SELECT id, username FROM users WHERE username = '{username}'")
    return cur.fetchall()


def ping(host):
    return subprocess.check_output("ping -c 1 " + host, shell=True).decode()


def load_config(text):
    return yaml.load(text, Loader=yaml.Loader)
`;

type Action = { type: "reset"; code: string } | { type: "start"; code: string } | { type: "event"; ev: StreamEvent };

function reducer(state: RunState, a: Action): RunState {
  if (a.type === "reset") return emptyRun(a.code);
  if (a.type === "start") return startRun(a.code);
  return applyEvent(state, a.ev);
}

export default function ReviewPage({ defaultMode }: { defaultMode: OracleMode }) {
  const [code, setCode] = useState(DEFAULT_CODE);
  const [mode, setMode] = useState<OracleMode>(defaultMode);
  const [samples, setSamples] = useState<{ id: string; cwe: string; code: string }[]>([]);
  const [run, dispatch] = useReducer(reducer, emptyRun(DEFAULT_CODE));
  const abort = useRef<AbortController | null>(null);

  useEffect(() => setMode(defaultMode), [defaultMode]);
  useEffect(() => {
    api.samples().then((r) => setSamples(r.samples)).catch(() => setSamples([]));
  }, []);

  async function go() {
    abort.current?.abort();
    const ctrl = new AbortController();
    abort.current = ctrl;
    dispatch({ type: "start", code });
    try {
      await auditStream(code, mode, (ev) => dispatch({ type: "event", ev }), ctrl.signal);
    } catch (e) {
      if ((e as Error).name !== "AbortError") dispatch({ type: "event", ev: { event: "error", data: { message: String((e as Error).message || e) } } });
    }
  }

  const running = run.status === "running";
  return (
    <div className="grid">
      <div className="stack">
        <div className="card">
          <div className="row" style={{ marginBottom: 12 }}>
            <h2 style={{ margin: 0 }}>Code to review</h2>
            <span className="spacer" />
            {samples.length > 0 && (
              <select
                className="input"
                value=""
                onChange={(e) => {
                  const s = samples.find((x) => x.id === e.target.value);
                  if (s) {
                    setCode(s.code);
                    dispatch({ type: "reset", code: s.code });
                  }
                }}
              >
                <option value="">Load a sample…</option>
                {samples.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.id} · {s.cwe}
                  </option>
                ))}
              </select>
            )}
          </div>
          <textarea className="editor" spellCheck={false} value={code} onChange={(e) => setCode(e.target.value)} />
        </div>
        <div className="card">
          <h2>Oracle configuration</h2>
          <div className="modes">
            {MODES.map((m) => (
              <button key={m.id} className={`mode ${mode === m.id ? "active" : ""}`} onClick={() => setMode(m.id)} title={m.hint}>
                <b>
                  {m.code} · {m.label}
                </b>
                <span>{m.hint}</span>
              </button>
            ))}
          </div>
          <div className="row" style={{ marginTop: 14 }}>
            <button className="btn primary" onClick={go} disabled={running || !code.trim()}>
              {running ? "Reviewing…" : "Audit & repair"}
            </button>
            {running && (
              <button className="btn" onClick={() => abort.current?.abort()}>
                Stop
              </button>
            )}
            <span className="spacer" />
            {run.replayId && <span className="tiny muted">saved as replay {run.replayId}</span>}
          </div>
        </div>
      </div>
      <RunResults run={run} />
    </div>
  );
}
