import { useEffect, useRef, useState } from "react";
import { RunResults } from "../components/RunView";
import { api, playReplay } from "../lib/api";
import { applyRepoEvent, emptyRepo, type RepoState } from "../lib/repoReducer";
import { applyEvent, startRun } from "../lib/runReducer";
import type { ReplayDoc, ReplayMeta, RunState } from "../lib/types";
import { RepoSummary, TargetsTable } from "./RepoPage";

export default function ReplaysPage() {
  const [list, setList] = useState<ReplayMeta[]>([]);
  const [doc, setDoc] = useState<ReplayDoc>();
  const [speed, setSpeed] = useState(1);
  const [run, setRun] = useState<RunState>();
  const [repo, setRepo] = useState<RepoState>();
  const [viewing, setViewing] = useState<string>();
  const [error, setError] = useState<string>();
  const stop = useRef<() => void>();

  const refresh = () => api.replays().then((r) => setList(r.replays)).catch((e) => setError(e.message));
  useEffect(() => {
    refresh();
    return () => stop.current?.();
  }, []);
  useEffect(() => {
    if (repo?.current) setViewing(repo.current);
  }, [repo?.current]);

  async function play(id: string, sp = speed) {
    stop.current?.();
    setError(undefined);
    try {
      const d = await api.replay(id);
      setDoc(d);
      setViewing(undefined);
      if (d.kind === "repo") {
        setRun(undefined);
        let s = emptyRepo();
        setRepo(s);
        stop.current = playReplay(d, sp, (ev) => {
          s = applyRepoEvent(s, ev);
          setRepo(s);
        });
      } else {
        setRepo(undefined);
        let s = startRun(String((d.meta as { code?: string })?.code || ""));
        setRun(s);
        stop.current = playReplay(d, sp, (ev) => {
          s = applyEvent(s, ev);
          setRun(s);
        });
      }
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className="grid" style={{ gridTemplateColumns: "minmax(300px, 3fr) 9fr" }}>
      <div className="stack">
        <div className="card">
          <div className="row" style={{ marginBottom: 10 }}>
            <h2 style={{ margin: 0 }}>Recorded runs</h2>
            <span className="spacer" />
            <button className="btn" onClick={refresh}>Refresh</button>
          </div>
          <div className="row small" style={{ marginBottom: 10 }}>
            Speed
            {[1, 2, 4, 8].map((s) => (
              <button key={s} className={`badge ${speed === s ? "orange" : ""}`} style={{ border: 0, cursor: "pointer" }} onClick={() => setSpeed(s)}>
                {s}×
              </button>
            ))}
          </div>
          <div className="replay-list">
            {list.length === 0 && <div className="empty">No runs recorded yet. Every review is saved automatically.</div>}
            {list.map((r) => (
              <div key={r.id} className={`replay-item ${doc?.id === r.id ? "active" : ""}`} onClick={() => play(r.id)}>
                <span className={`badge ${r.kind === "repo" ? "orange" : ""}`}>{r.kind}</span>
                <div style={{ minWidth: 0 }}>
                  <div className="small" style={{ fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.title}</div>
                  <div className="tiny muted">{r.created} · {r.duration_s}s</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
      <div className="stack">
        {error && <div className="error-box">{error}</div>}
        {!doc && <div className="card empty">Pick a recorded run to play it back with its original timing. Useful when there is no internet during a demo.</div>}
        {doc && (
          <div className="card row small">
            <b>Replaying:</b> {doc.title} <span className="muted">· recorded {doc.created}</span>
            <span className="spacer" />
            <button className="btn" onClick={() => play(doc.id)}>Restart</button>
          </div>
        )}
        {run && <RunResults run={run} />}
        {repo && (
          <>
            <div className="card">
              <h2>{repo.scan?.repo || "Scanning…"}</h2>
              <RepoSummary state={repo} />
            </div>
            {repo.scan && (
              <div className="grid">
                <div className="card">
                  <TargetsTable state={repo} viewing={viewing} onView={setViewing} selectable={false} />
                </div>
                <div className="stack">{viewing && repo.runs[viewing] && <RunResults run={repo.runs[viewing]} />}</div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
