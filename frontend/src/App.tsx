import { useEffect, useState } from "react";
import { api } from "./lib/api";
import type { Health, OracleMode } from "./lib/types";
import RepoPage from "./pages/RepoPage";
import ReplaysPage from "./pages/ReplaysPage";
import ReviewPage from "./pages/ReviewPage";

type Tab = "review" | "repo" | "replays";

export default function App() {
  const [tab, setTab] = useState<Tab>(() => (location.hash.slice(1) as Tab) || "review");
  const [health, setHealth] = useState<Health | null>(null);
  const [healthErr, setHealthErr] = useState(false);

  useEffect(() => {
    location.hash = tab;
  }, [tab]);
  useEffect(() => {
    const load = () =>
      api
        .health()
        .then((h) => {
          setHealth(h);
          setHealthErr(false);
        })
        .catch(() => setHealthErr(true));
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  const mode: OracleMode = health?.oracle_mode || "dual";
  return (
    <>
      <div className="bg-ring a" />
      <div className="bg-ring b" />
      <div className="bg-dot" />
      <div className="app">
        <header className="header">
          <div className="brand">
            <div className="brand-mark"><span /></div>
            <div>
              <h1>VOID</h1>
              <small>Oracle-grounded security repair</small>
            </div>
          </div>
          <nav className="tabs">
            {(["review", "repo", "replays"] as Tab[]).map((t) => (
              <button key={t} className={`tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>
                {t === "review" ? "Review code" : t === "repo" ? "Scan a repo" : "Replays"}
              </button>
            ))}
          </nav>
          <div className="health">
            {healthErr && <span className="pill bad"><span className="dot" />backend offline</span>}
            {health && (
              <>
                <span className={`pill ${health.stub_llm ? "warn" : health.api_key_configured ? "ok" : "bad"}`} title="LLM">
                  <span className="dot" />
                  {health.stub_llm ? "stub LLM (offline)" : health.api_key_configured ? health.model : "no API key"}
                </span>
                <span className={`pill ${health.sandbox === "docker" ? "ok" : "warn"}`} title="Execution sandbox">
                  <span className="dot" />
                  sandbox: {health.sandbox}
                </span>
              </>
            )}
          </div>
        </header>
        <div style={{ display: tab === "review" ? "block" : "none" }}><ReviewPage defaultMode={mode} /></div>
        <div style={{ display: tab === "repo" ? "block" : "none" }}><RepoPage defaultMode={mode} /></div>
        {tab === "replays" && <ReplaysPage />}
      </div>
    </>
  );
}
