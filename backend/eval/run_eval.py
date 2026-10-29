"""VOID evaluation harness: compares oracle configurations C0-C3 (paper Table II).

    cd backend
    python -m eval.run_eval --dataset eval/datasets/seed.jsonl --runs 3
    python -m eval.run_eval --stub --runs 1          # offline smoke test, no API key

Dataset: JSONL, one object per program with
    id              unique id
    code            the vulnerable program (must be flagged MEDIUM/HIGH by Bandit)
    heldout_tests   optional pytest code appended to the patched program; never shown to the agent
    heldout_security_tests  optional exploit tests (fail on the original); never shown to the agent
    cwe             optional label

Outputs (in --out, default eval/results/<timestamp>/):
    runs.csv        one row per (sample, mode, run)
    summary.csv     mean / std per mode
    summary.md      paper-ready table + McNemar tests (dual vs each baseline)
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.core import config  # noqa: E402
from app.core.llm import get_llm  # noqa: E402
from app.core.sandbox import active_backend, execute_in_sandbox  # noqa: E402
from app.graph.workflow import run_review  # noqa: E402
from app.tools.sast_scanner import compare, run_bandit_scan  # noqa: E402

MODES = {"single": "C0", "sast": "C1", "exec": "C2", "dual": "C3", "auto": "C4"}


# ----------------------------------------------------------------------------- helpers
def load_dataset(path: Path, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    items = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            items.append(json.loads(line))
    return items[:limit] if limit else items


def semgrep_ids(code: str) -> Optional[List[str]]:
    """Second, independent analyzer (avoids rewarding patches that only dodge Bandit)."""
    exe = shutil.which("semgrep")
    if not exe:
        return None
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
        fh.write(code)
        path = fh.name
    try:
        r = subprocess.run([exe, "--config", "p/python", "--json", "--quiet", "--metrics", "off", path],
                           capture_output=True, text=True, timeout=180)
        data = json.loads(r.stdout or "{}")
        return sorted({res.get("check_id", "") for res in data.get("results", [])})
    except Exception:
        return None
    finally:
        Path(path).unlink(missing_ok=True)


def evaluate_one(sample: Dict[str, Any], mode: str, max_retries: int, use_semgrep: bool) -> Dict[str, Any]:
    llm = get_llm()
    started = time.time()
    error = ""
    try:
        state = run_review(sample["code"], oracle_mode=mode, max_retries=max_retries, llm=llm)
    except Exception as e:  # keep going; record the failure
        state, error = {}, f"{type(e).__name__}: {e}"
    wall = round(time.time() - started, 2)

    final = state.get("refactored_code") or sample["code"]
    before = state.get("sast_before") or run_bandit_scan(sample["code"])
    verdict_sast = compare(before, run_bandit_scan(final))
    attempts = state.get("attempts", [])
    last_exec = (attempts[-1]["exec"] if attempts else {}) or {}

    heldout = sample.get("heldout_tests")
    fp = None
    if heldout and not error:
        fp = execute_in_sandbox(final, heldout).passed

    sec_tests = sample.get("heldout_security_tests")
    sec = None
    if sec_tests and not error:
        sec = execute_in_sandbox(final, sec_tests).passed

    sem = None
    if use_semgrep and not error:
        a, b = semgrep_ids(sample["code"]), semgrep_ids(final)
        if a is not None and b is not None:
            sem = not (set(a) & set(b))

    kinds = [a["exec"].get("error_kind") for a in attempts]
    usage = llm.usage() if hasattr(llm, "usage") else {}
    return {
        "id": sample["id"], "cwe": sample.get("cwe", ""), "mode": mode, "config": MODES[mode],
        "verdict": state.get("verdict", "error"), "error": error,
        "attempts": len(attempts),
        "vrr": int(verdict_sast["passed"]),                       # original MED/HIGH findings gone, nothing new
        "resolved": verdict_sast["resolved"],
        "nir": int(bool(verdict_sast["introduced"])),
        "semgrep_clean": "" if sem is None else int(sem),
        "gen_pass": int(bool(last_exec.get("passed"))),
        "heldout_pass": "" if fp is None else int(fp),
        "exploit_blocked": "" if sec is None else int(sec),
        "success": "" if fp is None else int(verdict_sast["passed"] and fp and (sec is None or sec)),
        "syntax_errors": kinds.count("syntax"),
        "runtime_errors": kinds.count("runtime") + kinds.count("timeout"),
        "first_attempt_feasible": int(bool(attempts) and kinds[0] not in ("syntax", "runtime", "timeout")),
        "llm_calls": usage.get("llm_calls", ""),
        "input_tokens": usage.get("input_tokens", ""),
        "output_tokens": usage.get("output_tokens", ""),
        "wall_s": wall,
    }


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value from discordant counts b, c."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = sum(math.comb(n, i) for i in range(0, k + 1)) / 2 ** n
    return min(1.0, 2 * p)


def _mean(vals: List[Any]) -> Optional[float]:
    nums = [float(v) for v in vals if v not in ("", None)]
    return statistics.mean(nums) if nums else None


def summarise(rows: List[Dict[str, Any]], modes: List[str], runs: int) -> Dict[str, Any]:
    table = {}
    for m in modes:
        per_run = []
        for r in range(runs):
            rs = [x for x in rows if x["mode"] == m and x["run"] == r]
            if not rs:
                continue
            gen = [x for x in rs if x["heldout_pass"] != ""]
            per_run.append({
                "VRR": _mean([x["vrr"] for x in rs]),
                "NIR": _mean([x["nir"] for x in rs]),
                "FP": _mean([x["heldout_pass"] for x in rs]),
                "EBR": _mean([x["exploit_blocked"] for x in rs]),
                "Success": _mean([x["success"] for x in rs]),
                "SGG": (_mean([x["gen_pass"] for x in gen]) - _mean([x["heldout_pass"] for x in gen])) if gen else None,
                "Semgrep": _mean([x["semgrep_clean"] for x in rs]),
                "Feasible@1": _mean([x["first_attempt_feasible"] for x in rs]),
                "Attempts": _mean([x["attempts"] for x in rs]),
                "Calls": _mean([x["llm_calls"] for x in rs]),
                "Tokens": _mean([(x["input_tokens"] or 0) + (x["output_tokens"] or 0) if x["input_tokens"] != "" else "" for x in rs]),
                "Seconds": _mean([x["wall_s"] for x in rs]),
            })
        agg = {}
        for k in per_run[0] if per_run else []:
            vals = [p[k] for p in per_run if p[k] is not None]
            agg[k] = (statistics.mean(vals), statistics.pstdev(vals) if len(vals) > 1 else 0.0) if vals else None
        table[m] = agg

    tests = {}
    if "dual" in modes:
        for m in modes:
            if m == "dual":
                continue
            b = c = 0
            for r in range(runs):
                d = {x["id"]: x for x in rows if x["mode"] == "dual" and x["run"] == r}
                o = {x["id"]: x for x in rows if x["mode"] == m and x["run"] == r}
                for i in d:
                    if i in o and d[i]["success"] != "" and o[i]["success"] != "":
                        if d[i]["success"] and not o[i]["success"]:
                            b += 1
                        elif o[i]["success"] and not d[i]["success"]:
                            c += 1
            tests[m] = {"dual_only": b, "other_only": c, "p": mcnemar_exact(b, c)}
    return {"table": table, "mcnemar": tests}


def to_markdown(summary: Dict[str, Any], meta: Dict[str, Any]) -> str:
    cols = ["VRR", "NIR", "FP", "EBR", "Success", "SGG", "Semgrep", "Feasible@1", "Attempts", "Calls", "Tokens", "Seconds"]
    pct = {"VRR", "NIR", "FP", "EBR", "Success", "SGG", "Semgrep", "Feasible@1"}
    lines = [f"# VOID evaluation - {meta['dataset']} ({meta['n']} programs x {meta['runs']} runs)", "",
             f"model: `{meta['model']}` · sandbox: `{meta['sandbox']}` · max retries: {meta['max_retries']}", "",
             "| Config | " + " | ".join(cols) + " |", "|" + "---|" * (len(cols) + 1)]
    for m, agg in summary["table"].items():
        cells = []
        for c in cols:
            v = agg.get(c)
            if v is None:
                cells.append("n/a")
            elif c in pct:
                cells.append(f"{100 * v[0]:.1f}% ± {100 * v[1]:.1f}")
            else:
                cells.append(f"{v[0]:.2f}")
        lines.append(f"| {MODES[m]} ({m}) | " + " | ".join(cells) + " |")
    lines += ["", "VRR = original MEDIUM/HIGH Bandit findings removed with nothing new introduced; "
              "NIR = new MEDIUM/HIGH finding introduced; FP = held-out tests pass; "
              "EBR = held-out exploit tests pass (attack blocked); Success = VRR and FP and EBR; "
              "SGG = P(pass generated tests) - P(pass held-out tests); Semgrep = no overlapping Semgrep rule after repair; "
              "Feasible@1 = first attempt has no syntax/runtime error.", ""]
    if summary["mcnemar"]:
        lines += ["## McNemar (exact), Success: C3 dual vs baseline", "", "| Baseline | C3 only | Baseline only | p |", "|---|---|---|---|"]
        for m, t in summary["mcnemar"].items():
            lines.append(f"| {MODES[m]} ({m}) | {t['dual_only']} | {t['other_only']} | {t['p']:.4f} |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default=str(ROOT / "eval" / "datasets" / "seed.jsonl"))
    ap.add_argument("--modes", default="single,sast,exec,dual")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--max-retries", type=int, default=3)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--workers", type=int, default=1, help="reviews to run in parallel")
    ap.add_argument("--out", default=None)
    ap.add_argument("--semgrep", action="store_true", help="also check every patch with Semgrep (needs semgrep installed)")
    ap.add_argument("--stub", action="store_true", help="use the rule-based stub instead of Gemini (pipeline smoke test)")
    args = ap.parse_args(argv)

    if args.stub:
        config.STUB_LLM = True
    elif not config.GEMINI_API_KEY:
        print("GEMINI_API_KEY is not set (use --stub for an offline smoke test).", file=sys.stderr)
        return 2

    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    for m in modes:
        if m not in MODES:
            ap.error(f"unknown mode {m}")
    data = load_dataset(Path(args.dataset), args.limit)
    out = Path(args.out) if args.out else ROOT / "eval" / "results" / time.strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)

    jobs = [(run, m, s) for run in range(args.runs) for m in modes for s in data]
    total = len(jobs)

    def work(job):
        run, m, s = job
        row = evaluate_one(s, m, args.max_retries, args.semgrep)
        row["run"] = run
        return row

    rows: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        for done, row in enumerate(pool.map(work, jobs), 1):
            rows.append(row)
            print(f"[{done}/{total}] run={row['run']} {row['config']:<2} {row['id']:<22} verdict={row['verdict']:<11} "
                  f"vrr={row['vrr']} heldout={row['heldout_pass']} exploit={row['exploit_blocked']} attempts={row['attempts']} {row['error'][:60]}",
                  flush=True)

    with open(out / "runs.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    summary = summarise(rows, modes, args.runs)
    meta = {"dataset": Path(args.dataset).name, "n": len(data), "runs": args.runs,
            "model": "stub (no LLM)" if config.STUB_LLM else config.GEMINI_MODEL,
            "sandbox": active_backend(), "max_retries": args.max_retries}
    with open(out / "summary.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["config", "metric", "mean", "std"])
        for m, agg in summary["table"].items():
            for k, v in agg.items():
                w.writerow([MODES[m], k, "" if v is None else v[0], "" if v is None else v[1]])
    md = to_markdown(summary, meta)
    (out / "summary.md").write_text(md, encoding="utf-8")
    (out / "meta.json").write_text(json.dumps({**meta, "mcnemar": summary["mcnemar"]}, indent=2), encoding="utf-8")
    print("\n" + md)
    print(f"Results written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
