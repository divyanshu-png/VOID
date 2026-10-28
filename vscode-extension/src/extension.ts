import * as vscode from "vscode";
import { auditStream, backendUrl, dashboardUrl, health, scan, type AuditResult, type ScanResult } from "./client";

const SOURCE = "VOID";
const SCHEME = "void-patch";
const patches = new Map<string, string>(); // virtual documents holding proposed patches

let diagnostics: vscode.DiagnosticCollection;
let output: vscode.OutputChannel;
let status: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext) {
  diagnostics = vscode.languages.createDiagnosticCollection("void");
  output = vscode.window.createOutputChannel("VOID");
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  status.command = "void.openDashboard";
  context.subscriptions.push(diagnostics, output, status);

  context.subscriptions.push(
    vscode.workspace.registerTextDocumentContentProvider(SCHEME, {
      provideTextDocumentContent: (uri) => patches.get(uri.toString()) ?? "",
    }),
    vscode.languages.registerCodeActionsProvider({ language: "python" }, new FixProvider(), {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    }),
    vscode.commands.registerCommand("void.fixAtCursor", (uri?: vscode.Uri, line?: number) => fix(uri, line, true)),
    vscode.commands.registerCommand("void.auditCurrentFile", () => fix(undefined, undefined, false)),
    vscode.commands.registerCommand("void.scanFile", () => {
      const doc = vscode.window.activeTextEditor?.document;
      if (doc) runScan(doc, true);
    }),
    vscode.commands.registerCommand("void.openDashboard", () => vscode.env.openExternal(vscode.Uri.parse(dashboardUrl() + "/"))),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (doc.languageId === "python" && vscode.workspace.getConfiguration("void").get("scanOnSave")) runScan(doc, false);
    }),
    vscode.workspace.onDidOpenTextDocument((doc) => {
      if (doc.languageId === "python" && doc.uri.scheme === "file" && vscode.workspace.getConfiguration("void").get("scanOnSave"))
        runScan(doc, false);
    }),
    vscode.workspace.onDidCloseTextDocument((doc) => diagnostics.delete(doc.uri)),
  );

  refreshStatus();
  const timer = setInterval(refreshStatus, 30000);
  context.subscriptions.push({ dispose: () => clearInterval(timer) });
  const active = vscode.window.activeTextEditor?.document;
  if (active?.languageId === "python") runScan(active, false);
}

export function deactivate() {}

async function refreshStatus() {
  const h = await health();
  if (!h) {
    status.text = "$(circle-slash) VOID offline";
    status.tooltip = `No VOID backend at ${backendUrl()}. Start it with: cd frontend && npm run dev`;
  } else {
    const llm = h.stub_llm ? "stub LLM" : h.api_key_configured ? h.model : "no API key";
    status.text = "$(shield) VOID";
    status.tooltip = `VOID backend online · ${llm} · sandbox: ${h.sandbox}. Click to open the dashboard.`;
  }
  status.show();
}

// --------------------------------------------------------------------------- diagnostics
function severityOf(s: string): vscode.DiagnosticSeverity {
  if (s === "HIGH") return vscode.DiagnosticSeverity.Error;
  if (s === "MEDIUM") return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}

async function runScan(doc: vscode.TextDocument, announce: boolean) {
  let res: ScanResult;
  try {
    res = await scan(doc.getText());
  } catch (e) {
    if (announce) vscode.window.showErrorMessage(`VOID scan failed: ${(e as Error).message}`);
    return;
  }
  const diags: vscode.Diagnostic[] = [];
  for (const f of res.findings) {
    const line = Math.max(0, (f.line_number || 1) - 1);
    if (line >= doc.lineCount) continue;
    const text = doc.lineAt(line);
    const range = new vscode.Range(line, text.firstNonWhitespaceCharacterIndex, line, text.text.length);
    const d = new vscode.Diagnostic(range, `${f.issue_text}${f.cwe ? ` (CWE-${f.cwe})` : ""}`, severityOf(f.severity));
    d.source = SOURCE;
    d.code = f.test_id;
    diags.push(d);
  }
  for (const p of res.packages.filter((x) => x.status === "not_found" || x.status === "suspicious")) {
    const root = p.import.split(".")[0];
    const re = new RegExp(`^\\s*(import|from)\\s+${root.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`);
    for (let i = 0; i < doc.lineCount; i++) {
      if (re.test(doc.lineAt(i).text)) {
        const d = new vscode.Diagnostic(
          doc.lineAt(i).range,
          `Package '${p.package}': ${p.reasons.join("; ")}`,
          p.status === "not_found" ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning,
        );
        d.source = SOURCE;
        d.code = p.status === "not_found" ? "hallucinated-package" : "suspicious-package";
        diags.push(d);
        break;
      }
    }
  }
  diagnostics.set(doc.uri, diags);
  if (announce) vscode.window.showInformationMessage(`VOID: ${diags.length} issue(s) found.`);
}

class FixProvider implements vscode.CodeActionProvider {
  provideCodeActions(doc: vscode.TextDocument, _range: vscode.Range, ctx: vscode.CodeActionContext) {
    return ctx.diagnostics
      .filter((d) => d.source === SOURCE && typeof d.code === "string" && d.code.startsWith("B"))
      .slice(0, 1)
      .map((d) => {
        const action = new vscode.CodeAction("Fix with VOID (verified repair)", vscode.CodeActionKind.QuickFix);
        action.diagnostics = [d];
        action.isPreferred = true;
        action.command = { command: "void.fixAtCursor", title: "Fix with VOID", arguments: [doc.uri, d.range.start.line + 1] };
        return action;
      });
  }
}

// --------------------------------------------------------------------------- repair
async function fix(uri: vscode.Uri | undefined, line: number | undefined, focused: boolean) {
  const editor = vscode.window.activeTextEditor;
  const doc = uri ? await vscode.workspace.openTextDocument(uri) : editor?.document;
  if (!doc) {
    vscode.window.showWarningMessage("VOID: open a Python file first.");
    return;
  }
  if (!doc.getText().trim()) {
    vscode.window.showWarningMessage("VOID: the file is empty.");
    return;
  }
  const focusLine = focused ? (line ?? (editor && editor.document === doc ? editor.selection.active.line + 1 : undefined)) : undefined;
  const version = doc.version;
  const original = doc.getText();

  let result: AuditResult;
  try {
    result = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: "VOID", cancellable: true },
      (progress, token) => {
        progress.report({ message: "Pre-checks: AST, Bandit, PyPI…" });
        return auditStream(original, focusLine, (m) => progress.report({ message: m }), token);
      },
    );
  } catch (e) {
    const msg = (e as Error).name === "AbortError" ? "cancelled or timed out" : (e as Error).message;
    vscode.window.showErrorMessage(`VOID: ${msg}`);
    return;
  }

  log(doc, result);
  if (result.verdict === "clean") {
    vscode.window.showInformationMessage("VOID: no exploitable issues found, so nothing to fix.");
    return;
  }
  if (result.verdict === "invalid_input") {
    vscode.window.showErrorMessage("VOID: the code does not parse.");
    return;
  }
  const proposed = result.merged_file ?? result.refactored_code;
  if (!proposed || proposed === original) {
    vscode.window.showWarningMessage("VOID: no patch was produced. See the VOID output panel.");
    return;
  }

  const name = doc.uri.path.split("/").pop() || "file.py";
  const patchUri = vscode.Uri.parse(`${SCHEME}:/${encodeURIComponent(name)}?${Date.now()}`);
  patches.set(patchUri.toString(), proposed);
  const verdict = result.verdict.toUpperCase();
  const attempts = result.attempts?.length ?? result.retries ?? 0;
  await vscode.commands.executeCommand("vscode.diff", doc.uri, patchUri, `VOID: ${name} ↔ patch (${verdict} · ${attempts} attempt${attempts === 1 ? "" : "s"})`);

  const verified = result.verdict === "verified";
  const choice = await vscode.window.showInformationMessage(
    verified
      ? `VOID: VERIFIED patch. Bandit re-scan is clean and generated tests pass (${attempts} attempt(s)).`
      : `VOID: UNVERIFIED patch. At least one oracle rejected it (Bandit: ${result.sast_status}, tests: ${result.test_status}). Review carefully.`,
    { modal: false },
    "Apply patch",
    "Show details",
  );
  if (choice === "Show details") output.show(true);
  if (choice === "Apply patch") {
    if (doc.version !== version) {
      vscode.window.showWarningMessage("VOID: the file changed since the review started; not applying. Run VOID again.");
      return;
    }
    const edit = new vscode.WorkspaceEdit();
    edit.replace(doc.uri, new vscode.Range(doc.positionAt(0), doc.positionAt(original.length)), proposed);
    await vscode.workspace.applyEdit(edit);
    vscode.window.showInformationMessage("VOID: patch applied. Save to re-scan.");
  }
}

function log(doc: vscode.TextDocument, r: AuditResult) {
  output.appendLine(`\n=== VOID review: ${doc.uri.fsPath} · ${new Date().toLocaleString()}`);
  output.appendLine(`verdict: ${r.verdict} · mode: ${r.oracle_mode} · model: ${r.usage?.model ?? "?"} · calls: ${r.usage?.llm_calls ?? "?"}`);
  if (r.focus) output.appendLine(`focus: ${r.focus.kind} ${r.focus.name} (lines ${r.focus.start_line}-${r.focus.end_line})`);
  if (r.audit?.summary) output.appendLine(`summary: ${r.audit.summary}`);
  for (const f of r.audit?.findings ?? []) output.appendLine(`  [${f.severity}] ${f.title} (${f.cwe}) line ${f.line ?? "?"}: ${f.explanation}\n      fix: ${f.fix}`);
  for (const a of r.attempts ?? [])
    output.appendLine(
      `  attempt ${a.n}: bandit ${a.sast.passed ? "clean" : `${a.sast.remaining.length} left / ${a.sast.introduced.length} new`} · tests ${a.exec.status}${a.exec.error_kind ? ` (${a.exec.error_kind})` : ""} → ${a.accepted ? "ACCEPTED" : "rejected"}`,
    );
  if (r.replay_id) output.appendLine(`replay: ${dashboardUrl()}/#replays (id ${r.replay_id})`);
}
