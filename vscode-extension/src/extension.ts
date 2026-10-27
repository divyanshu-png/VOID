import * as vscode from "vscode";
import axios from "axios";

export function activate(context: vscode.ExtensionContext) {
  const disposable = vscode.commands.registerCommand(
    "void.auditCurrentFile",
    async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("VOID: Open a file to audit.");
        return;
      }

      const document = editor.document;
      const code = document.getText();

      if (!code.trim()) {
        vscode.window.showWarningMessage("VOID: The file is empty.");
        return;
      }

      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title:
            "VOID: Running Agentic Security Review & Sandbox Verification...",
          cancellable: false,
        },
        async () => {
          try {
            const response = await axios.post(
              "http://localhost:8000/api/v1/audit",
              {
                code: code,
                language: document.languageId,
              },
              { timeout: 60000 },
            );

            const data = response.data;

            if (data.status === "SUCCESS" && data.refactored_code) {
              const originalDoc = document.uri;
              const refactoredDoc = vscode.Uri.parse(
                `untitled:REFACTORED_${document.fileName}`,
              );

              const edit = new vscode.WorkspaceEdit();
              edit.insert(
                refactoredDoc,
                new vscode.Position(0, 0),
                data.refactored_code,
              );
              await vscode.workspace.applyEdit(edit);

              await vscode.commands.executeCommand(
                "vscode.diff",
                originalDoc,
                refactoredDoc,
                `VOID Review: ${document.fileName} (Tests: ${data.test_status})`,
              );

              vscode.window.showInformationMessage(
                `Audit Complete! Sandbox Tests: ${data.test_status} (${data.retries} retries).`,
              );
            } else {
              vscode.window.showErrorMessage(
                "VOID: Review completed without refactored suggestions.",
              );
            }
          } catch (err: any) {
            vscode.window.showErrorMessage(
              `VOID Error: ${err.message || "Failed to connect to backend."}`,
            );
          }
        },
      );
    },
  );

  context.subscriptions.push(disposable);
}

export function deactivate() {}
