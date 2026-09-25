# VOID

An autonomous CODE reviwer and security audit agent, that refactors the security layer and vulnerabilities fatal for real world deployments.

## 1. Project Metadata & Revision Index

Project Codename: VOID
Full Title: Autonomous Code Reviewer & Security Auditing Agent

Primary Tech Stack: Python 3.11+, LangChain / LangGraph, Tree-sitter / AST Parser, ChromaDB / FAISS, Semgrep, FastAPI

  <!-- Revision Index Section -->
  <table>
    <thead>
      <tr>
        <th style="width: 20%;">Revision</th>
        <th style="width: 25%;">Date</th>
        <th style="width: 55%;">Target Milestone / Scope</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td class="empty-cell">v0</td>
        <td>25/09/2026</td>
        <td>Initialised the Project Directory Structure</td>
      </tr>
      <tr>
        <td class="empty-cell"></td>
        <td></td>
        <td></td>
      </tr>
      <tr>
        <td class="empty-cell"></td>
        <td></td>
        <td></td>
      </tr>
      <tr>
        <td class="empty-cell"></td>
        <td></td>
        <td></td>
      </tr>
    </tbody>
  </table>

</body>
</html>

## 2. System Architecture & Threat Model BaselineTarget Workflows:

    1. Autonomous PR reviews, patch diff analysis, zero-day & CWE pattern identification, auto-generated remediation PRs.
    2. Agent Topology: Multi-Agent Pipeline (Parser/Triage Agent $\to$ Security & CWE Auditor $\to$ Logic/Performance Reviewer $\to$ Deduplication & Verification Agent).
    3. Target Vulnerability Taxonomy: OWASP Top 10, CWE/SANS Top 25 (e.g., CWE-89 SQLi, CWE-79 XSS, CWE-798 Hardcoded Secrets, CWE-22 Path Traversal).

## 3. Production Directory Structure:

```plaintext
VOID/
├── backend/
│ ├── app/
│ │ ├── api/
│ │ │ ├── **init**.py
│ │ │ ├── routes.py # FastAPI endpoints (/audit, /refactor)
│ │ │ └── schemas.py # Pydantic request/response models
│ │ ├── core/
│ │ │ ├── config.py # Azure AI Foundry & environment settings
│ │ │ └── sandbox.py # Docker/isolated test execution runner
│ │ ├── graph/
│ │ │ ├── **init**.py
│ │ │ ├── state.py # LangGraph TypedDict state schema
│ │ │ ├── nodes.py # Agent nodes (AST, Security, Refactor, REPL)
│ │ │ ├── edges.py # Conditional routing & retry evaluation
│ │ │ └── workflow.py # StateGraph compilation
│ │ ├── tools/
│ │ │ ├── ast_parser.py # Tree-sitter / AST symbol analysis
│ │ │ ├── sast_scanner.py # Semgrep & Bandit CLI wrapper
│ │ │ └── pypi_validator.py # Slopsquatting / package registry checks
│ │ └── main.py # FastAPI app entrypoint
│ ├── tests/
│ │ └── test_graph.py # Unit tests for agent state transitions
│ ├── Dockerfile # Production container for Azure Container Apps
│ └── requirements.txt
│
├── vscode-extension/
│ ├── src/
│ │ ├── extension.ts # Extension activation and commands
│ │ ├── apiClient.ts # HTTP client calling Azure backend
│ │ └── diffViewer.ts # Native VS Code diff viewer triggers
│ ├── package.json # Extension configuration and commands
│ ├── tsconfig.json
│ └── README.md
│
├── dashboard/ # Optional: Streamlit demo for project viva
│ └── streamlit_app.py
├── .env.example
└── README.md
```

# void README

This is the README for your extension "void". After writing up a brief description, we recommend including the following sections.

## Features

Describe specific features of your extension including screenshots of your extension in action. Image paths are relative to this README file.

For example if there is an image subfolder under your extension project workspace:

\!\[feature X\]\(images/feature-x.png\)

> Tip: Many popular extensions utilize animations. This is an excellent way to show off your extension! We recommend short, focused animations that are easy to follow.

## Requirements

If you have any requirements or dependencies, add a section describing those and how to install and configure them.

## Extension Settings

Include if your extension adds any VS Code settings through the `contributes.configuration` extension point.

For example:

This extension contributes the following settings:

- `myExtension.enable`: Enable/disable this extension.
- `myExtension.thing`: Set to `blah` to do something.

## Known Issues

Calling out known issues can help limit users opening duplicate issues against your extension.

## Release Notes

Users appreciate release notes as you update your extension.

### 1.0.0

Initial release of ...

### 1.0.1

Fixed issue #.

### 1.1.0

Added features X, Y, and Z.

---
