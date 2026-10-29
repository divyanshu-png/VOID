# VOID for VS Code

Security findings as you save, and **verified** one-click fixes.

* **On save**: Bandit + package checks (no AI, instant). Issues show as squiggles; hallucinated or suspicious imports are flagged too.
* **Quick fix**: hover a VOID squiggle → *Fix with VOID*. Only the surrounding function/class is sent to the agent.
* **Every patch is checked by two oracles**: a Bandit re-scan and the generated tests run in a sandbox. You see VERIFIED or UNVERIFIED before applying.
* **Commands**: `VOID: Fix Vulnerability at Cursor`, `VOID: Audit & Refactor Whole File`, `VOID: Scan File`, `VOID: Open Dashboard`.

Requires the VOID backend running (default `http://localhost:8000`, configurable in Settings → VOID).
