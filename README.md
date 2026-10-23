# Security_CI-CD_Gateway
## Architecture Overview
A continuous integration gateway enforcing Shift-Left security principles via automated Static Application Security Testing (SAST) and Software Composition Analysis (SCA). The pipeline intercepts vulnerable pull requests, executes a custom AST (Abstract Syntax Tree) ruleset, and leverages an LLM integration to inject context-aware remediation code directly into the developer's PR thread before merge.

## Pipeline Execution Flow
1. **SCA & Container Scan**: `Trivy` scans `requirements.txt` and the `Dockerfile` to block CRITICAL and HIGH CVEs in base images and third-party dependencies.
2. **SAST & Custom Rules**: `Semgrep` parses the Python source code against community security standards (OWASP Top 10) and custom business-logic rules.
3. **AI Remediation Engine**: A custom Python adapter parses the SAST JSON output, extracts the vulnerable code window, queries the Google Gemini API for secure drop-in replacements, and publishes a consolidated Markdown review to the GitHub PR.
4. **Policy Enforcement Point (PEP)**: The CI runner forcefully exits with Code 1 upon detecting actionable vulnerabilities, physically blocking the PR merge until the developer commits the secure patch.

## Key Engineering Decisions

* **Custom AST Rule Engineering (IDOR)**: Extended native Semgrep rulesets with custom YAML definitions to detect business-logic IDOR (Broken Access Control) flaws (`flask-idor-missing-owner-check`). Standard out-of-the-box scanners natively fail to detect missing authorization boundaries; this rule enforces database queries to strictly check `owner_id` constraints.
* **$O(1)$ Batch Inference & Deduplication**: Engineered the LLM parser to deduplicate overlapping AST violations by exact line number and batch all findings into a single API prompt. This architectural decision mitigates $O(N)$ API exhaustion, prevents HTTP 429 rate-limiting from the LLM provider, and reduces CI pipeline execution time by over 80%.
* **AST Context Windowing**: Designed an extraction mechanism to pull $\pm 8$ lines of surrounding code context around the specific AST sink. Supplying the LLM with the full function signature and variable scope ensures the generation of accurate, drop-in function replacements rather than hallucinated syntax.

## Automated PR Interception (Visual Proof)
![PR Review Demo](./assets/pr-remediation-screenshot.png)