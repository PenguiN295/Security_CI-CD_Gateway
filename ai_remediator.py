import json
import os
import sys
from pathlib import Path
from typing import List, Dict, Any
import time
import requests
from google import genai

SEMGREP_JSON_PATH = Path("semgrep_results.json")
CONTEXT_LINES_PADDING = 8
TARGET_SEVERITIES = {"ERROR", "WARNING"}


class SourceContextExtractor:

    @staticmethod
    def get_snippet(file_path: str, start_line: int, end_line: int) -> str:
        path = Path(file_path)
        if not path.exists():
            return "Source file unavailable."

        lines = path.read_text(encoding="utf-8").splitlines()
        total_lines = len(lines)
        window_start = max(0, start_line - 1 - CONTEXT_LINES_PADDING)
        window_end = min(total_lines, end_line + CONTEXT_LINES_PADDING)

        numbered_lines = [
            f"{idx + 1}: {lines[idx]}" for idx in range(window_start, window_end)
        ]
        return "\n".join(numbered_lines)


class LLMRemediationClient:
    def __init__(self) -> None:
        api_key = os.getenv("LLM_API_KEY")
        if not api_key:
            raise EnvironmentError("Missing LLM_API_KEY environment variable.")
        self.model = os.getenv("LLM_MODEL", "gemini-2.5-flash") 
        self.client = genai.Client(
            api_key=api_key,
            http_options={'timeout': 120.0} 
        )

    def generate_patch(self, rule_id: str, message: str, code_snippet: str) -> str:
        prompt = (
            "You are a Principal Application Security Engineer. "
            "Analyze the provided vulnerable Python snippet and SAST finding. "
            "Respond strictly in Markdown with:\n"
            "1. **Root Cause**: 1-2 terse sentences explaining the exploit vector.\n"
            "2. **Patched Code**: A drop-in secure Python replacement block.\n\n"
            f"**Rule ID**: `{rule_id}`\n"
            f"**Scanner Message**: {message}\n\n"
            f"**Vulnerable Context (with line numbers)**:\n```python\n{code_snippet}\n```"
        )

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )
            return response.text
        except Exception as e:
            return f"**Remediation Generation Failed:** {str(e)}"


class GitHubPRReporter:
    @staticmethod
    def post_comment(markdown_body: str) -> None:
        token = os.getenv("GITHUB_TOKEN")
        repo = os.getenv("GITHUB_REPOSITORY")
        pr_number = os.getenv("PR_NUMBER")

        if not all([token, repo, pr_number]):
            print("\n[INFO] Local execution detected (No GitHub CI env vars). Outputting report to stdout:\n")
            print(markdown_body)
            return

        url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        resp = requests.post(url, headers=headers, json={"body": markdown_body}, timeout=15)
        resp.raise_for_status()
        print(f"[SUCCESS] Posted AI remediation report to PR #{pr_number}.")


def parse_findings(json_path: Path) -> List[Dict[str, Any]]:
    if not json_path.exists():
        print(f"[ERROR] {json_path} not found. Run Semgrep first.")
        sys.exit(1)

    raw_data = json.loads(json_path.read_text(encoding="utf-8"))
    findings = []

    for item in raw_data.get("results", []):
        severity = item.get("extra", {}).get("severity", "INFO")
        if severity in TARGET_SEVERITIES:
            findings.append({
                "rule_id": item.get("check_id"),
                "path": item.get("path"),
                "start_line": item.get("start", {}).get("line", 1),
                "end_line": item.get("end", {}).get("line", 1),
                "severity": severity,
                "message": item.get("extra", {}).get("message", ""),
            })
    return findings


def main() -> None:
    findings = parse_findings(SEMGREP_JSON_PATH)
    if not findings:
        print("[PASS] Zero actionable vulnerabilities detected.")
        sys.exit(0)

    print(f"[ALERT] Processing {len(findings)} high-priority findings via LLM...")
    llm_client = LLMRemediationClient()

    report_sections = [
        "## Automated AppSec Gate: Actionable Vulnerabilities Detected",
        f"The CI/CD pipeline intercepted **{len(findings)}** security flaw(s). Build blocked until remediated.\n",
    ]
    for idx, f in enumerate(findings, 1):
        snippet = SourceContextExtractor.get_snippet(f["path"], f["start_line"], f["end_line"])
        print(f"[{idx}/{len(findings)}] Requesting patch for {f['rule_id']}...")
        
        remediation = llm_client.generate_patch(f["rule_id"], f["message"], snippet)
        
        print(f"[{idx}/{len(findings)}] Patch received successfully.")
        
        section = (
            f"### {idx}. `{f['rule_id']}` ({f['severity']})\n"
            f"**Location:** `{f['path']}` (Lines {f['start_line']}–{f['end_line']})\n\n"
            f"{remediation}\n\n---"
        )
        report_sections.append(section)
        time.sleep(3)

    final_markdown = "\n".join(report_sections)
    GitHubPRReporter.post_comment(final_markdown)
    sys.exit(1)


if __name__ == "__main__":
    main()