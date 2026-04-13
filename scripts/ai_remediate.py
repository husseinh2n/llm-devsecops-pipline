#!/usr/bin/env python3
"""
ai_remediate.py
───────────────
Reads Semgrep and TruffleHog JSON results, sends each finding to the
Gemini API for context-aware remediation advice, applies the patches to
the source files, and opens a GitHub Pull Request with the fixes.

Environment variables required:
  GEMINI_API_KEY  — Google AI Studio key
  GH_TOKEN        — GitHub Personal Access Token (repo + PR scope)
  GH_REPO         — owner/repo  e.g. "chain-dev/ai-devsecops-pipeline"
  BASE_BRANCH     — branch to PR into (usually "main")
"""

import json
import os
import re
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from datetime import datetime

import google.generativeai as genai
import requests

# ─── Configuration ────────────────────────────────────────────────────────────

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GH_TOKEN       = os.environ.get("GH_TOKEN", "")
GH_REPO        = os.environ.get("GH_REPO", "")
BASE_BRANCH    = os.environ.get("BASE_BRANCH", "main")

SEMGREP_FILE    = "semgrep-results.json"
TRUFFLEHOG_FILE = "trufflehog-results.json"

BRANCH_NAME = f"fix/ai-security-remediation-{int(time.time())}"

GITHUB_API = "https://api.github.com"
GH_HEADERS = {
    "Authorization": f"Bearer {GH_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

# ─── Gemini setup ─────────────────────────────────────────────────────────────

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel("gemini-1.5-flash")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def load_json_safe(path: str) -> dict | list:
    """Load a JSON file; return an empty structure on failure.

    Handles both standard JSON and NDJSON (one JSON object per line),
    which is the format TruffleHog emits.
    """
    try:
        with open(path) as f:
            text = f.read().strip()
        if not text:
            return {}
        # Try standard JSON first (Semgrep uses this)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        # Fall back to NDJSON (TruffleHog uses this)
        items = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        if items:
            return items
        print(f"[warn] No parseable JSON found in {path}")
        return {}
    except FileNotFoundError as exc:
        print(f"[warn] Could not load {path}: {exc}")
        return {}


def read_file(path: str) -> str:
    """Read source file content safely."""
    try:
        return Path(path).read_text(encoding="utf-8")
    except Exception as exc:
        print(f"[warn] Cannot read {path}: {exc}")
        return ""


def write_file(path: str, content: str) -> None:
    """Write patched content back to disk."""
    Path(path).write_text(content, encoding="utf-8")


def git(*args: str) -> str:
    """Run a git command and return stdout."""
    result = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"[git error] git {' '.join(args)}")
        print(f"  stdout: {result.stdout.strip()}")
        print(f"  stderr: {result.stderr.strip()}")
        result.check_returncode()  # raise CalledProcessError
    return result.stdout.strip()


# ─── AI Remediation ───────────────────────────────────────────────────────────

SYSTEM_PROMPT = textwrap.dedent("""
    You are a senior security engineer and Python developer.
    You will be given:
      1. A description of a security vulnerability found by a static-analysis tool.
      2. The relevant source file content.

    Reply with ONLY a JSON object in the following format — no markdown fences,
    no extra text:
    {
      "patched_code": "<complete patched file content as a string>",
      "explanation":  "<one-paragraph plain-English explanation of the fix>"
    }

    Rules:
    - Fix ALL instances of the reported vulnerability category in the file.
    - Preserve formatting, comments, and unrelated logic exactly.
    - For SQL injection: use parameterised queries with ? placeholders.
    - For command injection: use subprocess.run() with a list, shell=False.
    - For eval(): replace with ast.literal_eval() or raise ValueError if the
      expression is non-trivial.
    - For pickle.loads(): replace with json.loads() and update the writer side.
    - For MD5 passwords: replace with hashlib.sha256() + salt, or note that
      bcrypt should be used in production.
    - For hardcoded secrets: replace with os.environ.get('VAR_NAME') calls.
    - Do NOT break the Flask routes or function signatures.
""").strip()


def ask_gemini(vuln_description: str, file_content: str) -> tuple[str, str]:
    """
    Send vulnerability + source to Gemini; return (patched_code, explanation).
    """
    prompt = (
        f"Vulnerability description:\n{vuln_description}\n\n"
        f"Source file:\n```python\n{file_content}\n```"
    )
    try:
        response = model.generate_content(
            [SYSTEM_PROMPT, prompt],
            generation_config=genai.types.GenerationConfig(
                temperature=0.1,
                max_output_tokens=8192,
            ),
        )
        raw = response.text.strip()
        # Strip accidental markdown fences
        raw = re.sub(r"^```json\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
        data = json.loads(raw)
        return data["patched_code"], data["explanation"]
    except Exception as exc:
        print(f"[error] Gemini call failed: {exc}")
        return file_content, f"Gemini call failed: {exc}"


# ─── Findings Parsing ─────────────────────────────────────────────────────────

def parse_semgrep(results: dict) -> list[dict]:
    """
    Return a list of findings:
      { file, line, rule_id, severity, message }
    """
    findings = []
    for r in results.get("results", []):
        findings.append(
            {
                "tool":     "semgrep",
                "file":     r["path"],
                "line":     r["start"]["line"],
                "rule_id":  r["check_id"],
                "severity": r.get("extra", {}).get("severity", "INFO"),
                "message":  r.get("extra", {}).get("message", ""),
            }
        )
    return findings


def parse_trufflehog(raw: dict | list) -> list[dict]:
    """
    TruffleHog outputs one JSON object per line (NDJSON).
    We already loaded the whole file, so handle both list and dict forms.
    """
    rows = raw if isinstance(raw, list) else [raw]
    findings = []
    for r in rows:
        if not r:
            continue
        source = r.get("SourceMetadata", {}).get("Data", {})
        file_path = (
            source.get("Filesystem", {}).get("file")
            or source.get("Git", {}).get("file")
            or "unknown"
        )
        findings.append(
            {
                "tool":        "trufflehog",
                "file":        file_path,
                "rule_id":     r.get("DetectorName", "secret"),
                "severity":    "ERROR",
                "message":     (
                    f"Secret detected — detector: {r.get('DetectorName')}. "
                    f"Move to environment variable."
                ),
            }
        )
    return findings


# ─── GitHub PR ────────────────────────────────────────────────────────────────

def create_pr(pr_body: str) -> str:
    """Create a pull request and return its URL."""
    payload = {
        "title": f"fix(security): AI-generated remediation [{datetime.utcnow().strftime('%Y-%m-%d')}]",
        "body":  pr_body,
        "head":  BRANCH_NAME,
        "base":  BASE_BRANCH,
        "draft": False,
    }
    resp = requests.post(
        f"{GITHUB_API}/repos/{GH_REPO}/pulls",
        headers=GH_HEADERS,
        json=payload,
        timeout=30,
    )
    if not resp.ok:
        print(f"[error] PR creation failed ({resp.status_code}): {resp.text}")
        resp.raise_for_status()
    return resp.json()["html_url"]


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    if not GEMINI_API_KEY:
        sys.exit("[fatal] GEMINI_API_KEY is not set.")
    if not GH_TOKEN or not GH_REPO:
        sys.exit("[fatal] GH_TOKEN and GH_REPO must be set.")

    # 1. Load findings
    semgrep_raw    = load_json_safe(SEMGREP_FILE)
    trufflehog_raw = load_json_safe(TRUFFLEHOG_FILE)

    all_findings = parse_semgrep(semgrep_raw) + parse_trufflehog(trufflehog_raw)

    if not all_findings:
        print("✅  No findings to remediate.")
        return

    print(f"Found {len(all_findings)} finding(s). Starting AI remediation…")

    # 2. Group findings by file
    by_file: dict[str, list[dict]] = {}
    for f in all_findings:
        by_file.setdefault(f["file"], []).append(f)

    # 3. Checkout a new remediation branch
    # (git identity & remote URL are configured by the workflow before this runs)
    git("checkout", "-b", BRANCH_NAME)

    pr_sections: list[str] = []

    for file_path, findings in by_file.items():
        if not Path(file_path).exists():
            print(f"[skip] {file_path} not found on disk.")
            continue

        original = read_file(file_path)
        if not original.strip():
            continue

        # Build a combined description for all findings in this file
        vuln_description = "\n".join(
            f"- [{f['tool'].upper()} / {f['rule_id']}] "
            f"Line {f.get('line', '?')}: {f['message']}"
            for f in findings
        )

        print(f"\n[ai] Remediating {file_path}…")
        patched, explanation = ask_gemini(vuln_description, original)

        if patched == original:
            print(f"  [skip] Gemini returned identical content for {file_path}.")
            continue

        write_file(file_path, patched)

        git("add", file_path)

        pr_sections.append(
            f"### `{file_path}`\n\n{explanation}\n\n"
            + "**Findings addressed:**\n"
            + "\n".join(f"- {f['rule_id']}: {f['message']}" for f in findings)
        )

        # Polite rate-limit buffer between API calls
        time.sleep(1)

    if not pr_sections:
        print("No files were modified — nothing to PR.")
        return

    # 4. Commit
    git(
        "commit", "-m",
        "fix(security): apply AI-generated security remediations\n\n"
        "Automated fixes generated by Gemini via the DevSecOps pipeline.\n"
        "Review each change carefully before merging.",
    )
    print(f"[git] Pushing branch {BRANCH_NAME} to origin…")
    git("push", "origin", BRANCH_NAME)

    # 5. Open PR
    pr_body = textwrap.dedent(f"""
        ## 🤖 AI Security Remediation

        This pull request was automatically generated by the **AI-Augmented
        DevSecOps Pipeline** after detecting security findings on `{BASE_BRANCH}`.

        **Tools that flagged issues:** Semgrep · TruffleHog  
        **Remediation model:** Gemini 1.5 Flash  
        **Generated at:** {datetime.utcnow().isoformat()} UTC

        ---

        {chr(10).join(pr_sections)}

        ---

        > ⚠️ **Review required.** AI-generated patches resolve the flagged
        > patterns but should be verified by a human before merging to
        > production. Check for logic correctness, test coverage, and any
        > indirect effects on dependent code.
    """).strip()

    pr_url = create_pr(pr_body)
    print(f"\n✅  Pull Request opened: {pr_url}")


if __name__ == "__main__":
    main()
