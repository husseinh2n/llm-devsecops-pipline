# AI-Augmented DevSecOps Pipeline

> **GitHub Actions · Docker · Semgrep · TruffleHog · Python · Gemini API**

A fully automated CI/CD security pipeline that scans every push for
vulnerabilities, sends findings to an LLM for contextual analysis, and opens
a pull request with AI-generated remediation code — reducing manual triage
time to zero.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Repository Structure](#repository-structure)
4. [The Intentional Vulnerabilities](#the-intentional-vulnerabilities)
5. [Pipeline Walkthrough](#pipeline-walkthrough)
   - [Stage 1 — Static Analysis (Semgrep)](#stage-1--static-analysis-semgrep)
   - [Stage 2 — Secret Scanning (TruffleHog)](#stage-2--secret-scanning-trufflehog)
   - [Stage 3 — AI Remediation (Gemini)](#stage-3--ai-remediation-gemini)
6. [Local Setup](#local-setup)
7. [GitHub Secrets Required](#github-secrets-required)
8. [How the AI Remediation Works](#how-the-ai-remediation-works)
9. [Sample Findings & Fixes](#sample-findings--fixes)
10. [Tech Stack](#tech-stack)

---

## Overview

Security review is a bottleneck in most development workflows. Developers push
code, a security tool flags something two days later, a ticket is created, and
eventually someone finds the time to fix it. This project eliminates that gap
entirely.

Every `git push` triggers a three-stage pipeline:

1. **Semgrep** runs custom SAST rules to catch injection flaws, weak crypto, and
   dangerous API usage.
2. **TruffleHog** scans the commit history for leaked secrets, tokens, and
   credentials.
3. If findings exist, **`ai_remediate.py`** collects the results, sends the
   affected source code to the **Gemini API** with a structured prompt, receives
   a patched version of each file, commits the patches to a new branch, and
   opens a **GitHub Pull Request** — automatically.

The demo application is a small Flask task-manager REST API that ships with
**seven deliberate vulnerabilities** so the pipeline has something real to find
and fix.

---

## Architecture

```
Developer push
      │
      ▼
┌─────────────────────────────────────────────────────┐
│               GitHub Actions Runner                  │
│                                                     │
│  ┌──────────────┐   ┌──────────────────────────┐   │
│  │   Semgrep    │   │       TruffleHog          │   │
│  │  (SAST scan) │   │   (secret / cred scan)    │   │
│  └──────┬───────┘   └─────────────┬─────────────┘   │
│         │  semgrep-results.json   │ trufflehog-results.json
│         └──────────────┬──────────┘                  │
│                        │                             │
│              ┌─────────▼──────────┐                  │
│              │  ai_remediate.py   │                  │
│              │  (Python script)   │                  │
│              └─────────┬──────────┘                  │
│                        │  prompt: vuln desc + code   │
│                        ▼                             │
│              ┌──────────────────┐                    │
│              │   Gemini API     │                    │
│              │ (1.5 Flash model)│                    │
│              └────────┬─────────┘                    │
│                       │  patched_code + explanation  │
│                       ▼                              │
│              git commit → git push                   │
│                       │                              │
│                       ▼                              │
│              GitHub Pull Request  ◄── human review   │
└─────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
ai-devsecops-pipeline/
├── .github/
│   └── workflows/
│       ├── security-scan.yml   # Main pipeline: Semgrep + TruffleHog + AI PR
│       └── docker-build.yml    # Build validation and unit tests
│
├── .semgrep/
│   └── rules.yml               # Custom SAST rules targeting the demo app
│
├── app/
│   ├── __init__.py
│   ├── main.py                 # Flask app — contains intentional vulnerabilities
│   ├── config.py               # Hardcoded secrets (TruffleHog bait)
│   └── utils.py                # Utility functions with injection flaws
│
├── scripts/
│   └── ai_remediate.py         # AI remediation orchestrator
│
├── tests/
│   └── test_app.py             # Pytest suite
│
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## The Intentional Vulnerabilities

The demo application contains the following deliberately broken code.
These are the exact findings the pipeline is built to detect and fix.

| # | File | Vulnerability | CWE | Tool |
|---|------|--------------|-----|------|
| 1 | `app/main.py` | SQL Injection — f-string in `get_tasks()` | CWE-89 | Semgrep |
| 2 | `app/main.py` | SQL Injection — concatenation in `search_tasks()` | CWE-89 | Semgrep |
| 3 | `app/main.py` | Command Injection — `os.system()` in `export_tasks()` | CWE-78 | Semgrep |
| 4 | `app/main.py` | Command Injection — `subprocess` with `shell=True` in `admin_run()` | CWE-78 | Semgrep |
| 5 | `app/main.py` | Code Injection — `eval()` in `calculate()` | CWE-94 | Semgrep |
| 6 | `app/main.py` | Insecure Deserialization — `pickle.loads()` in `import_tasks()` | CWE-502 | Semgrep |
| 7 | `app/main.py` | Weak Hashing — `hashlib.md5()` for passwords | CWE-327 | Semgrep |
| 8 | `app/utils.py` | Command Injection — `os.popen()` | CWE-78 | Semgrep |
| 9 | `app/utils.py` | Command Injection — `subprocess.call(shell=True)` | CWE-78 | Semgrep |
| 10 | `app/config.py` | Hardcoded API token, DB password, AWS credentials | CWE-798 | TruffleHog |

---

## Pipeline Walkthrough

### Stage 1 — Static Analysis (Semgrep)

```yaml
# .github/workflows/security-scan.yml  (semgrep job)
semgrep \
  --config .semgrep/rules.yml \
  --config "p/python" \
  --json \
  --output semgrep-results.json \
  .
```

- Runs **custom rules** (`.semgrep/rules.yml`) alongside the official Python
  rule pack.
- Outputs a structured JSON report that is uploaded as a workflow artifact.
- A small inline Python script counts `ERROR`-severity findings and **exits
  non-zero** (blocking deployment) if any are found.

**Example output:**

```
[sql-injection-fstring] app/main.py:52 — SQL Injection: user-controlled variable
'category' is directly interpolated into a SQL query.

[code-injection-eval] app/main.py:98 — Code Injection: 'eval()' executes
arbitrary Python. Use ast.literal_eval() or a math parser library.

Total findings : 9
Critical (ERROR): 7
❌  Critical findings block this deployment.
```

---

### Stage 2 — Secret Scanning (TruffleHog)

```bash
trufflehog filesystem . --json --no-update > trufflehog-results.json
```

- Scans the **full filesystem** of the checked-out repository.
- Detects high-entropy strings and pattern-matched credentials (AWS keys, GitHub
  tokens, connection strings).
- Blocks the workflow if any findings are written to the output file.

**Example findings in `app/config.py`:**

```python
API_TOKEN        = "ghp_1234567890abcdefABCDEF1234567890abcd"   # GitHub token
AWS_ACCESS_KEY   = "AKIAIOSFODNN7EXAMPLE"                        # AWS access key
DATABASE_URL     = "postgresql://admin:SuperSecret123!@db..."    # DB password
```

---

### Stage 3 — AI Remediation (Gemini)

The `ai-remediation` job runs **even when the scan jobs fail** (i.e., when
findings exist), using `if: always()`. It:

1. Downloads both JSON artifacts from the previous jobs.
2. Groups findings by source file.
3. For each affected file, sends the following to **Gemini 1.5 Flash**:
   - A structured description of every finding in that file.
   - The complete source code.
4. Gemini replies with `{ "patched_code": "...", "explanation": "..." }`.
5. The script writes the patch, commits it to a new branch, and pushes.
6. A GitHub Pull Request is opened via the REST API with full context.

---

## Local Setup

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- A [Google AI Studio](https://aistudio.google.com/) API key (free tier works)

### Run the app locally

```bash
git clone https://github.com/<you>/ai-devsecops-pipeline
cd ai-devsecops-pipeline

# Option A — Docker Compose
docker compose up --build

# Option B — plain Python
pip install -r requirements.txt
python -m app.main
```

The API is available at `http://localhost:5000`.

### Run the tests

```bash
pip install pytest flask
pytest tests/ -v
```

### Run Semgrep locally

```bash
pip install semgrep
semgrep --config .semgrep/rules.yml --config "p/python" .
```

### Run the AI remediation script locally

```bash
export GEMINI_API_KEY="your-key"
export GH_TOKEN="your-pat"
export GH_REPO="you/ai-devsecops-pipeline"
export BASE_BRANCH="main"

python scripts/ai_remediate.py
```

---

## GitHub Secrets Required

Navigate to **Settings → Secrets and Variables → Actions** in the repository
and add the following:

| Secret | Description |
|--------|-------------|
| `GEMINI_API_KEY` | Google AI Studio API key for the Gemini model |
| `GH_PAT` | GitHub Personal Access Token with `repo` + `pull_requests: write` scopes |

---

## How the AI Remediation Works

The script uses a carefully structured system prompt to constrain the model's
output to a predictable, parseable JSON format:

```
You are a senior security engineer and Python developer.
Reply with ONLY a JSON object:
{
  "patched_code": "<complete patched file>",
  "explanation":  "<one-paragraph explanation>"
}
Rules:
- Fix ALL instances of the reported vulnerability in the file.
- For SQL injection: use parameterised queries with ? placeholders.
- For command injection: subprocess.run() with a list, shell=False.
- For eval(): replace with ast.literal_eval() or raise ValueError.
- For pickle.loads(): replace with json.loads().
- For MD5 passwords: replace with hashlib.sha256() + salt.
- For hardcoded secrets: replace with os.environ.get('VAR') calls.
```

The low temperature (`0.1`) keeps the output deterministic and
focused on code, not prose. The full file is always sent so the model has
complete context and can fix every instance of a class of vulnerability in
one pass, rather than patching line-by-line.

---

## Sample Findings & Fixes

### SQL Injection `app/main.py:52`

**Before (vulnerable):**
```python
query = f"SELECT * FROM tasks WHERE category = '{category}'"
tasks = conn.execute(query).fetchall()
```

**After (AI-generated fix):**
```python
tasks = conn.execute(
    "SELECT * FROM tasks WHERE category = ?", (category,)
).fetchall()
```

---

### Command Injection `app/main.py:98`

**Before (vulnerable):**
```python
os.system(f"echo 'Exporting tasks as {fmt}' > /tmp/{filename}.log")
```

**After (AI-generated fix):**
```python
with open(f"/tmp/{os.path.basename(filename)}.log", "w") as log:
    log.write(f"Exporting tasks as {fmt}\n")
```

---

### Insecure Deserialization `app/main.py:107`

**Before (vulnerable):**
```python
tasks = pickle.loads(data)
```

**After (AI-generated fix):**
```python
tasks = json.loads(data)
```

---

### Hardcoded Secrets `app/config.py`

**Before (vulnerable):**
```python
API_TOKEN = "ghp_1234567890abcdefABCDEF1234567890abcd"
```

**After (AI-generated fix):**
```python
API_TOKEN = os.environ.get("API_TOKEN", "")
```

---

## Tech Stack

| Layer | Tool | Purpose |
|-------|------|---------|
| Application | Python / Flask | REST API demo target |
| Containerisation | Docker / Compose | Portable, reproducible runtime |
| CI/CD | GitHub Actions | Workflow orchestration |
| SAST | Semgrep | Static analysis, custom rules |
| Secret scanning | TruffleHog | Credential and key detection |
| AI remediation | Google Gemini 1.5 Flash | Vulnerability context + patch generation |
| PR automation | GitHub REST API | Automated pull request creation |
| Testing | Pytest | Regression baseline |
