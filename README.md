# RepoShield

**RepoShield by PauzeX Developments** is a GitHub repository security scanner that combines bounded static analysis with public vulnerability-advisory lookups.

- **Website:** published through GitHub Pages
- **API:** FastAPI service in `backend/`, deployable separately
- **Primary goal:** surface actionable security signals with evidence and remediation guidance
- **Safety model:** inspect files as data; never execute repository code, package scripts, build steps, or workflow commands

> RepoShield is an assistive scanner, not a malware verdict engine. A clean report does not prove that a repository is safe, and a finding does not prove malicious intent.

## Features

- Detect common credential patterns, including private-key headers, GitHub token formats, AWS access-key IDs, Slack tokens, Google API keys, and selected API-key assignments. Matching evidence is redacted before being returned.
- Flag suspicious static patterns such as remote shell pipes, encoded PowerShell execution, base64-to-shell chains, and dynamic evaluation of decoded content.
- Inspect GitHub Actions workflows for broad write permissions, mutable action references, untrusted event-data interpolation, and risky `pull_request_target` patterns.
- Parse supported pinned dependencies from npm `package-lock.json`, pinned Python requirements, `go.mod`, `Cargo.lock`, and Maven `pom.xml`; query OSV for published advisories.
- Provide severity counts, file/line locations where applicable, redacted evidence, remediation advice, and downloadable JSON reports.
- Apply archive, file-size, file-count, concurrency, and per-IP request limits.

## Architecture

```text
GitHub Pages (static frontend)
       |
       | HTTPS POST /api/scan
       v
FastAPI scanning API (backend/)
       |-- GitHub REST API + repository archive
       |-- Static rules (no code execution)
       |-- OSV vulnerability API
       v
JSON report -> browser report view / JSON export
```

The frontend and backend are intentionally separate. GitHub Pages serves static assets; it cannot run the Python API. The frontend's public API origin is configured in `config.js` using `window.REPOSHIELD_CONFIG.apiBase`. Never place API secrets or private tokens in this file.

## Local development

Requires Python 3.12+ and a modern browser.

### Run the API

```bash
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
uvicorn backend.main:app --reload --port 8080
```

Health check: `http://127.0.0.1:8080/health`.

For local frontend testing, temporarily set `apiBase: "http://127.0.0.1:8080"` in `config.js`, then serve the repository root with a static server (for example `python -m http.server 5500`). Restore the production API origin before deploying. The default CORS allowlist includes localhost:5500.

### Run tests

```bash
pytest -q
```

### Run the API with Docker

```bash
docker build -t reposhield-api .
docker run --rm -p 8080:8080 -e ALLOWED_ORIGINS=http://localhost:5500 reposhield-api
```

## Deployment

### Website: GitHub Pages

A GitHub Actions workflow at `.github/workflows/deploy.yml` validates the source and deploys the static site after pushes to `main`. In repository Settings → Pages, select **GitHub Actions** as the publishing source if it is not already selected.

Expected project URL: `https://pauzedevs.github.io/RepoShield/`.

### API: separate container service

The root `Dockerfile` and `railway.toml` configure a container deployment with a `/health` health check. Deploy the repository's service from the `main` branch and configure:

- `ALLOWED_ORIGINS=https://pauzedevs.github.io`
- The service platform must provide `PORT`; the container listens on it.
- Do not configure GitHub access tokens for this public-repository-only version.
- Do not store private credentials in the repository or frontend.

Once the API is deployed, copy its HTTPS origin into `config.js` as `apiBase`, commit, and allow the Pages workflow to redeploy. Verify `/health`, a known test repository, error handling, CORS, and the workflow result before announcing the scanner as live.

Hosting-provider plans and usage limits may change; check the selected service's billing and usage before keeping a public scanner online.

## API

- `GET /` — service name and route hints
- `GET /health` — health check
- `POST /api/scan` — scan a public GitHub repository

Example request:

```bash
curl -X POST https://YOUR-API-HOST/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"repository_url":"https://github.com/psf/requests"}'
```

The scan endpoint accepts only a GitHub URL with an owner and repository. It rejects private repositories. The archive is downloaded into memory under a size cap; selected text files are inspected without extraction to disk. Files that are oversized, binary, excluded, or beyond the scan budget are skipped and may be noted in warnings.

## Current coverage and limitations

- This is an initial, rule-based scanner. It is not a sandbox, EDR, antivirus replacement, or full SAST platform.
- Pattern matching can produce false positives and false negatives. Context matters.
- Dependency coverage depends on supported manifest formats, pinned versions, OSV availability, and API responses.
- The current version supports public repositories only; private-repository OAuth is not implemented.
- GitHub unauthenticated API quotas can limit scans.
- The in-memory rate limiter is a single-process abuse deterrent, not a distributed quota system.
- Malware execution, dynamic analysis, binary scanning, transitive dependency resolution beyond supported lockfiles, and historical Git-secret scanning are not implemented.
- The public website never receives a GitHub token and should not request one.
- Reports may include source snippets only after secret-pattern redaction; do not treat the report as a safe place to publish secrets.

## Responsible use

Scan repositories you own or are authorized to assess. RepoShield does not exploit vulnerabilities, attempt access to private repositories, or execute code from scanned projects. Validate important findings and follow coordinated disclosure practices when reporting issues.

## Project status

The repository contains the initial implementation. Do not describe the service as production-ready or deployed until CI passes, the API is deployed, the frontend is configured to reach it, and end-to-end scans have been verified.
