<p align="center">
  <a href="https://reposhield.devs.surf/">
    <img src="https://capsule-render.vercel.app/api?type=waving&color=0:101828,55:173A70,100:2563EB&height=230&section=header&text=RepoShield&fontSize=66&fontColor=FFFFFF&fontAlignY=35&desc=Static%20Repository%20Security%20Scanner&descAlignY=56&descSize=17&animation=fadeIn" alt="RepoShield — static repository security scanner" width="100%">
  </a>
</p>

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=500&size=15&pause=1300&color=60A5FA&center=true&vCenter=true&width=680&lines=Spot+common+secret+patterns;Review+GitHub+Actions+security+risks;Check+pinned+dependencies+with+OSV;Static+analysis+without+running+repository+code" alt="RepoShield feature highlights">
</p>

<p align="center">
  <a href="https://reposhield.devs.surf/"><img src="https://img.shields.io/badge/LIVE%20SITE-Open%20RepoShield-2563EB?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Open the live RepoShield scanner"></a>
  <a href="https://github.com/PauzeDevs/RepoShield"><img src="https://img.shields.io/badge/GitHub-Source%20Code-181717?style=for-the-badge&logo=github" alt="RepoShield source code"></a>
</p>

<p align="center">
  <a href="https://github.com/PauzeDevs/RepoShield/actions/workflows/pages-only.yml"><img src="https://img.shields.io/github/actions/workflow/status/PauzeDevs/RepoShield/pages-only.yml?branch=main&style=flat-square&label=CI" alt="CI status"></a>
  <a href="https://github.com/PauzeDevs/RepoShield/actions/workflows/self-scan.yml"><img src="https://img.shields.io/github/actions/workflow/status/PauzeDevs/RepoShield/self-scan.yml?branch=main&style=flat-square&label=RepoShield%20self-scan" alt="RepoShield self-scan status"></a>
  <a href="https://github.com/PauzeDevs/RepoShield/stargazers"><img src="https://img.shields.io/github/stars/PauzeDevs/RepoShield?style=flat-square&label=Stars" alt="GitHub stars"></a>
  <a href="https://github.com/PauzeDevs/RepoShield/commits/main"><img src="https://img.shields.io/github/last-commit/PauzeDevs/RepoShield?style=flat-square&label=Last%20commit" alt="Last commit"></a>
</p>

<p align="center">
  <strong>Small, transparent checks for common repository security mistakes.</strong><br>
  A browser-based scanner and reusable GitHub Actions workflow maintained by PauzeX Developments.
</p>

---

## What RepoShield checks

- **Exposed credentials:** recognises common GitHub, GitLab, npm, Slack, Google, AWS-style, bearer-token, and private-key patterns. Evidence is redacted in reports.
- **GitHub Actions risks:** flags broad workflow permissions, privileged `pull_request_target` triggers, unsafe interpolation of event text into shell commands, mutable action references, persisted checkout credentials, and risky pull-request head checkouts.
- **Suspicious code patterns:** looks for patterns such as piping remote scripts directly to a shell, encoded PowerShell commands, and some forms of encoded dynamic execution.
- **Pinned dependencies:** checks supported npm `package-lock.json` and exact-pinned Python `requirements*.txt` entries against the public OSV advisory service.
- **Actionable findings:** provides severity, file and line references where applicable, source links, remediation guidance, and coverage warnings.

## Try the scanner

**[Open RepoShield →](https://reposhield.devs.surf/)**

Paste a public GitHub repository URL into the web app and start a scan. The browser fetches public repository files from GitHub; files are not uploaded to a RepoShield backend. No personal access token or account is required.

## Add RepoShield to GitHub Actions

Create `.github/workflows/reposhield.yml` in the repository you want to scan:

```yaml
name: RepoShield

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  scan:
    uses: PauzeDevs/RepoShield/.github/workflows/reposhield-scan.yml@a0b672753c5bfa5493a0312f72afc9addf721734
    with:
      fail-on: high
```

The example pins the reusable workflow to a commit SHA. Update the pin deliberately when adopting a newer reviewed version.

| `fail-on` value | Behaviour |
|---|---|
| `critical` | Fail if a critical finding is reported. This is the default. |
| `high` | Fail on high or critical findings. |
| `medium`, `low`, `info` | Fail at that severity or above. |
| `never` | Report findings without failing due to their severity. |

The job needs only `contents: read`. It checks out the target revision and a separate pinned copy of the scanner, then reads files as data. RepoShield does not execute code or install scripts from the target repository, and it does not require repository secrets. Results are written to the GitHub Actions job summary.

## Project layout

| Path | Purpose |
|---|---|
| `index.html` | Static app shell and accessible page structure |
| `assets/styles.css` | Layout, responsive styling, and visual components |
| `browser-scan.js` | GitHub API access, scan orchestration, and UI rendering |
| `scanner-core.js` | Shared static pattern detection, redaction, and dependency parsing |
| `tools/reposhield-ci.cjs` | Local-filesystem scanner used by GitHub Actions |
| `.github/workflows/reposhield-scan.yml` | Reusable workflow for other repositories |
| `.github/workflows/self-scan.yml` | Runs RepoShield against its own repository |
| `tests/scanner-core.test.cjs` | Regression tests for scanner behaviour |

## Run the tests locally

Use Node.js and run:

```sh
node --check browser-scan.js
node --check scanner-core.js
node --check tools/reposhield-ci.cjs
node --test tests/scanner-core.test.cjs
```

## Limits and privacy

RepoShield is a bounded static scanner, not an antivirus tool or proof that a repository is safe.

- Scans up to 180 supported files.
- Skips supported files at or above 250 KB.
- Inspects approximately 3 MB of source per scan.
- Checks up to 60 unique pinned dependency versions against OSV.
- Supports npm `package-lock.json` and pinned entries in `requirements*.txt` for dependency checks.
- Depends on GitHub and OSV availability and rate limits; incomplete coverage is surfaced as a warning.

Findings can be false positives, and a clean scan can miss vulnerabilities. Review results and advisories before making security decisions. If a real credential is exposed, revoke or rotate it and consider removing it from Git history.

## Maintained by

**PauzeX Developments** · [GitHub repository](https://github.com/PauzeDevs/RepoShield) · [Live scanner](https://reposhield.devs.surf/)
