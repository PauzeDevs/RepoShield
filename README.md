# RepoShield

RepoShield by PauzeX Developments is a GitHub repository security scanner with a browser-based interface and a reusable GitHub Actions workflow.

**Live site:** https://reposhield.devs.surf/  
**Source:** https://github.com/PauzeDevs/RepoShield

## What it checks

- Common credential formats, including GitHub, GitLab, npm, Slack, Google, AWS-style access keys, bearer tokens, and PEM private-key headers. Findings show redacted evidence rather than the matched secret value.
- GitHub Actions threat signals, including broad `write-all` permissions, privileged `pull_request_target` triggers, untrusted pull-request/issue text interpolated into shell commands, mutable action tags/branches, persisted checkout credentials, and checking out an untrusted pull-request head ref in a privileged workflow.
- Suspicious static patterns such as remote scripts piped into a shell, PowerShell encoded commands, and encoded dynamic execution.
- Pinned npm dependency versions from `package-lock.json` (modern and legacy lockfiles) and exact-pinned Python versions from `requirements*.txt`, checked against the public OSV advisory service.
- Severity counts, source links, remediation guidance, and downloadable JSON reports in the browser scanner.

## Hosting and privacy

The website is a static GitHub Pages site. It has no scanning backend, does not require an account, and never asks website visitors for a GitHub token. Browser scans fetch public repository files directly from GitHub; those files are not uploaded to a RepoShield server.

The CI workflow scans a checkout on an ephemeral GitHub-hosted runner using a separate, pinned copy of RepoShield's scanner. It does not execute code from the target checkout, does not require repository secrets, and requests only read access to repository contents. Findings are written to the GitHub Actions job summary.

## Scan limits

The scanner inspects up to 180 supported files, skips supported files at or above 250 KB, and limits source inspection to approximately 3 MB per scan. It checks at most 60 unique pinned dependency versions per run. Scan limits and unavailable-file/API warnings are reported where applicable.

Supported dependency formats are intentionally limited to npm `package-lock.json` and exact-pinned entries in `requirements*.txt`. Other package-manager formats are not currently analysed. OSV outages produce a coverage warning; they are not treated as proof that dependencies are safe.

## Add RepoShield to another repository

Create `.github/workflows/reposhield.yml` in the target repository:

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

The example pins the reusable workflow to a commit SHA. Keep that pin when you need a fixed reviewed version, and update it deliberately when upgrading RepoShield. Supported `fail-on` values are `critical`, `high`, `medium`, `low`, `info`, and `never`. The default is `critical`. `never` reports findings without failing the job; other values fail when a finding reaches that severity or higher.

The reusable workflow checks out the target event's `github.sha` (the pull-request merge commit for a `pull_request` event), and checks out a separate pinned scanner version from RepoShield. It reads source files and dependency manifests only. Repository code and install scripts are never run by RepoShield itself.

## Deployment and tests

GitHub Pages is published from the `main` branch's root directory. The `.github/workflows/pages-only.yml` workflow runs syntax checks and scanner regression tests. The `.github/workflows/self-scan.yml` workflow runs RepoShield against this repository on pushes to `main`.

Run the regression suite locally with:

```sh
node --check tools/reposhield-ci.cjs
node --test tests/scanner-core.test.cjs
```

## Important limitations

RepoShield is an early-stage static scanner, not an antivirus product or a guarantee of repository safety. Pattern checks can miss issues and can produce false positives. Dependency findings need manual review; advisory severity is inferred from available OSV severity labels where present and defaults to medium when metadata is unavailable. This is not a full CVSS calculation. A clean report means only that the enabled checks did not flag an issue; it is not proof that software is safe.

## Responsible use

Scan repositories you are authorized to assess. If a credential is exposed, revoke or rotate it and consider removing it from Git history.
