# RepoShield

RepoShield by PauzeX Developments is a browser-only GitHub repository security scanner hosted on GitHub Pages.

**Live site:** https://reposhield.devs.surf/  
**Source:** https://github.com/PauzeDevs/RepoShield

## What it checks

- Common credential formats, including GitHub, GitLab, npm, Slack, Google, AWS-style access keys, bearer tokens, and PEM private-key headers. Findings show redacted evidence rather than the matched secret value.
- GitHub Actions threat signals, including broad `write-all` permissions, privileged `pull_request_target` triggers, untrusted pull-request/issue text interpolated into shell commands, mutable action tags/branches, and persisted checkout credentials.
- Suspicious static patterns such as remote scripts piped into a shell, PowerShell encoded commands, and encoded dynamic execution.
- Pinned npm dependency versions from `package-lock.json` (modern and legacy lockfile formats) and exact-pinned Python versions from `requirements*.txt`, checked against the public OSV advisory service.
- Advisory-informed dependency severity where OSV metadata provides it (otherwise defaults to medium for manual review).\n- Severity counts, source links, remediation guidance, and downloadable JSON reports.

## Hosting and privacy

The website is a static GitHub Pages site. There is no scanning backend, no account requirement, and no GitHub token requested from visitors. Repository files are fetched directly by the visitor's browser from public GitHub URLs and are not uploaded to a RepoShield server. The scanner never executes repository code.

## Scan limits

To keep browser scans bounded, RepoShield inspects up to 180 supported files, skips supported files at or above 250 KB, and limits source inspection to approximately 3 MB per scan. It checks at most 60 unique pinned dependency versions per run. These limits and unavailable-file/API warnings are included in the report where applicable. The scanner is subject to GitHub and OSV availability and rate limits.

Supported dependency formats are intentionally limited to npm `package-lock.json` and pinned entries in `requirements*.txt`; other package-manager formats are not currently analysed.

## Deployment and tests

GitHub Pages is published from the `main` branch's root directory. The `.github/workflows/pages-only.yml` workflow runs syntax checks and scanner regression tests; GitHub Pages' branch deployment workflow handles publishing.

Run the scanner-core regression suite locally with:

```sh
node --test tests/scanner-core.test.cjs
```

## Important limitations

RepoShield is an early-stage static scanner, not an antivirus product or a guarantee of repository safety. Pattern checks can miss issues and can produce false positives. Dependency findings need manual review; advisory severity is inferred from available OSV severity labels where present and defaults to medium when metadata is unavailable. This is not a full CVSS calculation. A clean report is not proof that software is safe.

## Responsible use

Scan public repositories you are authorized to assess. Do not treat a clean report as proof that software is safe.
