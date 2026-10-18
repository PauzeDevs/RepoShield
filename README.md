# RepoShield

RepoShield by PauzeX Developments is a browser-only GitHub repository security checker hosted on GitHub Pages.

**Live site:** https://reposhield.devs.surf/  
**Source:** https://github.com/PauzeDevs/RepoShield

## What it checks

- Common accidentally committed credential patterns, with matched values redacted in the report.
- Selected GitHub Actions workflow hardening issues.
- Pinned npm and Python dependencies against the OSV vulnerability database.
- File-level findings, severity, remediation guidance, and JSON report export.

## Hosting and privacy

The website is hosted only through GitHub Pages. There is no scanning backend, no account requirement, and no GitHub token requested from visitors. Repository files are fetched directly by the visitor's browser from public GitHub URLs and are not uploaded to a RepoShield server. The scanner never executes repository code.

The browser-only design has limits: it supports public repositories, selected text files and dependency manifests, capped file counts and sizes, and is subject to GitHub and OSV API availability and rate limits.

## Deployment

The GitHub Actions workflow validates the static site and publishes it to GitHub Pages. In repository Settings → Pages, choose **GitHub Actions** as the publishing source.

## Important limitations

RepoShield is an early-stage static scanner, not an antivirus product or a guarantee of repository safety. Pattern checks can miss issues and can produce false positives. Dependency coverage is limited to supported pinned formats and public OSV data. Always investigate findings and validate fixes.

## Responsible use

Scan public repositories you are authorized to assess. Do not treat a clean report as proof that software is safe.
