from __future__ import annotations

import asyncio
import io
import json
import os
import re
import time
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
import xml.etree.ElementTree as ET
from urllib.parse import quote, urlparse
from uuid import uuid4

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

APP_VERSION = "0.1.0"
MAX_ARCHIVE_BYTES = 15 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 24 * 1024 * 1024
MAX_FILE_BYTES = 1 * 1024 * 1024
MAX_FILES = 3000
MAX_FINDINGS = 250
MAX_DEPENDENCIES = 200
SCAN_LIMIT = 10
SCAN_WINDOW_SECONDS = 600
IGNORED_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__", ".next", "coverage", "target"}
TEXT_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py", ".pyw", ".sh", ".bash", ".zsh",
    ".ps1", ".bat", ".cmd", ".php", ".rb", ".go", ".rs", ".java", ".kt", ".kts", ".c",
    ".cc", ".cpp", ".h", ".hpp", ".yml", ".yaml", ".json", ".toml", ".ini", ".env",
    ".txt", ".md", ".xml", ".gradle", ".properties", ".lock", ".tf", ".html", ".sql",
    ".vue", ".svelte", ".dockerfile", ".config", ".plist", ".swift", ".dart", ".ex", ".exs"
}
SEVERITIES = ("critical", "high", "medium", "low", "info")
VERSION_RE = re.compile(r"^v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$")

app = FastAPI(
    title="RepoShield API",
    version=APP_VERSION,
    description="Bounded, non-executing static analysis for public GitHub repositories.",
    docs_url=None,
    redoc_url=None,
)
origins = [x.strip() for x in os.getenv(
    "ALLOWED_ORIGINS",
    "https://pauzedevs.github.io,http://localhost:5500,http://127.0.0.1:5500"
).split(",") if x.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)
scan_semaphore = asyncio.Semaphore(3)
rate_buckets: dict[str, list[float]] = defaultdict(list)


class ScanRequest(BaseModel):
    repository_url: str = Field(min_length=1, max_length=500)

    @field_validator("repository_url")
    @classmethod
    def validate_repository_url(cls, value: str) -> str:
        parsed = urlparse(value.strip())
        if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.username or parsed.password or parsed.port:
            raise ValueError("Only HTTPS GitHub repository URLs are supported.")
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) != 2:
            raise ValueError("Enter a repository URL in the form https://github.com/owner/repository.")
        owner, repo = parts
        if repo.lower().endswith(".git"):
            repo = repo[:-4]
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", owner):
            raise ValueError("Invalid GitHub owner name.")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", repo) or repo in {".", ".."}:
            raise ValueError("Invalid GitHub repository name.")
        return f"https://github.com/{owner}/{repo}"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def check_rate_limit(request: Request) -> None:
    forwarded = request.headers.get("x-forwarded-for", "")
    client_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")
    current = time.monotonic()
    recent = [stamp for stamp in rate_buckets[client_ip] if current - stamp < SCAN_WINDOW_SECONDS]
    if len(recent) >= SCAN_LIMIT:
        raise HTTPException(status_code=429, detail="Scan rate limit reached. Please wait a few minutes before trying again.")
    recent.append(current)
    rate_buckets[client_ip] = recent
    # Bound memory growth from arbitrary forwarded addresses.
    if len(rate_buckets) > 5000:
        for key in list(rate_buckets)[:1000]:
            if not rate_buckets[key] or current - rate_buckets[key][-1] >= SCAN_WINDOW_SECONDS:
                rate_buckets.pop(key, None)


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(f.get("severity", "info")).lower() for f in findings)
    return {level: counts.get(level, 0) for level in SEVERITIES}


def safe_source_url(owner: str, repo: str, branch: str, path: str, line: int | None) -> str:
    url = f"https://github.com/{owner}/{repo}/blob/{quote(branch, safe='')}/{quote(path, safe='/')}"
    return url + (f"#L{line}" if line else "")


def make_finding(
    *, severity: str, category: str, title: str, description: str, file: str | None = None,
    line: int | None = None, evidence: str | None = None, remediation: str | None = None,
    source_url: str | None = None, fingerprint: str | None = None
) -> dict[str, Any]:
    return {
        "id": fingerprint or uuid4().hex[:12],
        "severity": severity if severity in SEVERITIES else "info",
        "category": category,
        "title": title,
        "description": description,
        "file": file,
        "line": line,
        "evidence": evidence,
        "remediation": remediation,
        "source_url": source_url,
    }


SECRET_RULES: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("critical", "secret", "Private key material", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("critical", "secret", "GitHub access token pattern", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("critical", "secret", "AWS access key ID pattern", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("critical", "secret", "Stripe live secret key pattern", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("high", "secret", "Slack token pattern", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{15,}\b")),
    ("high", "secret", "Google API key pattern", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("high", "secret", "OpenAI-style API key pattern", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b")),
    ("high", "secret", "Generic credential assignment", re.compile(r"""(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|secret[_-]?key)\b\s*[:=]\s*['"]?([A-Za-z0-9_./+=-]{16,})""")),
]

MALWARE_RULES: list[tuple[str, str, str, re.Pattern[str], str]] = [
    ("high", "suspicious_code", "Remote script piped to a shell", re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]{0,400}\|\s*(?:sudo\s+)?(?:ba)?sh\b"), "Avoid piping remote content directly into a shell. Download it, verify its source and checksum, and inspect it before execution."),
    ("high", "suspicious_code", "Encoded PowerShell execution", re.compile(r"(?i)\bpowershell(?:\.exe)?\b[^\n]{0,160}(?:-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,}|-e\s+[A-Za-z0-9+/=]{20,})"), "Inspect the encoded command offline and remove it unless its purpose and origin are fully understood."),
    ("high", "suspicious_code", "PowerShell download-and-execute pattern", re.compile(r"(?is)(?:Invoke-WebRequest|iwr|DownloadString)[^\n]{0,500}(?:Invoke-Expression|\biex\b)"), "Do not download and execute remote scripts in one step. Pin and verify trusted artifacts."),
    ("high", "suspicious_code", "Base64 payload piped to shell", re.compile(r"(?i)\bbase64\s+(?:--decode|-d)\b[^\n|]{0,160}\|\s*(?:sudo\s+)?(?:ba)?sh\b"), "Inspect decoded content and remove opaque execution chains unless required and independently verified."),
    ("medium", "suspicious_code", "Dynamic evaluation of decoded content", re.compile(r"(?i)\beval\s*\(\s*(?:atob|Buffer\.from)\s*\("), "Avoid evaluating decoded strings. Replace with explicit, auditable code and validate all input."),
    ("medium", "suspicious_code", "Shell execution combined with remote URL", re.compile(r"(?is)(?:child_process\.(?:exec|execSync)|subprocess\.(?:run|Popen|call)|os\.system)\s*\([^\n]{0,250}https?://"), "Review whether untrusted or remotely sourced content can reach a shell. Prefer argument arrays and verified downloads."),
]


def line_evidence(line: str, match: re.Match[str] | None = None) -> str:
    evidence = line.strip()[:300]
    # Never return matched credential material. Redact the match plus common assignment values.
    if match:
        try:
            start, end = match.span(1) if match.lastindex else match.span()
            if start >= 0 and end > start:
                evidence = evidence.replace(line.strip()[max(0, start - len(line[:len(line) - len(line.lstrip())])):max(0, end - len(line[:len(line) - len(line.lstrip())]))], "[REDACTED]")
        except Exception:
            pass
    evidence = re.sub(r"(?i)(api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|secret[_-]?key)(\s*[:=]\s*['\"]?)[^\s'\"]{6,}", r"\1\2[REDACTED]", evidence)
    evidence = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]{8,}|(?:AKIA|ASIA)[A-Z0-9]{8,}|sk_live_[A-Za-z0-9]+|xox[baprs]-[A-Za-z0-9-]+)\b", "[REDACTED]", evidence)
    return evidence


def add_line_finding(
    findings: list[dict[str, Any]], seen: set[tuple[str, int, str]], *,
    owner: str, repo: str, branch: str, path: str, line_number: int,
    severity: str, category: str, title: str, description: str,
    evidence: str, remediation: str
) -> None:
    key = (path, line_number, title)
    if key in seen or len(findings) >= MAX_FINDINGS:
        return
    seen.add(key)
    findings.append(make_finding(
        severity=severity, category=category, title=title, description=description,
        file=path, line=line_number, evidence=evidence, remediation=remediation,
        source_url=safe_source_url(owner, repo, branch, path, line_number),
        fingerprint=__import__("hashlib").sha256(f"{path}:{line_number}:{title}".encode()).hexdigest()[:12],
    ))


def inspect_source(owner: str, repo: str, branch: str, path: str, content: str, findings: list[dict[str, Any]], seen: set[tuple[str, int, str]]) -> None:
    lines = content.splitlines()
    workflow = path.startswith(".github/workflows/") and path.lower().endswith((".yml", ".yaml"))
    full = content[:MAX_FILE_BYTES]
    for index, line in enumerate(lines, start=1):
        if len(findings) >= MAX_FINDINGS:
            return
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "/*", "*")):
            # Do not completely skip comments: credentials sometimes get pasted into them.
            if not stripped:
                continue
        for severity, category, title, pattern in SECRET_RULES:
            match = pattern.search(line)
            if not match:
                continue
            value = match.group(1) if match.lastindex else match.group(0)
            if value and value.lower() in {"your_api_key_here", "changeme", "replace_me", "example", "placeholder", "password123"}:
                continue
            # Generic assignment rule only reports values that look non-placeholder and not obvious examples.
            if title == "Generic credential assignment" and re.search(r"(?i)(example|sample|placeholder|changeme|your[_-]|dummy|test[_-]?key)", value or ""):
                continue
            add_line_finding(
                findings, seen, owner=owner, repo=repo, branch=branch, path=path, line_number=index,
                severity=severity, category=category, title=title,
                description="A value matching a known credential format appears in source. This may be a false positive; verify the value and revoke it if it is real.",
                evidence=line_evidence(line, match),
                remediation="If this is a real credential, revoke or rotate it immediately, remove it from current source, and clean the Git history if needed. Store secrets in a secret manager or CI secret store.",
            )
            break

        for severity, category, title, pattern, remediation in MALWARE_RULES:
            match = pattern.search(line)
            if match:
                add_line_finding(
                    findings, seen, owner=owner, repo=repo, branch=branch, path=path, line_number=index,
                    severity=severity, category=category, title=title,
                    description="This pattern can be used in legitimate automation but is also commonly abused. Inspect the surrounding code and source of the payload; this is not proof of malware.",
                    evidence=line_evidence(line, match),
                    remediation=remediation,
                )
                break

        if workflow:
            lower = line.lower()
            if re.search(r"(?i)permissions\s*:\s*write-all", line):
                add_line_finding(
                    findings, seen, owner=owner, repo=repo, branch=branch, path=path, line_number=index,
                    severity="high", category="workflow", title="Workflow grants write-all permissions",
                    description="Broad write permissions increase the impact of a compromised action or workflow step.",
                    evidence=line_evidence(line),
                    remediation="Use least-privilege permissions at workflow or job scope, granting only the specific read/write permissions needed.",
                )
            if re.search(r"(?i)uses\s*:\s*[^\s#]+@(main|master)\b", line):
                add_line_finding(
                    findings, seen, owner=owner, repo=repo, branch=branch, path=path, line_number=index,
                    severity="medium", category="workflow", title="Third-party action is not pinned to a version or commit",
                    description="A moving branch reference can change without a reviewed workflow update.",
                    evidence=line_evidence(line),
                    remediation="Pin third-party actions to a full commit SHA and use Dependabot or a documented process to update pins.",
                )
            if re.search(r"(?i)\$\{\{\s*github\.event\.(?:pull_request\.(?:title|body|head\.ref)|issue\.(?:title|body))\s*\}\}", line) and re.search(r"(?i)\brun\s*:", line):
                add_line_finding(
                    findings, seen, owner=owner, repo=repo, branch=branch, path=path, line_number=index,
                    severity="high", category="workflow", title="Untrusted event data interpolated into a shell command",
                    description="Pull request or issue text interpolated directly into a run command may allow script injection.",
                    evidence=line_evidence(line),
                    remediation="Pass untrusted event fields through environment variables and quote/validate them; avoid direct expression interpolation in shell scripts.",
                )

    if workflow and re.search(r"(?i)pull_request_target", full) and re.search(r"(?i)pull_request\.head\.(?:sha|ref)", full) and re.search(r"(?i)actions/checkout", full):
        add_line_finding(
            findings, seen, owner=owner, repo=repo, branch=branch, path=path, line_number=1,
            severity="high", category="workflow", title="Privileged pull_request_target workflow checks out pull request code",
            description="Combining pull_request_target with checkout of a pull request's head can expose write-capable tokens or secrets to untrusted code.",
            evidence="Workflow contains pull_request_target, checkout, and a pull_request.head reference.",
            remediation="Avoid checking out or executing untrusted pull request code in a privileged pull_request_target workflow. Use pull_request for untrusted validation or separate a read-only validation job.",
        )


def parse_dependencies(path: str, text: str) -> list[dict[str, str]]:
    deps: list[dict[str, str]] = []
    basename = path.rsplit("/", 1)[-1].lower()
    try:
        if basename == "package-lock.json":
            data = json.loads(text)
            packages = data.get("packages", {})
            for package_path, item in packages.items():
                if not package_path.startswith("node_modules/") or not isinstance(item, dict):
                    continue
                name = package_path[len("node_modules/"):]
                version = str(item.get("version", ""))
                if name and version and VERSION_RE.match(version):
                    deps.append({"name": name, "version": version, "ecosystem": "npm"})
            if not packages:
                def walk(items: dict[str, Any]) -> None:
                    for name, item in items.items():
                        if not isinstance(item, dict):
                            continue
                        version = str(item.get("version", ""))
                        if version and VERSION_RE.match(version):
                            deps.append({"name": name, "version": version, "ecosystem": "npm"})
                        walk(item.get("dependencies", {}))
                walk(data.get("dependencies", {}))
        elif basename in {"requirements.txt", "requirements-prod.txt", "requirements-dev.txt"}:
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "-")):
                    continue
                match = re.match(r"^([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+-]+)", line)
                if match and VERSION_RE.match(match.group(2).lstrip("v")):
                    deps.append({"name": match.group(1).lower().replace("_", "-"), "version": match.group(2).lstrip("v"), "ecosystem": "PyPI"})
        elif basename == "go.mod":
            for line in text.splitlines():
                match = re.match(r"^\s*([A-Za-z0-9./_-]+)\s+(v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\s*$", line)
                if match:
                    deps.append({"name": match.group(1), "version": match.group(2).lstrip("v"), "ecosystem": "Go"})
        elif basename == "cargo.lock":
            try:
                import tomllib
                data = tomllib.loads(text)
                for item in data.get("package", []):
                    name, version = str(item.get("name", "")), str(item.get("version", ""))
                    if name and VERSION_RE.match(version):
                        deps.append({"name": name, "version": version, "ecosystem": "crates.io"})
            except (ImportError, ValueError):
                pass
        elif basename == "pom.xml":
            root = ET.fromstring(text)
            ns = {"m": "http://maven.apache.org/POM/4.0.0"}
            for item in root.findall(".//m:dependency", ns):
                group = item.findtext("m:groupId", default="", namespaces=ns).strip()
                name = item.findtext("m:artifactId", default="", namespaces=ns).strip()
                version = item.findtext("m:version", default="", namespaces=ns).strip()
                if group and name and VERSION_RE.match(version):
                    deps.append({"name": f"{group}:{name}", "version": version, "ecosystem": "Maven"})
    except (json.JSONDecodeError, TypeError, ValueError, ET.ParseError):
        return deps
    # Stable de-duplication and sensible per-repository cap.
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, str]] = []
    for dep in deps:
        key = (dep["ecosystem"], dep["name"], dep["version"])
        if key not in seen:
            seen.add(key)
            unique.append(dep)
        if len(unique) >= MAX_DEPENDENCIES:
            break
    return unique


async def request_json(client: httpx.AsyncClient, url: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> Any:
    try:
        response = await (client.post(url, json=payload) if method == "POST" else client.get(url))
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail=f"An upstream security data service returned HTTP {exc.response.status_code}. Please retry later.") from exc
    except (httpx.TimeoutException, httpx.RequestError, ValueError) as exc:
        raise HTTPException(status_code=502, detail="An upstream service could not be reached. Please retry later.") from exc


async def inspect_dependencies(client: httpx.AsyncClient, dependencies: list[dict[str, str]], owner: str, repo: str, branch: str) -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[dict[str, Any]] = []
    warnings: list[str] = []
    if not dependencies:
        return findings, warnings
    advisory_candidates: list[tuple[dict[str, str], str]] = []
    for offset in range(0, len(dependencies), 100):
        batch = dependencies[offset:offset + 100]
        queries = [{"package": {"name": dep["name"], "ecosystem": dep["ecosystem"]}, "version": dep["version"]} for dep in batch]
        try:
            data = await request_json(client, "https://api.osv.dev/v1/querybatch", method="POST", payload={"queries": queries})
        except HTTPException:
            warnings.append("Dependency vulnerability lookup was unavailable; dependency results may be incomplete.")
            return findings, warnings
        results = data.get("results", [])
        for dep, result in zip(batch, results):
            for vuln in result.get("vulns", []):
                vuln_id = str(vuln.get("id", ""))
                if vuln_id:
                    advisory_candidates.append((dep, vuln_id))
                if len(advisory_candidates) >= 60:
                    warnings.append("Dependency advisory details were capped at 60 to keep scan time bounded.")
                    break
            if len(advisory_candidates) >= 60:
                break
        if len(advisory_candidates) >= 60:
            break

    semaphore = asyncio.Semaphore(8)

    async def load_detail(vuln_id: str) -> dict[str, Any]:
        async with semaphore:
            try:
                return await request_json(client, f"https://api.osv.dev/v1/vulns/{quote(vuln_id, safe='')}")
            except HTTPException:
                return {}

    details = await asyncio.gather(*(load_detail(vuln_id) for _, vuln_id in advisory_candidates))
    for (dep, vuln_id), detail in zip(advisory_candidates, details):
        summary = str(detail.get("summary") or detail.get("details") or "This pinned dependency version is associated with a published vulnerability advisory.")
        summary = re.sub(r"\\s+", " ", summary).strip()[:500]
        score = 0.0
        for severity in detail.get("severity", []):
            try:
                score = max(score, float(severity.get("score", 0)))
            except (TypeError, ValueError):
                continue
        database_severity = str(detail.get("database_specific", {}).get("severity", "")).lower()
        if score >= 9 or database_severity == "critical":
            level = "critical"
        elif score >= 7 or database_severity == "high":
            level = "high"
        elif score >= 4 or database_severity == "moderate":
            level = "medium"
        else:
            level = "medium"
        fixed_versions: list[str] = []
        for affected in detail.get("affected", []):
            package = affected.get("package", {})
            if package.get("name") != dep["name"] or package.get("ecosystem") != dep["ecosystem"]:
                continue
            for version_range in affected.get("ranges", []):
                for event in version_range.get("events", []):
                    if event.get("fixed"):
                        fixed_versions.append(str(event["fixed"]))
        remediation = "Upgrade to a patched version if one is available, verify compatibility, and review the advisory."
        if fixed_versions:
            remediation = "Upgrade to a fixed version (for example: " + ", ".join(dict.fromkeys(fixed_versions))[:180] + ") and verify compatibility."
        findings.append(make_finding(
            severity=level, category="dependency", title=f"{dep['name']} {dep['version']} — {vuln_id}",
            description=summary, file=None, line=None,
            evidence=f"Package: {dep['name']}\\nInstalled version: {dep['version']}\\nEcosystem: {dep['ecosystem']}\\nAdvisory: https://osv.dev/vulnerability/{vuln_id}",
            remediation=remediation, source_url=f"https://osv.dev/vulnerability/{quote(vuln_id, safe='')}",
            fingerprint=__import__("hashlib").sha256(f"{dep['ecosystem']}:{dep['name']}:{dep['version']}:{vuln_id}".encode()).hexdigest()[:12],
        ))
    return findings, warnings

async def download_archive(client: httpx.AsyncClient, url: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    try:
        async with client.stream("GET", url, headers={"Accept": "application/vnd.github+json"}) as response:
            if response.status_code == 404:
                raise HTTPException(status_code=404, detail="Repository archive not found. Check the URL and ensure the repository is public.")
            if response.status_code in (401, 403):
                raise HTTPException(status_code=429, detail="GitHub refused the archive request, possibly due to rate limits. Try again later.")
            response.raise_for_status()
            length = response.headers.get("content-length")
            if length and int(length) > MAX_ARCHIVE_BYTES:
                raise HTTPException(status_code=413, detail="Repository archive is larger than the scan limit (15 MB compressed).")
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise HTTPException(status_code=413, detail="Repository archive exceeded the 15 MB scan limit.")
                chunks.append(chunk)
    except HTTPException:
        raise
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="Timed out downloading the repository. Try a smaller repository.") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="GitHub could not provide the repository archive. Check the repository and try again.") from exc
    return b"".join(chunks)


def extract_text_files(archive_bytes: bytes) -> tuple[list[tuple[str, str]], int, list[str]]:
    files: list[tuple[str, str]] = []
    warnings: list[str] = []
    total_source_bytes = 0
    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_bytes))
    except (zipfile.BadZipFile, OSError) as exc:
        raise HTTPException(status_code=502, detail="GitHub returned an archive that could not be read.") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) > 12000:
            raise HTTPException(status_code=413, detail="Repository contains too many archive entries to scan safely.")
        for info in infos:
            if len(files) >= MAX_FILES:
                warnings.append(f"File scan capped at {MAX_FILES} files.")
                break
            if info.is_dir() or info.file_size <= 0:
                continue
            parts = info.filename.replace("\\", "/").split("/")
            if len(parts) < 2 or any(part in IGNORED_DIRS for part in parts[:-1]):
                continue
            relative = "/".join(parts[1:])
            basename = parts[-1]
            suffix = os.path.splitext(basename.lower())[1]
            is_special = basename.lower() in {"dockerfile", "package-lock.json", "requirements.txt", "requirements-prod.txt", "requirements-dev.txt", "go.mod", "cargo.lock", "pom.xml"}
            if not is_special and suffix not in TEXT_EXTENSIONS:
                continue
            if info.file_size > MAX_FILE_BYTES:
                warnings.append(f"Skipped oversized file: {relative}")
                continue
            if info.compress_size and info.file_size / max(1, info.compress_size) > 250 and info.file_size > 256 * 1024:
                warnings.append(f"Skipped unusually compressed file: {relative}")
                continue
            if total_source_bytes + info.file_size > MAX_TOTAL_SOURCE_BYTES:
                warnings.append("Source scan stopped at the 24 MB expanded-text limit.")
                break
            try:
                raw = archive.read(info)
                text = raw.decode("utf-8", errors="replace")
            except (RuntimeError, zipfile.BadZipFile, OSError):
                warnings.append(f"Could not read file: {relative}")
                continue
            if "\x00" in text[:4096]:
                continue
            files.append((relative, text))
            total_source_bytes += len(raw)
    return files, total_source_bytes, warnings


async def scan_repository(owner: str, repo: str) -> dict[str, Any]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "RepoShield-PauzeX/0.1", "X-GitHub-Api-Version": "2022-11-28"}
    timeout = httpx.Timeout(20.0, connect=8.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
        metadata = await request_json(client, f"https://api.github.com/repos/{quote(owner)}/{quote(repo)}")
        if metadata.get("private"):
            raise HTTPException(status_code=403, detail="Only public repositories are supported in this version.")
        if metadata.get("disabled"):
            raise HTTPException(status_code=400, detail="This repository is disabled and cannot be scanned.")
        default_branch = str(metadata.get("default_branch") or "main")
        archive_url = f"https://api.github.com/repos/{quote(owner)}/{quote(repo)}/zipball/{quote(default_branch, safe='')}"
        archive_bytes = await download_archive(client, archive_url)
        source_files, source_bytes, warnings = extract_text_files(archive_bytes)
        findings: list[dict[str, Any]] = []
        seen: set[tuple[str, int, str]] = set()
        dependency_files: list[tuple[str, str]] = []
        for path, content in source_files:
            inspect_source(owner, repo, default_branch, path, content, findings, seen)
            if path.rsplit("/", 1)[-1].lower() in {
                "package-lock.json", "requirements.txt", "requirements-prod.txt",
                "requirements-dev.txt", "go.mod", "cargo.lock", "pom.xml"
            }:
                dependency_files.append((path, content))
            if len(findings) >= MAX_FINDINGS:
                warnings.append(f"Static findings capped at {MAX_FINDINGS}.")
                break
        dependencies: list[dict[str, str]] = []
        for path, content in dependency_files:
            dependencies.extend(parse_dependencies(path, content))
        unique_deps: dict[tuple[str, str, str], dict[str, str]] = {}
        for dep in dependencies:
            unique_deps[(dep["ecosystem"], dep["name"], dep["version"])] = dep
        dependency_findings, dependency_warnings = await inspect_dependencies(client, list(unique_deps.values())[:MAX_DEPENDENCIES], owner, repo, default_branch)
        warnings.extend(dependency_warnings)
        findings.extend(dependency_findings)
        findings.sort(key=lambda item: (SEVERITIES.index(item["severity"]), item.get("file") or "", item.get("line") or 0))
        findings = findings[:MAX_FINDINGS]
        return {
            "schema_version": "1.0",
            "scan_id": uuid4().hex,
            "generated_at": now_iso(),
            "scanner_version": APP_VERSION,
            "repository": {
                "full_name": metadata.get("full_name") or f"{owner}/{repo}",
                "html_url": metadata.get("html_url") or f"https://github.com/{owner}/{repo}",
                "default_branch": default_branch,
                "stars": int(metadata.get("stargazers_count") or 0),
                "language": metadata.get("language"),
                "license": (metadata.get("license") or {}).get("spdx_id"),
            },
            "scanned_files": len(source_files),
            "scanned_source_bytes": source_bytes,
            "dependencies_checked": min(len(unique_deps), MAX_DEPENDENCIES),
            "findings": findings,
            "counts": severity_counts(findings),
            "warnings": list(dict.fromkeys(warnings)),
            "limitations": [
                "Static analysis cannot prove that a repository is safe or malicious.",
                "Repository code and build scripts are never executed.",
                "Only supported text files and pinned dependency formats are inspected.",
                "Public GitHub and upstream vulnerability-service availability and rate limits can affect coverage.",
            ],
        }


@app.get("/")
async def root() -> dict[str, str]:
    return {"name": "RepoShield API", "version": APP_VERSION, "health": "/health", "scan": "/api/scan"}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "reposhield-api", "version": APP_VERSION}


@app.post("/api/scan")
async def scan(body: ScanRequest, request: Request) -> dict[str, Any]:
    check_rate_limit(request)
    parsed = urlparse(body.repository_url)
    parts = [part for part in parsed.path.split("/") if part]
    owner, repo = parts[0], parts[1]
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    if scan_semaphore.locked():
        raise HTTPException(status_code=429, detail="The scanner is busy. Please retry in a moment.")
    async with scan_semaphore:
        return await scan_repository(owner, repo)
