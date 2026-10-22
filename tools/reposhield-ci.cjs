#!/usr/bin/env node
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const scannerCore = require("../scanner-core.js");
const { scanText, parseDeps } = require("../advanced-rules.js")(scannerCore);
// Keep the CLI's coverage limits aligned with the browser scanner.
const SEVERITIES = ["critical",
"high",
"medium",
"low",
"info"];
const ALLOWED_EXTENSIONS = new Set(["js", "ts", "py", "sh", "ps1", "json", "yml", "yaml", "toml", "env", "txt", "md", "xml", "lock", "html", "pem", "key", "crt"]);
const IGNORED_DIRS = new Set([".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "coverage", "target", ".next", ".gradle"]);
const LIMITS = Object.freeze({
  files: 180,
  fileBytes: 250000,
  totalBytes: 3000000,
  dependencies: 60
});

function markdownEscape(value) {
  return String(value == null ? "": value)
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\\/g, "\\\\")
    .replace(/([\x60*_{}\[\]()#+.!|>~-])/g, "\\$1")
    .replace(/\s+/g, " ")
    .slice(0, 500);
}

function isSupportedFile(filePath) {
  const base = path.basename(filePath)
    .toLowerCase();
  const ext = path.extname(base)
    .replace(/^\./, "");
  return ALLOWED_EXTENSIONS.has(ext) || base === "package-lock.json" || (base.startsWith("requirements") && base.endsWith(".txt"));
}
// Traverse deterministically and exclude generated or installed dependencies.

function listFiles(root, limits = LIMITS) {
  const files = [],
  warnings = [];
  let oversizedFiles = 0,
  supportedCount = 0;

  function walk(directory, relativeDirectory) {
    let entries;
    try {
      entries = fs.readdirSync(directory, {
        withFileTypes: true
      })
        .sort((a, b) => a.name.localeCompare(b.name));
    } catch {
      warnings.push("Some directories could not be read; scan coverage may be incomplete.");
      return;
    }
    for (const entry of entries) {
      if (entry.name === "." || entry.name === "..") continue;
      const relativePath = relativeDirectory ? path.posix.join(relativeDirectory, entry.name): entry.name;
      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name)) walk(path.join(directory, entry.name), relativePath);
        continue;
      }
      if (!entry.isFile() || !isSupportedFile(relativePath)) continue;
      let stat;
      try {
        stat = fs.statSync(path.join(directory, entry.name));
      } catch {
        continue;
      }
      if (!stat.size) continue;
      supportedCount++;
      if (stat.size >= limits.fileBytes) {
        oversizedFiles++;
        continue;
      }
      files.push({
        path: relativePath,
        absolutePath: path.join(directory, entry.name),
        size: stat.size
      });
    }
  }
  walk(root, "");
  if (oversizedFiles) warnings.push(oversizedFiles + " supported file(s) at or above the per-file limit were skipped.");
  if (files.length > limits.files) warnings.push("Repository exceeds the " + limits.files + "-file scan limit; some files were not inspected.");
  if (supportedCount === 0) warnings.push("No supported source files or dependency manifests were found.");
  return {
    files: files.slice(0, limits.files),
    warnings,
    supportedCount,
    oversizedFiles
  };
}

function advisorySeverity(vulnerability) {
  const values = [vulnerability.database_specific && vulnerability.database_specific.severity,
  vulnerability.ecosystem_specific && vulnerability.ecosystem_specific.severity,
  ...(vulnerability.severity || [])
    .map(item => item.type === "CVSS_V3" || item.type === "CVSS_V4" ? item.score: "")].filter(Boolean)
    .map(value => String(value)
    .toUpperCase());
  for (const value of values) {
    if (value.includes("CRITICAL")) return "critical";
    if (value.includes("HIGH")) return "high";
    if (value.includes("MODERATE") || value.includes("MEDIUM")) return "medium";
    if (value.includes("LOW")) return "low";
  }
  return "medium";
}
// Advisory lookups are best-effort; outages become explicit coverage warnings.
async function lookupOSV(dependencies, fetchImpl = globalThis.fetch) {
  if (!dependencies.length) return {
    findings: [],
    warnings: []
  };
  if (typeof fetchImpl !== "function") return {
    findings: [],
    warnings: ["OSV lookup is unavailable in this Node.js runtime; dependency checks were skipped."]
  };
  const unique = [...new Map(dependencies.map(item => [[item.ecosystem, item.name, item.version].join(":"), item])).values()];
  const toCheck = unique.slice(0, LIMITS.dependencies);
  const warnings = [];
  if (unique.length > toCheck.length) warnings.push("Only " + LIMITS.dependencies + " pinned dependency versions are checked per scan.");
  try {
    const response = await fetchImpl("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({
        queries: toCheck.map(item => ({
          package: {
            name: item.name,
            ecosystem: item.ecosystem
          },
          version: item.version
        }))
      })
    });
    if (!response.ok) throw new Error("OSV HTTP " + response.status);
    const result = await response.json(),
    findings = [];
    (result.results || [])
      .forEach((item, index) => {
      for (const vulnerability of item.vulns || []) {
        findings.push({
          severity: advisorySeverity(vulnerability),
          category: "Dependency",
          title: toCheck[index].name + " " + toCheck[index].version + " — " + vulnerability.id,
          description: "This pinned dependency version matches a published OSV advisory. Review the advisory before prioritizing or upgrading.",
          evidence: "Package: " + toCheck[index].name + "\nVersion: " + toCheck[index].version,
          remediation: "Review the advisory and upgrade to a patched version if available.",
          source_url: "https://osv.dev/vulnerability/" + encodeURIComponent(vulnerability.id)
        });
      }
    });
    return {
      findings,
      warnings
    };
  } catch {
    return {
      findings: [],
      warnings: [...warnings,
      "OSV lookup unavailable or rate-limited; dependency results may be incomplete."]
    };
  }
}
// Read files as data only. This scanner never imports or executes target code.
async function scanDirectory(root, options = {}) {
  const resolvedRoot = path.resolve(root);
  if (!fs.existsSync(resolvedRoot) || !fs.statSync(resolvedRoot).isDirectory()) throw new Error("Target path does not exist or is not a directory: " + resolvedRoot);
  const owner = options.owner || "local",
  repo = options.repo || "repository",
  ref = options.ref || "main";
  const limits = options.limits || LIMITS,
  list = listFiles(resolvedRoot, limits);
  const warnings = [...list.warnings],
  findings = [],
  dependencies = [];
  let bytesRead = 0,
  scannedFiles = 0;
  for (const file of list.files) {
    if (bytesRead >= limits.totalBytes) {
      warnings.push("The source scan byte limit was reached; remaining files were not inspected.");
      break;
    }
    if (bytesRead + file.size > limits.totalBytes) {
      warnings.push("Some files were skipped to stay within the total source scan byte limit.");
      continue;
    }
    let content;
    try {
      content = fs.readFileSync(file.absolutePath, "utf8");
    } catch {
      warnings.push("Some source files could not be read; scan coverage may be incomplete.");
      continue;
    }
    if (content.includes("\u0000")) continue;
    bytesRead += Buffer.byteLength(content, "utf8");
    scannedFiles++;
    require("../scanner-core.js").scanText(content, file.path, owner, repo, ref, findings);
    const base = path.basename(file.path)
      .toLowerCase();
    if (base === "package-lock.json" || (base.startsWith("requirements") && base.endsWith(".txt"))) dependencies.push(...parseDeps(file.path, content));
  }
  if (options.lookupAdvisories !== false && dependencies.length) {
    const advisoryResult = await lookupOSV(dependencies, options.fetch);
    findings.push(...advisoryResult.findings);
    warnings.push(...advisoryResult.warnings);
  }
  const counts = Object.fromEntries(SEVERITIES.map(level => [level, findings.filter(item => item.severity === level).length]));
  findings.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || String(a.file || "").localeCompare(String(b.file || "")) || (a.line || 0) - (b.line || 0));
  return {
    generated_at: new Date().toISOString(),
    repository: {
      full_name: options.fullName || [owner,
      repo].join("/"),
      html_url: "https://github.com/" + owner + "/" + repo
    },
    scanned_files: scannedFiles,
    scanned_bytes: bytesRead,
    findings,
    counts,
    warnings: [...new Set(warnings)],
    limits: {
      ...limits
    }
  };
}
// Make the build threshold explicit and predictable for callers.

function shouldFail(findings, threshold = "critical") {
  if (threshold === "never") return false;
  if (!SEVERITIES.includes(threshold)) throw new Error("Invalid fail threshold: " + threshold);
  const thresholdIndex = SEVERITIES.indexOf(threshold);
  return findings.some(item => SEVERITIES.includes(item.severity) && SEVERITIES.indexOf(item.severity) <= thresholdIndex);
}
// Keep the report suitable for GitHub Actions' Markdown job summary.

function writeSummary(report, threshold, summaryPath) {
  const lines = [ "# RepoShield scan",
  "",
  "**Repository:** " + markdownEscape(report.repository.full_name),
  "**Files inspected:** " + report.scanned_files + "  ",
  "**Source bytes inspected:** " + report.scanned_bytes + "  ",
  "**Failure threshold:** " + markdownEscape(threshold),
  "",
  "## Findings by severity",
  "",
  "| Severity | Count |",
  "|---|---:|",
  ...SEVERITIES.map(level => "| " + level + " | " + report.counts[level] + " |"),
  ""];
  if (report.findings.length) {
    lines.push("## Findings", "");
    for (const item of report.findings) {
      const location = item.file ? markdownEscape(item.file + (item.line ? ":" + item.line: "")): "dependency advisory";
      lines.push("### [" + item.severity.toUpperCase() + "] " + markdownEscape(item.title), "");
      lines.push("- **Location:** " + location);
      lines.push("- **Category:** " + markdownEscape(item.category || "General"));
      lines.push("- **Details:** " + markdownEscape(item.description || ""));
      if (item.remediation) lines.push("- **Recommended action:** " + markdownEscape(item.remediation));
      if (item.source_url && /^https:\/\/(?:github\.com|osv\.dev)\//.test(item.source_url)) lines.push("- **Source:** " + item.source_url);
      if (item.evidence) {
        const tick = String.fromCharCode(96);
        lines.push("- **Redacted evidence:** " + tick + markdownEscape(item.evidence) + tick);
      }
      lines.push("");
    }
  } else {
    lines.push("No findings were detected by the enabled static checks. This does not guarantee the repository is safe.", "");
  }
  if (report.warnings.length) {
    lines.push("## Coverage warnings", "");
    for (const warning of report.warnings) lines.push("- " + markdownEscape(warning));
    lines.push("");
  }
  lines.push("_RepoShield performs bounded static checks only. Repository code is not executed by the scanner. False positives and false negatives are possible._", "");
  const body = lines.join("\n") + "\n";
  if (summaryPath) fs.appendFileSync(summaryPath, body);
  else process.stdout.write(body);
  return body;
}
async function main() {
  const threshold = String(process.env.REPOSHIELD_FAIL_ON || "critical")
    .toLowerCase();
  if (threshold !== "never" && !SEVERITIES.includes(threshold)) throw new Error("REPOSHIELD_FAIL_ON must be critical, high, medium, low, info, or never.");
  const target = process.argv[2] || process.env.REPOSHIELD_TARGET_DIR || process.env.GITHUB_WORKSPACE || process.cwd();
  const fullName = process.env.GITHUB_REPOSITORY || "local/repository";
  const parts = fullName.split("/");
  const owner = parts.length === 2 ? parts[0]: "local",
  repo = parts.length === 2 ? parts[1]: "repository";
  const ref = process.env.GITHUB_SHA || process.env.GITHUB_REF_NAME || "main";
  const report = await scanDirectory(target, {
    owner,
    repo,
    ref,
    fullName
  });
  writeSummary(report, threshold, process.env.GITHUB_STEP_SUMMARY);
  if (process.env.REPOSHIELD_REPORT_PATH) fs.writeFileSync(process.env.REPOSHIELD_REPORT_PATH, JSON.stringify(report, null, 2) + "\n");
  if (shouldFail(report.findings, threshold)) {
    process.stderr.write("RepoShield: findings met the configured failure threshold (" + threshold + ").\n");
    process.exitCode = 1;
  } else {
    process.stdout.write("RepoShield: scan completed; no findings met the configured failure threshold (" + threshold + ").\n");
  }
}
if (require.main === module) main().catch (error => {
  process.stderr.write("RepoShield error: " + error.message + "\n");
  process.exitCode = 2;
});
module.exports = {
  LIMITS,
  markdownEscape,
  isSupportedFile,
  listFiles,
  lookupOSV,
  scanDirectory,
  shouldFail,
  writeSummary
};
