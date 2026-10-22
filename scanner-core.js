(function(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.RepoShieldScanner = api;
})(typeof window !== "undefined" ? window: (typeof globalThis !== "undefined" ? globalThis: this), function() {
  "use strict";
  function isPlaceholder(value) {
    const v = String(value || "").trim().toLowerCase();
    if (!v)return true;
    return /^(?:your(?:[-_\s]|$)|replace(?:[-_\s]|$)|insert(?:[-_\s]|$)|example(?:[-_\s]|$)|sample(?:[-_\s]|$)|dummy(?:[-_\s]|$)|fake(?:[-_\s]|$)|change(?:me|it)(?:[-_\s]|$)|redacted(?:[-_\s]|$)|placeholder(?:[-_\s]|$)|x{4,}(?:[-_\s]|$)|<|\$|process\.env\b|os\.(?:getenv|environ)\b|(?:none|null|undefined)$)/i.test(v) || /^test(?:[-_\s](?:value|password|key|token|secret|credential)|$)/i.test(v);
  }
  function tokenIsPlaceholder(value) {
    const suffix = String(value || "").replace(/^(?:ghp_|github_pat_|xox[bp]-|AIza|AKIA)/i, "");
    return isPlaceholder(suffix) || /(?:example|placeholder|dummy|fake|redacted|your(?:token|key|secret)|x{5,})/i.test(suffix);
  }
  function redactEvidence(line) {
    return String(line).replace(/(?:ghp_|github_pat_)[A-Za-z0-9_]{8,}/g, "[REDACTED]").replace(/glpat-[A-Za-z0-9_-]{20,}/g, "[REDACTED]").replace(/npm_[A-Za-z0-9]{30,}/g, "[REDACTED]").replace(/sk_live_[A-Za-z0-9]{16,}/g, "[REDACTED]").replace(/sk-(?:proj-)?[A-Za-z0-9_-]{20,}/g, "[REDACTED]").replace(/xox[bp]-[A-Za-z0-9-]{8,}/g, "[REDACTED]").replace(/AIza[A-Za-z0-9_-]{20,}/g, "[REDACTED]").replace(/\bAKIA[A-Z0-9]{16}\b/g, "[REDACTED]").replace(/(\b[\w.-]*(?:password|passwd|client_secret|api_key|secret_key|access_token|aws_secret_access_key|aws_session_token|stripe_secret_key|private_key)\b\s*[:=]\s*["']?)[^"'\s,;#}\]]+/ig, "$1[REDACTED]").replace(/(\bBearer\s+)[A-Za-z0-9._~-]{20,}/ig, "$1[REDACTED]").slice(0, 180);
  }
  function sourceUrl(owner, repo, branch, path, line) {
    const branchPath = String(branch || "main").split("/").map(encodeURIComponent).join("/");
    const filePath = String(path || "").split("/").map(encodeURIComponent).join("/");
    return "https://github.com/" + owner + "/" + repo + "/blob/" + branchPath + "/" + filePath + "#L" + line;
  }
  function scanText(text, path, owner, repo, branch, findings) {
    const output = findings || [];
    const source = String(text);
    const lines = source.split(/\r?\n/);
    const isWorkflowFile = String(path).startsWith(".github/workflows/");
    const hasPullRequestTarget = isWorkflowFile && /\bpull_request_target\s*:/i.test(source);
    lines.forEach((line, index) => {
      let title = "",
      severity = "high",
      category = "Secret";
      const privateKey = line.match(/-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/i);
      const githubToken = line.match(/(?:ghp_|github_pat_)[A-Za-z0-9_]{8,}/);
      const gitlabToken = line.match(/glpat-[A-Za-z0-9_-]{20,}/);
      const npmToken = line.match(/npm_[A-Za-z0-9]{30,}/);
      const stripeToken = line.match(/sk_live_[A-Za-z0-9]{16,}/);
      const openAIToken = line.match(/sk-(?:proj-)?[A-Za-z0-9_-]{20,}/);
      const slackToken = line.match(/xox[bp]-[A-Za-z0-9-]{8,}/);
      const googleToken = line.match(/AIza[A-Za-z0-9_-]{20,}/);
      const awsKey = line.match(/\bAKIA[A-Z0-9]{16}\b/);
      const bearerToken = line.match(/\bBearer\s+([A-Za-z0-9._~-]{20,})/i);
      const genericAssignment = line.match(/\b[\w.-]*(?:password|passwd|client_secret|api_key|secret_key|access_token|aws_secret_access_key|aws_session_token|stripe_secret_key|private_key)\s*[:=]\s*["']?([^"'\s,;#}\]]+)/i);
      if (privateKey) {
        title = "Private key material";
        severity = "critical";
      } else if (githubToken && !tokenIsPlaceholder(githubToken[0])) title = "Possible GitHub credential";
      else if (gitlabToken && !tokenIsPlaceholder(gitlabToken[0])) title = "Possible GitLab credential";
      else if (npmToken && !tokenIsPlaceholder(npmToken[0])) title = "Possible npm token";
      else if (stripeToken && !tokenIsPlaceholder(stripeToken[0])) title = "Possible Stripe secret key";
      else if (openAIToken && !tokenIsPlaceholder(openAIToken[0])) title = "Possible OpenAI API key";
      else if (slackToken && !tokenIsPlaceholder(slackToken[0])) title = "Possible Slack credential";
      else if (googleToken && !tokenIsPlaceholder(googleToken[0])) title = "Possible Google API key";
      else if (awsKey && !tokenIsPlaceholder(awsKey[0])) title = "Possible cloud access key";
      else if (bearerToken && !tokenIsPlaceholder(bearerToken[1])) title = "Possible hard-coded bearer token";
      else if (genericAssignment && line.length > 25 && !isPlaceholder(genericAssignment[1])) title = "Possible hard-coded credential";
      if (title) {
        output.push({
          severity,
          category,
          title,
          description: "This line resembles a credential pattern. It may be a false positive; verify whether the value is real.",
          file: path,
          line: index + 1,
          evidence: redactEvidence(line),
          remediation: "If real, revoke or rotate the credential, remove it from source, and consider cleaning Git history.",
          source_url: sourceUrl(owner, repo, branch, path, index + 1)
        });
      }
      const isWorkflow = String(path).startsWith(".github/workflows/");
      if (isWorkflow && /\bpermissions\s*:\s*write-all\b/i.test(line)) {
        output.push({
          severity: "high",
          category: "Workflow",
          title: "Broad workflow permissions",
          description: "The workflow grants write access broadly, increasing the impact of a compromised action or injected command.",
          file: path,
          line: index + 1,
          evidence: redactEvidence(line),
          remediation: "Declare permissions explicitly and grant only the minimum required scope to each job.",
          source_url: sourceUrl(owner, repo, branch, path, index + 1)
        });
      }
      if (isWorkflow && /\bpull_request_target\s*:/i.test(line)) {
        output.push({
          severity: "high",
          category: "Workflow",
          title: "Privileged pull_request_target trigger",
          description: "This event can run with base-repository privileges. Checking out or executing untrusted pull-request content in the same workflow can expose secrets or write permissions.",
          file: path,
          line: index + 1,
          evidence: redactEvidence(line),
          remediation: "Avoid checking out or executing pull-request head code in this privileged workflow. Prefer pull_request for untrusted validation and keep permissions minimal.",
          source_url: sourceUrl(owner, repo, branch, path, index + 1)
        });
      }
      if (hasPullRequestTarget && /\bref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}/i.test(line)) {
        output.push({
          severity: "critical",
          category: "Workflow",
          title: "Untrusted pull request checked out by privileged workflow",
          description: "This workflow uses pull_request_target and checks out a pull-request head ref. Untrusted code may then run with access to base-repository secrets or write permissions.",
          file: path,
          line: index + 1,
          evidence: redactEvidence(line),
          remediation: "Do not check out or execute pull-request head code in a pull_request_target workflow. Use pull_request for untrusted validation, or isolate any required processing in a least-privilege environment without secrets.",
          source_url: sourceUrl(owner, repo, branch, path, index + 1)
        });
      }
      if (isWorkflow && /\buses\s*:\s*[^\s#]+@(?:main|master|v?\d+(?:\.\d+){0,2})\s*(?:#.*)?$/i.test(line.trim())) {
        output.push({
          severity: "medium",
          category: "Workflow",
          title: "Action uses a mutable reference",
          description: "A branch or version tag can move, so the action code may change without a reviewed workflow diff.",
          file: path,
          line: index + 1,
          evidence: redactEvidence(line),
          remediation: "Pin third-party actions to a verified full commit SHA and update pins deliberately.",
          source_url: sourceUrl(owner, repo, branch, path, index + 1)
        });
      }
      if (isWorkflow && /\brun\s*:\s*.*\$\{\{\s*github\.event\.(?:pull_request\.(?:title|body|head\.ref)|issue\.(?:title|body)|comment\.body)/i.test(line)) {
        output.push({
          severity: "high",
          category: "Workflow",
          title: "Untrusted event data interpolated into shell",
          description: "Pull-request or issue text can be attacker-controlled. Direct interpolation into a shell command can create command injection.",
          file: path,
          line: index + 1,
          evidence: redactEvidence(line),
          remediation: "Pass event values through environment variables and quote them carefully; avoid eval and shell string construction. Treat the value as untrusted input.",
          source_url: sourceUrl(owner, repo, branch, path, index + 1)
        });
      }
      if (isWorkflow && /\bpersist-credentials\s*:\s*true\b/i.test(line)) {
        output.push({
          severity: "low",
          category: "Workflow",
          title: "Checkout persists repository credentials",
          description: "The checkout action leaves its token in Git configuration for later steps, where an untrusted or compromised step may access it.",
          file: path,
          line: index + 1,
          evidence: redactEvidence(line),
          remediation: "Set persist-credentials: false unless a later step explicitly requires authenticated Git operations.",
          source_url: sourceUrl(owner, repo, branch, path, index + 1)
        });
      }
      if (!/\.(?:md|txt)$/i.test(String(path))) {
        let risk = "",
        riskSeverity = "medium";
        if (/(?:curl|wget)\b[^|]{0,240}\|\s*(?:sh|bash|zsh)\b/i.test(line)) {
          risk = "Remote script piped directly to a shell";
          riskSeverity = "high";
        } else if (/powershell(?:\.exe)?\b.{0,100}-(?:enc|encodedcommand)\b/i.test(line)) {
          risk = "PowerShell encoded command";
          riskSeverity = "high";
        } else if (/\beval\s*\(\s*(?:atob|Buffer\.from)\s*\(/i.test(line)) {
          risk = "Dynamic execution of encoded content";
          riskSeverity = "high";
        } else if (/(?:execSync|spawn|child_process)\s*\([^)]{0,180}(?:https?:\/\/|curl\b|wget\b)/i.test(line)) {
          risk = "Process execution combined with remote content";
          riskSeverity = "medium";
        }
        if (risk) {
          output.push({
            severity: riskSeverity,
            category: "Suspicious code",
            title: risk,
            description: "This pattern can be used for unsafe remote-code execution or obfuscation. Inspect surrounding code and confirm its purpose.",
            file: path,
            line: index + 1,
            evidence: redactEvidence(line),
            remediation: "Avoid piping remote scripts directly to shells. Verify downloads, pin trusted sources, and remove unnecessary dynamic execution.",
            source_url: sourceUrl(owner, repo, branch, path, index + 1)
          });
        }
      }
    });
    return output;
  }
  function parseDeps(path, text) {
    const out = [];
    const base = String(path).split("/").pop().toLowerCase();
    const add = (name, version, ecosystem) => {
      if (name && /^\d+\.\d+\.\d+/.test(version)) out.push({
        name,
        version,
        ecosystem
      });
    };
    try {
      if (base === "package-lock.json") {
        const parsed = JSON.parse(text);
        const packages = parsed.packages || {};
        for (const[packagePath, pkg] of Object.entries(packages)) {
          const marker = "node_modules/";
          const offset = packagePath.lastIndexOf(marker);
          if (offset >= 0 && pkg.version) add(packagePath.slice(offset + marker.length), String(pkg.version), "npm");
        }
        if (Object.keys(packages).length === 0 && parsed.dependencies) {
          const walk = dependencies => {
            for (const[name, pkg] of Object.entries(dependencies || {})) {
              if (pkg && pkg.version) add(name, String(pkg.version), "npm");
              if (pkg && pkg.dependencies) walk(pkg.dependencies);
            }
          };
          walk(parsed.dependencies);
        }
      } else if (base.startsWith("requirements") && base.endsWith(".txt")) {
        for (const line of String(text).split(/\r?\n/)) {
          const parts = line.split("==");
          if (parts.length === 2) add(parts[0].trim(), parts[1].trim().split(";")[0].trim(), "PyPI");
        }
      }
    } catch {}
    return out;
  }
  return {
    isPlaceholder,
    tokenIsPlaceholder,
    redactEvidence,
    scanText,
    parseDeps,
    sourceUrl
  };
});
