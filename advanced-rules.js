(() => {
  "use strict";
  const engine = window.RepoShieldScanner;
  if (!engine || typeof engine.scanText !== "function") return;
  const scanBase = engine.scanText;
  const makeUrl = engine.sourceUrl;
  engine.scanText = function(text, path, owner, repo, branch, findings) {
    const output = scanBase(text, path, owner, repo, branch, findings || []);
    const file = String(path || "");
    const source = String(text || "");
    const lines = source.split(/\r?\n/);
    const add = (line, title, severity, description, remediation, category = "Supply chain") => {
      output.push({ severity, category, title, description, file, line,
        evidence: engine.redactEvidence(lines[line - 1] || ""),
        remediation, source_url: makeUrl(owner, repo, branch, file, line) });
    };

    if (/(^|\/)package\.json$/i.test(file)) {
      let manifest;
      try { manifest = JSON.parse(source); } catch { manifest = null; }
      for (const hook of ["preinstall", "install", "postinstall", "prepare"]) {
        const command = manifest?.scripts?.[hook];
        if (typeof command !== "string") continue;
        if (!/(?:curl|wget)\b[^\n]{0,180}(?:\|\s*(?:sh|bash)|-o\s*[-\w./]+)|\b(?:powershell|pwsh)\b[^\n]{0,100}-(?:enc|encodedcommand)\b|\b(?:eval|exec)\s*\(|\bnode\s+-e\b|\b(?:bash|sh)\s+-c\b/i.test(command)) continue;
        const found = lines.findIndex(line => line.includes(command));
        add(found < 0 ? 1 : found + 1, "Risky npm lifecycle script: " + hook,
          hook === "prepare" ? "medium" : "high",
          "This install-time hook contains a download, shell, or dynamic-execution pattern. Lifecycle scripts can run automatically when dependencies are installed; review the surrounding context.",
          "Inspect the command and referenced files. Remove unnecessary install hooks, pin trusted sources, and never install untrusted dependencies in a privileged environment.");
      }
      for (const group of ["dependencies", "devDependencies", "optionalDependencies"]) {
        const deps = manifest?.[group];
        if (!deps || typeof deps !== "object") continue;
        for (const [name, version] of Object.entries(deps)) {
          if (typeof version !== "string" || !/^(?:git\+|git:|https?:|github:|file:|\.{1,2}\/)/i.test(version)) continue;
          const found = lines.findIndex(line => line.includes(JSON.stringify(name)) && line.includes(JSON.stringify(version)));
          add(found < 0 ? 1 : found + 1, "Non-registry dependency source",
            /^(?:https?:|git\+|git:|github:)/i.test(version) ? "medium" : "low",
            "This dependency uses a URL, Git source, or local path rather than a normal registry version. Review source ownership and whether the reference is immutable.",
            "Verify the source is trusted and pin an immutable commit where possible.");
        }
      }
    }

    if (/^\.github\/workflows\/.*\.ya?ml$/i.test(file)) {
      lines.forEach((line, index) => {
        const lineNo = index + 1;
        if (/\brun\s*:\s*.*\$\{\{\s*github\.event\.inputs\.[\w-]+/i.test(line)) {
          add(lineNo, "Workflow input interpolated directly into shell", "high",
            "Manually supplied workflow inputs can be attacker-controlled. Embedding an expression directly in a shell command can enable shell injection.",
            "Pass the input through an environment variable, validate it, and treat it as data rather than shell source.", "Workflow");
        }
        if (/^\s*workflow_run\s*:/i.test(line)) {
          add(lineNo, "Privileged workflow_run trigger needs review", "medium",
            "workflow_run may execute with base-repository privileges even when an upstream workflow handled untrusted code. Review checkout and artifact trust boundaries.",
            "Use least-privilege permissions; do not execute upstream artifacts or check out untrusted pull-request code in a privileged workflow.", "Workflow");
        }
        if (/\b(?:actions\/download-artifact|download-artifact)@/i.test(line) && lines.some(value => /^\s*workflow_run\s*:/i.test(value))) {
          add(lineNo, "Artifact download in workflow_run pipeline", "medium",
            "Artifacts from a workflow_run pipeline may originate from untrusted pull-request code. Executing them in a privileged workflow can cross a trust boundary.",
            "Verify artifact provenance and treat downloaded content as untrusted data. Never execute it with secrets or write permissions.", "Workflow");
        }
      });
    }
    return output;
  };
})();