(() => {
  "use strict";
  const $ = (selector) => document.querySelector(selector);
  const form = $("#scan-form");
  const repoInput = $("#repo-url");
  const scanButton = $("#scan-button");
  const status = $("#scan-status");
  const resultsSection = $("#results");
  const findingsList = $("#findings-list");
  const severityFilter = $("#severity-filter");
  let currentReport = null;
  $("#year").textContent = new Date().getFullYear();

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const severityLabels = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

  function setStatus(message, kind = "") {
    status.textContent = message;
    status.className = "status-message" + (kind ? " " + kind : "");
  }

  function setBusy(busy) {
    scanButton.disabled = busy;
    scanButton.querySelector(".button-label").textContent = busy ? "Scanning repository…" : "Analyze repository";
    scanButton.querySelector(".button-arrow").innerHTML = busy ? '<span class="spinner" aria-hidden="true"></span>' : "↗";
  }

  function normalizeRepositoryUrl(value) {
    let parsed;
    try { parsed = new URL(value.trim()); } catch { throw new Error("Enter a valid GitHub repository URL."); }
    if (parsed.protocol !== "https:" || parsed.hostname.toLowerCase() !== "github.com" || parsed.username || parsed.password || parsed.port) {
      throw new Error("Only HTTPS URLs on github.com are supported.");
    }
    const parts = parsed.pathname.split("/").filter(Boolean);
    if (parts.length !== 2) throw new Error("Use a repository URL in the form https://github.com/owner/repository.");
    const clean = (part) => part.replace(/\.git$/i, "");
    const owner = clean(parts[0]);
    const repo = clean(parts[1]);
    if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(owner) || !/^[A-Za-z0-9_.-]{1,100}$/.test(repo) || repo === "." || repo === "..") {
      throw new Error("That repository URL contains an invalid owner or repository name.");
    }
    return "https://github.com/" + encodeURIComponent(owner) + "/" + encodeURIComponent(repo);
  }

  function make(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function severityCount(findings, severity) {
    return findings.filter((finding) => String(finding.severity || "info").toLowerCase() === severity).length;
  }

  function renderSummary(report) {
    const findings = Array.isArray(report.findings) ? report.findings : [];
    const counts = report.counts || {};
    const critical = counts.critical ?? severityCount(findings, "critical");
    const high = counts.high ?? severityCount(findings, "high");
    const medium = counts.medium ?? severityCount(findings, "medium");
    const low = (counts.low ?? severityCount(findings, "low")) + (counts.info ?? severityCount(findings, "info"));
    const total = findings.length;
    $("#count-critical").textContent = critical;
    $("#count-high").textContent = high;
    $("#count-medium").textContent = medium;
    $("#count-low").textContent = low;

    const summary = $("#scan-summary");
    summary.replaceChildren();
    const level = critical ? "critical" : high ? "high" : medium ? "medium" : low ? "low" : "clean";
    summary.dataset.level = level;
    const icon = make("div", "summary-icon", level === "clean" ? "✓" : level === "critical" || level === "high" ? "!" : "⌁");
    icon.setAttribute("aria-hidden", "true");
    const copy = make("div", "summary-copy");
    const headline = make("strong", "", total ? total + " finding" + (total === 1 ? "" : "s") + " require review" : "No findings from enabled checks");
    const detail = make("p", "", total ? "Review the evidence and recommendations below. Findings can be false positives." : "No issues were flagged by the checks that ran. This does not prove the repository is safe.");
    copy.append(headline, detail);
    const score = make("div", "summary-score");
    const scoreValue = critical ? "CRITICAL" : high ? "HIGH" : medium ? "MODERATE" : low ? "LOW" : "CLEAR";
    score.append(make("strong", "", scoreValue), make("span", "", "HIGHEST SEVERITY"));
    summary.append(icon, copy, score);

    const repository = report.repository || {};
    const name = repository.full_name || repository.name || "GitHub repository";
    const meta = $("#repo-meta");
    meta.replaceChildren();
    const link = make("a", "", name);
    link.href = repository.html_url || report.repository_url || "#";
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.style.color = "inherit";
    link.style.textDecoration = "underline";
    meta.append(link, document.createTextNode("  ·  " + (report.scanned_files ?? 0) + " files inspected"));
    if (report.generated_at) meta.append(document.createTextNode("  ·  " + new Date(report.generated_at).toLocaleString()));
    if (Array.isArray(report.warnings) && report.warnings.length) {
      const warning = make("p", "report-footnote", report.warnings.join(" "));
      meta.append(document.createElement("br"), warning);
    }
    renderFindings();
  }

  function renderFinding(finding) {
    const severity = String(finding.severity || "info").toLowerCase();
    const card = make("article", "finding-card");
    const main = make("div", "finding-main");
    const mark = make("span", "severity-mark " + (severityOrder[severity] !== undefined ? severity : "info"));
    mark.setAttribute("aria-hidden", "true");
    const content = make("div", "finding-content");
    const titleRow = make("div", "finding-title-row");
    titleRow.append(make("span", "finding-title", finding.title || "Security finding"), make("span", "severity-badge " + (severityOrder[severity] !== undefined ? severity : "info"), severityLabels[severity] || "Info"));
    content.append(titleRow, make("p", "finding-description", finding.description || "Review this indicator in context."));
    const meta = make("div", "finding-meta");
    if (finding.category) meta.append(make("span", "", String(finding.category).replace(/_/g, " ").toUpperCase()));
    if (finding.file) {
      const location = make("span", "file-path", finding.file + (finding.line ? ":" + finding.line : ""));
      meta.append(location);
    }
    if (finding.source_url) {
      const source = make("a", "", "Open source ↗");
      source.href = finding.source_url;
      source.target = "_blank";
      source.rel = "noopener noreferrer";
      meta.append(source);
    }
    content.append(meta);
    if (finding.remediation) {
      const fix = make("div", "finding-fix");
      fix.append(make("strong", "", "Recommended action: "), document.createTextNode(finding.remediation));
      content.append(fix);
    }
    main.append(mark, content);
    card.append(main);
    if (finding.evidence) {
      const details = document.createElement("details");
      details.className = "finding-details";
      details.append(make("summary", "", "View redacted evidence"));
      details.append(make("pre", "", finding.evidence));
      card.append(details);
    }
    return card;
  }

  function renderFindings() {
    if (!currentReport) return;
    const all = Array.isArray(currentReport.findings) ? currentReport.findings.slice() : [];
    all.sort((a, b) => (severityOrder[String(a.severity || "info").toLowerCase()] ?? 4) - (severityOrder[String(b.severity || "info").toLowerCase()] ?? 4));
    const filter = severityFilter.value;
    const filtered = filter === "all" ? all : all.filter((item) => String(item.severity || "info").toLowerCase() === filter);
    findingsList.replaceChildren();
    if (!filtered.length) {
      const empty = make("div", "empty-state");
      empty.append(make("strong", "", all.length ? "No findings at this severity" : "No findings from the checks that ran"), make("p", "", all.length ? "Choose another severity to view other results." : "This is not a guarantee of safety. See the scan coverage and limitations."));
      findingsList.append(empty);
      return;
    }
    const fragment = document.createDocumentFragment();
    filtered.forEach((finding) => fragment.append(renderFinding(finding)));
    findingsList.append(fragment);
  }

  async function runScan(repositoryUrl) {
    const apiBase = String(window.REPOSHIELD_CONFIG?.apiBase || "").trim().replace(/\/$/, "");
    if (!apiBase) {
      throw new Error("The scanning service is not connected yet. The frontend is deployed separately; configure apiBase in config.js after the backend is deployed.");
    }
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 150000);
    try {
      const response = await fetch(apiBase + "/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ repository_url: repositoryUrl }),
        signal: controller.signal,
        cache: "no-store"
      });
      let payload;
      try { payload = await response.json(); } catch { throw new Error("The scanner returned an unreadable response. Try again later."); }
      if (!response.ok) {
        const detail = typeof payload.detail === "string" ? payload.detail : (payload.error || "The scan could not be completed.");
        throw new Error(detail);
      }
      return payload;
    } catch (error) {
      if (error.name === "AbortError") throw new Error("The scan timed out. Try a smaller repository.");
      if (error instanceof TypeError) throw new Error("Could not reach the scanning service. It may be starting, unavailable, or blocked by CORS.");
      throw error;
    } finally {
      window.clearTimeout(timeout);
    }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    let repositoryUrl;
    try { repositoryUrl = normalizeRepositoryUrl(repoInput.value); }
    catch (error) { setStatus(error.message, "error"); repoInput.focus(); return; }

    setBusy(true);
    setStatus("Validating repository and inspecting source files. Repository code will not be executed.");
    resultsSection.hidden = true;
    try {
      currentReport = await runScan(repositoryUrl);
      if (!currentReport || !Array.isArray(currentReport.findings)) throw new Error("The scanner response did not contain a valid findings list.");
      renderSummary(currentReport);
      resultsSection.hidden = false;
      setStatus("Scan completed. Review each finding before taking action.", "success");
      resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
      setStatus(error.message || "The scan failed unexpectedly. Please try again.", "error");
    } finally {
      setBusy(false);
    }
  });

  severityFilter.addEventListener("change", renderFindings);
  $("#export-report").addEventListener("click", () => {
    if (!currentReport) return;
    const safeName = String(currentReport.repository?.full_name || "repository").replace(/[^A-Za-z0-9_.-]/g, "_");
    const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = make("a");
    anchor.href = url;
    anchor.download = "reposhield-" + safeName + "-report.json";
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  });
})();