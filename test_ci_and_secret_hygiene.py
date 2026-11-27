"""Phase 3a CI Pipeline & Deterministic Secret Hygiene Tests for CouncilEngine."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

FORBIDDEN_FILENAMES = (
    re.compile(r"^\.env$", re.IGNORECASE),
    re.compile(r"^\.env\.(?!example$|sample$|template$).+", re.IGNORECASE),
    re.compile(r"(?:^|/)id_rsa$", re.IGNORECASE),
    re.compile(r"(?:^|/)id_ed25519$", re.IGNORECASE),
)

SECRET_PATTERNS = {
    "private_key_pem": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    "github_pat": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{24,}\b"),
}

FIXTURE_EXEMPTIONS = {
    "test_ci_and_secret_hygiene.py",
    "test_redaction_and_dlp.py",
    "test_security_invariants.py",
}


def test_council_ci_workflow_enforces_ordered_gates() -> None:
    ci_path = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    assert ci_path.exists(), "CouncilEngine .github/workflows/ci.yml must exist"
    text = ci_path.read_text(encoding="utf-8")

    required_fragments = [
        "python -m pytest -q test_ci_and_secret_hygiene.py",
        "python -m pytest -q",
        "anti_wrapper_audit.py --target-dir . --baseline-file ANTI_WRAPPER_BASELINE.json --fail-on-regression",
        "test_dizzy_approval_contract.py",
        "pip-audit",
    ]
    for fragment in required_fragments:
        assert fragment in text, f"Missing required CI verification step: {fragment}"


def test_council_tracked_files_contain_no_leaked_secrets() -> None:
    proc = subprocess.run(
        ["git", "ls-files"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=True,
    )
    tracked_files = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    assert len(tracked_files) > 10

    leaks: list[str] = []
    for rel_path in tracked_files:
        if any(pattern.search(rel_path) for pattern in FORBIDDEN_FILENAMES):
            leaks.append(f"{rel_path}: forbidden credential file tracked in git")
            continue
        if rel_path in FIXTURE_EXEMPTIONS:
            continue
        if rel_path.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".ico", ".sqlite", ".db")):
            continue

        file_path = REPO_ROOT / rel_path
        if not file_path.is_file() or file_path.stat().st_size > 2 * 1024 * 1024:
            continue

        content = file_path.read_text(encoding="utf-8-sig", errors="replace")
        for rule_id, regex in SECRET_PATTERNS.items():
            if regex.search(content):
                leaks.append(f"{rel_path}: matched secret pattern {rule_id}")

    assert leaks == [], f"Secret hygiene scan failed: {leaks}"
