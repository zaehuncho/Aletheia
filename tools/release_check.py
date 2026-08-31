"""Fail CI when public-release invariants drift."""

from __future__ import annotations

import json
import re
import subprocess
import tomllib
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "0.2.0"


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8-sig")


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def main() -> int:
    errors: list[str] = []

    required = (
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
        "README.md",
        "SECURITY.md",
        "CHANGELOG.md",
        "pyproject.toml",
        "uv.lock",
        "rust/Cargo.lock",
        "rust/aletheia-app/package-lock.json",
        "docs/python-engine.md",
        "docs/limits.md",
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
    )
    for path in required:
        require((ROOT / path).is_file(), f"missing required file: {path}", errors)

    pyproject = tomllib.loads(read("pyproject.toml"))
    workspace = tomllib.loads(read("rust/Cargo.toml"))
    app_cargo = tomllib.loads(read("rust/aletheia-app/src-tauri/Cargo.toml"))
    package = json.loads(read("rust/aletheia-app/package.json"))
    tauri = json.loads(read("rust/aletheia-app/src-tauri/tauri.conf.json"))
    versions = {
        "pyproject.toml": pyproject["project"]["version"],
        "rust/Cargo.toml": workspace["workspace"]["package"]["version"],
        "src-tauri/Cargo.toml": app_cargo["package"]["version"],
        "package.json": package["version"],
        "tauri.conf.json": tauri["version"],
    }
    for path, version in versions.items():
        require(version == EXPECTED_VERSION, f"{path} has version {version}", errors)

    require(package["devDependencies"].get("@tauri-apps/cli") == "2.11.4",
            "Tauri CLI must remain exactly pinned", errors)
    csp = tauri.get("app", {}).get("security", {}).get("csp")
    require(isinstance(csp, str) and "default-src 'self'" in csp,
            "Tauri CSP must be a restrictive string", errors)
    capabilities = json.loads(read("rust/aletheia-app/src-tauri/capabilities/default.json"))
    require("core:default" not in capabilities["permissions"],
            "Tauri capability must not grant the broad core:default set", errors)
    require("dialog:allow-open" in capabilities["permissions"],
            "Tauri capability must grant only the needed file-open dialog", errors)

    workflow_text = read(".github/workflows/ci.yml") + read(".github/workflows/release.yml")
    actions = re.findall(r"^\s*uses:\s*([^\s#]+)", workflow_text, flags=re.MULTILINE)
    require(bool(actions), "no GitHub Actions found", errors)
    for action in actions:
        require(bool(re.fullmatch(r"[^@]+@[0-9a-f]{40}", action)),
                f"GitHub Action is not pinned to a commit: {action}", errors)

    driver = read("hv/src/driver.c")
    sensitive_codes = re.findall(r"#define\s+IOCTL_ALETHEIA_(?:START|STOP|READ_GPA)[^\n]+", driver)
    require(len(sensitive_codes) == 3, "missing sensitive HV IOCTL definitions", errors)
    require(all("FILE_ANY_ACCESS" not in line for line in sensitive_codes),
            "sensitive HV IOCTL uses FILE_ANY_ACCESS", errors)
    require("IoCreateDeviceSecure" in driver and "SDDL_DEVOBJ_SYS_ALL_ADM_ALL" in driver,
            "HV device must use an administrator-only secure ACL", errors)
    require("SeDebugPrivilege" in driver, "HV control plane lacks a privilege gate", errors)
    require("VmOnlyAcknowledged" in read("hv/build.ps1"),
            "HV build must retain its explicit VM-only gate", errors)

    require("private vulnerability reporting form" in read("SECURITY.md"),
            "SECURITY.md must use private reporting", errors)
    require("not a sandbox" in read("README.md").lower(),
            "README lacks the dynamic-analysis sandbox warning", errors)

    skipped_dirs = {".git", ".venv", "build", "dist", "node_modules", "target"}
    for markdown in ROOT.rglob("*.md"):
        if any(part in skipped_dirs for part in markdown.parts):
            continue
        body = markdown.read_text(encoding="utf-8-sig")
        for link in re.findall(r"!?\[[^\]]*\]\(([^)]+)\)", body):
            link = link.strip().strip("<>").split(maxsplit=1)[0]
            parsed = urlsplit(link)
            if parsed.scheme or link.startswith("#"):
                continue
            destination = markdown.parent / unquote(parsed.path)
            require(destination.exists(),
                    f"broken local link in {markdown.relative_to(ROOT)}: {link}", errors)

    metadata = read("rust/Cargo.toml") + read("rust/aletheia-app/src-tauri/Cargo.toml")
    require(not re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", metadata),
            "public package metadata contains a personal email address", errors)

    tracked = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.splitlines()
    forbidden = (".exe", ".dll", ".sys", ".msi", ".pdb", ".pfx", ".p12", ".pem", ".key")
    bad_artifacts = [path for path in tracked if path.lower().endswith(forbidden)]
    require(not bad_artifacts, f"tracked binary/key artifacts: {bad_artifacts}", errors)

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print(f"release policy OK: Aletheia {EXPECTED_VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
