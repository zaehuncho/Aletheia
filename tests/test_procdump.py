"""Tests for the process-memory module dumper.

Windows-only — skipped elsewhere. Self-contained: the "target" is the current
Python process (``os.getpid()``), so there is no separate debuggee to spawn and
the test stays fast and deterministic. Every running Python on Windows has
``kernel32.dll`` loaded, which we use as the stable module to dump.
"""
import os
import sys
from pathlib import Path

import pytest

if sys.platform != "win32":
    pytest.skip("process dumper is Windows-only", allow_module_level=True)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aletheia import procdump  # noqa: E402
from aletheia.pe import parse_bytes  # noqa: E402


def _kernel32(modules):
    """Return the ModuleInfo whose name is kernel32.dll (case-insensitive)."""
    for m in modules:
        if m.name.lower() == "kernel32.dll":
            return m
    return None


# --- module enumeration ----------------------------------------------------
def test_list_modules_finds_kernel32():
    modules = procdump.list_modules(os.getpid())
    assert modules, "the current process must have loaded modules"
    for m in modules:
        assert m.base > 0, f"{m.name} has a zero base"
        assert m.size > 0, f"{m.name} has a zero size"
    assert _kernel32(modules) is not None, \
        "kernel32.dll should be loaded in the current process"


# --- dump a single stable module -------------------------------------------
def test_dump_module_reconstructs_kernel32_pe():
    pid = os.getpid()
    k32 = _kernel32(procdump.list_modules(pid))
    assert k32 is not None

    dumped = procdump.dump_module(pid, k32.base)
    assert dumped[:2] == b"MZ", "dump must start with the MZ header"

    pe = parse_bytes(dumped)
    assert pe.ok, f"reconstructed PE failed to parse: {pe.error}"
    assert pe.sections, "reconstructed PE should have at least one section"


# --- dump every module to disk ---------------------------------------------
def test_dump_process_writes_parseable_pes(tmp_path):
    results = procdump.dump_process(os.getpid(), str(tmp_path))
    assert results, "dump_process should report at least one module"

    ok_paths = [path for path, ok in results if ok]
    assert ok_paths, "at least one module should dump successfully"

    for path in ok_paths:
        assert os.path.isfile(path), f"reported ok but missing: {path}"
        with open(path, "rb") as fh:
            data = fh.read()
        pe = parse_bytes(data)
        assert pe.ok, f"dumped file did not parse as a PE: {path} ({pe.error})"
