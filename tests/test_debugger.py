"""Tests for Aletheia's dynamic layer: the Win32 x64 debugger engine.

Windows-only — skipped elsewhere. The debuggee is ``cmd.exe /c exit 7``: benign,
deterministic, native x64, and exits promptly, so the tests stay fast and stable.
"""
import os
import sys
from pathlib import Path

import pytest

if sys.platform != "win32":
    pytest.skip("debugger engine is Windows-only", allow_module_level=True)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aletheia.debugger import CONTEXT, DEBUG_EVENT, Debugger  # noqa: E402
from aletheia.pe import parse_bytes  # noqa: E402

import ctypes  # noqa: E402

CMD = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                   "System32", "cmd.exe")
CMDLINE = f'"{CMD}" /c exit 7'


# --- struct sanity: catches a mis-modelled layout before any live call -----
def test_context_layout_is_the_x64_context():
    assert ctypes.sizeof(CONTEXT) == 1232
    assert CONTEXT.ContextFlags.offset == 48
    assert CONTEXT.EFlags.offset == 68
    assert CONTEXT.Rax.offset == 120
    assert CONTEXT.Rip.offset == 248
    assert CONTEXT.FltSave.offset == 256          # XMM save area starts here
    # DEBUG_EVENT: 3 DWORD header (+4 pad) then the 160-byte event union.
    assert ctypes.sizeof(DEBUG_EVENT) == 176


# --- create-process, memory read, exit code --------------------------------
def test_spawn_reads_image_base_and_reports_exit_code():
    dbg = Debugger()
    seen = {}

    def on_create(d, ev):
        seen["created"] = True
        seen["base"] = ev.image_base
        seen["mz"] = d.read_memory(ev.image_base, 2)

    dbg.on_create_process = on_create
    pid = dbg.spawn(CMDLINE)
    assert pid > 0
    dbg.run()

    assert seen.get("created") is True
    assert seen.get("base", 0) != 0
    assert seen.get("mz") == b"MZ"          # image maps as an MZ/PE
    assert dbg.exit_code == 7


# --- software breakpoint at the PE entry point -----------------------------
def test_breakpoint_fires_at_entry_point():
    dbg = Debugger()
    state = {"hit": 0, "rip": None, "target": None}

    def on_create(d, ev):
        # Parse the mapped headers with the house PE reader to find the entry.
        headers = d.read_memory(ev.image_base, 0x1000)
        pe = parse_bytes(headers)
        assert pe.ok, f"failed to parse mapped PE: {pe.error}"
        target = ev.image_base + pe.entry_rva
        state["target"] = target

        def on_bp(dd, tid):
            state["hit"] += 1
            state["rip"] = dd.get_context(tid).Rip

        d.set_breakpoint(target, on_bp)

    dbg.on_create_process = on_create
    dbg.spawn(CMDLINE)
    dbg.run()

    assert state["hit"] == 1, "entry breakpoint should fire exactly once"
    assert state["rip"] == state["target"], "RIP must be rewound onto the bp"
    assert dbg.exit_code == 7               # ran cleanly through to exit
