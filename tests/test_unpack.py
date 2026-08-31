"""Tests for the dynamic unpacker: write-then-execute detection.

Windows-only -- skipped elsewhere. Self-contained: we build the "packed" scenario
ourselves against a benign, deterministic debuggee (``cmd.exe /c exit 7``). No
external packed sample is needed.

Checks, cheapest first:

* ``test_is_image_address_predicate_boundaries`` -- the pure classification
  predicate (half-open ranges, multiple modules) with no live process.
* ``test_is_image_address_classifies_live_image_vs_alloc`` -- on a real spawned
  process, an in-image address classifies True and a fresh ``VirtualAllocEx``'d
  region classifies False (the core predicate, live). cmd then exits 7 untouched.
* ``test_is_dynamic_executable_gate`` -- the memory-type gate on a real process:
  a ``VirtualAllocEx(PAGE_EXECUTE_READWRITE)`` region (MEM_PRIVATE + executable)
  is True; the image base (MEM_IMAGE) is False; an unmapped high address is False.
* ``test_monitor_detects_execution_in_allocated_region`` -- the full write-then-
  execute integration: write a stub into a fresh RWX allocation, borrow the main
  thread at its entry point to run one instruction of that stub, and assert the
  monitor's single-step scan reports execution OUTSIDE the image, inside the
  allocation. The thread's original context is restored so cmd still exits 7.
* ``test_run_unpack_reports_result_shape`` -- the ``run_unpack`` plumbing on
  benign cmd.exe: with the memory-type gate the loader thunks are no longer a
  false positive, so detection is False and cmd exits 7.
"""
import ctypes
import os
import sys
from ctypes import POINTER, byref, sizeof
from pathlib import Path

import pytest

if sys.platform != "win32":
    pytest.skip("dynamic unpacker is Windows-only", allow_module_level=True)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aletheia.debugger import Debugger  # noqa: E402
from aletheia.pe import parse_bytes  # noqa: E402
from aletheia.unpack import (  # noqa: E402
    ImageMap, UnpackMonitor, is_dynamic_executable, run_unpack,
)

CMD = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                   "System32", "cmd.exe")
CMDLINE = f'"{CMD}" /c exit 7'

# xor rax, rax ; ret  -- 3-byte instruction + a 1-byte ret. Only the xor ever
# executes (the single-step traps right after it); the ret is never reached.
STUB = b"\x48\x31\xC0\xC3"

# --- VirtualAllocEx (allocate executable memory in the debuggee) ------------
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_VirtualAllocEx = _k32.VirtualAllocEx
_VirtualAllocEx.restype = ctypes.c_void_p
_VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                            ctypes.c_uint32, ctypes.c_uint32]


def _alloc_rwx(process_handle: int, size: int = 0x1000) -> int:
    """VirtualAllocEx an RWX page in the debuggee; returns its base address."""
    addr = _VirtualAllocEx(process_handle, None, size,
                           MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not addr:
        raise ctypes.WinError(ctypes.get_last_error(), "VirtualAllocEx failed")
    return int(addr)


# ===========================================================================
# 1. the predicate in isolation (no live process)
# ===========================================================================
def test_is_image_address_predicate_boundaries():
    m = ImageMap()
    m.add(0x140000000, 0x10000)          # a main image
    m.add(0x7FFAB0000000, 0x2000)        # a "DLL"

    assert m.is_image_address(0x140000000)                # base is inclusive
    assert m.is_image_address(0x140000000 + 0xFFFF)       # last mapped byte
    assert not m.is_image_address(0x140000000 + 0x10000)  # end is exclusive
    assert not m.is_image_address(0x140000000 - 1)        # just below the base
    assert m.is_image_address(0x7FFAB0000000 + 0x100)     # inside the DLL
    assert not m.is_image_address(0x50000)                # a fresh-alloc-like addr

    m.remove(0x7FFAB0000000)
    assert not m.is_image_address(0x7FFAB0000000 + 0x100)  # gone after remove


# ===========================================================================
# 2. the predicate on a real spawned process (image vs. VirtualAllocEx region)
# ===========================================================================
def test_is_image_address_classifies_live_image_vs_alloc():
    dbg = Debugger()
    state = {}

    def on_create(d, ev):
        alloc = _alloc_rwx(ev.process_handle)
        state["alloc"] = alloc
        state["base"] = ev.image_base
        # main image is recorded by the monitor BEFORE this chained handler runs
        state["in_image"] = mon.is_image_address(ev.image_base + 0x40)
        state["out_image"] = mon.is_image_address(alloc)

    dbg.on_create_process = on_create             # set BEFORE constructing monitor
    mon = UnpackMonitor(dbg, auto_arm=False)      # chains on_create; records images

    dbg.spawn(CMDLINE)
    dbg.run()

    assert state["base"] and state["base"] != 0
    assert state["in_image"] is True, "an in-image address must classify True"
    assert state["out_image"] is False, "a VirtualAllocEx region must classify False"
    assert dbg.exit_code == 7                      # cmd ran untouched to exit


# ===========================================================================
# 2b. the memory-type gate (MEM_PRIVATE + executable) on a real process
# ===========================================================================
def test_is_dynamic_executable_gate():
    dbg = Debugger()
    state = {}

    def on_create(d, ev):
        handle = ev.process_handle
        alloc = _alloc_rwx(handle)                 # MEM_PRIVATE + PAGE_EXECUTE_READWRITE
        state["alloc_private_exec"] = is_dynamic_executable(handle, alloc)
        # The image base is MEM_IMAGE, not MEM_PRIVATE -> not a dynamic payload.
        state["image_base"] = is_dynamic_executable(handle, ev.image_base)
        # An unmapped, absurdly high address -> VirtualQueryEx fails -> False.
        state["unmapped"] = is_dynamic_executable(handle, 0x7FFF_FFFF_0000)
        # A null handle fails closed.
        state["null_handle"] = is_dynamic_executable(0, alloc)

    dbg.on_create_process = on_create
    dbg.spawn(CMDLINE)
    dbg.run()

    assert state["alloc_private_exec"] is True, \
        "a VirtualAllocEx(PAGE_EXECUTE_READWRITE) region is MEM_PRIVATE+exec"
    assert state["image_base"] is False, "the image base is MEM_IMAGE, not private"
    assert state["unmapped"] is False, "an unmapped address must classify False"
    assert state["null_handle"] is False, "a null handle must fail closed"
    assert dbg.exit_code == 7                       # cmd ran untouched to exit


# ===========================================================================
# 3. full write-then-execute detection (single-step scan finds the OEP)
# ===========================================================================
def test_monitor_detects_execution_in_allocated_region():
    dbg = Debugger()
    saved = {}
    state = {}

    def on_create(d, ev):
        # Write a tiny stub into a fresh, executable, dynamically-allocated page.
        alloc = _alloc_rwx(ev.process_handle)
        d.write_memory(alloc, STUB)
        state["alloc"] = alloc

        # Breakpoint the real entry point so we can borrow the thread from a clean,
        # in-image moment, then divert it into the freshly written buffer.
        pe = parse_bytes(d.read_memory(ev.image_base, 0x1000))
        assert pe.ok, f"failed to parse mapped PE: {pe.error}"
        entry = ev.image_base + pe.entry_rva

        def at_entry(dd, tid):
            saved["ctx"] = dd.get_context(tid)        # full, clean context @ entry
            dd.remove_breakpoint(entry)               # one-shot
            dd.set_register(tid, "Rip", alloc)        # divert into the allocation
            mon.begin_stepping(tid)                   # start the single-step scan

        d.set_breakpoint(entry, at_entry)

    dbg.on_create_process = on_create
    mon = UnpackMonitor(dbg, auto_arm=False)

    def on_unpacked(addr):
        state["oep"] = addr
        # Restore the clean entry context so cmd resumes normally and exits 7
        # (the stub's `ret` is never executed).
        dbg.set_context(mon.stepping_tid, saved["ctx"])

    mon.on_unpacked = on_unpacked

    dbg.spawn(CMDLINE)
    dbg.run()

    alloc = state["alloc"]
    assert mon.detected is True, "monitor should have flagged out-of-image execution"
    assert "oep" in state, "on_unpacked should have fired"
    oep = state["oep"]
    assert oep == mon.oep
    # The detected address is inside our allocation and OUTSIDE every known image.
    assert alloc <= oep < alloc + 0x1000, \
        f"OEP {oep:#x} not inside the allocation at {alloc:#x}"
    assert mon.is_image_address(oep) is False
    assert mon.is_image_address(alloc) is False
    assert mon.is_image_address(mon.main_base) is True
    # Context restored -> cmd finished cleanly.
    assert dbg.exit_code == 7


# ===========================================================================
# 4. run_unpack convenience wiring (no detection expected on an unpacked target)
# ===========================================================================
def test_run_unpack_reports_result_shape():
    # Exercises the run_unpack plumbing + UnpackResult shape with a bounded step
    # budget (so we never single-step the whole program). The memory-type gate
    # now rejects the loader-generated executable thunks a benign program steps
    # through (they are MEM_IMAGE pages just past a module's SizeOfImage, not the
    # MEM_PRIVATE executable buffers a real payload runs from). So benign cmd.exe
    # must NOT detect, and must run on to its natural exit (7).
    res = run_unpack(CMDLINE, terminate_on_detect=False, max_steps=500)
    assert res.main_base and res.main_base != 0
    assert isinstance(res.detected, bool)

    # Surprising for benign cmd: a private-executable region would have tripped
    # the gate. Fail loudly with the OEP so it is diagnosable rather than silently
    # weakening the assertion. (Investigated live: every out-of-image address cmd
    # steps through in the first 500 steps is a MEM_IMAGE loader thunk, which the
    # gate rejects -- so this branch is not expected to be taken.)
    assert not res.detected, (
        f"benign cmd.exe unexpectedly detected at oep={res.oep:#x}; the gate "
        f"should reject every non-private-executable loader thunk -- inspect "
        f"that region's Type/Protect")
    assert res.oep is None
    assert res.exit_code == 7                        # stepping stopped; cmd ran on
