"""Tests for the debugger cloak: PEB normalisation + NtQueryInformationProcess
interception.

Two layers, mirroring the module:

* OFFLINE unit tests (run everywhere -- no live process). Pin the class-constant
  patch table (7/30/31 -> not-debugged values), the NtGlobalFlag mask math, the
  PROCESS_BASIC_INFORMATION layout (``PebBaseAddress`` at offset 8, sizeof 48),
  and the documented PEB / status constants. No process is spawned.

* LIVE integration (Windows only -- skipped elsewhere):
  - **PEB cloak (mandatory).** ``cmd.exe /c exit 7`` is spawned under the
    debugger; at CREATE_PROCESS we read BeingDebugged/NtGlobalFlag *before*,
    run :func:`cloak_peb`, and read them *after* -- proving BeingDebugged went
    to 0 and the 0x70 NtGlobalFlag bits are cleared, while cmd still exits 7.
  - **NtQIP arm + stability.** With the real breakpoint armed on the ntdll stub,
    cmd is traced to exit: the stub resolves and arms, the entry handler fires
    (cmd genuinely calls NtQIP during startup), and the hot breakpoint does not
    destabilise the run.
  - **NtQIP patch (driven-synthetic).** cmd may never call NtQIP with a *debug*
    class, so the OUT-buffer patch is proved by driving the REAL ``_apply_patch``
    over a scratch buffer allocated in the live debuggee: a nonzero
    ProcessDebugPort/ObjectHandle buffer is zeroed, a ProcessDebugFlags buffer
    becomes 1, and the ProcessDebugObjectHandle path sets RAX to
    STATUS_PORT_NOT_SET. This exercises the shipped code, not a reimplementation.
"""
import ctypes
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# The module imports cleanly off-Windows (its live pieces come from the
# Windows-guarded Debugger), so the offline unit tests below run everywhere.
from aletheia.antidebug import (  # noqa: E402
    NT_GLOBAL_FLAG_DEBUG_BITS, PEB_BEING_DEBUGGED, PEB_NT_GLOBAL_FLAG,
    PEB_PROCESS_HEAP, PROCESS_BASIC_INFORMATION, ProcessDebugFlags,
    ProcessDebugObjectHandle, ProcessDebugPort, STATUS_PORT_NOT_SET, _PATCH,
    _PendingQuery,
)


# ===========================================================================
# 1. OFFLINE: the interception patch table (7/30/31 -> not-debugged values)
# ===========================================================================
def test_patch_table_maps_debug_classes_to_not_debugged_values():
    # ProcessDebugPort (7): pointer-sized 0.
    assert ProcessDebugPort == 7
    assert _PATCH[ProcessDebugPort] == (8, 0)
    # ProcessDebugObjectHandle (30 / 0x1E): pointer-sized 0 handle.
    assert ProcessDebugObjectHandle == 0x1E == 30
    assert _PATCH[ProcessDebugObjectHandle] == (8, 0)
    # ProcessDebugFlags (31 / 0x1F): DWORD 1 (NoDebugInherit == not debugged).
    assert ProcessDebugFlags == 0x1F == 31
    assert _PATCH[ProcessDebugFlags] == (4, 1)
    # Exactly the three debug-detection classes are intercepted.
    assert set(_PATCH) == {7, 30, 31}


def test_status_port_not_set_constant():
    # A not-debugged process reports STATUS_PORT_NOT_SET for the debug object.
    assert STATUS_PORT_NOT_SET == 0xC0000353


# ===========================================================================
# 2. OFFLINE: NtGlobalFlag mask math
# ===========================================================================
def test_nt_global_flag_mask_clears_only_the_heap_debug_bits():
    # FLG_HEAP_ENABLE_TAIL_CHECK 0x10 | _FREE_CHECK 0x20 | _VALIDATE_PARAMETERS 0x40.
    assert NT_GLOBAL_FLAG_DEBUG_BITS == 0x70

    # A debugged process typically reads 0x70; clearing yields 0.
    assert (0x70 & ~NT_GLOBAL_FLAG_DEBUG_BITS) == 0

    # Unrelated bits are preserved; only the 0x70 set is cleared.
    value = 0x12345678
    cleared = value & ~NT_GLOBAL_FLAG_DEBUG_BITS
    assert cleared == (value & ~0x70)
    assert cleared & 0x70 == 0
    assert cleared & ~0x70 == value & ~0x70   # every other bit untouched


# ===========================================================================
# 3. OFFLINE: PROCESS_BASIC_INFORMATION layout + PEB offsets
# ===========================================================================
def test_process_basic_information_layout_x64():
    # PebBaseAddress at offset 8 (ExitStatus DWORD at 0, then pointer alignment).
    assert PROCESS_BASIC_INFORMATION.ExitStatus.offset == 0
    assert PROCESS_BASIC_INFORMATION.PebBaseAddress.offset == 8
    assert PROCESS_BASIC_INFORMATION.AffinityMask.offset == 16
    assert PROCESS_BASIC_INFORMATION.UniqueProcessId.offset == 32
    assert ctypes.sizeof(PROCESS_BASIC_INFORMATION) == 48


def test_peb_field_offsets_x64():
    assert PEB_BEING_DEBUGGED == 0x02
    assert PEB_NT_GLOBAL_FLAG == 0xBC
    assert PEB_PROCESS_HEAP == 0x30


# ===========================================================================
# 4. LIVE integration (Windows only)
# ===========================================================================
live = pytest.mark.skipif(sys.platform != "win32",
                          reason="debugger cloak is Windows-only")

CMD = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                   "System32", "cmd.exe")
CMDLINE = f'"{CMD}" /c exit 7'

# A safety cap the trivial target never reaches, in case a breakpoint runs hot.
_LIVE_CAP = 50000


# ---- live PEB cloak (MUST run) --------------------------------------------
@live
def test_live_peb_cloak_zeroes_being_debugged():
    from aletheia.antidebug import cloak_peb, query_peb_base
    from aletheia.debugger import Debugger

    dbg = Debugger()
    cap = {}

    def on_create(d, ev):
        peb = query_peb_base(d.process_handle)
        cap["peb"] = peb
        # Read BeingDebugged + NtGlobalFlag BEFORE the cloak ...
        cap["bd_before"] = d.read_memory(peb + PEB_BEING_DEBUGGED, 1)[0]
        cap["ngf_before"] = int.from_bytes(
            d.read_memory(peb + PEB_NT_GLOBAL_FLAG, 4), "little")
        # ... run the cloak ...
        cap["result"] = cloak_peb(d)
        # ... and read them back AFTER.
        cap["bd_after"] = d.read_memory(peb + PEB_BEING_DEBUGGED, 1)[0]
        cap["ngf_after"] = int.from_bytes(
            d.read_memory(peb + PEB_NT_GLOBAL_FLAG, 4), "little")

    dbg.on_create_process = on_create
    dbg.spawn(CMDLINE)
    dbg.run()

    # The cloak did not disturb the target.
    assert dbg.exit_code == 7, f"cmd exited {dbg.exit_code}, expected 7"

    # PEB was located.
    assert cap.get("peb", 0) != 0, "failed to locate the debuggee PEB"
    result = cap["result"]
    assert result.get("peb") == cap["peb"]

    # Proof of the flip: under our own debugger BeingDebugged is set beforehand,
    # and 0 after the cloak (the read-back is the live proof).
    assert cap["bd_before"] == 1, \
        f"expected BeingDebugged==1 under the debugger, got {cap['bd_before']}"
    assert cap["bd_after"] == 0, "BeingDebugged must be 0 after the cloak"
    assert result["being_debugged"] == (1, 0)

    # NtGlobalFlag: the 0x70 heap-debug bits are cleared (read back live).
    assert cap["ngf_after"] & 0x70 == 0, \
        f"NtGlobalFlag still has debug bits: {cap['ngf_after']:#x}"
    old, new = result["nt_global_flag"]
    assert new == old & ~0x70
    assert cap["ngf_after"] == new

    print(f"\n[antidebug] peb={cap['peb']:#x} "
          f"BeingDebugged {cap['bd_before']}->{cap['bd_after']} "
          f"NtGlobalFlag {cap['ngf_before']:#x}->{cap['ngf_after']:#x}")


# ---- live NtQIP arm + stability -------------------------------------------
@live
def test_live_nqip_breakpoint_arms_and_runs():
    """The real breakpoint path: the ntdll stub resolves and arms, the entry
    handler fires (cmd calls NtQIP during startup), and the hot breakpoint does
    not destabilise the run. Debug-class hits on cmd are typically 0 -- the
    OUT-buffer patch itself is proved by the driven test below."""
    from aletheia.antidebug import DebugCloak
    from aletheia.debugger import Debugger

    dbg = Debugger()
    cloak = DebugCloak(dbg, peb=True, intercept_nqip=True)
    dbg.spawn(CMDLINE)
    dbg.run()

    assert dbg.exit_code == 7, f"cmd exited {dbg.exit_code}, expected 7"
    assert cloak.armed, "NtQueryInformationProcess breakpoint should have armed"
    assert cloak.nqip_entry_hits > 0, \
        "expected NtQIP to be called during cmd startup (entry handler ran)"
    # PEB cloak also happened via the chained create handler.
    assert cloak.peb_result.get("being_debugged") == (1, 0)

    print(f"\n[antidebug] armed={cloak.armed} "
          f"nqip_entry_hits={cloak.nqip_entry_hits} "
          f"intercepts={cloak.intercepts}")


# ---- live NtQIP patch (driven-synthetic, exercises the REAL _apply_patch) --
if sys.platform == "win32":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _VirtualAllocEx = _k32.VirtualAllocEx
    _VirtualAllocEx.restype = ctypes.c_void_p
    _VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_size_t, ctypes.c_uint32,
                                ctypes.c_uint32]
    _MEM_COMMIT = 0x1000
    _MEM_RESERVE = 0x2000
    _PAGE_READWRITE = 0x04


@live
def test_live_nqip_apply_patch_zeroes_debug_buffers():
    from aletheia.antidebug import DebugCloak
    from aletheia.debugger import Debugger

    dbg = Debugger()
    # Do NOT arm the real breakpoint here: we drive _apply_patch directly so the
    # interception count is exactly our three synthetic calls.
    cloak = DebugCloak(dbg, peb=False, intercept_nqip=False)
    cap = {}

    def on_create(d, ev):
        tid = ev.tid
        # A scratch page inside the live debuggee to stand in for the OUT buffer.
        scratch = _VirtualAllocEx(d.process_handle, None, 0x1000,
                                  _MEM_COMMIT | _MEM_RESERVE, _PAGE_READWRITE)
        assert scratch, "VirtualAllocEx failed in the debuggee"
        scratch = int(scratch)

        # ProcessDebugPort (7): a nonzero "debug port" must be zeroed.
        d.write_memory(scratch, b"\xAA" * 8)
        cloak._apply_patch(d, tid, _PendingQuery(
            cls=ProcessDebugPort, buffer=scratch, length=8, ret_addr=0))
        cap["port"] = d.read_memory(scratch, 8)

        # ProcessDebugFlags (31): buffer starts 0, becomes 1 (NoDebugInherit).
        d.write_memory(scratch, b"\x00\x00\x00\x00")
        cloak._apply_patch(d, tid, _PendingQuery(
            cls=ProcessDebugFlags, buffer=scratch, length=4, ret_addr=0))
        cap["flags"] = int.from_bytes(d.read_memory(scratch, 4), "little")

        # ProcessDebugObjectHandle (30): a nonzero handle must be zeroed, and the
        # call's RAX set to STATUS_PORT_NOT_SET. Save/restore RAX so the patch to
        # the live thread does not disturb cmd's own exit.
        orig_rax = d.get_register(tid, "Rax")
        d.write_memory(scratch, b"\xBB" * 8)
        cloak._apply_patch(d, tid, _PendingQuery(
            cls=ProcessDebugObjectHandle, buffer=scratch, length=8, ret_addr=0))
        cap["objhandle"] = d.read_memory(scratch, 8)
        cap["rax"] = d.get_register(tid, "Rax")
        d.set_register(tid, "Rax", orig_rax)   # restore -> cmd runs on cleanly

        cap["done"] = True

    dbg.on_create_process = on_create
    dbg.spawn(CMDLINE)
    dbg.run()

    assert cap.get("done"), "on_create driver did not complete"
    assert dbg.exit_code == 7, f"cmd exited {dbg.exit_code}, expected 7"

    # The real _apply_patch zeroed / set each OUT buffer.
    assert cap["port"] == b"\x00" * 8, "ProcessDebugPort buffer not zeroed"
    assert cap["flags"] == 1, "ProcessDebugFlags buffer not set to 1"
    assert cap["objhandle"] == b"\x00" * 8, \
        "ProcessDebugObjectHandle buffer not zeroed"
    assert cap["rax"] == STATUS_PORT_NOT_SET, \
        f"RAX not set to STATUS_PORT_NOT_SET: {cap['rax']:#x}"
    # Three successful buffer patches were counted.
    assert cloak.intercepts == 3, f"intercepts={cloak.intercepts}, expected 3"

    print(f"\n[antidebug] driven patch: port={cap['port'].hex()} "
          f"flags={cap['flags']} objhandle={cap['objhandle'].hex()} "
          f"rax={cap['rax']:#x} intercepts={cloak.intercepts}")


# ---- live convenience runner ----------------------------------------------
@live
def test_live_run_cloaked_convenience():
    from aletheia.antidebug import run_cloaked

    cloak = run_cloaked(CMDLINE)
    assert cloak.dbg.exit_code == 7
    assert cloak.armed, "run_cloaked should arm the NtQIP breakpoint"
    assert cloak.peb_result.get("being_debugged") == (1, 0), \
        "run_cloaked should have cloaked the PEB at create"
