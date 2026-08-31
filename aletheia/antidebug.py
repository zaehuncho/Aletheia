"""Debugger cloak for Aletheia's dynamic layer -- neutralise the anti-debug
checks a sample uses to notice it is being analysed, so it runs its real
behaviour under observation instead of bailing out.

This is standard defensive sandbox tech: the same job ScyllaHide / TitanHide do
for x64dbg. A packed or evasive sample commonly asks Windows a handful of
questions whose answers change when a debugger is attached, and refuses to
detonate if any of them says "debugged". We answer those questions with the
not-debugged values, using only the primitives the house :class:`Debugger`
already exposes (process-memory read/write, the x64 register file, and software
breakpoints).

Two mechanisms:

1. **PEB cloak** (:func:`cloak_peb`). The Process Environment Block carries the
   tell-tale flags ``IsDebuggerPresent`` / ``CheckRemoteDebuggerPresent`` and the
   NtGlobalFlag heap-debug bits read from. We find the debuggee's PEB base by
   asking ntdll from the *analyzer* process
   (``NtQueryInformationProcess(hProcess, ProcessBasicInformation, ...)``), then
   normalise the flags in the debuggee's own PEB via ``read``/``write_memory``.

2. **NtQueryInformationProcess interception** (:class:`DebugCloak`). The other
   reliable probe is ``NtQueryInformationProcess`` itself with a debug-detection
   information class (ProcessDebugPort / ProcessDebugObjectHandle /
   ProcessDebugFlags). We breakpoint the ntdll stub, and for those classes patch
   the OUT buffer *on return* (after the real syscall has written the detected
   value) to the not-debugged answer.

PEB / struct offsets are x64 and Windows-version-sensitive; each is cited at its
use site. ``BeingDebugged`` and ``NtGlobalFlag`` are the reliable, universal
wins and are proved live (read back after the write). The heap-flag scrub is
version-sensitive, so it is gated behind ``heap=`` and defaults OFF.

House style mirrors ``aletheia.behavior`` / ``aletheia.debugger``: dependency-free
``ctypes``, imports cleanly off-Windows (the live pieces come from the
Windows-guarded :class:`Debugger`), best-effort operations never throw and tear
down a run, tests skip off-Windows.
"""
from __future__ import annotations

import ctypes
import sys
from ctypes import POINTER, Structure, byref, sizeof
from dataclasses import dataclass
from typing import Dict, Optional

from aletheia.behavior import _normalise_module, _resolve_export_rva
from aletheia.debugger import Debugger
from aletheia.imports import parse_exports

# ===========================================================================
# constants
# ===========================================================================
# --- PROCESS_BASIC_INFORMATION / NtQueryInformationProcess class ids --------
# ProcessBasicInformation returns a PROCESS_BASIC_INFORMATION whose
# PebBaseAddress field is the debuggee's PEB. (winternl.h / ntpsapi.h.)
ProcessBasicInformation = 0

# The debug-detection information classes we intercept, and their
# not-debugged answers.  (ntpsapi.h / documented reversing.)
ProcessDebugPort = 7            # PVOID*  -> 0 means "no debug port"
ProcessDebugObjectHandle = 0x1E  # 30; HANDLE* -> 0, call -> STATUS_PORT_NOT_SET
ProcessDebugFlags = 0x1F        # 31; ULONG*  -> 1 (NoDebugInherit == not debugged)

# A process that is NOT being debugged has no debug object: the query fails
# with STATUS_PORT_NOT_SET.  (A debugged process succeeds and hands back a
# non-zero handle -- exactly the tell we erase.)
STATUS_PORT_NOT_SET = 0xC0000353

# Per-class OUT-buffer patch: (native width in bytes, value to write).
#   ProcessDebugPort         -> pointer-sized 0
#   ProcessDebugObjectHandle -> pointer-sized 0 (+ RAX = STATUS_PORT_NOT_SET)
#   ProcessDebugFlags        -> DWORD 1
_PATCH: Dict[int, "tuple[int, int]"] = {
    ProcessDebugPort: (8, 0),
    ProcessDebugObjectHandle: (8, 0),
    ProcessDebugFlags: (4, 1),
}

# --- PEB field offsets (x64) ------------------------------------------------
# Source: _PEB as documented in Windows Internals / ntdll symbols (x64 build);
# cross-checked against public references (vergilius / ReactOS / ScyllaHide).
#   +0x002  UCHAR  BeingDebugged        (also present at +0x002 on x86)
#   +0x030  PVOID  ProcessHeap
#   +0x0BC  ULONG  NtGlobalFlag         (x86 puts this at +0x068)
PEB_BEING_DEBUGGED = 0x02
PEB_PROCESS_HEAP = 0x30
PEB_NT_GLOBAL_FLAG = 0xBC

# NtGlobalFlag heap-debug bits a debugger turns on; clearing them makes the
# field read as "not debugged".  (winnt.h FLG_* constants.)
#   FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#   FLG_HEAP_ENABLE_FREE_CHECK   0x20
#   FLG_HEAP_VALIDATE_PARAMETERS 0x40
NT_GLOBAL_FLAG_DEBUG_BITS = 0x10 | 0x20 | 0x40  # 0x70

# --- heap Flags/ForceFlags (x64) -- VERSION-SENSITIVE, gated OFF by default --
# Offsets of RTL_HEAP.Flags / ForceFlags within the default heap on x64 Win10/11
# per ScyllaHide's HideFromDebugger (heap struct is undocumented and has moved
# across builds).  Because they are not stable, the heap scrub is behind
# ``heap=`` and defaults OFF; BeingDebugged + NtGlobalFlag are the reliable wins.
HEAP_FLAGS_OFF = 0x70
HEAP_FORCE_FLAGS_OFF = 0x74
# Debug bits a debugger sets in the heap Flags/ForceFlags (winnt.h HEAP_*).
_HEAP_DEBUG_BITS = (0x20            # HEAP_TAIL_CHECKING_ENABLED
                    | 0x40          # HEAP_FREE_CHECKING_ENABLED
                    | 0x40000000    # HEAP_VALIDATE_PARAMETERS_ENABLED
                    | 0x20000000    # HEAP_VALIDATE_ALL_ENABLED
                    | 0x10000000)   # HEAP_SKIP_VALIDATION_CHECKS


# ===========================================================================
# ctypes: NtQueryInformationProcess (called from the analyzer, on the debuggee)
# ===========================================================================
NTSTATUS = ctypes.c_long
HANDLE = ctypes.c_void_p
LPVOID = ctypes.c_void_p
ULONG = ctypes.c_ulong


class PROCESS_BASIC_INFORMATION(Structure):
    """The subset returned by ``ProcessBasicInformation`` (x64 layout).

    ``PebBaseAddress`` sits at **offset 8**: ``ExitStatus`` is a 4-byte NTSTATUS
    at 0, then 4 bytes of padding align the pointer to 8. (winternl.h.)"""
    _fields_ = [
        ("ExitStatus", NTSTATUS),                 # +0x00  (4 bytes, then pad)
        ("PebBaseAddress", LPVOID),               # +0x08
        ("AffinityMask", ctypes.c_size_t),        # +0x10  (ULONG_PTR)
        ("BasePriority", ctypes.c_long),          # +0x18  (KPRIORITY)
        ("UniqueProcessId", ctypes.c_size_t),     # +0x20  (ULONG_PTR)
        ("InheritedFromUniqueProcessId", ctypes.c_size_t),  # +0x28
    ]


if sys.platform == "win32":
    _ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    _NtQueryInformationProcess = _ntdll.NtQueryInformationProcess
    _NtQueryInformationProcess.restype = NTSTATUS
    _NtQueryInformationProcess.argtypes = [
        HANDLE, ULONG, LPVOID, ULONG, POINTER(ULONG)]
else:  # pragma: no cover - imports cleanly off-Windows, but is inert
    _ntdll = None
    _NtQueryInformationProcess = None


def query_peb_base(process_handle: Optional[int]) -> int:
    """Return the PEB base of the process behind ``process_handle`` (the
    debuggee's ``hProcess`` from the CREATE_PROCESS event), via
    ``NtQueryInformationProcess(ProcessBasicInformation)`` from this process.

    Returns 0 for a NULL handle. Raises ``RuntimeError`` off-Windows and
    ``OSError`` if the query returns a non-zero NTSTATUS."""
    if _NtQueryInformationProcess is None:
        raise RuntimeError("query_peb_base requires Windows (ntdll)")
    if not process_handle:
        return 0
    pbi = PROCESS_BASIC_INFORMATION()
    ret_len = ULONG(0)
    status = _NtQueryInformationProcess(
        process_handle, ProcessBasicInformation, byref(pbi), sizeof(pbi),
        byref(ret_len))
    if status != 0:
        raise OSError("NtQueryInformationProcess(ProcessBasicInformation) "
                      f"failed: NTSTATUS 0x{status & 0xFFFFFFFF:08x}")
    return int(pbi.PebBaseAddress or 0)


# ===========================================================================
# 1. PEB cloak
# ===========================================================================
def cloak_peb(dbg: Debugger, heap: bool = False) -> dict:
    """Normalise the debuggee's PEB so ``IsDebuggerPresent`` /
    ``CheckRemoteDebuggerPresent`` / NtGlobalFlag heap checks report
    not-debugged.

    Returns a dict of what it read/wrote -- e.g.::

        {"peb": 0x..., "being_debugged": (1, 0), "nt_global_flag": (0x70, 0x0)}

    BEST-EFFORT: never raises. On failure to locate the PEB it returns ``{}``;
    an individual flag that cannot be read/written is simply omitted (partial
    result). The heap scrub is only attempted when ``heap=True`` (its offsets
    are version-sensitive -- see module constants) and, even then, is
    conservative read-modify-write that never fails the rest of the cloak."""
    result: dict = {}
    try:
        peb = query_peb_base(dbg.process_handle)
    except Exception:            # noqa: BLE001 - best-effort; no PEB -> no cloak
        return {}
    if not peb:
        return {}
    result["peb"] = peb

    # BeingDebugged (PEB+0x02, one byte) -> 0.
    try:
        old = dbg.read_memory(peb + PEB_BEING_DEBUGGED, 1)[0]
        dbg.write_memory(peb + PEB_BEING_DEBUGGED, b"\x00")
        result["being_debugged"] = (old, 0)
    except Exception:            # noqa: BLE001
        pass

    # NtGlobalFlag (PEB+0xBC, DWORD) -> clear the heap-debug bits (0x70).
    try:
        raw = dbg.read_memory(peb + PEB_NT_GLOBAL_FLAG, 4)
        if len(raw) == 4:
            old = int.from_bytes(raw, "little")
            new = old & ~NT_GLOBAL_FLAG_DEBUG_BITS
            dbg.write_memory(peb + PEB_NT_GLOBAL_FLAG, new.to_bytes(4, "little"))
            result["nt_global_flag"] = (old, new)
    except Exception:            # noqa: BLE001
        pass

    if heap:
        _cloak_heap(dbg, peb, result)

    return result


def _cloak_heap(dbg: Debugger, peb: int, result: dict) -> None:
    """Best-effort scrub of the default heap's Flags/ForceFlags debug bits.

    Version-sensitive (see ``HEAP_FLAGS_OFF`` / ``HEAP_FORCE_FLAGS_OFF``); any
    failure is swallowed so the reliable PEB wins still land."""
    try:
        raw = dbg.read_memory(peb + PEB_PROCESS_HEAP, 8)
        if len(raw) < 8:
            return
        heap_base = int.from_bytes(raw, "little")
        if not heap_base:
            return
        for label, off in (("heap_flags", HEAP_FLAGS_OFF),
                           ("heap_force_flags", HEAP_FORCE_FLAGS_OFF)):
            fraw = dbg.read_memory(heap_base + off, 4)
            if len(fraw) != 4:
                continue
            old = int.from_bytes(fraw, "little")
            new = old & ~_HEAP_DEBUG_BITS
            if new != old:
                dbg.write_memory(heap_base + off, new.to_bytes(4, "little"))
            result[label] = (old, new)
    except Exception:            # noqa: BLE001 - version-sensitive, never fatal
        pass


# ===========================================================================
# 2. NtQueryInformationProcess interception
# ===========================================================================
@dataclass
class _PendingQuery:
    """One in-flight NtQueryInformationProcess call captured at entry, so the
    return handler can patch the OUT buffer the real syscall wrote."""
    cls: int            # ProcessInformationClass (RDX)
    buffer: int         # ProcessInformation OUT buffer (R8)
    length: int         # ProcessInformationLength (R9)
    ret_addr: int       # caller's return address ([RSP] at entry)


class DebugCloak:
    """Watch a :class:`Debugger` and keep the target blind to the analysis.

    Construction installs chaining handlers for ``on_create_process`` (do the PEB
    cloak once the process/PEB exists -- valid at the initial CREATE_PROCESS
    event) and ``on_dll_load`` (arm the ``ntdll!NtQueryInformationProcess``
    breakpoint once ntdll is mapped), like :class:`aletheia.behavior.BehaviorMonitor`:
    set your own versions of those handlers BEFORE constructing the cloak; the
    cloak does its bookkeeping first, then calls yours.

    After (or during) a run it exposes what it did:

    * ``peb_result``       -- the :func:`cloak_peb` dict (``{}`` until create).
    * ``armed``            -- True once the NtQIP breakpoint is planted.
    * ``intercepts``       -- count of debug-class OUT buffers patched.
    * ``nqip_entry_hits``  -- count of NtQIP entries seen (any class).
    """

    def __init__(self, debugger: Debugger, peb: bool = True,
                 intercept_nqip: bool = True, heap: bool = False) -> None:
        self.dbg = debugger
        self.do_peb = peb
        self.do_intercept = intercept_nqip
        self.heap = heap

        self.peb_result: dict = {}
        self.armed: bool = False
        self.intercepts: int = 0
        self.nqip_entry_hits: int = 0

        self._nqip_addr: Optional[int] = None
        self._pending: Dict[int, _PendingQuery] = {}   # tid -> in-flight call

        # Chain whatever handlers were already registered.
        self._user_create = debugger.on_create_process
        self._user_dll = debugger.on_dll_load
        debugger.on_create_process = self._handle_create
        debugger.on_dll_load = self._handle_dll

    # -- debugger event handlers (chained) ---------------------------------
    def _handle_create(self, dbg: Debugger, ev) -> None:
        if self.do_peb and not self.peb_result:
            try:
                self.peb_result = cloak_peb(dbg, heap=self.heap)
            except Exception:        # noqa: BLE001 - cloak is best-effort
                self.peb_result = {}
        if self._user_create:
            self._user_create(dbg, ev)

    def _handle_dll(self, dbg: Debugger, base: int, name) -> None:
        if self.do_intercept and not self.armed:
            try:
                self._try_arm_nqip(dbg, base, name)
            except Exception:        # noqa: BLE001 - arming is best-effort
                pass
        if self._user_dll:
            self._user_dll(dbg, base, name)

    # -- arming -------------------------------------------------------------
    def _try_arm_nqip(self, dbg: Debugger, base: int, name) -> None:
        """If ``base`` is ntdll, plant the NtQueryInformationProcess breakpoint."""
        if not base:
            return
        exp = parse_exports(dbg.read_memory, base)
        if not exp.ok:
            return
        module_key = _normalise_module(exp.dll_name) or _normalise_module(name)
        if module_key != "ntdll":
            return
        name_to_rva: Dict[str, int] = {}
        for rva, nm in exp.by_rva.items():
            name_to_rva.setdefault(nm, rva)
        # parse_exports keeps one name per RVA (Zw sorts last), so the Nt name is
        # often absent; _resolve_export_rva falls through to the Zw twin.
        rva = _resolve_export_rva(name_to_rva, "NtQueryInformationProcess")
        if rva is None:
            return
        self._nqip_addr = base + rva
        dbg.set_breakpoint(self._nqip_addr, self._on_nqip_entry)
        self.armed = True

    # -- the breakpoint callbacks ------------------------------------------
    def _on_nqip_entry(self, dbg: Debugger, tid: int) -> None:
        """Entry of NtQueryInformationProcess. x64 args: RCX=handle, RDX=class,
        R8=OUT buffer, R9=length; [RSP]=return address. For a debug-detection
        class, record the call and set a one-shot breakpoint at the return."""
        self.nqip_entry_hits += 1
        try:
            ctx = dbg.get_context(tid)
        except Exception:            # noqa: BLE001 - never kill the run
            return
        cls = ctx.Rdx & 0xFFFFFFFF
        if cls not in _PATCH:
            return
        buffer = int(ctx.R8)
        length = int(ctx.R9) & 0xFFFFFFFF
        try:
            raw = dbg.read_memory(ctx.Rsp, 8)
            ret_addr = int.from_bytes(raw, "little") if len(raw) == 8 else 0
        except Exception:            # noqa: BLE001
            ret_addr = 0
        if not ret_addr:
            return
        self._pending[tid] = _PendingQuery(cls=cls, buffer=buffer,
                                           length=length, ret_addr=ret_addr)
        # One-shot: removed in the return handler once consumed.
        dbg.set_breakpoint(ret_addr, self._on_nqip_return)

    def _on_nqip_return(self, dbg: Debugger, tid: int) -> None:
        """Return site of a tracked NtQIP call: patch the OUT buffer the real
        syscall just wrote, then retire the one-shot breakpoint (unless another
        thread's in-flight call still shares this exact return address)."""
        pending = self._pending.pop(tid, None)
        if pending is None:
            # A thread we are not tracking reached this address (a different
            # call site sharing it, or a non-debug-class call). Leave the
            # breakpoint for whichever thread still owns it.
            return
        self._apply_patch(dbg, tid, pending)
        addr = pending.ret_addr
        if not any(p.ret_addr == addr for p in self._pending.values()):
            try:
                dbg.remove_breakpoint(addr)
            except Exception:        # noqa: BLE001
                pass

    def _apply_patch(self, dbg: Debugger, tid: int,
                     pending: _PendingQuery) -> bool:
        """Overwrite the OUT buffer with the not-debugged value for
        ``pending.cls``. Returns True if the buffer was patched.

        This is the real interception code the driven tests exercise directly.
        Best-effort: an unwritable buffer is skipped, never raised."""
        spec = _PATCH.get(pending.cls)
        if spec is None:
            return False
        nbytes, value = spec
        n = min(nbytes, pending.length)
        wrote = False
        if pending.buffer and n > 0:
            try:
                dbg.write_memory(pending.buffer,
                                 value.to_bytes(nbytes, "little")[:n])
                wrote = True
            except Exception:        # noqa: BLE001 - bad buffer -> skip
                pass
        # ProcessDebugObjectHandle: a not-debugged process reports STATUS_PORT_NOT_SET.
        if pending.cls == ProcessDebugObjectHandle:
            try:
                dbg.set_register(tid, "Rax", STATUS_PORT_NOT_SET)
            except Exception:        # noqa: BLE001
                pass
        if wrote:
            self.intercepts += 1
        return wrote


# ===========================================================================
# convenience runner
# ===========================================================================
def run_cloaked(command: str, peb: bool = True, intercept_nqip: bool = True,
                heap: bool = False) -> DebugCloak:
    """Spawn ``command`` under a fresh debugger with a :class:`DebugCloak`
    installed, run it to exit, and return the cloak.

    Inspect ``cloak.peb_result`` / ``cloak.armed`` / ``cloak.intercepts`` and the
    exit code via ``cloak.dbg.exit_code`` afterwards."""
    dbg = Debugger()
    cloak = DebugCloak(dbg, peb=peb, intercept_nqip=intercept_nqip, heap=heap)
    dbg.spawn(command)
    dbg.run()
    return cloak
