"""Scriptable Windows x64 debugger engine for Aletheia's dynamic layer.

A thin, dependency-free wrapper over the Win32 Debug API (``ctypes`` over
``kernel32``) that exposes the same primitives WinDbg / x64dbg do: launch or
attach, a ``WaitForDebugEvent`` loop, process-memory read/write, the full x64
register file, software (``0xCC``) breakpoints with automatic re-arm, and single
stepping. It is the dynamic-analysis foundation of layer 2 (the dynamic
unpacker) and is exercised against a benign, deterministic process (``cmd.exe``).

Design notes / Windows details that have to be exact:

* **Handles.** Memory and context calls use the ``hProcess`` / ``hThread`` that
  the ``CREATE_PROCESS_DEBUG_EVENT`` (and ``CREATE_THREAD``) hand us, *not* the
  ones ``CreateProcessW`` returns — the debug-event handles are the ones the
  kernel guarantees for the debugged process.
* **CONTEXT alignment.** The x64 ``CONTEXT`` is ``DECLSPEC_ALIGN(16)``;
  ``GetThreadContext`` faults if it is not 16-byte aligned. ``ctypes`` only
  aligns a structure to 8, so we allocate an over-sized backing buffer and place
  the ``CONTEXT`` at the next 16-byte boundary inside it (``_aligned_context``).
* **DEBUG_EVENT union.** ``DEBUG_EVENT`` is a 3-``DWORD`` header followed by a
  union of the nine per-event records; we model the union as a ``ctypes.Union``
  sized to its largest member (``EXCEPTION_DEBUG_INFO``).
* **Native x64 only.** WOW64 (32-bit) targets need ``Wow64GetThreadContext`` and
  a different ``CONTEXT``; we detect and flag such a target but the CONTEXT path
  assumes a native 64-bit debuggee (``cmd.exe`` is native on x64 Windows).
"""
from __future__ import annotations

import ctypes
import sys
from ctypes import POINTER, Structure, Union, byref, sizeof
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional

# --- Win32 scalar typedefs -------------------------------------------------
BOOL = ctypes.c_int
DWORD = ctypes.c_uint32
WORD = ctypes.c_uint16
HANDLE = ctypes.c_void_p
LPVOID = ctypes.c_void_p
ULONG_PTR = ctypes.c_uint64          # x64
SIZE_T = ctypes.c_size_t
LPCWSTR = ctypes.c_wchar_p
LPWSTR = ctypes.c_wchar_p

# --- creation flags / event codes / statuses -------------------------------
DEBUG_PROCESS = 0x00000001
DEBUG_ONLY_THIS_PROCESS = 0x00000002

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

# --- NTSTATUS exception codes we care about --------------------------------
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
STATUS_WX86_BREAKPOINT = 0x4000001F   # the WOW64 loader breakpoint
STATUS_WX86_SINGLE_STEP = 0x4000001E

INFINITE = 0xFFFFFFFF
TRAP_FLAG = 0x100                      # EFlags bit 8 (single-step)
INT3 = b"\xCC"

# --- x64 CONTEXT flags (AMD64 = 0x00100000) --------------------------------
CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x2
CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x4
CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x8
CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10
CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT
CONTEXT_ALL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS
               | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS)  # 0x0010001F

_EXCEPTION_MAXIMUM_PARAMETERS = 15

# The general-purpose registers we expose as convenience accessors.
GP_REGISTERS = (
    "Rip", "Rax", "Rbx", "Rcx", "Rdx", "Rsp", "Rbp", "Rsi", "Rdi",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "EFlags",
)


# ===========================================================================
# ctypes structures
# ===========================================================================
class M128A(Structure):
    _fields_ = [("Low", ctypes.c_uint64), ("High", ctypes.c_uint64)]


class CONTEXT(Structure):
    """x64 ``CONTEXT`` (1232 bytes). Must be 16-byte aligned — see
    :func:`_aligned_context`. The FltSave/XMM save area is kept as an opaque
    512-byte block so the integer/control offsets land exactly where the kernel
    expects them without our having to spell out the whole FXSAVE layout."""
    _fields_ = [
        ("P1Home", ctypes.c_uint64), ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64), ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64), ("P6Home", ctypes.c_uint64),
        ("ContextFlags", DWORD), ("MxCsr", DWORD),
        ("SegCs", WORD), ("SegDs", WORD), ("SegEs", WORD),
        ("SegFs", WORD), ("SegGs", WORD), ("SegSs", WORD),
        ("EFlags", DWORD),
        ("Dr0", ctypes.c_uint64), ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64), ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64), ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64), ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64), ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64), ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64), ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64), ("R9", ctypes.c_uint64),
        ("R10", ctypes.c_uint64), ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64), ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64), ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
        ("FltSave", ctypes.c_ubyte * 512),     # XMM_SAVE_AREA32 (offset 256)
        ("VectorRegister", M128A * 26),
        ("VectorControl", ctypes.c_uint64),
        ("DebugControl", ctypes.c_uint64),
        ("LastBranchToRip", ctypes.c_uint64),
        ("LastBranchFromRip", ctypes.c_uint64),
        ("LastExceptionToRip", ctypes.c_uint64),
        ("LastExceptionFromRip", ctypes.c_uint64),
    ]


class EXCEPTION_RECORD(Structure):
    # The chained ``ExceptionRecord`` pointer is kept opaque (c_void_p): we do
    # not walk nested records, and it keeps the struct self-contained.
    _fields_ = [
        ("ExceptionCode", DWORD),
        ("ExceptionFlags", DWORD),
        ("ExceptionRecord", LPVOID),
        ("ExceptionAddress", LPVOID),
        ("NumberParameters", DWORD),
        ("ExceptionInformation", ULONG_PTR * _EXCEPTION_MAXIMUM_PARAMETERS),
    ]


class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD),
                ("dwFirstChance", DWORD)]


class CREATE_THREAD_DEBUG_INFO(Structure):
    _fields_ = [("hThread", HANDLE),
                ("lpThreadLocalBase", LPVOID),
                ("lpStartAddress", LPVOID)]


class CREATE_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [("hFile", HANDLE),
                ("hProcess", HANDLE),
                ("hThread", HANDLE),
                ("lpBaseOfImage", LPVOID),
                ("dwDebugInfoFileOffset", DWORD),
                ("nDebugInfoSize", DWORD),
                ("lpThreadLocalBase", LPVOID),
                ("lpStartAddress", LPVOID),
                ("lpImageName", LPVOID),
                ("fUnicode", WORD)]


class EXIT_THREAD_DEBUG_INFO(Structure):
    _fields_ = [("dwExitCode", DWORD)]


class EXIT_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [("dwExitCode", DWORD)]


class LOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [("hFile", HANDLE),
                ("lpBaseOfDll", LPVOID),
                ("dwDebugInfoFileOffset", DWORD),
                ("nDebugInfoSize", DWORD),
                ("lpImageName", LPVOID),
                ("fUnicode", WORD)]


class UNLOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [("lpBaseOfDll", LPVOID)]


class OUTPUT_DEBUG_STRING_INFO(Structure):
    _fields_ = [("lpDebugStringData", LPVOID),
                ("fUnicode", WORD),
                ("nDebugStringLength", WORD)]


class RIP_INFO(Structure):
    _fields_ = [("dwError", DWORD), ("dwType", DWORD)]


class _DebugEventUnion(Union):
    _fields_ = [("Exception", EXCEPTION_DEBUG_INFO),
                ("CreateThread", CREATE_THREAD_DEBUG_INFO),
                ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
                ("ExitThread", EXIT_THREAD_DEBUG_INFO),
                ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
                ("LoadDll", LOAD_DLL_DEBUG_INFO),
                ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
                ("DebugString", OUTPUT_DEBUG_STRING_INFO),
                ("RipInfo", RIP_INFO)]


class DEBUG_EVENT(Structure):
    _fields_ = [("dwDebugEventCode", DWORD),
                ("dwProcessId", DWORD),
                ("dwThreadId", DWORD),
                ("u", _DebugEventUnion)]


class STARTUPINFOW(Structure):
    _fields_ = [("cb", DWORD),
                ("lpReserved", LPWSTR),
                ("lpDesktop", LPWSTR),
                ("lpTitle", LPWSTR),
                ("dwX", DWORD), ("dwY", DWORD),
                ("dwXSize", DWORD), ("dwYSize", DWORD),
                ("dwXCountChars", DWORD), ("dwYCountChars", DWORD),
                ("dwFillAttribute", DWORD), ("dwFlags", DWORD),
                ("wShowWindow", WORD), ("cbReserved2", WORD),
                ("lpReserved2", LPVOID),
                ("hStdInput", HANDLE), ("hStdOutput", HANDLE),
                ("hStdError", HANDLE)]


class PROCESS_INFORMATION(Structure):
    _fields_ = [("hProcess", HANDLE),
                ("hThread", HANDLE),
                ("dwProcessId", DWORD),
                ("dwThreadId", DWORD)]


# ===========================================================================
# kernel32 prototypes (Windows only)
# ===========================================================================
if sys.platform == "win32":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    def _proto(name, restype, argtypes):
        fn = getattr(_k32, name)
        fn.restype = restype
        fn.argtypes = argtypes
        return fn

    CreateProcessW = _proto(
        "CreateProcessW", BOOL,
        [LPCWSTR, LPWSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCWSTR,
         POINTER(STARTUPINFOW), POINTER(PROCESS_INFORMATION)])
    DebugActiveProcess = _proto("DebugActiveProcess", BOOL, [DWORD])
    DebugActiveProcessStop = _proto("DebugActiveProcessStop", BOOL, [DWORD])
    DebugSetProcessKillOnExit = _proto("DebugSetProcessKillOnExit", BOOL, [BOOL])
    WaitForDebugEvent = _proto("WaitForDebugEvent", BOOL,
                               [POINTER(DEBUG_EVENT), DWORD])
    ContinueDebugEvent = _proto("ContinueDebugEvent", BOOL,
                                [DWORD, DWORD, DWORD])
    ReadProcessMemory = _proto("ReadProcessMemory", BOOL,
                               [HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)])
    WriteProcessMemory = _proto("WriteProcessMemory", BOOL,
                                [HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)])
    GetThreadContext = _proto("GetThreadContext", BOOL,
                              [HANDLE, POINTER(CONTEXT)])
    SetThreadContext = _proto("SetThreadContext", BOOL,
                              [HANDLE, POINTER(CONTEXT)])
    FlushInstructionCache = _proto("FlushInstructionCache", BOOL,
                                   [HANDLE, LPVOID, SIZE_T])
    CloseHandle = _proto("CloseHandle", BOOL, [HANDLE])
    TerminateProcess = _proto("TerminateProcess", BOOL, [HANDLE, ctypes.c_uint])
    IsWow64Process = _proto("IsWow64Process", BOOL, [HANDLE, POINTER(BOOL)])
else:  # pragma: no cover - the module imports cleanly off-Windows, but is inert
    _k32 = None


def _raise(fn_name: str) -> None:
    """Raise an ``OSError`` carrying the current ``GetLastError`` value."""
    raise ctypes.WinError(ctypes.get_last_error(), f"{fn_name} failed")


def _aligned_context(flags: int = CONTEXT_ALL):
    """Return a 16-byte-aligned :class:`CONTEXT`.

    ``ctypes`` aligns a structure to 8 bytes, but ``GetThreadContext`` requires
    16 on x64. We over-allocate by 16, drop the ``CONTEXT`` on the next 16-byte
    boundary via ``from_address``, and pin the backing buffer to the instance so
    it is not freed while the ``CONTEXT`` (which does not own the memory) lives.
    """
    size = sizeof(CONTEXT)
    backing = (ctypes.c_char * (size + 16))()
    aligned = (ctypes.addressof(backing) + 15) & ~15
    ctx = CONTEXT.from_address(aligned)
    ctx._backing = backing            # keep the buffer alive
    ctx.ContextFlags = flags
    return ctx


# ===========================================================================
# public value types
# ===========================================================================
@dataclass
class CreateProcessEvent:
    """Payload handed to an ``on_create_process`` handler."""
    pid: int
    tid: int
    process_handle: int
    thread_handle: int
    image_base: int
    start_address: int


@dataclass
class Breakpoint:
    address: int
    original: bytes                       # the byte we overwrote with 0xCC
    callback: Optional[Callable] = None
    active: bool = False
    hits: int = 0


# ===========================================================================
# Debugger
# ===========================================================================
class Debugger:
    """A scriptable Windows x64 debugger.

    Typical use::

        dbg = Debugger()
        dbg.on_create_process = lambda d, ev: d.set_breakpoint(ev.image_base)
        dbg.spawn('cmd.exe /c exit 7')
        dbg.run()
        assert dbg.exit_code == 7

    Handler attributes (all optional, default ``None``):

    * ``on_create_process(dbg, CreateProcessEvent)``
    * ``on_create_thread(dbg, tid, handle)``
    * ``on_exit_thread(dbg, tid, exit_code)``
    * ``on_exit_process(dbg, exit_code)``
    * ``on_dll_load(dbg, base, name)`` / ``on_dll_unload(dbg, base, name)``
    * ``on_output_string(dbg, text)``
    * ``on_breakpoint(dbg, tid, addr)``      (global; per-bp callbacks also fire)
    * ``on_single_step(dbg, tid)``
    * ``on_exception(dbg, code, addr, first_chance) -> bool``  (True == handled)
    * ``on_rip(dbg, error, type)``
    """

    def __init__(self) -> None:
        self.pid: int = 0
        self.image_base: int = 0
        self.exit_code: Optional[int] = None
        self.is_wow64: bool = False

        self._process: Optional[int] = None          # debug-event hProcess
        self._threads: Dict[int, int] = {}           # tid -> hThread
        self._modules: Dict[int, str] = {}           # base -> name
        self._breakpoints: Dict[int, Breakpoint] = {}
        self._pending_rearm: Dict[int, int] = {}     # tid -> bp addr to re-arm
        self._seen_initial_bp = False
        self._running = False
        self._attached = False

        # handler slots
        self.on_create_process: Optional[Callable] = None
        self.on_create_thread: Optional[Callable] = None
        self.on_exit_thread: Optional[Callable] = None
        self.on_exit_process: Optional[Callable] = None
        self.on_dll_load: Optional[Callable] = None
        self.on_dll_unload: Optional[Callable] = None
        self.on_output_string: Optional[Callable] = None
        self.on_breakpoint: Optional[Callable] = None
        self.on_single_step: Optional[Callable] = None
        self.on_exception: Optional[Callable] = None
        self.on_rip: Optional[Callable] = None

    # -- launch / attach ----------------------------------------------------
    def spawn(self, command_line: str) -> int:
        """Launch ``command_line`` under the debugger (``DEBUG_ONLY_THIS_PROCESS``).

        Returns the new process id. The ``CreateProcessW`` handles are closed
        immediately; memory/context use the handles the debug events deliver.
        """
        self._require_windows()
        si = STARTUPINFOW()
        si.cb = sizeof(STARTUPINFOW)
        pi = PROCESS_INFORMATION()
        # CreateProcessW may write into lpCommandLine -> pass a mutable buffer.
        cmd_buf = ctypes.create_unicode_buffer(command_line)
        ok = CreateProcessW(None, cmd_buf, None, None, False,
                            DEBUG_ONLY_THIS_PROCESS, None, None,
                            byref(si), byref(pi))
        if not ok:
            _raise("CreateProcessW")
        self.pid = pi.dwProcessId
        # We rely on the CREATE_PROCESS_DEBUG_EVENT handles, so release these.
        CloseHandle(pi.hProcess)
        CloseHandle(pi.hThread)
        return self.pid

    def attach(self, pid: int) -> None:
        """Attach to a running process (``DebugActiveProcess``). The system then
        synthesizes a ``CREATE_PROCESS`` event (with fresh handles) plus module
        and thread events for the current state."""
        self._require_windows()
        if not DebugActiveProcess(pid):
            _raise("DebugActiveProcess")
        self.pid = pid
        self._attached = True

    # -- event loop ---------------------------------------------------------
    def run(self) -> Optional[int]:
        """Pump ``WaitForDebugEvent`` / ``ContinueDebugEvent`` until the process
        exits. Returns the process exit code."""
        self._require_windows()
        self._running = True
        ev = DEBUG_EVENT()
        while self._running:
            if not WaitForDebugEvent(byref(ev), INFINITE):
                _raise("WaitForDebugEvent")
            status = self._dispatch(ev)
            if not ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status):
                _raise("ContinueDebugEvent")
        return self.exit_code

    def _dispatch(self, ev: DEBUG_EVENT) -> int:
        code = ev.dwDebugEventCode
        tid = ev.dwThreadId
        u = ev.u
        if code == CREATE_PROCESS_DEBUG_EVENT:
            return self._on_create_process(ev, u.CreateProcessInfo)
        if code == EXCEPTION_DEBUG_EVENT:
            return self._on_exception(tid, u.Exception)
        if code == CREATE_THREAD_DEBUG_EVENT:
            return self._on_create_thread(tid, u.CreateThread)
        if code == EXIT_THREAD_DEBUG_EVENT:
            return self._on_exit_thread(tid, u.ExitThread)
        if code == EXIT_PROCESS_DEBUG_EVENT:
            return self._on_exit_process(u.ExitProcess)
        if code == LOAD_DLL_DEBUG_EVENT:
            return self._on_load_dll(u.LoadDll)
        if code == UNLOAD_DLL_DEBUG_EVENT:
            return self._on_unload_dll(u.UnloadDll)
        if code == OUTPUT_DEBUG_STRING_EVENT:
            return self._on_output_string(u.DebugString)
        if code == RIP_EVENT:
            return self._on_rip(u.RipInfo)
        return DBG_CONTINUE

    # -- individual event handlers -----------------------------------------
    def _on_create_process(self, ev, info) -> int:
        self._process = info.hProcess
        self.image_base = info.lpBaseOfImage or 0
        self._threads[ev.dwThreadId] = info.hThread
        self._modules[self.image_base] = self._resolve_image_name(
            info.lpImageName, info.fUnicode) or "<image>"
        self._detect_wow64()
        # The debugger owns the file handle the event carries; close it.
        if info.hFile:
            CloseHandle(info.hFile)
        if self.on_create_process:
            self.on_create_process(self, CreateProcessEvent(
                pid=ev.dwProcessId, tid=ev.dwThreadId,
                process_handle=info.hProcess, thread_handle=info.hThread,
                image_base=self.image_base,
                start_address=info.lpStartAddress or 0))
        return DBG_CONTINUE

    def _on_create_thread(self, tid, info) -> int:
        self._threads[tid] = info.hThread
        if self.on_create_thread:
            self.on_create_thread(self, tid, info.hThread)
        return DBG_CONTINUE

    def _on_exit_thread(self, tid, info) -> int:
        if self.on_exit_thread:
            self.on_exit_thread(self, tid, info.dwExitCode)
        self._threads.pop(tid, None)
        self._pending_rearm.pop(tid, None)
        return DBG_CONTINUE

    def _on_exit_process(self, info) -> int:
        self.exit_code = info.dwExitCode
        self._running = False
        if self.on_exit_process:
            self.on_exit_process(self, info.dwExitCode)
        return DBG_CONTINUE

    def _on_load_dll(self, info) -> int:
        base = info.lpBaseOfDll or 0
        name = self._resolve_image_name(info.lpImageName, info.fUnicode)
        self._modules[base] = name or f"<dll@0x{base:x}>"
        if info.hFile:
            CloseHandle(info.hFile)
        if self.on_dll_load:
            self.on_dll_load(self, base, self._modules[base])
        return DBG_CONTINUE

    def _on_unload_dll(self, info) -> int:
        base = info.lpBaseOfDll or 0
        name = self._modules.pop(base, None)
        if self.on_dll_unload:
            self.on_dll_unload(self, base, name)
        return DBG_CONTINUE

    def _on_output_string(self, info) -> int:
        text = ""
        if info.lpDebugStringData and info.nDebugStringLength:
            try:
                raw = self.read_memory(info.lpDebugStringData,
                                       info.nDebugStringLength)
                if info.fUnicode:
                    text = raw.decode("utf-16-le", "replace")
                else:
                    text = raw.decode("latin-1", "replace")
                text = text.split("\x00", 1)[0]
            except OSError:
                text = ""
        if self.on_output_string:
            self.on_output_string(self, text)
        return DBG_CONTINUE

    def _on_rip(self, info) -> int:
        if self.on_rip:
            self.on_rip(self, info.dwError, info.dwType)
        return DBG_CONTINUE

    def _on_exception(self, tid, info) -> int:
        rec = info.ExceptionRecord
        code = rec.ExceptionCode & 0xFFFFFFFF
        addr = rec.ExceptionAddress or 0
        first_chance = bool(info.dwFirstChance)

        if code in (EXCEPTION_BREAKPOINT, STATUS_WX86_BREAKPOINT):
            if addr in self._breakpoints:
                return self._handle_user_breakpoint(tid, addr)
            if not self._seen_initial_bp:
                # The loader/system breakpoint Windows raises once at startup:
                # swallow it, do not treat it as a user breakpoint.
                self._seen_initial_bp = True
                return DBG_CONTINUE
            # An unknown int3 in the target -> hand to the exception handler.
            return self._deliver_exception(tid, code, addr, first_chance)

        if code in (EXCEPTION_SINGLE_STEP, STATUS_WX86_SINGLE_STEP):
            return self._handle_single_step(tid)

        return self._deliver_exception(tid, code, addr, first_chance)

    def _deliver_exception(self, tid, code, addr, first_chance) -> int:
        handled = False
        if self.on_exception:
            handled = bool(self.on_exception(self, code, addr, first_chance))
        return DBG_CONTINUE if handled else DBG_EXCEPTION_NOT_HANDLED

    # -- breakpoints --------------------------------------------------------
    def set_breakpoint(self, addr: int, callback: Optional[Callable] = None) -> Breakpoint:
        """Plant a software breakpoint at ``addr``: save the original byte and
        write ``0xCC``. ``callback(dbg, tid)`` fires each time it is hit (after
        RIP has been rewound to ``addr``)."""
        self._require_process()
        addr = int(addr)
        existing = self._breakpoints.get(addr)
        if existing and existing.active:
            existing.callback = callback or existing.callback
            return existing
        original = self.read_memory(addr, 1)
        bp = Breakpoint(address=addr, original=original, callback=callback)
        self._breakpoints[addr] = bp
        self._arm(bp)
        return bp

    def remove_breakpoint(self, addr: int) -> None:
        """Remove a breakpoint and restore the original byte."""
        bp = self._breakpoints.pop(int(addr), None)
        if bp and bp.active:
            self._restore(bp)

    def _arm(self, bp: Breakpoint) -> None:
        self._write_code(bp.address, INT3)
        bp.active = True

    def _restore(self, bp: Breakpoint) -> None:
        self._write_code(bp.address, bp.original)
        bp.active = False

    def _handle_user_breakpoint(self, tid: int, addr: int) -> int:
        bp = self._breakpoints[addr]
        bp.hits += 1
        # Restore the real instruction and rewind RIP so it re-executes.
        self._restore(bp)
        ctx = self.get_context(tid)
        ctx.Rip = addr
        self.set_context(tid, ctx)

        # Fire callbacks with RIP already sitting on the breakpoint.
        if bp.callback:
            bp.callback(self, tid)
        if self.on_breakpoint:
            self.on_breakpoint(self, tid, addr)

        # If the breakpoint is still wanted, single-step over the restored
        # instruction; the next SINGLE_STEP re-arms the 0xCC.
        if self._breakpoints.get(addr) is bp and not bp.active:
            ctx2 = self.get_context(tid)
            ctx2.EFlags |= TRAP_FLAG
            self.set_context(tid, ctx2)
            self._pending_rearm[tid] = addr
        return DBG_CONTINUE

    def _handle_single_step(self, tid: int) -> int:
        addr = self._pending_rearm.pop(tid, None)
        if addr is not None:
            bp = self._breakpoints.get(addr)
            if bp and not bp.active:
                self._arm(bp)               # re-plant the 0xCC
            return DBG_CONTINUE
        if self.on_single_step:
            self.on_single_step(self, tid)
        return DBG_CONTINUE

    def single_step(self, tid: int) -> None:
        """Arm a single-step (EFlags trap flag) on ``tid``; the next continue
        executes one instruction and raises ``EXCEPTION_SINGLE_STEP``."""
        ctx = self.get_context(tid)
        ctx.EFlags |= TRAP_FLAG
        self.set_context(tid, ctx)

    # -- memory -------------------------------------------------------------
    def read_memory(self, addr: int, size: int) -> bytes:
        """Read ``size`` bytes from the debuggee at ``addr``."""
        self._require_process()
        buf = (ctypes.c_char * size)()
        nread = SIZE_T(0)
        if not ReadProcessMemory(self._process, addr, buf, size, byref(nread)):
            _raise("ReadProcessMemory")
        return buf.raw[:nread.value]

    def write_memory(self, addr: int, data: bytes) -> int:
        """Write ``data`` into the debuggee at ``addr``; returns bytes written."""
        self._require_process()
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        nwritten = SIZE_T(0)
        if not WriteProcessMemory(self._process, addr, buf, len(data),
                                  byref(nwritten)):
            _raise("WriteProcessMemory")
        return nwritten.value

    def _write_code(self, addr: int, data: bytes) -> None:
        """Patch code bytes and flush the instruction cache so the CPU sees it."""
        self.write_memory(addr, data)
        FlushInstructionCache(self._process, addr, len(data))

    # -- registers ----------------------------------------------------------
    def get_context(self, tid: int, flags: int = CONTEXT_ALL) -> CONTEXT:
        """Return the (16-byte-aligned) x64 ``CONTEXT`` of thread ``tid``."""
        h = self._threads.get(tid)
        if h is None:
            raise KeyError(f"unknown thread id {tid}")
        ctx = _aligned_context(flags)
        if not GetThreadContext(h, byref(ctx)):
            _raise("GetThreadContext")
        return ctx

    def set_context(self, tid: int, ctx: CONTEXT) -> None:
        """Write ``ctx`` back to thread ``tid``."""
        h = self._threads.get(tid)
        if h is None:
            raise KeyError(f"unknown thread id {tid}")
        if not SetThreadContext(h, byref(ctx)):
            _raise("SetThreadContext")

    def get_register(self, tid: int, name: str) -> int:
        """Convenience read of one register (e.g. ``"Rip"``, ``"Rax"``)."""
        return getattr(self.get_context(tid), name)

    def set_register(self, tid: int, name: str, value: int) -> None:
        """Convenience write of one register, preserving the rest of the context."""
        ctx = self.get_context(tid)
        setattr(ctx, name, value)
        self.set_context(tid, ctx)

    # -- shutdown -----------------------------------------------------------
    def detach(self) -> None:
        """Stop debugging without killing the target (``DebugActiveProcessStop``)."""
        if self._k32_ready() and self.pid:
            for bp in list(self._breakpoints.values()):
                if bp.active:
                    try:
                        self._restore(bp)
                    except OSError:
                        pass
            DebugActiveProcessStop(self.pid)
        self._running = False

    def kill(self, exit_code: int = 0) -> None:
        """Terminate the debuggee."""
        if self._process:
            TerminateProcess(self._process, exit_code)
        self._running = False

    # -- helpers ------------------------------------------------------------
    @property
    def process_handle(self) -> Optional[int]:
        """The debuggee's process handle from the ``CREATE_PROCESS`` event — the
        ``hProcess`` that memory / context / ``VirtualQueryEx`` calls must use.
        ``None`` until the create-process event has arrived."""
        return self._process

    @property
    def threads(self) -> Dict[int, int]:
        return dict(self._threads)

    @property
    def modules(self) -> Dict[int, str]:
        return dict(self._modules)

    def _resolve_image_name(self, name_ptr, is_unicode) -> Optional[str]:
        """Best-effort module-name resolution from a debug event's ``lpImageName``.

        The field is a pointer, in the *debuggee's* address space, to a pointer
        to the name string — either link may be NULL. Failures are non-fatal.
        """
        if not name_ptr:
            return None
        try:
            str_ptr = int.from_bytes(self.read_memory(name_ptr, 8), "little")
            if not str_ptr:
                return None
            raw = self.read_memory(str_ptr, 512)
        except OSError:
            return None
        if is_unicode:
            text = raw.decode("utf-16-le", "replace")
        else:
            text = raw.decode("latin-1", "replace")
        return text.split("\x00", 1)[0] or None

    def _detect_wow64(self) -> None:
        if not self._process:
            return
        flag = BOOL(0)
        if IsWow64Process(self._process, byref(flag)):
            self.is_wow64 = bool(flag.value)

    def _require_windows(self) -> None:
        if _k32 is None:
            raise RuntimeError("Debugger requires Windows (kernel32)")

    def _require_process(self) -> None:
        self._require_windows()
        if not self._process:
            raise RuntimeError("no debuggee process handle yet "
                               "(call after CREATE_PROCESS)")

    @staticmethod
    def _k32_ready() -> bool:
        return _k32 is not None
