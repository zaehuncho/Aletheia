"""Behavior logger for Aletheia's dynamic layer: an API-call timeline.

The blue-team question a sandbox answers is not "what does this binary contain?"
(that is layer-1 static triage) but "what did it *do* when it ran?" -- which DLLs
it pulled in, where it allocated RWX, what it spawned, which files and registry
keys it touched. CAPE / Cuckoo build that timeline by hooking a curated set of
security-relevant Win32 / NT APIs and recording every call. This module does the
same thing with the primitive Aletheia already has: the software breakpoints of
:class:`aletheia.debugger.Debugger`.

Mechanism:

1. As each module maps (``on_dll_load`` -- the reliable hook, since ntdll and
   kernel32 arrive as LOAD_DLL events *before* the main image runs; the
   CREATE_PROCESS event only names the exe), parse its export table with
   :func:`aletheia.imports.parse_exports` and invert ``by_rva`` into
   ``name -> rva``. For every watch-list API that this module actually exports,
   plant a breakpoint at ``base + rva``. Cache per base so we never double-arm.
   Modules are identified by their *export-directory* name (``Exports.dll_name``),
   not the debugger's ``lpImageName`` -- the latter is often NULL for ntdll.

2. Each breakpoint fires ``_on_hit(dbg, tid)`` with RIP rewound onto the function
   entry (the debugger handles the 0xCC save/restore/rewind/re-arm). At the entry,
   before the prologue runs, the x64 calling convention is exact: integer/pointer
   args 1-4 are in **RCX, RDX, R8, R9**; arg 5+ live on the stack at
   ``[RSP+0x28]``, ``[RSP+0x30]``, ... (8-byte return address + 32-byte shadow
   space); ``[RSP]`` itself is the return address (the caller). We read the arg(s)
   named in the entry's arg-spec and record a :class:`BehaviorEvent`.

Every argument read is BEST-EFFORT: a bad or unreadable pointer yields
``"<unreadable>"`` (or ``"<null>"`` for a NULL pointer) and never an exception --
one malformed arg must not tear down the trace.

Calling-convention note that had to be corrected against the real signature:
``LdrLoadDll(PWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName,
PVOID *DllHandle)`` -- the ``UNICODE_STRING*`` module name is the **3rd** argument,
so it is in **R8**, not R9. (Verified live: reading R8 yields real DLL names such
as ``KERNELBASE.dll``; R9 is the ``OUT`` handle slot and parses to garbage.)

House style mirrors ``aletheia.unpack`` / ``aletheia.debugger``: dependency-free,
imports cleanly off-Windows (the live pieces come from :class:`Debugger`, which is
itself Windows-guarded), tests skip off-Windows.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple, Union

from aletheia.debugger import Debugger
from aletheia.imports import parse_exports

# ===========================================================================
# arg-spec vocabulary
# ===========================================================================
# An argument's SOURCE is either a general-purpose register name (the value is
# read straight out of the thread CONTEXT) or a stack slot ``("stk", offset)``
# whose value is read from ``[RSP + offset]`` (offset 0x28 == the 5th integer
# arg). Its KIND says how to render the fetched 64-bit value:
#
#   "hex"    -- an integer (size / protection / flags / handle) -> ``0x...``
#   "wstr"   -- a pointer to a NUL-terminated UTF-16 string
#   "astr"   -- a pointer to a NUL-terminated ANSI string
#   "ustr"   -- a pointer to a UNICODE_STRING (Length WORD @0, Buffer PTR @8)
#   "getproc"-- GetProcAddress lpProcName: an ANSI pointer, OR a packed ordinal
#               when the value is < 0x10000 (MAKEINTRESOURCEA) -> ``#<ordinal>``
#   "lgpa"   -- LdrGetProcedureAddress: RDX is an ANSI_STRING*; if it is NULL /
#               empty the ordinal in R8 is used -> name or ``#<ordinal>``
RegSource = str
StkSource = Tuple[str, int]
Source = Union[RegSource, StkSource]

# Read granularity clamps -- a captured string is a label, not a payload dump.
_MAX_STR_BYTES = 520          # 260 wide chars / 520 ansi bytes (MAX_PATH-ish)
_MAX_USTR_BYTES = 2048        # UNICODE_STRING.Length is a WORD; clamp anyway


@dataclass(frozen=True)
class ArgField:
    """One captured argument: a display ``label``, where to read it, how to render."""
    label: str
    source: Source
    kind: str


@dataclass(frozen=True)
class WatchEntry:
    """One watch-list row: ``(module, func, category)`` plus its arg-spec.

    ``module`` is the export-directory name without extension, lower-cased
    (``"ntdll"``, ``"kernel32"``, ``"advapi32"``). ``args`` is the (possibly
    empty) list of :class:`ArgField` to capture at the call."""
    module: str
    func: str
    category: str
    args: Tuple[ArgField, ...] = ()

    @property
    def key(self) -> str:
        return f"{self.module}!{self.func}"


# ===========================================================================
# the curated watch-list  (extend by adding rows -- each is self-describing)
# ===========================================================================
# Register cheat-sheet for the arg-specs below (x64, at function ENTRY):
#   arg1=Rcx  arg2=Rdx  arg3=R8  arg4=R9   arg5=[RSP+0x28]  arg6=[RSP+0x30]
def _F(label: str, source: Source, kind: str) -> ArgField:
    return ArgField(label, source, kind)


_STK5 = ("stk", 0x28)         # 5th integer argument
_STK6 = ("stk", 0x30)         # 6th integer argument

DEFAULT_WATCHLIST: Tuple[WatchEntry, ...] = (
    # ---- loader ----------------------------------------------------------
    # LdrLoadDll(PWSTR DllPath, PULONG Chars, PUNICODE_STRING DllName [R8],
    #            PVOID *DllHandle). DllName is arg3 -> R8 (NOT R9; see docstring).
    WatchEntry("ntdll", "LdrLoadDll", "loader",
               (_F("dll", "R8", "ustr"),)),
    # LdrGetProcedureAddress(PVOID Base, PANSI_STRING Name [Rdx], ULONG Ord [R8],
    #                        PVOID *Addr) -- Name is a *counted* ANSI_STRING, and
    # when it is NULL the ordinal in R8 is used. "lgpa" reads both.
    WatchEntry("ntdll", "LdrGetProcedureAddress", "loader",
               (_F("proc", "Rdx", "lgpa"),)),
    WatchEntry("kernel32", "LoadLibraryA", "loader",
               (_F("lib", "Rcx", "astr"),)),
    WatchEntry("kernel32", "LoadLibraryW", "loader",
               (_F("lib", "Rcx", "wstr"),)),
    # LoadLibraryExW(LPCWSTR lpLibFileName [Rcx], HANDLE hFile, DWORD dwFlags [R8]).
    WatchEntry("kernel32", "LoadLibraryExW", "loader",
               (_F("lib", "Rcx", "wstr"), _F("flags", "R8", "hex"))),
    # GetProcAddress(HMODULE hModule, LPCSTR lpProcName [Rdx]) -- ansi ptr or
    # packed ordinal.
    WatchEntry("kernel32", "GetProcAddress", "loader",
               (_F("proc", "Rdx", "getproc"),)),

    # ---- memory ----------------------------------------------------------
    # VirtualAlloc(lpAddress, SIZE_T dwSize [Rdx], DWORD type, DWORD flProtect [R9]).
    WatchEntry("kernel32", "VirtualAlloc", "memory",
               (_F("size", "Rdx", "hex"), _F("protect", "R9", "hex"))),
    # VirtualAllocEx(hProcess, lpAddress, SIZE_T dwSize [R8], DWORD type,
    #                DWORD flProtect [RSP+0x28]).
    WatchEntry("kernel32", "VirtualAllocEx", "memory",
               (_F("size", "R8", "hex"), _F("protect", _STK5, "hex"))),
    # VirtualProtect(lpAddress [Rcx], SIZE_T dwSize [Rdx], DWORD flNewProtect [R8],
    #                PDWORD lpflOldProtect).
    WatchEntry("kernel32", "VirtualProtect", "memory",
               (_F("addr", "Rcx", "hex"), _F("size", "Rdx", "hex"),
                _F("newprotect", "R8", "hex"))),
    # VirtualProtectEx(hProcess, lpAddress [Rdx], SIZE_T dwSize [R8],
    #                  DWORD flNewProtect [R9], PDWORD lpflOldProtect).
    WatchEntry("kernel32", "VirtualProtectEx", "memory",
               (_F("addr", "Rdx", "hex"), _F("size", "R8", "hex"),
                _F("newprotect", "R9", "hex"))),
    # WriteProcessMemory(hProcess, lpBaseAddress [Rdx], lpBuffer, SIZE_T nSize [R9]).
    WatchEntry("kernel32", "WriteProcessMemory", "memory",
               (_F("dest", "Rdx", "hex"), _F("size", "R9", "hex"))),
    # NtProtectVirtualMemory(hProc, PVOID *Base, PSIZE_T Size, ULONG NewProtect [R9],
    #                        PULONG OldProtect). NewProtect is a direct value.
    WatchEntry("ntdll", "NtProtectVirtualMemory", "memory",
               (_F("newprotect", "R9", "hex"),)),
    # NtAllocateVirtualMemory(hProc, PVOID *Base, ULONG_PTR ZeroBits,
    #   PSIZE_T RegionSize, ULONG Type [RSP+0x28], ULONG Protect [RSP+0x30]).
    WatchEntry("ntdll", "NtAllocateVirtualMemory", "memory",
               (_F("type", _STK5, "hex"), _F("protect", _STK6, "hex"))),

    # ---- process ---------------------------------------------------------
    # CreateProcessA(LPCSTR lpApplicationName [Rcx], LPSTR lpCommandLine [Rdx], ...).
    WatchEntry("kernel32", "CreateProcessA", "process",
               (_F("app", "Rcx", "astr"), _F("cmdline", "Rdx", "astr"))),
    # CreateProcessW(LPCWSTR lpApplicationName [Rcx], LPWSTR lpCommandLine [Rdx], ...).
    WatchEntry("kernel32", "CreateProcessW", "process",
               (_F("app", "Rcx", "wstr"), _F("cmdline", "Rdx", "wstr"))),
    # NtCreateThreadEx(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE Process [R9],
    #   PVOID StartRoutine [RSP+0x28], PVOID Argument, ...).
    WatchEntry("ntdll", "NtCreateThreadEx", "process",
               (_F("process", "R9", "hex"), _F("start", _STK5, "hex"))),
    # CreateRemoteThread(HANDLE hProcess [Rcx], ..., LPTHREAD_START_ROUTINE
    #   lpStartAddress [R9], ...).
    WatchEntry("kernel32", "CreateRemoteThread", "process",
               (_F("process", "Rcx", "hex"), _F("start", "R9", "hex"))),

    # ---- file ------------------------------------------------------------
    # CreateFileW(LPCWSTR lpFileName [Rcx], DWORD dwDesiredAccess [Rdx], ...).
    WatchEntry("kernel32", "CreateFileW", "file",
               (_F("path", "Rcx", "wstr"), _F("access", "Rdx", "hex"))),
    WatchEntry("kernel32", "CreateFileA", "file",
               (_F("path", "Rcx", "astr"), _F("access", "Rdx", "hex"))),

    # ---- registry --------------------------------------------------------
    # RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey [Rdx], ...).
    WatchEntry("advapi32", "RegCreateKeyExW", "registry",
               (_F("subkey", "Rdx", "wstr"),)),
    # RegSetValueExW(HKEY hKey, LPCWSTR lpValueName [Rdx], DWORD Reserved,
    #   DWORD dwType [R9], const BYTE *lpData, DWORD cbData).
    WatchEntry("advapi32", "RegSetValueExW", "registry",
               (_F("value", "Rdx", "wstr"), _F("type", "R9", "hex"))),
)


# ===========================================================================
# arg rendering  (best-effort; a bad read is a label, never an exception)
# ===========================================================================
ReadMem = Callable[[int, int], bytes]


def _read_bounded_wstr(read_mem: ReadMem, addr: int,
                       max_bytes: int = _MAX_STR_BYTES) -> str:
    """NUL-terminated UTF-16-LE string at ``addr``. ``"<null>"`` / ``"<unreadable>"``
    on a NULL / unreadable pointer."""
    if not addr:
        return "<null>"
    try:
        raw = read_mem(addr, max_bytes)
    except Exception:            # noqa: BLE001 - a bad read is just "no string"
        return "<unreadable>"
    # find a 16-bit NUL on an even boundary
    end = len(raw) - (len(raw) % 2)
    for i in range(0, end, 2):
        if raw[i] == 0 and raw[i + 1] == 0:
            end = i
            break
    return raw[:end].decode("utf-16-le", "replace")


def _read_bounded_astr(read_mem: ReadMem, addr: int,
                       max_bytes: int = _MAX_STR_BYTES) -> str:
    """NUL-terminated ANSI string at ``addr`` (decoded utf-8 w/ replacement)."""
    if not addr:
        return "<null>"
    try:
        raw = read_mem(addr, max_bytes)
    except Exception:            # noqa: BLE001
        return "<unreadable>"
    nul = raw.find(b"\x00")
    if nul >= 0:
        raw = raw[:nul]
    return raw.decode("utf-8", "replace")


def _read_ptr(read_mem: ReadMem, addr: int) -> Optional[int]:
    """Read one little-endian 8-byte pointer; ``None`` on a bad read."""
    try:
        raw = read_mem(addr, 8)
    except Exception:            # noqa: BLE001
        return None
    if len(raw) < 8:
        return None
    return int.from_bytes(raw, "little")


def _read_unicode_string(read_mem: ReadMem, addr: int) -> str:
    """Render a ``UNICODE_STRING*`` (``{USHORT Length; USHORT Max; PWSTR Buffer@+8}``)."""
    if not addr:
        return "<null>"
    try:
        hdr = read_mem(addr, 16)
    except Exception:            # noqa: BLE001
        return "<unreadable>"
    if len(hdr) < 16:
        return "<unreadable>"
    length = int.from_bytes(hdr[0:2], "little")
    buffer = int.from_bytes(hdr[8:16], "little")
    if not buffer:
        return "<null>"
    if length == 0:
        return ""
    length = min(length, _MAX_USTR_BYTES)
    try:
        raw = read_mem(buffer, length)
    except Exception:            # noqa: BLE001
        return "<unreadable>"
    return raw.decode("utf-16-le", "replace")


def _read_ansi_string(read_mem: ReadMem, addr: int) -> Optional[str]:
    """Render an ``ANSI_STRING*`` (``{USHORT Length; USHORT Max; PCHAR Buffer@+8}``).

    Returns ``None`` (not a string) when the struct pointer / Buffer is NULL or
    Length is 0 -- the caller falls back to an ordinal. ``"<unreadable>"`` on a
    genuinely bad read."""
    if not addr:
        return None
    try:
        hdr = read_mem(addr, 16)
    except Exception:            # noqa: BLE001
        return "<unreadable>"
    if len(hdr) < 16:
        return "<unreadable>"
    length = int.from_bytes(hdr[0:2], "little")
    buffer = int.from_bytes(hdr[8:16], "little")
    if not buffer or length == 0:
        return None
    length = min(length, _MAX_USTR_BYTES)
    try:
        raw = read_mem(buffer, length)
    except Exception:            # noqa: BLE001
        return "<unreadable>"
    return raw.decode("utf-8", "replace")


def _render_getproc(read_mem: ReadMem, value: int) -> str:
    """GetProcAddress lpProcName: packed ordinal (< 0x10000) or ANSI pointer."""
    if value == 0:
        return "<null>"
    if value < 0x10000:                      # MAKEINTRESOURCEA(ordinal)
        return "#%d" % value
    return _read_bounded_astr(read_mem, value)


def _render_field(read_mem: ReadMem, field_val: int, kind: str,
                  ordinal_val: int = 0) -> str:
    """Render one fetched 64-bit ``field_val`` according to ``kind``.

    ``ordinal_val`` carries the R8 ordinal for the ``"lgpa"`` kind (its only
    two-source case). Never raises: an unreadable pointer renders as a marker."""
    if kind == "hex":
        return "0x%x" % (field_val & 0xFFFFFFFFFFFFFFFF)
    if kind == "wstr":
        return _read_bounded_wstr(read_mem, field_val)
    if kind == "astr":
        return _read_bounded_astr(read_mem, field_val)
    if kind == "ustr":
        return _read_unicode_string(read_mem, field_val)
    if kind == "getproc":
        return _render_getproc(read_mem, field_val)
    if kind == "lgpa":
        name = _read_ansi_string(read_mem, field_val)
        if name:
            return name
        return "#%d" % (ordinal_val & 0xFFFFFFFF)     # NULL name -> R8 ordinal
    return "0x%x" % (field_val & 0xFFFFFFFFFFFFFFFF)   # unknown kind -> hex


# ===========================================================================
# event + monitor
# ===========================================================================
@dataclass
class BehaviorEvent:
    """One recorded API call.

    ``args`` maps each arg-spec label to its rendered string; ``detail`` is the
    same, joined for display. ``ret_addr`` is the caller (``[RSP]`` at entry)."""
    seq: int
    tid: int
    module: str
    func: str
    category: str
    args: Dict[str, str] = field(default_factory=dict)
    detail: str = ""
    ret_addr: int = 0

    def __str__(self) -> str:
        who = "0x%x" % self.ret_addr if self.ret_addr else "?"
        body = f"({self.detail})" if self.detail else "()"
        return (f"#{self.seq:<4} tid={self.tid:<6} {self.category:<8} "
                f"{self.module}!{self.func}{body}  <- {who}")


class BehaviorMonitor:
    """Watch a :class:`Debugger` and record a timeline of watch-list API calls.

    Construction installs chaining handlers for ``on_create_process`` and
    ``on_dll_load`` (like :class:`aletheia.unpack.UnpackMonitor`): set your own
    versions of those handlers on the debugger BEFORE constructing the monitor;
    the monitor does its bookkeeping first, then calls yours.

    After a run, ``events`` is the ordered timeline, ``armed`` maps every armed
    ``"module!func"`` key to the absolute address it is planted at, and
    ``summary()`` gives per-category counts."""

    def __init__(self, debugger: Debugger,
                 watchlist: Tuple[WatchEntry, ...] = DEFAULT_WATCHLIST,
                 max_events: Optional[int] = None) -> None:
        self.dbg = debugger
        self.max_events = max_events
        self.events: List[BehaviorEvent] = []
        self.armed: Dict[str, int] = {}          # "module!func" -> address
        self.capped: bool = False

        # module (lower, no ext) -> [WatchEntry, ...]
        self._by_module: Dict[str, List[WatchEntry]] = {}
        for entry in watchlist:
            self._by_module.setdefault(entry.module, []).append(entry)

        self._parsed_bases: set = set()          # modules already inspected
        self._bp_meta: Dict[int, WatchEntry] = {}   # bp addr -> watch row
        self._seq = 0

        # Chain whatever handlers were already registered.
        self._user_create = debugger.on_create_process
        self._user_dll = debugger.on_dll_load
        debugger.on_create_process = self._handle_create
        debugger.on_dll_load = self._handle_dll

    # -- debugger event handlers (chained) ---------------------------------
    def _handle_create(self, dbg: Debugger, ev) -> None:
        # The main image is the only module named here; arm anything it exports
        # from the watch-list (usually nothing, but correct for a re-exporting
        # or DLL target). ntdll/kernel32 arrive as their own LOAD_DLL events.
        if ev.image_base:
            self._inspect_module(dbg, ev.image_base)
        if self._user_create:
            self._user_create(dbg, ev)

    def _handle_dll(self, dbg: Debugger, base: int, name) -> None:
        if base:
            self._inspect_module(dbg, base, hint_name=name)
        if self._user_dll:
            self._user_dll(dbg, base, name)

    # -- arming -------------------------------------------------------------
    def _inspect_module(self, dbg: Debugger, base: int,
                        hint_name: Optional[str] = None) -> None:
        """Parse ``base``'s exports and arm every watch-list API it exports."""
        if base in self._parsed_bases:
            return
        self._parsed_bases.add(base)

        exp = parse_exports(dbg.read_memory, base)
        module_key = _normalise_module(exp.dll_name) or _normalise_module(hint_name)
        if not module_key:
            return
        wanted = self._by_module.get(module_key)
        if not wanted:
            return
        if not exp.ok:
            return

        name_to_rva: Dict[str, int] = {}
        for rva, nm in exp.by_rva.items():
            # First writer wins is fine; these are unique export names.
            name_to_rva.setdefault(nm, rva)

        for entry in wanted:
            if entry.key in self.armed:          # already armed elsewhere
                continue
            rva = _resolve_export_rva(name_to_rva, entry.func)
            if rva is None:                      # forwarder / not exported here
                continue
            addr = base + rva
            self._bp_meta[addr] = entry
            self.armed[entry.key] = addr
            dbg.set_breakpoint(addr, self._on_hit)

    # -- the breakpoint callback -------------------------------------------
    def _on_hit(self, dbg: Debugger, tid: int) -> None:
        if self.capped:
            return
        rip = dbg.get_register(tid, "Rip")
        entry = self._bp_meta.get(rip)
        if entry is None:                        # not one of ours (defensive)
            return
        try:
            ctx = dbg.get_context(tid)
        except Exception:                        # noqa: BLE001 - never kill the trace
            return

        read_mem = dbg.read_memory
        rsp = ctx.Rsp
        ret_addr = _read_ptr(read_mem, rsp) or 0

        rendered: Dict[str, str] = {}
        for af in entry.args:
            try:
                val = _fetch_source(read_mem, ctx, af.source)
                if val is None:
                    rendered[af.label] = "<unreadable>"
                    continue
                ordinal_val = 0
                if af.kind == "lgpa":            # ordinal companion lives in R8
                    ordinal_val = ctx.R8
                rendered[af.label] = _render_field(read_mem, val, af.kind,
                                                   ordinal_val)
            except Exception:                    # noqa: BLE001 - best-effort per arg
                rendered[af.label] = "<unreadable>"

        detail = ", ".join(f"{k}={v}" for k, v in rendered.items())
        self._seq += 1
        self.events.append(BehaviorEvent(
            seq=self._seq, tid=tid, module=entry.module, func=entry.func,
            category=entry.category, args=rendered, detail=detail,
            ret_addr=ret_addr))

        if self.max_events is not None and len(self.events) >= self.max_events:
            self._disarm_all()

    def _disarm_all(self) -> None:
        """Runaway guard: stop recording and pull every breakpoint so the target
        finishes at native speed."""
        self.capped = True
        for addr in list(self._bp_meta):
            try:
                self.dbg.remove_breakpoint(addr)
            except Exception:                    # noqa: BLE001
                pass

    # -- reporting ----------------------------------------------------------
    def summary(self) -> Dict[str, int]:
        """Per-category call counts over the recorded timeline."""
        counts: Dict[str, int] = {}
        for ev in self.events:
            counts[ev.category] = counts.get(ev.category, 0) + 1
        return counts


# ===========================================================================
# helpers
# ===========================================================================
def _resolve_export_rva(name_to_rva: Dict[str, int], func: str) -> Optional[int]:
    """Look ``func`` up in a module's ``name -> rva`` map, resolving the ntdll
    ``Nt*`` / ``Zw*`` alias.

    In user-mode ntdll the ``NtXxx`` and ``ZwXxx`` stubs are byte-identical and
    export the *same* RVA. :func:`aletheia.imports.parse_exports` keeps only one
    name per RVA (last-wins), and ``Zw`` sorts after ``Nt``, so ``by_rva`` carries
    ``ZwProtectVirtualMemory`` while the requested ``NtProtectVirtualMemory`` is
    absent. Arming the ``Zw`` twin plants the breakpoint on the identical stub, so
    fall through to it (and the reverse, for completeness)."""
    rva = name_to_rva.get(func)
    if rva is not None:
        return rva
    if func.startswith("Nt"):
        return name_to_rva.get("Zw" + func[2:])
    if func.startswith("Zw"):
        return name_to_rva.get("Nt" + func[2:])
    return None


def _normalise_module(name: Optional[str]) -> str:
    """``'C:\\...\\KERNEL32.DLL'`` / ``'ntdll.dll'`` -> ``'kernel32'`` / ``'ntdll'``."""
    if not name:
        return ""
    base = name.replace("/", "\\").rsplit("\\", 1)[-1].strip().lower()
    if base.endswith(".dll"):
        base = base[:-4]
    return base


def _fetch_source(read_mem: ReadMem, ctx, source: Source) -> Optional[int]:
    """Resolve an arg SOURCE to its 64-bit value.

    A register name reads straight from the CONTEXT; a ``("stk", off)`` slot is
    read from ``[RSP + off]`` in the debuggee. Returns ``None`` on a bad stack
    read (rendered as ``"<unreadable>"`` by the caller)."""
    if isinstance(source, tuple):
        _tag, off = source
        return _read_ptr(read_mem, ctx.Rsp + off)
    return int(getattr(ctx, source))


# ===========================================================================
# convenience runner
# ===========================================================================
def run_trace(command: str,
              watchlist: Tuple[WatchEntry, ...] = DEFAULT_WATCHLIST,
              max_events: Optional[int] = None) -> List[BehaviorEvent]:
    """Spawn ``command`` under a fresh debugger, trace it to exit, return the
    timeline.

    ``max_events`` bounds a runaway target: on reaching it the monitor disarms
    every breakpoint and the debuggee runs on to its natural exit. Only the
    timeline is returned -- construct a :class:`BehaviorMonitor` directly if you
    also need ``armed`` / ``summary()`` / the exit code afterwards.
    """
    dbg = Debugger()
    mon = BehaviorMonitor(dbg, watchlist=watchlist, max_events=max_events)
    dbg.spawn(command)
    dbg.run()
    return mon.events
