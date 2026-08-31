"""Process-memory module dumper for Aletheia's dynamic layer.

Attach to a live process and dump its loaded modules back to PE files on disk —
the standard memory-forensics move (Process Hacker / PE-sieve / procdump): the
mapped image of every module is read out and reconstructed into a file with
:func:`aletheia.dump.dump_pe`. Purely a *reader* — it opens the target with
``PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`` only and never writes to it.

Dependency-free ``ctypes`` over ``kernel32`` + ``psapi``, mirroring
``aletheia.debugger``'s house style. Windows-only: the module imports cleanly
off-Windows but the calls raise :class:`RuntimeError`.

Windows details that have to be exact:

* **Handle rights.** ``OpenProcess`` needs ``PROCESS_VM_READ`` (to read memory)
  and ``PROCESS_QUERY_INFORMATION`` (for ``GetModuleInformation``). It returns
  ``NULL`` on failure with the reason in ``GetLastError`` (typically
  ``ERROR_ACCESS_DENIED`` for a higher-integrity / protected target).
* **``EnumProcessModulesEx`` two-call sizing.** The first call reports the byte
  count needed via ``lpcbNeeded``; we divide by ``sizeof(HMODULE)`` to size the
  array, then call again to fill it. ``LIST_MODULES_ALL`` (0x03) enumerates both
  32- and 64-bit modules. If a module is loaded/unloaded between the two calls
  we clamp to whatever the second call actually returned.
* **WOW64.** A 64-bit reader (native Python on x64 Windows) can enumerate a
  32-bit target's modules with ``EnumProcessModulesEx`` + ``LIST_MODULES_ALL``;
  we do not need ``EnumProcessModulesEx`` from a matching-bitness process for the
  read path. (Enumerating a 64-bit target from a 32-bit process is the case that
  fails — not our situation.)
* **Unicode.** We use the ``...W`` name API (``GetModuleFileNameExW``) so paths
  with non-ANSI characters survive; the ANSI ``...A`` variant would mangle them.
* **Best-effort reads.** A mapped module has ranges that may not be fully
  committed/readable (uninitialised ``.bss``-style tails, guard pages). We read
  page-by-page and ZERO-FILL any page ``ReadProcessMemory`` refuses, so a dump
  always completes: the headers and committed sections read fine, which is all
  the reconstruction needs.
"""
from __future__ import annotations

import ctypes
import os
import sys
from ctypes import POINTER, Structure, byref, sizeof
from dataclasses import dataclass
from typing import Callable, List, Tuple

from aletheia.dump import dump_pe

# --- Win32 scalar typedefs -------------------------------------------------
BOOL = ctypes.c_int
DWORD = ctypes.c_uint32
HANDLE = ctypes.c_void_p
HMODULE = ctypes.c_void_p
LPVOID = ctypes.c_void_p
LPWSTR = ctypes.c_wchar_p
SIZE_T = ctypes.c_size_t

# --- access rights / enum filter -------------------------------------------
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
LIST_MODULES_ALL = 0x03

_PAGE = 0x1000            # read granularity for best-effort zero-fill


# ===========================================================================
# ctypes structures
# ===========================================================================
class MODULEINFO(Structure):
    """psapi ``MODULEINFO``: mapped base, image size, and absolute entry point."""
    _fields_ = [("lpBaseOfDll", LPVOID),
                ("SizeOfImage", DWORD),
                ("EntryPoint", LPVOID)]


# ===========================================================================
# kernel32 / psapi prototypes (Windows only)
# ===========================================================================
if sys.platform == "win32":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _psapi = ctypes.WinDLL("psapi", use_last_error=True)

    def _proto(dll, name, restype, argtypes):
        fn = getattr(dll, name)
        fn.restype = restype
        fn.argtypes = argtypes
        return fn

    OpenProcess = _proto(_k32, "OpenProcess", HANDLE, [DWORD, BOOL, DWORD])
    CloseHandle = _proto(_k32, "CloseHandle", BOOL, [HANDLE])
    ReadProcessMemory = _proto(
        _k32, "ReadProcessMemory", BOOL,
        [HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)])
    EnumProcessModulesEx = _proto(
        _psapi, "EnumProcessModulesEx", BOOL,
        [HANDLE, POINTER(HMODULE), DWORD, POINTER(DWORD), DWORD])
    GetModuleInformation = _proto(
        _psapi, "GetModuleInformation", BOOL,
        [HANDLE, HMODULE, POINTER(MODULEINFO), DWORD])
    GetModuleFileNameExW = _proto(
        _psapi, "GetModuleFileNameExW", DWORD,
        [HANDLE, HMODULE, LPWSTR, DWORD])
else:  # pragma: no cover - imports cleanly off-Windows, but is inert
    _k32 = _psapi = None


def _raise(fn_name: str) -> None:
    """Raise an ``OSError`` carrying the current ``GetLastError`` value."""
    raise ctypes.WinError(ctypes.get_last_error(), f"{fn_name} failed")


def _require_windows() -> None:
    if _k32 is None:
        raise RuntimeError("procdump requires Windows (kernel32 / psapi)")


# ===========================================================================
# public value type
# ===========================================================================
@dataclass
class ModuleInfo:
    """One loaded module in the target process."""
    base: int             # mapped base address (absolute)
    size: int             # SizeOfImage (bytes)
    entry: int            # absolute entry-point address (0 for data-only)
    path: str             # full on-disk path of the module
    name: str             # basename, e.g. "kernel32.dll"


# ===========================================================================
# process / module enumeration
# ===========================================================================
def open_process(pid: int) -> int:
    """Open ``pid`` for module enumeration + memory reads.

    Uses ``PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`` (read-only rights).
    Raises ``OSError`` (with the ``GetLastError`` reason) on failure.
    """
    _require_windows()
    handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        _raise(f"OpenProcess(pid={pid})")
    return handle


def _module_handles(handle: int) -> List[int]:
    """Two-call ``EnumProcessModulesEx``: size, then fill."""
    needed = DWORD(0)
    # First pass with cb=0 (a valid one-slot buffer) learns the byte count.
    probe = (HMODULE * 1)()
    if not EnumProcessModulesEx(handle, probe, 0, byref(needed), LIST_MODULES_ALL):
        _raise("EnumProcessModulesEx")
    count = needed.value // sizeof(HMODULE)
    if count == 0:
        return []
    arr = (HMODULE * count)()
    got = DWORD(0)
    # Second pass fills the sized buffer.
    if not EnumProcessModulesEx(handle, arr, sizeof(arr), byref(got),
                                LIST_MODULES_ALL):
        _raise("EnumProcessModulesEx")
    # Clamp to what the second call reported (modules can come/go between calls).
    count = min(count, got.value // sizeof(HMODULE))
    return [arr[i] for i in range(count) if arr[i]]


def _module_path(handle: int, hmod: int) -> str:
    """Full module path via ``GetModuleFileNameExW``, growing on truncation."""
    size = 260                                   # MAX_PATH; grow if it fills
    while size <= (1 << 16):
        buf = ctypes.create_unicode_buffer(size)
        n = GetModuleFileNameExW(handle, hmod, buf, size)
        if n == 0:
            return ""
        if n < size - 1:                         # not truncated
            return buf.value
        size *= 2
    return buf.value


def list_modules(pid: int) -> List[ModuleInfo]:
    """Enumerate every loaded module in ``pid`` (opens + closes its own handle)."""
    handle = open_process(pid)
    try:
        mods: List[ModuleInfo] = []
        for i, hmod in enumerate(_module_handles(handle)):
            mi = MODULEINFO()
            if not GetModuleInformation(handle, hmod, byref(mi), sizeof(mi)):
                continue                         # skip a module we can't query
            path = _module_path(handle, hmod)
            name = os.path.basename(path) if path else f"module_{i:04d}"
            mods.append(ModuleInfo(
                base=mi.lpBaseOfDll or 0,
                size=mi.SizeOfImage,
                entry=mi.EntryPoint or 0,
                path=path,
                name=name))
        return mods
    finally:
        CloseHandle(handle)


# ===========================================================================
# memory reads (best-effort, page-granular zero-fill)
# ===========================================================================
def read_memory(handle: int, addr: int, size: int) -> bytes:
    """Read ``size`` bytes at absolute ``addr`` from the process ``handle``.

    BEST-EFFORT: reads one page at a time and substitutes zeros for any page
    ``ReadProcessMemory`` cannot read (uncommitted / no-access ranges). Always
    returns exactly ``size`` bytes so a dump never aborts mid-module.
    """
    _require_windows()
    if size <= 0:
        return b""
    out = bytearray()
    end = addr + size
    cur = addr
    while cur < end:
        chunk = min(_PAGE - (cur % _PAGE), end - cur)   # up to next page boundary
        buf = (ctypes.c_char * chunk)()
        nread = SIZE_T(0)
        ok = ReadProcessMemory(handle, cur, buf, chunk, byref(nread))
        got = nread.value if ok else 0
        if got:
            out += buf.raw[:got]
        if got < chunk:                                 # zero-fill the shortfall
            out += b"\x00" * (chunk - got)
        cur += chunk
    return bytes(out)


def make_reader(handle: int) -> Callable[[int, int], bytes]:
    """Return a ``read_mem(addr, size) -> bytes`` closure bound to ``handle``,
    suitable to pass straight to :func:`aletheia.dump.dump_pe`."""
    def read_mem(addr: int, size: int) -> bytes:
        return read_memory(handle, addr, size)
    return read_mem


# ===========================================================================
# dumping
# ===========================================================================
def dump_module(pid: int, base: int) -> bytes:
    """Dump the single module mapped at ``base`` in ``pid`` to reconstructed PE
    bytes. Opens the process, reads the mapped image, closes the handle."""
    handle = open_process(pid)
    try:
        return dump_pe(make_reader(handle), base)
    finally:
        CloseHandle(handle)


def _dump_name(mod: ModuleInfo) -> str:
    """``<name>_<base:016x>.dump<ext>`` — keep the original extension."""
    stem, ext = os.path.splitext(mod.name)
    stem = stem or "module"
    return f"{stem}_{mod.base:016x}.dump{ext}"


def dump_process(pid: int, out_dir: str) -> List[Tuple[str, bool]]:
    """Dump EVERY module of ``pid`` into ``out_dir``.

    Returns ``(path, ok)`` per module. One bad module (an image we cannot
    reconstruct) never aborts the rest — it is reported ``ok=False`` and we move
    on. Opens the process once for all the reads.
    """
    os.makedirs(out_dir, exist_ok=True)
    modules = list_modules(pid)
    handle = open_process(pid)
    results: List[Tuple[str, bool]] = []
    try:
        reader = make_reader(handle)
        for mod in modules:
            path = os.path.join(out_dir, _dump_name(mod))
            try:
                data = dump_pe(reader, mod.base)
                with open(path, "wb") as fh:
                    fh.write(data)
                results.append((path, True))
            except Exception:                            # noqa: BLE001 - never abort the batch
                results.append((path, False))
    finally:
        CloseHandle(handle)
    return results
