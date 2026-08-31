"""Dynamic unpacker for Aletheia's dynamic layer: catch *write-then-execute*.

The universal tell of a self-unpacking or code-injecting binary is that control
eventually transfers into memory that was *not* part of any originally-loaded
module -- a freshly ``VirtualAlloc``'d payload buffer, an RWX scratch section the
stub decompressed into, or a region injected into another process. This is the
exact signal defensive tools such as PE-sieve / hollows_hunter key on. Once we
catch that moment we have the real (unpacked) entry point (OEP) and can dump the
revealed image with :func:`aletheia.dump.dump_module`.

Mechanism (first cut, deliberately simple and exact over fast):

1. Track ``[base, base + SizeOfImage)`` for the main image (from the
   ``CREATE_PROCESS`` event) and for every DLL as it loads. :meth:`is_image_address`
   answers "does this address live inside a known, originally-loaded module?".
2. From a chosen start point (the loader/entry breakpoint), **single-step** the
   thread. On each step, classify ``Rip``. When it lands *outside* all
   known-image ranges we do NOT fire immediately: the Windows loader plants tiny
   executable thunks on pages just past a module's ``SizeOfImage`` (observed on
   plain ``cmd.exe`` at ``ntdll_base + SizeOfImage + 0xC0``), so "outside every
   image" alone has a real false positive. We add a memory-type gate
   (:func:`is_dynamic_executable`): a genuine unpacked payload lives in a
   dynamically produced, *private*, *executable* buffer (``MEM_PRIVATE`` +
   ``PAGE_EXECUTE*``), whereas a loader thunk is ``MEM_IMAGE`` (or otherwise not
   private-executable). Only when the out-of-image address is a private
   executable region is that the candidate OEP: record it, fire
   ``on_unpacked(addr)``, and stop stepping. An out-of-image thunk that fails the
   gate is not a payload -- keep stepping.

Single-stepping every instruction is slow for a real program (one debug round
trip per instruction). It is perfectly fine for the synthetic, deterministic
test here. The production optimization is to *not* single-step: mark the known
image ranges no-execute (or leave the rest of the address space guarded) with
``PAGE_GUARD`` / ``PAGE_NOACCESS`` and take a fault the instant execution leaves
them, or use the hardware branch-trap / MTF facilities -- O(1) instead of
O(instructions). The classification predicate below is identical either way;
only the trigger changes.

House style mirrors ``aletheia.debugger`` / ``aletheia.procdump``: dependency-free,
imports cleanly off-Windows (the live pieces come from :class:`Debugger`, which is
itself Windows-guarded), and the tests skip off-Windows.
"""
from __future__ import annotations

import ctypes
import struct
import sys
from ctypes import POINTER, Structure, byref, sizeof
from dataclasses import dataclass
from typing import Callable, Dict, Optional

from aletheia.debugger import Debugger
from aletheia.dump import dump_module

# Optional-header offsets (identical for PE32 and PE32+): SizeOfImage lives at
# +56 past the start of the optional header regardless of the 32/64-bit magic.
_OPT_SIZE_OF_IMAGE = 56


# ===========================================================================
# VirtualQueryEx: the memory-type gate that separates a real unpacked payload
# (a private, executable, dynamically produced buffer) from a benign loader
# thunk on a page just past a mapped module.
# ===========================================================================
# --- Win32 scalar typedefs -------------------------------------------------
_DWORD = ctypes.c_uint32
_WORD = ctypes.c_uint16
_HANDLE = ctypes.c_void_p
_LPCVOID = ctypes.c_void_p
_SIZE_T = ctypes.c_size_t

# --- memory State / Type / Protect constants -------------------------------
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000

PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
_EXECUTABLE_PROTECT = frozenset((
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
))

# Protection modifier flags that OR onto the base protection and must be masked
# off before the comparison: PAGE_GUARD (0x100), PAGE_NOCACHE (0x200),
# PAGE_WRITECOMBINE (0x400).
_PROTECT_MODIFIER_MASK = 0x100 | 0x200 | 0x400


class MEMORY_BASIC_INFORMATION(Structure):
    """x64 ``MEMORY_BASIC_INFORMATION`` (48 bytes).

    The ``PartitionId`` ``WORD`` (Win10+ SDK) occupies the two bytes after
    ``AllocationProtect`` that older headers left as pure alignment padding;
    either way ``RegionSize`` re-aligns to offset 24 and the whole struct is
    48 bytes on x64. Field offsets (verified): BaseAddress 0, AllocationBase 8,
    AllocationProtect 16, PartitionId 20, RegionSize 24, State 32, Protect 36,
    Type 40."""
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", _DWORD),
        ("PartitionId", _WORD),
        ("RegionSize", _SIZE_T),
        ("State", _DWORD),
        ("Protect", _DWORD),
        ("Type", _DWORD),
    ]


if sys.platform == "win32":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _VirtualQueryEx = _k32.VirtualQueryEx
    _VirtualQueryEx.restype = _SIZE_T
    _VirtualQueryEx.argtypes = [_HANDLE, _LPCVOID,
                                POINTER(MEMORY_BASIC_INFORMATION), _SIZE_T]
else:  # pragma: no cover - imports cleanly off-Windows, but is inert
    _k32 = None
    _VirtualQueryEx = None


def is_dynamic_executable(handle: Optional[int], addr: int) -> bool:
    """True iff ``addr`` sits in a committed, private, executable region.

    This is the signature of a dynamically produced payload buffer -- a
    ``VirtualAlloc``'d RWX/RX scratch region the packer stub decompressed or
    injected into -- as opposed to a mapped image or a loader-generated thunk
    near one. Concretely, ``VirtualQueryEx(handle, addr)`` must report

    * ``State == MEM_COMMIT`` (0x1000),
    * ``Type  == MEM_PRIVATE`` (0x20000), and
    * ``Protect`` (after masking off ``PAGE_GUARD`` / ``PAGE_NOCACHE`` /
      ``PAGE_WRITECOMBINE``) is one of ``PAGE_EXECUTE`` / ``PAGE_EXECUTE_READ``
      / ``PAGE_EXECUTE_READWRITE`` / ``PAGE_EXECUTE_WRITECOPY``.

    Fail closed: a null handle, a non-Windows host, or a ``VirtualQueryEx`` that
    fails / does not fill the whole struct -> ``False`` (do not fire on a region
    we cannot classify)."""
    if _VirtualQueryEx is None or not handle:
        return False
    mbi = MEMORY_BASIC_INFORMATION()
    n = _VirtualQueryEx(handle, ctypes.c_void_p(int(addr)), byref(mbi), sizeof(mbi))
    if n < sizeof(mbi):                              # 0 on failure; short == bad
        return False
    if mbi.State != MEM_COMMIT or mbi.Type != MEM_PRIVATE:
        return False
    base_protect = mbi.Protect & ~_PROTECT_MODIFIER_MASK
    return base_protect in _EXECUTABLE_PROTECT


def size_of_image(read_mem: Callable[[int, int], bytes], base: int) -> int:
    """Read ``SizeOfImage`` from the PE mapped at ``base``.

    ``read_mem(addr, size) -> bytes`` is any reader over the debuggee (e.g.
    ``Debugger.read_memory``). Returns 0 if the header cannot be read or is not a
    PE -- callers treat a 0 size as "range unknown, skip it".
    """
    try:
        hdr = read_mem(base, 0x1000)
    except OSError:
        return 0
    if len(hdr) < 0x40 or hdr[:2] != b"MZ":
        return 0
    try:
        (e_lfanew,) = struct.unpack_from("<I", hdr, 0x3C)
        if hdr[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return 0
        opt = e_lfanew + 4 + 20                       # skip PE sig + COFF header
        (soi,) = struct.unpack_from("<I", hdr, opt + _OPT_SIZE_OF_IMAGE)
    except struct.error:
        return 0
    return soi


# ===========================================================================
# image-range map + the classification predicate
# ===========================================================================
class ImageMap:
    """The set of ``[base, base + size)`` ranges backed by originally-loaded
    modules (the main image + each DLL). ``[base, base + SizeOfImage)`` is a fine
    first approximation of a module's mapped extent."""

    def __init__(self) -> None:
        self._ranges: Dict[int, int] = {}            # base -> size

    def add(self, base: int, size: int) -> None:
        if base and size > 0:
            self._ranges[int(base)] = int(size)

    def remove(self, base: int) -> None:
        self._ranges.pop(int(base), None)

    def is_image_address(self, addr: int) -> bool:
        """True iff ``addr`` falls inside a known module's mapped range. The
        range is half-open: ``base`` is in, ``base + size`` is out."""
        addr = int(addr)
        for base, size in self._ranges.items():
            if base <= addr < base + size:
                return True
        return False

    @property
    def ranges(self) -> Dict[int, int]:
        return dict(self._ranges)


# ===========================================================================
# public result type
# ===========================================================================
@dataclass
class UnpackResult:
    """Outcome of a monitored run.

    ``detected``   -- did execution reach code outside every known image?
    ``oep``        -- that first out-of-image address (the candidate OEP), or None.
    ``main_base``  -- mapped base of the main image (for ``dump_module``).
    """
    detected: bool
    oep: Optional[int]
    main_base: int
    exit_code: Optional[int] = None
    dump: Optional[bytes] = None


# ===========================================================================
# the monitor
# ===========================================================================
class UnpackMonitor:
    """Watch a :class:`Debugger` for execution of dynamically produced code.

    Construction installs chaining handlers on the debugger for
    ``on_create_process``, ``on_dll_load`` and ``on_single_step`` -- so set any of
    *your own* versions of those handlers on the debugger BEFORE constructing the
    monitor; the monitor records its bookkeeping first, then calls yours.

    Typical (auto) use, for a real packed sample::

        dbg = Debugger()
        mon = UnpackMonitor(dbg)                    # auto_arm: step from the OEP
        mon.on_unpacked = lambda addr: print(hex(addr))
        dbg.spawn(sample)
        dbg.run()

    With ``auto_arm=True`` the monitor plants a one-shot breakpoint at the image
    entry point and begins single-stepping the instant it is hit (the packer stub
    runs from there). With ``auto_arm=False`` the caller drives stepping via
    :meth:`begin_stepping` -- used by the deterministic test to borrow a thread and
    point it at a freshly written buffer.
    """

    def __init__(self, debugger: Debugger, auto_arm: bool = True,
                 max_steps: Optional[int] = None) -> None:
        self.dbg = debugger
        self.auto_arm = auto_arm
        self.max_steps = max_steps               # None -> step until detect/exit
        self.images = ImageMap()
        self.main_base: int = 0
        self.detected: bool = False
        self.oep: Optional[int] = None
        self.stepping: bool = False
        self.stepping_tid: Optional[int] = None
        self.step_count: int = 0
        self.gave_up: bool = False               # ran out of step budget
        self.on_unpacked: Optional[Callable[[int], None]] = None

        # Chain whatever handlers were already registered.
        self._user_create = debugger.on_create_process
        self._user_dll = debugger.on_dll_load
        self._user_step = debugger.on_single_step
        debugger.on_create_process = self._handle_create
        debugger.on_dll_load = self._handle_dll
        debugger.on_single_step = self._handle_step

    # -- the predicate ------------------------------------------------------
    def is_image_address(self, addr: int) -> bool:
        """Does ``addr`` lie inside a known, originally-loaded module?"""
        return self.images.is_image_address(addr)

    # -- driving the single-step scan --------------------------------------
    def begin_stepping(self, tid: int) -> None:
        """Start single-stepping thread ``tid``: each continue now executes one
        instruction and reports back through ``on_single_step``."""
        self.stepping = True
        self.stepping_tid = tid
        self.dbg.single_step(tid)

    def stop_stepping(self) -> None:
        self.stepping = False

    # -- debugger event handlers (chained) ---------------------------------
    def _handle_create(self, dbg: Debugger, ev) -> None:
        self.main_base = ev.image_base or 0
        self.images.add(ev.image_base, size_of_image(dbg.read_memory, ev.image_base))
        if self.auto_arm and ev.image_base:
            self._arm_entry(dbg, ev.image_base)
        if self._user_create:
            self._user_create(dbg, ev)

    def _handle_dll(self, dbg: Debugger, base: int, name) -> None:
        self.images.add(base, size_of_image(dbg.read_memory, base))
        if self._user_dll:
            self._user_dll(dbg, base, name)

    def _handle_step(self, dbg: Debugger, tid: int) -> None:
        if self.stepping and not self.detected:
            self.step_count += 1
            rip = dbg.get_register(tid, "Rip")
            # Fire only when execution has left every image AND landed in a
            # private, executable, dynamically produced buffer -- the real OEP.
            # An out-of-image address that fails the memory-type gate is a benign
            # loader thunk (MEM_IMAGE past a module's SizeOfImage): keep stepping.
            if (not self.is_image_address(rip)
                    and is_dynamic_executable(dbg.process_handle, rip)):
                self._fire_unpacked(rip)             # unpacked payload -> OEP found
            elif self.max_steps is not None and self.step_count >= self.max_steps:
                self.stepping = False                # budget spent; stop the scan
                self.gave_up = True
            else:
                dbg.single_step(tid)                 # in image / benign thunk -> go
        if self._user_step:
            self._user_step(dbg, tid)

    def _fire_unpacked(self, addr: int) -> None:
        self.detected = True
        self.oep = addr
        self.stepping = False                        # stop the scan
        if self.on_unpacked:
            self.on_unpacked(addr)

    def _arm_entry(self, dbg: Debugger, base: int) -> None:
        """Plant a one-shot breakpoint at the image entry point; stepping starts
        when it fires. Best-effort -- if the header/entry can't be read we simply
        never auto-start (the caller can still drive :meth:`begin_stepping`)."""
        try:
            hdr = dbg.read_memory(base, 0x1000)
        except OSError:
            return
        from aletheia.pe import parse_bytes
        pe = parse_bytes(hdr)
        if not pe.ok or not pe.entry_rva:
            return
        entry = base + pe.entry_rva

        def _at_entry(d: Debugger, tid: int) -> None:
            d.remove_breakpoint(entry)               # one-shot
            self.begin_stepping(tid)

        dbg.set_breakpoint(entry, _at_entry)


# ===========================================================================
# convenience runner
# ===========================================================================
def run_unpack(command: str, dump_payload: bool = False,
               terminate_on_detect: bool = True,
               max_steps: Optional[int] = None) -> UnpackResult:
    """Spawn ``command`` under a fresh debugger and monitor it to detection or exit.

    On the first out-of-image execution the candidate OEP is recorded; if
    ``dump_payload`` is set, the main image is dumped at that OEP into
    ``UnpackResult.dump``. By default the debuggee is then terminated
    (``terminate_on_detect``) so a real payload does not run on past the catch;
    pass ``terminate_on_detect=False`` to let it continue to a natural exit.

    NB: this single-steps from the entry point, so it is only practical on an
    actually-packed target (which transfers out of its image quickly). On an
    ordinary program it would step the whole run and never detect -- see the
    module docstring for the PAGE_GUARD/hardware production trigger.
    """
    dbg = Debugger()
    mon = UnpackMonitor(dbg, auto_arm=True, max_steps=max_steps)
    captured: Dict[str, Optional[bytes]] = {"dump": None}

    def _on_unpacked(addr: int) -> None:
        if dump_payload and mon.main_base:
            try:
                captured["dump"] = dump_module(
                    dbg, mon.main_base, oep_rva=addr - mon.main_base)
            except Exception:                        # noqa: BLE001 - dump is best-effort
                captured["dump"] = None
        if terminate_on_detect:
            dbg.kill()                               # stop the run promptly

    mon.on_unpacked = _on_unpacked
    dbg.spawn(command)
    dbg.run()
    return UnpackResult(detected=mon.detected, oep=mon.oep,
                        main_base=mon.main_base, exit_code=dbg.exit_code,
                        dump=captured["dump"])
