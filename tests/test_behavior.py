"""Tests for the behavior logger: the watch-list-driven API-call timeline.

Two layers, mirroring the module:

* OFFLINE unit tests (run everywhere -- no live process). The watch-list table is
  well-formed, and each arg-render helper is exercised over a synthetic
  ``read_mem`` closure: bounded ANSI/UTF-16 string reads, the ``UNICODE_STRING``
  and ``ANSI_STRING`` parsers, GetProcAddress ordinal detection, the
  LdrGetProcedureAddress name/ordinal fallback, the ntdll ``Nt*``/``Zw*`` export
  resolver, and module-name normalisation.

* LIVE integration (Windows only -- skipped elsewhere). ``cmd.exe /c exit 7`` is
  traced end to end: it exits 7, ``ntdll!LdrLoadDll`` is armed, and at least one
  ``LdrLoadDll`` call is captured with a real DLL-name arg (every process routes
  its startup dependency loads through the ntdll loader, so this is deterministic
  on any Windows box). A sample of the timeline is printed for eyeballing (``-s``).

Empirical notes baked into the assertions below (see the probe findings):
* ``LdrLoadDll``'s ``PUNICODE_STRING DllName`` is arg 3 -> **R8** (the task brief
  said R9; R9 is the OUT handle and reads as NULL). ``test_watchlist_*`` pins R8.
* ntdll's ``NtProtectVirtualMemory`` / ``NtAllocateVirtualMemory`` are reachable
  only via their ``Zw*`` export twins (parse_exports keeps one name per RVA); the
  live test asserts they still arm, proving the ``Nt``/``Zw`` resolver.
"""
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# The module imports cleanly off-Windows (its live pieces come from the
# Windows-guarded Debugger), so the offline unit tests below run everywhere.
from aletheia.behavior import (  # noqa: E402
    ArgField, BehaviorMonitor, DEFAULT_WATCHLIST, WatchEntry,
    _normalise_module, _read_ansi_string, _read_bounded_astr,
    _read_bounded_wstr, _read_unicode_string, _render_field, _render_getproc,
    _resolve_export_rva, run_trace,
)

_VALID_REGS = {"Rcx", "Rdx", "R8", "R9"}
_VALID_KINDS = {"hex", "wstr", "astr", "ustr", "getproc", "lgpa"}
_VALID_MODULES = {"ntdll", "kernel32", "advapi32"}
_VALID_CATEGORIES = {"loader", "memory", "process", "file", "registry"}


# ===========================================================================
# a tiny synthetic address space for the offline helper tests
# ===========================================================================
class FakeMem:
    """A sparse debuggee-memory stand-in.

    ``place(addr, data)`` maps bytes; ``read(addr, size)`` returns up to ``size``
    bytes from whichever region contains ``addr`` (a short read at a region's tail,
    exactly as ``ReadProcessMemory`` can), and raises ``OSError`` for an address in
    no region (so the helpers' ``"<unreadable>"`` path is covered)."""

    def __init__(self) -> None:
        self._regions = []                       # (start, bytes)
        self._next = 0x4000_0000

    def place(self, data: bytes, addr=None) -> int:
        if addr is None:
            addr = self._next
            self._next += (len(data) + 0xFFF) & ~0xFFF
        self._regions.append((addr, bytes(data)))
        return addr

    def read(self, addr: int, size: int) -> bytes:
        for start, data in self._regions:
            if start <= addr < start + len(data):
                off = addr - start
                return data[off:off + size]
        raise OSError(f"unmapped 0x{addr:x}")

    # convenience builders --------------------------------------------------
    def place_wstr(self, text: str) -> int:
        return self.place(text.encode("utf-16-le") + b"\x00\x00")

    def place_astr(self, text: str) -> int:
        return self.place(text.encode("utf-8") + b"\x00")

    def place_counted(self, text: str, wide: bool) -> int:
        """A UNICODE_STRING (wide) / ANSI_STRING (narrow): Length WORD, Max WORD,
        4 pad, Buffer PTR@+8 -> the string bytes."""
        raw = text.encode("utf-16-le") if wide else text.encode("utf-8")
        buf = self.place(raw)
        hdr = struct.pack("<HHI Q", len(raw), len(raw), 0, buf)
        return self.place(hdr)


# ===========================================================================
# 1. the watch-list table is well-formed
# ===========================================================================
def test_watchlist_table_is_well_formed():
    assert DEFAULT_WATCHLIST, "watch-list must not be empty"
    keys = set()
    for e in DEFAULT_WATCHLIST:
        assert isinstance(e, WatchEntry)
        assert e.module in _VALID_MODULES, f"unexpected module {e.module!r}"
        assert e.module.islower() and not e.module.endswith(".dll")
        assert e.func and isinstance(e.func, str)
        assert e.category in _VALID_CATEGORIES, f"bad category {e.category!r}"
        assert e.key == f"{e.module}!{e.func}"
        assert e.key not in keys, f"duplicate watch-list key {e.key}"
        keys.add(e.key)
        assert isinstance(e.args, tuple)
        for af in e.args:
            assert isinstance(af, ArgField)
            assert af.label and isinstance(af.label, str)
            assert af.kind in _VALID_KINDS, f"bad kind {af.kind!r} on {e.key}"
            src = af.source
            if isinstance(src, tuple):
                tag, off = src
                assert tag == "stk"
                # 5th+ integer arg: past return addr (8) + shadow space (0x20).
                assert off >= 0x28 and off % 8 == 0, f"bad stack off {off:#x}"
            else:
                assert src in _VALID_REGS, f"bad register {src!r} on {e.key}"


def test_watchlist_covers_the_documented_families():
    """Each documented category is represented, and the loader set is present."""
    by_cat = {}
    for e in DEFAULT_WATCHLIST:
        by_cat.setdefault(e.category, set()).add(e.func)
    assert _VALID_CATEGORIES <= set(by_cat), "a documented category is missing"
    assert "LdrLoadDll" in by_cat["loader"]
    assert "GetProcAddress" in by_cat["loader"]
    assert {"CreateProcessW", "CreateRemoteThread"} <= by_cat["process"]
    assert {"NtProtectVirtualMemory", "NtAllocateVirtualMemory"} <= by_cat["memory"]


def test_ldrloaddll_reads_the_unicode_string_from_r8_not_r9():
    """Regression pin for the corrected calling convention: LdrLoadDll's
    PUNICODE_STRING DllName is arg 3 (R8), not R9 (which is the OUT handle)."""
    entry = next(e for e in DEFAULT_WATCHLIST if e.key == "ntdll!LdrLoadDll")
    assert len(entry.args) == 1
    dll = entry.args[0]
    assert dll.source == "R8", "DllName must be read from R8 (arg 3)"
    assert dll.kind == "ustr"


# ===========================================================================
# 2. bounded string readers
# ===========================================================================
def test_bounded_wstr_read():
    m = FakeMem()
    addr = m.place_wstr("USER32.dll")
    assert _read_bounded_wstr(m.read, addr) == "USER32.dll"
    assert _read_bounded_wstr(m.read, 0) == "<null>"
    assert _read_bounded_wstr(m.read, 0xDEAD_0000) == "<unreadable>"


def test_bounded_astr_read():
    m = FakeMem()
    addr = m.place_astr("kernel32.dll")
    assert _read_bounded_astr(m.read, addr) == "kernel32.dll"
    assert _read_bounded_astr(m.read, 0) == "<null>"
    assert _read_bounded_astr(m.read, 0xDEAD_0000) == "<unreadable>"


# ===========================================================================
# 3. UNICODE_STRING / ANSI_STRING parsers
# ===========================================================================
def test_unicode_string_parse():
    m = FakeMem()
    us = m.place_counted("api-ms-win-core-synch-l1-2-0", wide=True)
    assert _read_unicode_string(m.read, us) == "api-ms-win-core-synch-l1-2-0"
    assert _read_unicode_string(m.read, 0) == "<null>"
    assert _read_unicode_string(m.read, 0xDEAD_0000) == "<unreadable>"

    # Length 0 -> empty string (Buffer present but nothing to read).
    buf = m.place_wstr("ignored")
    empty_hdr = m.place(struct.pack("<HHI Q", 0, 0, 0, buf))
    assert _read_unicode_string(m.read, empty_hdr) == ""

    # NULL Buffer -> "<null>".
    nullbuf = m.place(struct.pack("<HHI Q", 8, 8, 0, 0))
    assert _read_unicode_string(m.read, nullbuf) == "<null>"


def test_ansi_string_parse_and_null_fallback():
    m = FakeMem()
    a = m.place_counted("RtlAllocateHeap", wide=False)
    assert _read_ansi_string(m.read, a) == "RtlAllocateHeap"
    # NULL struct pointer / NULL buffer / zero length -> None (caller uses ordinal).
    assert _read_ansi_string(m.read, 0) is None
    nullbuf = m.place(struct.pack("<HHI Q", 4, 4, 0, 0))
    assert _read_ansi_string(m.read, nullbuf) is None


# ===========================================================================
# 4. GetProcAddress ordinal detection + LdrGetProcedureAddress fallback
# ===========================================================================
def test_getproc_ordinal_vs_named():
    m = FakeMem()
    named = m.place_astr("MessageBoxW")
    assert _render_getproc(m.read, named) == "MessageBoxW"
    assert _render_getproc(m.read, 0x1) == "#1"            # packed ordinal
    assert _render_getproc(m.read, 0xFFFF) == "#65535"     # just under the cutoff
    assert _render_getproc(m.read, 0) == "<null>"


def test_render_field_kinds_and_lgpa_fallback():
    m = FakeMem()
    # hex
    assert _render_field(m.read, 0x40, "hex") == "0x40"
    # wstr / astr / ustr / getproc
    assert _render_field(m.read, m.place_wstr("A.dll"), "wstr") == "A.dll"
    assert _render_field(m.read, m.place_astr("B.dll"), "astr") == "B.dll"
    assert _render_field(m.read, m.place_counted("C", True), "ustr") == "C"
    assert _render_field(m.read, m.place_astr("Ordinal0"), "getproc") == "Ordinal0"
    # lgpa: named ANSI_STRING wins ...
    ansi = m.place_counted("LdrLoadDll", wide=False)
    assert _render_field(m.read, ansi, "lgpa", ordinal_val=99) == "LdrLoadDll"
    # ... and a NULL Name falls back to the R8 ordinal.
    assert _render_field(m.read, 0, "lgpa", ordinal_val=7) == "#7"


# ===========================================================================
# 5. ntdll Nt/Zw export resolver + module-name normalisation
# ===========================================================================
def test_nt_zw_export_resolution():
    # by_rva keeps only the Zw twin (parse_exports last-wins); an Nt request must
    # resolve through it, and vice versa. A direct hit is returned as-is.
    tbl = {"ZwProtectVirtualMemory": 0x160a50, "LdrLoadDll": 0x1000,
           "NtQueryFoo": 0x2000}
    assert _resolve_export_rva(tbl, "NtProtectVirtualMemory") == 0x160a50
    assert _resolve_export_rva(tbl, "LdrLoadDll") == 0x1000       # direct
    assert _resolve_export_rva(tbl, "ZwQueryFoo") == 0x2000       # reverse Zw->Nt
    assert _resolve_export_rva(tbl, "NtNotThere") is None
    assert _resolve_export_rva(tbl, "GetProcAddress") is None


def test_module_normalisation():
    assert _normalise_module(r"C:\Windows\System32\KERNEL32.DLL") == "kernel32"
    assert _normalise_module("ntdll.dll") == "ntdll"
    assert _normalise_module("ADVAPI32.dll") == "advapi32"
    assert _normalise_module("kernel32") == "kernel32"
    assert _normalise_module(None) == ""
    assert _normalise_module("") == ""


# ===========================================================================
# 6. LIVE integration (Windows only)
# ===========================================================================
pytestmark_live = pytest.mark.skipif(
    sys.platform != "win32", reason="behavior tracing is Windows-only")

import os  # noqa: E402

CMD = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                   "System32", "cmd.exe")
CMDLINE = f'"{CMD}" /c exit 7'

# A safety cap the trivial target never reaches (~241 events observed), so a
# runaway can never wedge the suite while the full timeline is still captured.
_LIVE_CAP = 20000


def _nonempty_dll(value: str) -> bool:
    return bool(value) and not value.startswith("<")


@pytestmark_live
def test_live_trace_captures_loader_activity():
    from aletheia.debugger import Debugger

    dbg = Debugger()
    mon = BehaviorMonitor(dbg, max_events=_LIVE_CAP)
    dbg.spawn(CMDLINE)
    dbg.run()

    # The hot Nt* memory breakpoints (hundreds of hits) must not destabilise the
    # run: cmd still exits 7.
    assert dbg.exit_code == 7, f"cmd exited {dbg.exit_code}, expected 7"
    assert not mon.capped, "did not expect to hit the runaway cap on cmd.exe"

    # The loader hook was armed, and it fired with real DLL names.
    assert "ntdll!LdrLoadDll" in mon.armed, f"armed={sorted(mon.armed)}"
    ldr = [e for e in mon.events if e.func == "LdrLoadDll"]
    assert ldr, "expected at least one LdrLoadDll call during startup"
    dll_names = [e.args.get("dll", "") for e in ldr]
    assert any(_nonempty_dll(n) for n in dll_names), \
        f"no readable DLL-name arg captured: {dll_names}"
    # KERNEL32.DLL / KERNELBASE.dll are loaded through LdrLoadDll on every process.
    assert any(n.lower().endswith(".dll") for n in dll_names), \
        f"expected a real *.dll among the loaded names: {dll_names}"

    # The Nt/Zw resolver armed the memory stubs via their Zw twins, and they fired
    # with hex-rendered protections.
    for key in ("ntdll!NtProtectVirtualMemory", "ntdll!NtAllocateVirtualMemory"):
        assert key in mon.armed, f"{key} should arm via its Zw twin; armed={sorted(mon.armed)}"
    prot = [e for e in mon.events if e.func == "NtProtectVirtualMemory"]
    if prot:                                     # essentially always non-empty
        assert prot[0].args["newprotect"].startswith("0x")

    # kernel32's classic loader exports are real (not forwarders) and armed.
    for key in ("kernel32!LoadLibraryW", "kernel32!GetProcAddress"):
        assert key in mon.armed, f"{key} missing; armed={sorted(mon.armed)}"

    # ---- eyeball sample (visible under -s) --------------------------------
    print(f"\n[behavior] exit={dbg.exit_code} events={len(mon.events)} "
          f"armed={len(mon.armed)} summary={mon.summary()}")
    print(f"[behavior] LdrLoadDll saw: {dll_names[:8]}")
    print("[behavior] first 10 timeline events:")
    for e in mon.events[:10]:
        print("   ", e)


@pytestmark_live
def test_run_trace_convenience_returns_timeline():
    events = run_trace(CMDLINE, max_events=_LIVE_CAP)
    assert isinstance(events, list) and events, "run_trace returned no events"
    ldr = [e for e in events if e.func == "LdrLoadDll"]
    assert ldr, "run_trace timeline had no LdrLoadDll call"
    assert any(_nonempty_dll(e.args.get("dll", "")) for e in ldr), \
        "run_trace captured no readable DLL name"
    # Sequence numbers are monotonic and 1-based.
    assert [e.seq for e in events] == list(range(1, len(events) + 1))
