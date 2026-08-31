"""Tests for import reconstruction (aletheia.imports).

Two layers:

* **Offline / pure (runs everywhere):** a synthetic mapped image with a real
  IMAGE_EXPORT_DIRECTORY -- named exports, one name-less ordinal export, and one
  forwarder -- served through a ``read_mem`` closure. Asserts ``parse_exports``
  reads it, then lays out a fake IAT (pointers into two fake modules + a NULL
  terminator) and asserts ``resolve_imports`` maps each slot to ``module!func``.
* **Live smoke (Windows-only):** parse the real export table of kernel32.dll out
  of THIS process and resolve a well-known export (``LoadLibraryA``) through the
  same code path -- best-effort, skipped (never failed) if a clean handle isn't
  had. ``LoadLibraryA`` is a real, non-forwarded, non-aliased kernel32 export, so
  it survives the address->name map intact (unlike ntdll's Nt*/Zw* pairs, which
  share one RVA -- an ``rva -> name`` map necessarily keeps just one alias).
"""
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aletheia import imports  # noqa: E402
from aletheia.imports import (  # noqa: E402
    Purpose,
    ResolvedImport,
    classify_api,
    parse_exports,
    purpose_summary,
    resolve_imports,
)

EXP_RVA = 0x1000            # where each synthetic module puts its export data


# ===========================================================================
# synthetic mapped-image builder
# ===========================================================================
def _pe32plus_header(export_rva: int, export_size: int) -> bytes:
    """Minimal PE32+ headers with data-directory[0] (EXPORT) pointing at the blob."""
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)      # e_lfanew = 64
    opt = bytearray(240)                                    # 112 + 16*8 == full DDs
    struct.pack_into("<H", opt, 0, 0x20B)                   # PE32+
    struct.pack_into("<I", opt, 16, 0x1000)                 # AddressOfEntryPoint
    struct.pack_into("<Q", opt, 24, 0x140000000)            # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)                 # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x1000)                 # FileAlignment
    struct.pack_into("<I", opt, 60, 0x1000)                 # SizeOfHeaders
    struct.pack_into("<I", opt, 108, 16)                    # NumberOfRvaAndSizes
    struct.pack_into("<II", opt, 112, export_rva, export_size)   # DD[0] = EXPORT
    coff = struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 240, 0x0022)
    return dos + b"PE\x00\x00" + coff + bytes(opt)


def _export_blob(dll_name, named, ordinal_only, forwarders, base_ord):
    """Assemble an IMAGE_EXPORT_DIRECTORY + its arrays/strings at ``EXP_RVA``.

    ``named``        = [(name, func_rva), ...]        -> named exports
    ``ordinal_only`` = [func_rva, ...]                -> name-less (ordinal) exports
    ``forwarders``   = [(name, "TARGET.func"), ...]   -> forwarder exports
    All three share one EAT; each entry's ordinal is ``eat_index + base_ord``.
    Returns (blob_bytes, export_size). Ordinal-only entries are placed BETWEEN the
    named ones so a real name-less gap in the EAT is exercised."""
    # EAT index assignment: named first, then ordinal-only, then forwarders.
    eat_specs = []          # (kind, payload)  kind in {"rva","ord","fwd"}
    for name, rva in named:
        eat_specs.append(("named", name, rva))
    for rva in ordinal_only:
        eat_specs.append(("ord", None, rva))
    for name, target in forwarders:
        eat_specs.append(("fwd", name, target))
    num_funcs = len(eat_specs)
    # names table = named exports + forwarder exports (both have names)
    named_pairs = [(name, i) for i, (k, name, _p) in enumerate(eat_specs)
                   if k in ("named", "fwd")]
    num_names = len(named_pairs)

    dir_sz = 40
    eat_off = dir_sz
    names_off = eat_off + 4 * num_funcs
    ords_off = names_off + 4 * num_names
    strings_off = ords_off + 2 * num_names

    # Lay out strings, remember each RVA.
    strings = bytearray()
    str_rva = {}

    def _emit(key, s):
        str_rva[key] = EXP_RVA + strings_off + len(strings)
        strings.extend(s.encode("latin-1") + b"\x00")

    for name, _rva in named:
        _emit(("name", name), name)
    for name, _t in forwarders:
        _emit(("name", name), name)
    _emit(("dll",), dll_name)
    for name, target in forwarders:
        _emit(("fwd", name), target)

    export_size = strings_off + len(strings)             # whole blob is the EXPORT dir

    # EAT: real rva, or the forwarder-string rva (which is INSIDE the export dir).
    eat_bytes = bytearray()
    for kind, name, payload in eat_specs:
        if kind == "fwd":
            eat_bytes += struct.pack("<I", str_rva[("fwd", name)])
        else:
            eat_bytes += struct.pack("<I", payload)      # payload is the func rva

    names_bytes = bytearray()
    ords_bytes = bytearray()
    for name, eat_index in named_pairs:
        names_bytes += struct.pack("<I", str_rva[("name", name)])
        ords_bytes += struct.pack("<H", eat_index)

    directory = struct.pack(
        "<IIHHIIIIIII",
        0, 0, 0, 0,
        str_rva[("dll",)],                               # Name
        base_ord,                                        # Base (ordinal base)
        num_funcs, num_names,
        EXP_RVA + eat_off, EXP_RVA + names_off, EXP_RVA + ords_off)

    blob = bytearray(export_size)
    blob[0:dir_sz] = directory
    blob[eat_off:eat_off + len(eat_bytes)] = eat_bytes
    blob[names_off:names_off + len(names_bytes)] = names_bytes
    blob[ords_off:ords_off + len(ords_bytes)] = ords_bytes
    blob[strings_off:strings_off + len(strings)] = strings
    return bytes(blob), export_size


def _module_image(dll_name, named, ordinal_only=(), forwarders=(), base_ord=1):
    blob, export_size = _export_blob(dll_name, named, list(ordinal_only),
                                     list(forwarders), base_ord)
    hdr = _pe32plus_header(EXP_RVA, export_size)
    img = bytearray(EXP_RVA + len(blob))
    img[0:len(hdr)] = hdr
    img[EXP_RVA:EXP_RVA + len(blob)] = blob
    return bytes(img)


class FakeMemory:
    """A tiny multi-segment address space with a make_reader-style zero-filling
    ``read`` (always returns exactly ``size`` bytes; unmapped -> zeros)."""

    def __init__(self):
        self._segs = []          # (base, bytes)

    def add(self, base, data):
        self._segs.append((int(base), bytes(data)))

    def read(self, addr, size):
        for base, data in self._segs:
            if base <= addr < base + len(data):
                off = addr - base
                chunk = data[off:off + size]
                if len(chunk) < size:
                    chunk = chunk + b"\x00" * (size - len(chunk))
                return chunk
        return b"\x00" * size


# ===========================================================================
# parse_exports -- offline
# ===========================================================================
A_BASE = 0x180000000
B_BASE = 0x190000000
IAT_BASE = 0x200000000

# testmod.dll: two named, one ordinal-only, one forwarder. Ordinal base 10.
_TESTMOD = _module_image(
    "testmod.dll",
    named=[("Alpha", 0x5000), ("Beta", 0x5010)],
    ordinal_only=[0x5020],
    forwarders=[("Fwd", "OTHER.RealFunc")],
    base_ord=10)
# second.dll: one named export. Ordinal base 1.
_SECOND = _module_image("second.dll", named=[("Gamma", 0x3000)], base_ord=1)


def _testmod_reader():
    mem = FakeMemory()
    mem.add(A_BASE, _TESTMOD)
    return mem.read


def test_parse_exports_named_ordinal_and_forwarder():
    exp = parse_exports(_testmod_reader(), A_BASE)
    assert exp.ok
    assert exp.dll_name == "testmod.dll"
    # named + name-less ordinal export; forwarder is NOT in the code map
    assert exp.by_rva == {0x5000: "Alpha", 0x5010: "Beta", 0x5020: "#12"}
    # ordinals: base 10, EAT indices 0,1,2  (forwarder sits at index 3)
    assert exp.ordinal_by_rva == {0x5000: 10, 0x5010: 11, 0x5020: 12}
    # forwarder captured separately, keyed by its export name
    assert exp.forwarders == {"Fwd": "OTHER.RealFunc"}


def test_parse_exports_fails_closed_without_export_dir():
    # A valid PE header but data-directory[0] = (0, 0): no exports.
    hdr = _pe32plus_header(0, 0)
    mem = FakeMemory()
    mem.add(A_BASE, hdr + b"\x00" * 0x1000)
    exp = parse_exports(mem.read, A_BASE)
    assert not exp.ok and exp.dll_name == "" and exp.by_rva == {}


def test_parse_exports_fails_closed_on_garbage():
    exp = parse_exports(lambda a, s: b"\x00" * s, A_BASE)      # not even MZ
    assert not exp.ok and exp.by_rva == {}


# ===========================================================================
# resolve_imports -- offline
# ===========================================================================
def _two_module_mem(iat_slots):
    mem = FakeMemory()
    mem.add(A_BASE, _TESTMOD)
    mem.add(B_BASE, _SECOND)
    mem.add(IAT_BASE, b"".join(struct.pack("<Q", v) for v in iat_slots))
    modules = [(A_BASE, 0x8000, "testmod.dll"), (B_BASE, 0x8000, "second.dll")]
    return mem, modules


def test_resolve_imports_auto_walk_maps_each_slot():
    mem, modules = _two_module_mem([
        A_BASE + 0x5000,        # testmod!Alpha
        A_BASE + 0x5010,        # testmod!Beta
        A_BASE + 0x5020,        # testmod!#12   (ordinal-only)
        B_BASE + 0x3000,        # second!Gamma  (a DIFFERENT module)
        0,                      # NULL terminator -> auto-walk stops here
        A_BASE + 0x5000,        # (never read: past the terminator)
    ])
    res = resolve_imports(mem.read, modules, IAT_BASE)   # count=None -> auto
    assert len(res) == 4

    assert (res[0].module_name, res[0].func_name, res[0].ordinal) == \
        ("testmod.dll", "Alpha", 10)
    assert res[0].slot_addr == IAT_BASE and res[0].slot_rva == 0
    assert res[0].value == A_BASE + 0x5000

    assert (res[1].module_name, res[1].func_name, res[1].ordinal) == \
        ("testmod.dll", "Beta", 11)
    assert res[1].slot_rva == 8

    assert (res[2].module_name, res[2].func_name, res[2].ordinal) == \
        ("testmod.dll", "#12", 12)

    assert (res[3].module_name, res[3].func_name, res[3].ordinal) == \
        ("second.dll", "Gamma", 1)
    assert res[3].slot_rva == 24


def test_resolve_imports_in_module_but_no_exact_rva_is_kept_as_none():
    # A slot inside testmod's range but on no export RVA -> diagnostic, func None.
    mem, modules = _two_module_mem([A_BASE + 0x5008])
    res = resolve_imports(mem.read, modules, IAT_BASE, count=1)
    assert len(res) == 1
    assert res[0].module_name == "testmod.dll"
    assert res[0].func_name is None
    assert res[0].ordinal is None
    assert res[0].value == A_BASE + 0x5008


def test_resolve_imports_auto_walk_stops_at_pointer_to_nowhere():
    mem, modules = _two_module_mem([A_BASE + 0x5000, 0xCCCCCCCCCCCC])
    res = resolve_imports(mem.read, modules, IAT_BASE)   # 2nd slot points nowhere
    assert len(res) == 1 and res[0].func_name == "Alpha"


def test_resolve_imports_count_skips_zero_and_out_of_module():
    # count=4: NULL and out-of-module slots are skipped (not recorded), walk continues.
    mem, modules = _two_module_mem([
        A_BASE + 0x5000,        # Alpha           -> recorded
        0,                      # NULL            -> skipped (count mode)
        0xDEADBEEF00,           # out of module   -> skipped (count mode)
        B_BASE + 0x3000,        # Gamma           -> recorded
    ])
    res = resolve_imports(mem.read, modules, IAT_BASE, count=4)
    assert [r.func_name for r in res] == ["Alpha", "Gamma"]
    assert [r.module_name for r in res] == ["testmod.dll", "second.dll"]


def test_rebuild_import_directory_is_documented_stub():
    with pytest.raises(NotImplementedError):
        imports.rebuild_import_directory()


# ===========================================================================
# classify_api / Purpose -- offline
# ===========================================================================
def test_classify_api_canonical_set():
    # One representative per family, plus a hard UNKNOWN.
    cases = [
        ("kernel32.dll", "LoadLibraryA", Purpose.LOADER),
        ("kernel32.dll", "GetProcAddress", Purpose.LOADER),
        ("kernel32.dll", "VirtualAllocEx", Purpose.MEMORY),
        ("kernel32.dll", "WriteProcessMemory", Purpose.MEMORY),
        ("advapi32.dll", "RegOpenKeyExW", Purpose.REGISTRY),
        ("advapi32.dll", "RegDeleteValueW", Purpose.REGISTRY),
        ("ws2_32.dll", "socket", Purpose.NETWORK),
        ("wininet.dll", "InternetOpenW", Purpose.NETWORK),
        ("bcrypt.dll", "BCryptEncrypt", Purpose.CRYPTO),
        ("advapi32.dll", "CryptAcquireContextW", Purpose.CRYPTO),
        ("user32.dll", "MessageBoxW", Purpose.GUI),
        ("user32.dll", "SetWindowsHookExW", Purpose.GUI),
        ("kernel32.dll", "GetTickCount", Purpose.SYSINFO),
        ("kernel32.dll", "IsDebuggerPresent", Purpose.SYSINFO),
        ("kernel32.dll", "CreateFileW", Purpose.FILE),
        ("kernel32.dll", "CreateProcessW", Purpose.PROCESS),
        ("kernel32.dll", "CreateThread", Purpose.THREAD),
        ("kernel32.dll", "CreateNamedPipeW", Purpose.IPC),
        ("kernel32.dll", "CreateFileMappingW", Purpose.IPC),   # NOT file
        ("kernel32.dll", "MapViewOfFile", Purpose.MEMORY),     # NOT ipc (per spec)
        ("ntdll.dll", "NtOpenFile", Purpose.FILE),
        ("ntdll.dll", "LdrLoadDll", Purpose.LOADER),
        ("somedll.dll", "DoesNotExistXyz", Purpose.UNKNOWN),
    ]
    for module, func, expected in cases:
        assert classify_api(module, func) == expected, f"{module}!{func}"


def test_classify_api_strips_aw_suffix():
    # The A and W charset variants collapse to the same family...
    assert classify_api("kernel32.dll", "LoadLibraryA") == Purpose.LOADER
    assert classify_api("kernel32.dll", "LoadLibraryW") == Purpose.LOADER
    assert classify_api("advapi32.dll", "RegSetValueExA") == Purpose.REGISTRY
    assert classify_api("advapi32.dll", "RegSetValueExW") == Purpose.REGISTRY
    # ...but a name that GENUINELY ends in 'a' is matched raw, not mis-stripped.
    assert classify_api("ws2_32.dll", "inet_ntoa") == Purpose.NETWORK


def test_classify_api_module_fallback():
    # Unknown function name -> the module hint decides (novel Reg*/WSA* still land).
    assert classify_api("advapi32.dll", "RegBrandNewApi") == Purpose.REGISTRY
    assert classify_api("ws2_32.dll", "WSABrandNewCall") == Purpose.NETWORK
    assert classify_api("user32.dll", "SomeFutureWindowApi") == Purpose.GUI
    # A DLL with no dominant family -> UNKNOWN.
    assert classify_api("randomvendor.dll", "Frobnicate") == Purpose.UNKNOWN
    # kernel32 spans too many families to have a single fallback -> UNKNOWN.
    assert classify_api("kernel32.dll", "SomeObscureUndocApi") == Purpose.UNKNOWN
    # func_name None (in-module, no export RVA) still gets the module hint.
    assert classify_api("ws2_32.dll", None) == Purpose.NETWORK
    assert classify_api("testmod.dll", None) == Purpose.UNKNOWN


# A synthetic module exporting REAL Windows API names, so resolve_imports has
# something the classifier recognises (classify_api is module-independent for exact
# names, so the module label is cosmetic here).
_APIMOD = _module_image(
    "apimod.dll",
    named=[("LoadLibraryA", 0x5000),      # LOADER
           ("VirtualAllocEx", 0x5010),    # MEMORY
           ("RegOpenKeyExW", 0x5020),     # REGISTRY
           ("socket", 0x5030),            # NETWORK
           ("MessageBoxW", 0x5040)],      # GUI
    base_ord=1)


def test_resolve_imports_populates_purpose():
    mem = FakeMemory()
    mem.add(A_BASE, _APIMOD)
    slots = [A_BASE + 0x5000, A_BASE + 0x5010, A_BASE + 0x5020,
             A_BASE + 0x5030, A_BASE + 0x5040]
    mem.add(IAT_BASE, b"".join(struct.pack("<Q", v) for v in slots))
    modules = [(A_BASE, 0x8000, "apimod.dll")]

    res = resolve_imports(mem.read, modules, IAT_BASE, count=len(slots))
    assert len(res) == 5
    # every slot's purpose is exactly what the classifier says for its func name
    for r in res:
        assert r.purpose == classify_api(r.module_name, r.func_name)
    assert [r.purpose for r in res] == [
        Purpose.LOADER, Purpose.MEMORY, Purpose.REGISTRY,
        Purpose.NETWORK, Purpose.GUI]


def test_resolve_imports_unknown_purpose_default_for_unnamed_slot():
    # testmod exports non-API names -> classifier returns UNKNOWN (not the field's
    # bare default by accident: an in-module slot with no export RVA is also UNKNOWN).
    mem, modules = _two_module_mem([A_BASE + 0x5000,        # testmod!Alpha (named)
                                    A_BASE + 0x5008])       # in-module, no RVA
    res = resolve_imports(mem.read, modules, IAT_BASE, count=2)
    assert res[0].func_name == "Alpha" and res[0].purpose == Purpose.UNKNOWN
    assert res[1].func_name is None and res[1].purpose == Purpose.UNKNOWN


def test_purpose_summary_counts_and_separates_unknown():
    def _ri(func, purpose):
        return ResolvedImport(slot_addr=0, slot_rva=0, module_name="m.dll",
                              func_name=func, ordinal=None, value=0, purpose=purpose)

    resolved = [
        _ri("LoadLibraryA", Purpose.LOADER),
        _ri("socket", Purpose.NETWORK),
        _ri("connect", Purpose.NETWORK),
        _ri("RegSetValueExW", Purpose.REGISTRY),
        _ri("MysteryFunc", Purpose.UNKNOWN),
        _ri("AnotherMystery", Purpose.UNKNOWN),
    ]
    summary = purpose_summary(resolved)
    assert summary == {
        Purpose.LOADER: 1,
        Purpose.NETWORK: 2,
        Purpose.REGISTRY: 1,
        Purpose.UNKNOWN: 2,      # tallied on its own, never folded into a family
    }
    assert sum(summary.values()) == len(resolved)
    assert purpose_summary([]) == {}


def test_purpose_is_str_enum_json_friendly():
    # Purpose is a str-enum: it equals its plain value, keeping project.py's verbatim
    # round-trip (asdict -> json string -> ResolvedImport(**d)) backward-compatible.
    assert Purpose.NETWORK == "network"
    assert Purpose.LOADER.value == "loader"
    import json
    assert json.dumps({"p": Purpose.CRYPTO}) == '{"p": "crypto"}'


# ===========================================================================
# live smoke -- Windows only, best-effort
# ===========================================================================
@pytest.mark.skipif(sys.platform != "win32",
                    reason="live export parse is Windows-only")
def test_live_kernel32_export_resolves():
    import os

    from aletheia import procdump

    pid = os.getpid()
    try:
        mods = procdump.list_modules(pid)
    except OSError as exc:                       # pragma: no cover - environment
        pytest.skip(f"could not enumerate modules: {exc}")

    k32 = next((m for m in mods if m.name.lower() == "kernel32.dll"), None)
    if k32 is None:
        pytest.skip("kernel32.dll not found in this process")

    try:
        handle = procdump.open_process(pid)
    except OSError as exc:                       # pragma: no cover - environment
        pytest.skip(f"could not open own process: {exc}")

    try:
        reader = procdump.make_reader(handle)

        # 1) parse_exports on a REAL module.
        exp = parse_exports(reader, k32.base)
        assert exp.ok, "failed to parse kernel32's export directory"
        assert exp.dll_name.lower() == "kernel32.dll"
        assert len(exp.by_rva) > 100, "kernel32 should export many functions"

        # LoadLibraryA is a real, non-forwarded, non-aliased kernel32 export.
        rva = next((r for r, n in exp.by_rva.items() if n == "LoadLibraryA"), None)
        assert rva is not None, "LoadLibraryA not found among kernel32 exports"

        # 2) resolve_imports end-to-end: put its absolute address in a 1-slot IAT
        #    served through a wrapper over the live process, and name it back.
        iat_base = 0xABCD0000                     # sentinel; the wrapper intercepts it
        slot = struct.pack("<Q", k32.base + rva)

        def wrapped(addr, size):
            if iat_base <= addr < iat_base + len(slot):
                off = addr - iat_base
                chunk = slot[off:off + size]
                return chunk + b"\x00" * (size - len(chunk))
            return reader(addr, size)

        modules = [(m.base, m.size, m.name) for m in mods]
        res = resolve_imports(wrapped, modules, iat_base, count=1)
        assert len(res) == 1
        assert res[0].module_name.lower() == "kernel32.dll"
        assert res[0].func_name == "LoadLibraryA"
        assert res[0].value == k32.base + rva
    finally:
        procdump.CloseHandle(handle)
