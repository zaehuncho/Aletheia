"""PDB symbol resolver for Aletheia — turn raw addresses into ``module!symbol``.

Every binary Aletheia dumps back off a live process (see :mod:`aletheia.procdump`)
is a wall of nameless addresses. For the *Windows OS* modules that dominate any
dump — ``kernel32`` / ``ntdll`` / ``user32`` / … — Microsoft ships the answer for
free: a public **symbol server** hosting the matching PDB for every build they
have ever released. This module fetches those PDBs and gives an
``rva -> symbol_name`` map, so ``0x42ce0`` becomes ``kernel32!LoadLibraryAStub``.

The pipeline is four small steps, each fail-safe (never raises on bad input /
network trouble — returns ``None`` / ``ok=False``):

1. :func:`read_rsds` — read the PE's ``IMAGE_DEBUG_DIRECTORY`` (data-directory
   index 6) and its CodeView **RSDS** record. That record's ``(GUID, age,
   pdb_name)`` is exactly the key the symbol server is indexed by.
2. :func:`fetch_pdb` — GET ``<server>/<pdb>/<GUID><age>/<pdb>`` into an on-disk
   :class:`SymbolCache`. Stdlib ``urllib`` only; the MS server needs a
   ``Microsoft-Symbol-Server`` User-Agent or it refuses the request.
3. :func:`parse_pdb` — parse the **MSF v7** container, follow the **DBI** stream
   to the symbol-record stream and the section-header stream, and harvest every
   ``S_PUB32`` public symbol into ``rva -> name``.
4. :func:`resolve_module_symbols` — the three above, wired end to end for one
   module, cache-first.

House style mirrors :mod:`aletheia.pe` / :mod:`aletheia.imports`: dependency-free
``struct`` parsing, fails closed, ``ctypes`` stays out of here (this module is
pure-Python and imports cleanly off-Windows; only the live *reads* in a caller
touch Windows).

Scope of this first cut — deliberately honest about what it does NOT do:

* We recover **public symbols only** (the ``S_PUB32`` records). That alone names
  the vast majority of exported functions across the OS DLLs, which is the whole
  point of pulling OS symbols. NOTE a real-world wrinkle you WILL hit: modern
  ``kernel32`` is largely a forwarding shim over ``kernelbase``, and its public
  symbol for an exported API is often the internal stub name — e.g. the exported
  ``LoadLibraryA`` (RVA 0x42ce0) carries the public symbol ``LoadLibraryAStub``,
  alongside a separate ``__imp_LoadLibraryA`` thunk. The RVA is exact; the *name*
  is the compiland's, not always the export's. Cross-reference the export table
  (:func:`aletheia.imports.parse_exports`) when you need the exported name.

TODO (documented, out of scope for this cut):
* **Global symbol stream (GSI)** — S_GDATA32/S_GPROC references; the publics
  already cover exported functions.
* **SYM per-module streams** — locals / block scopes; not needed to name exports.
* **TPI/IPI streams** — type recovery. We recover types from our own IR, not the
  PDB, so this stays out on purpose.
* **Line-number info** — would need the C11/C13 debug subsections.
* **C++ name demangling** — mangled ``?name@@…`` publics are surfaced RAW; an
  analyst can paste them into ``undname.exe``. No demangler is bundled.
"""
from __future__ import annotations

import os
import pathlib
import struct
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union

from aletheia import pe

__all__ = [
    "RSDSInfo", "PdbSymbol", "PdbInfo", "SymbolCache",
    "read_rsds", "fetch_pdb", "parse_pdb", "resolve_module_symbols",
]

# --- IMAGE_DEBUG_DIRECTORY -------------------------------------------------
_DEBUG_DIR_INDEX = 6                 # data-directory slot for the debug directory
_DEBUG_ENTRY_SIZE = 28               # sizeof(IMAGE_DEBUG_DIRECTORY)
_IMAGE_DEBUG_TYPE_CODEVIEW = 2
_RSDS_MAGIC = b"RSDS"                # CodeView PDB70 signature

# --- MSF v7 container ------------------------------------------------------
_MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"  # 32 bytes
_SUPERBLOCK_TAIL = "<IIIIII"         # BlockSize, FreeBlockMap, NumBlocks,
#                                      NumDirBytes, Unknown, BlockMapAddr
_MAX_STREAMS = 1 << 20               # sanity clamp on the stream count
_VALID_BLOCK_SIZES = (512, 1024, 2048, 4096)

# --- fixed PDB stream indices ----------------------------------------------
_STREAM_PDB_INFO = 1                 # PDB Info (version/sig/age/GUID)
_STREAM_DBI = 3                      # DBI (Debug Info) stream

# --- DBI stream ------------------------------------------------------------
_DBI_HEADER = "<iIIHHHHHHiiiiiIiiHHI"   # 64-byte new-format DBI header
_DBI_HEADER_SIZE = 64
_DBGHDR_SECTION_HDR = 5              # optional-dbg-header slot: section headers
_DBGHDR_SECTION_HDR_ORIG = 10        # fallback slot: original section headers
_SECTION_HEADER_SIZE = 40           # sizeof(IMAGE_SECTION_HEADER)

# --- CodeView symbol records ----------------------------------------------
_S_PUB32 = 0x110E                    # PUBSYM32: a public symbol
# PUBSYM32 payload after the 2-byte record kind: flags(u32) off(u32) seg(u16) name
_PUB32_NAME_OFF = 4 + 4 + 4 + 2      # reclen(2)+kind(2) already skipped -> +14 abs

_UA = "Microsoft-Symbol-Server/10.0.0.0"   # MS server rejects a blank User-Agent


# ===========================================================================
# value types
# ===========================================================================
@dataclass
class RSDSInfo:
    """The three fields that key a PDB on the symbol server.

    ``guid`` is the 32-char UPPERCASE hex form the server URL uses (the GUID with
    dashes removed: ``Data1`` big-endian, ``Data2``/``Data3`` big-endian, then the
    8 ``Data4`` bytes verbatim). ``age`` is a small integer; the URL/cache key
    appends it in hex. ``pdb_name`` is the bare PDB filename, e.g. ``kernel32.pdb``.
    """
    guid: str
    age: int
    pdb_name: str

    def key(self) -> str:
        """The ``<GUID><age>`` directory component (age in uppercase hex)."""
        return f"{self.guid}{self.age:X}"


@dataclass
class PdbSymbol:
    """One recovered public symbol."""
    rva: int                         # symbol address within the module
    name: str                        # public name (raw; mangled names left as-is)
    length: int = 0                  # length hint (0 — publics carry no size)
    is_function: bool = False        # CV_PUBSYMFLAGS "function" bit


@dataclass
class PdbInfo:
    """Result of :func:`parse_pdb` / :func:`resolve_module_symbols`.

    ``symbols`` is the headline product: ``rva -> name``. ``symbols_detailed``
    carries the same entries as :class:`PdbSymbol` records (with the function bit)
    for callers that want more than the flat map. ``ok`` is False on any failure —
    inspect ``warnings`` for why (a cached-but-unparsed PDB, a missing debug dir,
    a truncated container, …)."""
    rsds: Optional[RSDSInfo] = None
    symbols: Dict[int, str] = field(default_factory=dict)
    symbols_detailed: List[PdbSymbol] = field(default_factory=list)
    ok: bool = False
    warnings: List[str] = field(default_factory=list)


# ===========================================================================
# tiny helpers
# ===========================================================================
def _as_bytes(pe_path_or_bytes: Union[str, os.PathLike, bytes, bytearray]
              ) -> Optional[bytes]:
    """Accept a path or raw bytes; return bytes (or None on an unreadable path)."""
    if isinstance(pe_path_or_bytes, (bytes, bytearray)):
        return bytes(pe_path_or_bytes)
    try:
        with open(os.fspath(pe_path_or_bytes), "rb") as fh:
            return fh.read()
    except (OSError, TypeError):
        return None


def _pdb_basename(name: str) -> str:
    """Bare filename of a possibly-pathed PDB string (handles / and \\)."""
    return name.replace("\\", "/").rsplit("/", 1)[-1]


def _cstr(buf: bytes, off: int, limit: Optional[int] = None) -> str:
    """NUL-terminated UTF-8 string at ``off`` (bounded by ``limit`` / EOF)."""
    if off < 0 or off >= len(buf):
        return ""
    hi = len(buf) if limit is None else min(off + limit, len(buf))
    end = buf.find(b"\x00", off, hi)
    if end < 0:
        end = hi
    return buf[off:end].decode("utf-8", "replace")


# ===========================================================================
# 1. RSDS extraction from the PE debug directory
# ===========================================================================
def _debug_data_dir(data: bytes) -> Optional[tuple]:
    """Return ``(rva, size)`` of data-directory index 6 (DEBUG), or None.

    Mirrors :func:`aletheia.imports._export_dir_dir`: reads only the PE headers,
    fails closed to None on anything that is not a well-formed PE with a non-empty
    debug directory."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    try:
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        opt = e_lfanew + 4 + 20
        (opt_magic,) = struct.unpack_from("<H", data, opt)
        if opt_magic == 0x20B:                    # PE32+
            num_dd_off, dd_off = opt + 108, opt + 112
        elif opt_magic == 0x10B:                  # PE32
            num_dd_off, dd_off = opt + 92, opt + 96
        else:
            return None
        (num_dd,) = struct.unpack_from("<I", data, num_dd_off)
        if num_dd <= _DEBUG_DIR_INDEX:
            return None
        rva, size = struct.unpack_from("<II", data, dd_off + 8 * _DEBUG_DIR_INDEX)
    except struct.error:
        return None
    if not rva or not size:
        return None
    return rva, size


def _parse_codeview(cv: bytes) -> Optional[RSDSInfo]:
    """Parse a CodeView RSDS record into an :class:`RSDSInfo` (or None)."""
    if len(cv) < 24 or cv[:4] != _RSDS_MAGIC:
        return None
    try:
        data1, data2, data3 = struct.unpack_from("<IHH", cv, 4)
        data4 = cv[12:20]
        (age,) = struct.unpack_from("<I", cv, 20)
    except struct.error:
        return None
    guid = "%08X%04X%04X%s" % (data1, data2, data3, data4.hex().upper())
    name = _pdb_basename(_cstr(cv, 24)) or "unknown.pdb"
    return RSDSInfo(guid=guid, age=age, pdb_name=name)


def read_rsds(pe_path_or_bytes: Union[str, os.PathLike, bytes, bytearray]
              ) -> Optional[RSDSInfo]:
    """Parse ``IMAGE_DEBUG_DIRECTORY`` + the CodeView RSDS entry of a PE.

    Returns None if the PE cannot be parsed, has no debug directory, or has no
    CodeView (PDB70/RSDS) entry — all common for stripped or non-PDB binaries."""
    data = _as_bytes(pe_path_or_bytes)
    if data is None:
        return None
    info = pe.parse_bytes(data)
    if not info.ok:
        return None
    dd = _debug_data_dir(data)
    if dd is None:
        return None
    debug_rva, debug_size = dd
    base = pe._rva_to_off(info.sections, debug_rva)
    if base is None:
        return None
    for i in range(debug_size // _DEBUG_ENTRY_SIZE):
        eoff = base + i * _DEBUG_ENTRY_SIZE
        if eoff + _DEBUG_ENTRY_SIZE > len(data):
            break
        try:
            (_ch, _ts, _maj, _min, typ, size_of_data, addr_raw, ptr_raw) = \
                struct.unpack_from("<IIHHIIII", data, eoff)
        except struct.error:
            break
        if typ != _IMAGE_DEBUG_TYPE_CODEVIEW:
            continue
        # PointerToRawData is a file offset (preferred on disk); fall back to
        # translating AddressOfRawData through the section table.
        cv_off = ptr_raw if ptr_raw else pe._rva_to_off(info.sections, addr_raw)
        if cv_off is None or cv_off >= len(data):
            continue
        rsds = _parse_codeview(data[cv_off:cv_off + size_of_data])
        if rsds is not None:
            return rsds
    return None


# ===========================================================================
# 2. on-disk symbol cache + fetch
# ===========================================================================
class SymbolCache:
    """Local on-disk cache of downloaded PDBs.

    Default root: ``%LOCALAPPDATA%\\Aletheia\\symbols`` on Windows, or
    ``~/.cache/aletheia/symbols`` elsewhere. Layout matches a symbol store's
    two-tier shape::

        <root>/<pdb_name>/<GUID><age>/<pdb_name>
    """

    def __init__(self, root: Optional[str] = None):
        if root is not None:
            self.root = pathlib.Path(root)
        else:
            self.root = pathlib.Path(self._default_root())

    @staticmethod
    def _default_root() -> str:
        local = os.environ.get("LOCALAPPDATA")
        if local:                                  # Windows
            return os.path.join(local, "Aletheia", "symbols")
        return os.path.join(os.path.expanduser("~"), ".cache", "aletheia", "symbols")

    def path_for(self, rsds: RSDSInfo) -> pathlib.Path:
        """The on-disk path a PDB for ``rsds`` would live at (may not exist)."""
        name = _pdb_basename(rsds.pdb_name) or "unknown.pdb"
        return self.root / name / rsds.key() / name

    def has(self, rsds: RSDSInfo) -> bool:
        """True iff a non-empty cached PDB exists for ``rsds``."""
        p = self.path_for(rsds)
        try:
            return p.is_file() and p.stat().st_size > 0
        except OSError:
            return False


def _download(url: str, timeout: float) -> Optional[bytes]:
    """GET ``url`` with a symbol-server User-Agent. None on any failure."""
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if getattr(resp, "status", 200) not in (200, None):
                return None
            return resp.read()
    except (urllib.error.URLError, OSError, ValueError):
        return None
    except Exception:                              # noqa: BLE001 - never raise
        return None


def fetch_pdb(rsds: RSDSInfo, cache: Optional[SymbolCache] = None,
              server: str = "https://msdl.microsoft.com/download/symbols",
              timeout: float = 15.0) -> Optional[pathlib.Path]:
    """Fetch a PDB from a symbol server into the cache; return the cached path.

    Cache-first: an already-cached PDB is returned without touching the network.
    URL form ``<server>/<pdb_name>/<GUID><age>/<pdb_name>``. Best-effort — a 404,
    timeout, or any network/IO error returns None (callers handle None); never
    raises. Stdlib ``urllib`` only."""
    cache = cache or SymbolCache()
    dest = cache.path_for(rsds)
    if cache.has(rsds):
        return dest

    name = _pdb_basename(rsds.pdb_name)
    url = f"{server.rstrip('/')}/{name}/{rsds.key()}/{name}"
    body = _download(url, timeout)
    if not body:
        return None

    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".part")
        with open(tmp, "wb") as fh:
            fh.write(body)
        os.replace(tmp, dest)                      # atomic publish into the cache
    except OSError:
        return None
    return dest


# ===========================================================================
# 3. MSF v7 container + Publics
# ===========================================================================
class _Msf:
    """A parsed MSF v7 multi-stream file: block store + per-stream block lists."""

    def __init__(self, data: bytes, block_size: int,
                 streams: List[tuple]):
        self._data = data
        self._bs = block_size
        self._streams = streams                    # [(size, [block_index, ...]), ...]

    @property
    def num_streams(self) -> int:
        return len(self._streams)

    def read_stream(self, idx: int) -> bytes:
        """Reassemble stream ``idx`` from its blocks (b'' for nil/oob streams)."""
        if idx < 0 or idx >= len(self._streams):
            return b""
        size, blocks = self._streams[idx]
        if size <= 0:
            return b""
        out = bytearray()
        bs = self._bs
        for b in blocks:
            off = b * bs
            out += self._data[off:off + bs]
        return bytes(out[:size])


def _open_msf(data: bytes) -> Optional[_Msf]:
    """Parse the MSF superblock + stream directory. None on any structural fault."""
    if data[:len(_MSF_MAGIC)] != _MSF_MAGIC:
        return None
    try:
        (block_size, _free_map, num_blocks, num_dir_bytes, _unk,
         block_map_addr) = struct.unpack_from(_SUPERBLOCK_TAIL, data, len(_MSF_MAGIC))
        if block_size not in _VALID_BLOCK_SIZES or num_dir_bytes == 0:
            return None
        if len(data) < num_blocks * block_size or block_map_addr >= num_blocks:
            return None

        def _blk(i: int) -> bytes:
            return data[i * block_size:(i + 1) * block_size]

        # The block map lists the blocks holding the stream directory.
        n_dir_blocks = (num_dir_bytes + block_size - 1) // block_size
        dir_block_idx = struct.unpack_from(
            "<%dI" % n_dir_blocks, data, block_map_addr * block_size)
        directory = b"".join(_blk(i) for i in dir_block_idx)[:num_dir_bytes]

        (num_streams,) = struct.unpack_from("<I", directory, 0)
        if not 0 < num_streams <= _MAX_STREAMS:
            return None
        pos = 4
        sizes = struct.unpack_from("<%dI" % num_streams, directory, pos)
        pos += 4 * num_streams
        streams: List[tuple] = []
        for size in sizes:
            if size == 0xFFFFFFFF:                 # nil stream
                streams.append((0, []))
                continue
            n_blocks = (size + block_size - 1) // block_size
            blocks = list(struct.unpack_from("<%dI" % n_blocks, directory, pos)) \
                if n_blocks else []
            pos += 4 * n_blocks
            streams.append((size, blocks))
    except struct.error:
        return None
    return _Msf(data, block_size, streams)


def _pdb_info_rsds(msf: _Msf, pdb_name: str) -> Optional[RSDSInfo]:
    """Build an RSDSInfo from the PDB Info stream (stream 1) — GUID + age."""
    info = msf.read_stream(_STREAM_PDB_INFO)
    if len(info) < 28:
        return None
    try:
        _ver, _sig, age = struct.unpack_from("<III", info, 0)
        data1, data2, data3 = struct.unpack_from("<IHH", info, 12)
        data4 = info[20:28]
    except struct.error:
        return None
    guid = "%08X%04X%04X%s" % (data1, data2, data3, data4.hex().upper())
    return RSDSInfo(guid=guid, age=age, pdb_name=_pdb_basename(pdb_name))


def _section_vas(msf: _Msf, dbi: bytes) -> List[int]:
    """Section VirtualAddresses via the DBI optional-debug-header's section stream.

    The publics carry ``(segment, offset)``; ``rva = section_va[segment-1] +
    offset``. The section headers are a copy of the PE's ``IMAGE_SECTION_HEADER``
    array, pointed at by slot 5 (or the original-headers slot 10) of the DBI
    optional debug header substream."""
    try:
        (_vsig, _vhdr, _age, _gsi, _bld, _psi, _pv, _symrec, _rbld,
         modinfo, seccontr, secmap, srcinfo, tsmap, _mfc,
         optdbg, ecsub, _flags, _machine, _pad) = \
            struct.unpack_from(_DBI_HEADER, dbi, 0)
    except struct.error:
        return []
    # Physical order of substreams: EC precedes the optional debug header even
    # though the header lists OptionalDbgHeaderSize before ECSubstreamSize.
    optdbg_off = (_DBI_HEADER_SIZE + modinfo + seccontr + secmap
                  + srcinfo + tsmap + ecsub)
    count = max(optdbg, 0) // 2
    if count <= _DBGHDR_SECTION_HDR or optdbg_off + optdbg > len(dbi):
        return []
    try:
        slots = struct.unpack_from("<%dH" % count, dbi, optdbg_off)
    except struct.error:
        return []
    for slot in (_DBGHDR_SECTION_HDR, _DBGHDR_SECTION_HDR_ORIG):
        if slot >= count:
            continue
        stream_idx = slots[slot]
        if stream_idx == 0xFFFF:
            continue
        sh = msf.read_stream(stream_idx)
        vas: List[int] = []
        for i in range(len(sh) // _SECTION_HEADER_SIZE):
            try:
                (va,) = struct.unpack_from("<I", sh, i * _SECTION_HEADER_SIZE + 12)
            except struct.error:
                break
            vas.append(va)
        if vas:
            return vas
    return []


def _walk_publics(sym: bytes, section_vas: List[int]) -> List[PdbSymbol]:
    """Walk the symbol-record stream, collecting every ``S_PUB32`` public symbol.

    Records are ``reclen(u16) kind(u16) payload``; ``reclen`` counts the payload,
    and each record's total (2 + reclen) is 4-byte aligned, so ``reclen`` alone
    steps to the next record. A malformed length ends the walk (fail-safe)."""
    out: List[PdbSymbol] = []
    n_sections = len(section_vas)
    pos, end = 0, len(sym)
    while pos + 4 <= end:
        try:
            reclen, kind = struct.unpack_from("<HH", sym, pos)
        except struct.error:
            break
        if reclen < 2:
            break
        rec_end = pos + 2 + reclen
        if rec_end > end:
            break
        if kind == _S_PUB32 and pos + 4 + 10 <= rec_end:
            flags, offset, seg = struct.unpack_from("<IIH", sym, pos + 4)
            if 1 <= seg <= n_sections:
                name = _cstr(sym, pos + _PUB32_NAME_OFF, limit=rec_end - (pos + _PUB32_NAME_OFF))
                if name:
                    out.append(PdbSymbol(
                        rva=section_vas[seg - 1] + offset,
                        name=name,
                        is_function=bool(flags & 0x2)))   # CV_PUBSYMFLAGS: function
        pos = rec_end
    return out


def parse_pdb(pdb_path: pathlib.Path) -> PdbInfo:
    """Parse a PDB (MSF v7) far enough to extract its PUBLIC symbols.

    Returns a populated :class:`PdbInfo` (``ok=True``) on success, or
    ``PdbInfo(ok=False, warnings=[...])`` on any container/stream fault — never
    raises. See the module docstring for the scope of "public symbols only"."""
    result = PdbInfo()
    try:
        with open(pdb_path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        result.warnings.append(f"cannot read PDB: {exc}")
        return result

    msf = _open_msf(data)
    if msf is None:
        result.warnings.append("not an MSF v7 container (or corrupt superblock)")
        return result

    result.rsds = _pdb_info_rsds(msf, _pdb_basename(str(pdb_path)))

    dbi = msf.read_stream(_STREAM_DBI)
    if len(dbi) < _DBI_HEADER_SIZE:
        result.warnings.append("DBI stream missing/too small; no publics recovered")
        return result
    try:
        sym_stream = struct.unpack_from(_DBI_HEADER, dbi, 0)[7]  # SymRecordStream
    except struct.error:
        result.warnings.append("corrupt DBI header")
        return result

    section_vas = _section_vas(msf, dbi)
    if not section_vas:
        result.warnings.append("no section-header stream; cannot map segment->rva")
        return result

    sym = msf.read_stream(sym_stream)
    if not sym:
        result.warnings.append("empty symbol-record stream")
        return result

    symbols = _walk_publics(sym, section_vas)
    if not symbols:
        result.warnings.append("no S_PUB32 public symbols found")
        return result

    result.symbols_detailed = symbols
    # Flat rva->name map (last write wins on the rare aliased RVA).
    result.symbols = {s.rva: s.name for s in symbols}
    result.ok = True
    return result


# ===========================================================================
# 4. full pipeline for one module
# ===========================================================================
def resolve_module_symbols(pe_path_or_bytes: Union[str, os.PathLike, bytes, bytearray],
                           cache: Optional[SymbolCache] = None,
                           allow_download: bool = True) -> PdbInfo:
    """``read_rsds`` -> ``fetch_pdb`` (cache-first) -> ``parse_pdb`` for one module.

    Returns ``PdbInfo(ok=False, warnings=[...])`` if any step fails: no debug
    directory, the PDB is not cached and downloading is disabled/unavailable, or
    the PDB will not parse. The returned ``rsds`` is the PE's RSDS (it carries the
    real ``pdb_name``), overriding the one recovered from the PDB itself."""
    cache = cache or SymbolCache()
    rsds = read_rsds(pe_path_or_bytes)
    if rsds is None:
        return PdbInfo(ok=False, warnings=["no CodeView RSDS debug record in PE"])

    if cache.has(rsds):
        path = cache.path_for(rsds)
    elif allow_download:
        path = fetch_pdb(rsds, cache=cache)
        if path is None:
            return PdbInfo(rsds=rsds, ok=False,
                           warnings=["PDB fetch failed (offline / 404 / timeout)"])
    else:
        return PdbInfo(rsds=rsds, ok=False,
                       warnings=["PDB not cached and downloading disabled"])

    info = parse_pdb(path)
    info.rsds = rsds                               # prefer the PE's RSDS (has name)
    return info
