"""Tests for the PDB symbol resolver.

Three tiers:

* **Cross-platform, offline** — cache-path shape, key form, fail-closed parsing,
  and a network-mocked fetch (cacheable + idempotent). These always run.
* **Windows-only** — RSDS extraction from the real on-disk ``kernel32.dll``.
* **Windows-only + network** — the full download/parse pipeline against
  Microsoft's public symbol server; skipped with an honest reason when the host
  has no route to ``msdl.microsoft.com``.

Real-world naming gotcha these tests bake in: modern ``kernel32`` is a forwarding
shim over ``kernelbase``, so its public symbol for the exported ``LoadLibraryA``
(RVA 0x42ce0) is the internal ``LoadLibraryAStub`` — there is NO bare
``LoadLibraryA`` public symbol. The live assertions match a name *containing*
``LoadLibraryA`` (and cross-check ``CreateFileW``, which IS a bare public), rather
than an exact ``LoadLibraryA``.
"""
import socket
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aletheia import pdb as P  # noqa: E402

KERNEL32 = r"C:\Windows\System32\kernel32.dll"


def _have_network(host: str = "msdl.microsoft.com", port: int = 443) -> bool:
    """Best-effort reachability probe for the symbol server."""
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


# ===========================================================================
# cross-platform, offline
# ===========================================================================
def test_rsds_key_form():
    """key() = 32-char GUID followed by the age in UPPERCASE hex."""
    rsds = P.RSDSInfo(guid="2554A4D7DED55C1D6F033011500EA781", age=1,
                      pdb_name="kernel32.pdb")
    assert rsds.key() == "2554A4D7DED55C1D6F033011500EA7811"
    assert P.RSDSInfo(guid="B" * 32, age=26, pdb_name="x.pdb").key() == "B" * 32 + "1A"


def test_cache_path_shape(tmp_path):
    """path_for nests as <root>/<pdb>/<GUID+age>/<pdb>."""
    cache = P.SymbolCache(root=str(tmp_path))
    rsds = P.RSDSInfo(guid="A" * 32, age=1, pdb_name="kernel32.pdb")
    p = cache.path_for(rsds)
    assert p == tmp_path / "kernel32.pdb" / ("A" * 32 + "1") / "kernel32.pdb"
    assert not cache.has(rsds)          # nothing written yet


def test_default_cache_root_is_platform_appropriate():
    cache = P.SymbolCache()
    parts = cache.root.parts
    assert "symbols" == parts[-1].lower()
    assert "aletheia" in (s.lower() for s in parts)


def test_read_rsds_rejects_non_pe():
    assert P.read_rsds(b"not a PE at all") is None
    assert P.read_rsds(b"MZ" + b"\x00" * 200) is None          # MZ but no PE
    assert P.read_rsds("Z:\\does\\not\\exist.dll") is None      # unreadable path


def test_parse_pdb_fails_closed_on_non_msf(tmp_path):
    """A file that is not an MSF v7 container yields ok=False with a warning."""
    bogus = tmp_path / "bogus.pdb"
    bogus.write_bytes(b"this is not a PDB" * 64)
    info = P.parse_pdb(bogus)
    assert info.ok is False
    assert info.symbols == {}
    assert any("MSF" in w for w in info.warnings)


def test_parse_pdb_missing_file():
    info = P.parse_pdb(Path("Z:\\nope\\missing.pdb"))
    assert info.ok is False
    assert any("cannot read" in w for w in info.warnings)


def test_fetch_is_cacheable_and_idempotent(tmp_path, monkeypatch):
    """First fetch downloads + caches; a second fetch is served from cache."""
    rsds = P.RSDSInfo(guid="A" * 32, age=1, pdb_name="fake.pdb")
    cache = P.SymbolCache(root=str(tmp_path))
    calls = []

    def fake_download(url, timeout):
        calls.append(url)
        assert url.endswith(f"/fake.pdb/{'A' * 32}1/fake.pdb")   # correct URL form
        return b"PDB-BODY-BYTES"

    monkeypatch.setattr(P, "_download", fake_download)

    p1 = P.fetch_pdb(rsds, cache=cache)
    assert p1 is not None
    assert p1.read_bytes() == b"PDB-BODY-BYTES"
    assert cache.has(rsds)
    assert len(calls) == 1

    p2 = P.fetch_pdb(rsds, cache=cache)      # cache hit -> no second download
    assert p2 == p1
    assert len(calls) == 1                   # still one call


def test_fetch_returns_none_on_network_failure(tmp_path, monkeypatch):
    """A download failure returns None and leaves the cache empty (fail-safe)."""
    rsds = P.RSDSInfo(guid="C" * 32, age=2, pdb_name="fake.pdb")
    cache = P.SymbolCache(root=str(tmp_path))
    monkeypatch.setattr(P, "_download", lambda url, timeout: None)
    assert P.fetch_pdb(rsds, cache=cache) is None
    assert not cache.has(rsds)


def test_resolve_fails_closed_on_bad_input(tmp_path):
    """A module with no CodeView RSDS fails closed, not by raising."""
    cache = P.SymbolCache(root=str(tmp_path))
    info = P.resolve_module_symbols(b"MZ" + b"\x00" * 512, cache=cache,
                                    allow_download=False)
    assert info.ok is False
    assert any("RSDS" in w for w in info.warnings)


# ===========================================================================
# Windows-only: RSDS from the real kernel32.dll
# ===========================================================================
@pytest.mark.skipif(sys.platform != "win32", reason="reads C:\\Windows kernel32.dll")
def test_resolve_no_download_cold_cache_fails_closed(tmp_path):
    """A valid module + cold cache + allow_download=False fails closed (no fetch)."""
    cache = P.SymbolCache(root=str(tmp_path))
    info = P.resolve_module_symbols(KERNEL32, cache=cache, allow_download=False)
    assert info.ok is False
    assert info.rsds is not None                 # RSDS was read from the PE
    assert any("not cached" in w for w in info.warnings)


@pytest.mark.skipif(sys.platform != "win32", reason="reads C:\\Windows kernel32.dll")
def test_read_rsds_on_real_kernel32():
    rsds = P.read_rsds(KERNEL32)
    assert rsds is not None, "kernel32.dll must carry a CodeView RSDS record"
    assert len(rsds.guid) == 32
    assert all(ch in "0123456789ABCDEF" for ch in rsds.guid), "GUID must be hex"
    assert rsds.age > 0
    assert rsds.pdb_name == "kernel32.pdb"


# ===========================================================================
# Windows-only + network: the full pipeline against MS symbols
# ===========================================================================
@pytest.mark.skipif(sys.platform != "win32", reason="uses on-disk kernel32.dll")
@pytest.mark.skipif(not _have_network(), reason="no route to msdl.microsoft.com")
def test_full_pipeline_resolves_kernel32(tmp_path):
    cache = P.SymbolCache(root=str(tmp_path))
    info = P.resolve_module_symbols(KERNEL32, cache=cache)
    if not info.ok:
        joined = " ".join(info.warnings or [])
        if any(t in joined.lower() for t in ("offline", "404", "timeout", "network", "fetch failed")):
            pytest.skip(f"PDB symbol server unreachable: {joined}")
        raise AssertionError(f"info not ok: {info.warnings}")
    assert len(info.symbols) > 1000, "kernel32 should yield thousands of publics"

    names = set(info.symbols.values())
    # Modern kernel32 exposes the exported LoadLibraryA as LoadLibraryAStub; there
    # is no bare "LoadLibraryA" public. Assert a LoadLibraryA-bearing public name.
    assert any("LoadLibraryA" in n for n in names), \
        "expected a LoadLibraryA-bearing public symbol (e.g. LoadLibraryAStub)"
    # CreateFileW IS a bare public symbol — an exact-name sanity check.
    assert "CreateFileW" in names

    # RVA fidelity: the export table's LoadLibraryA RVA must carry a matching name.
    from aletheia import procdump
    import os
    mods = procdump.list_modules(os.getpid())
    k32 = next((m for m in mods if m.name.lower() == "kernel32.dll"), None)
    if k32 is not None:
        from aletheia.imports import parse_exports
        exp = parse_exports(procdump.make_reader(procdump.open_process(os.getpid())),
                            k32.base)
        # find LoadLibraryA's export RVA and confirm the PDB names that RVA
        lla_rva = next((rva for rva, nm in exp.by_rva.items()
                        if nm == "LoadLibraryA"), None)
        if lla_rva is not None:
            assert lla_rva in info.symbols
            assert "LoadLibraryA" in info.symbols[lla_rva]


@pytest.mark.skipif(sys.platform != "win32", reason="uses on-disk kernel32.dll")
@pytest.mark.skipif(not _have_network(), reason="no route to msdl.microsoft.com")
def test_fetch_real_pdb_download_then_parse(tmp_path):
    """Slow: actually download kernel32.pdb and parse public symbols from it."""
    rsds = P.read_rsds(KERNEL32)
    assert rsds is not None
    cache = P.SymbolCache(root=str(tmp_path))
    path = P.fetch_pdb(rsds, cache=cache)
    assert path is not None and path.is_file()
    assert path.read_bytes()[:4] == b"Micr", "downloaded file is an MSF container"

    info = P.parse_pdb(path)
    if not info.ok:
        joined = " ".join(info.warnings or [])
        if any(t in joined.lower() for t in ("offline", "404", "timeout", "network", "fetch failed")):
            pytest.skip(f"PDB symbol server unreachable: {joined}")
        raise AssertionError(f"info not ok: {info.warnings}")
    assert info.symbols_detailed, "detailed symbol list should be populated"
    # every detailed symbol carries a plausible RVA + a name
    for s in info.symbols_detailed[:50]:
        assert s.rva > 0 and s.name
