"""Packer adapters for the Aletheia benchmark harness.

Each adapter presents the same tiny interface -- ``name``, ``binary``,
``available()`` and ``pack(in, out)`` -- so the runner iterates them uniformly
and degrades gracefully to whatever real packers are installed on the host.

Design notes
------------
* Adapters are DEPENDENCY-CHECKED, not tried-and-caught: ``available()`` looks
  the tool up (``shutil.which`` or an env var) BEFORE the runner asks it to
  pack. A missing tool is a skip with a warning, not a failed run.
* ``RawPasser`` is always available -- it just copies the input to the output.
  Its ``name`` is ``"raw"`` and it is the harness's baseline.
* ``ThemidaDemoPacker`` is shipped disabled on purpose: the Themida GUI's
  command-line surface isn't scriptable for the demo build. The adapter reports
  ``available() -> False`` so the runner records it as skipped; a user who has a
  Themida-packed file already can drop it into the samples/ dir and run the
  harness against it directly.
* ``LethePacker`` is gated on the ``LETHE_BIN`` env var (a path to the Lethe
  CLI script). Absent env var -> unavailable.

The adapters never raise on tool errors -- ``pack`` returns
``(success: bool, error: str)`` so the runner records the failure on the
PackerRun row and moves on.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Tuple


class Packer:
    """Base packer adapter. Subclasses set ``name`` / ``binary`` and override
    ``available()`` / ``pack()``. The base class implementation of ``pack`` is a
    stub -- every concrete adapter overrides it."""

    name: str = ""
    binary: str = ""

    def available(self) -> bool:
        """Is the underlying tool present on this host? Called BEFORE ``pack``
        so the runner can skip cleanly rather than fail loudly."""
        return False

    def pack(self, input_path: Path, output_path: Path) -> Tuple[bool, str]:
        """Pack ``input_path`` -> ``output_path``.

        Returns ``(success, error_message)``: on success, error is the empty
        string; on failure, success is False and error carries a short reason
        (tool absent, non-zero exit, missing output file, etc.). Never raises."""
        return False, "not implemented"


# ===========================================================================
# baseline: no packing, just copy
# ===========================================================================
class RawPasser(Packer):
    """The baseline. Copies the input file to the output path unchanged so the
    rest of the pipeline treats it exactly like a "packed" variant. Always
    available."""

    name = "raw"
    binary = ""

    def available(self) -> bool:
        return True

    def pack(self, input_path: Path, output_path: Path) -> Tuple[bool, str]:
        try:
            shutil.copyfile(str(input_path), str(output_path))
        except OSError as exc:
            return False, f"copy failed: {exc}"
        return True, ""


# ===========================================================================
# UPX -- the free, ubiquitous baseline packer
# ===========================================================================
class UpxPacker(Packer):
    """``upx --best <in> -o <out>``. Availability = ``shutil.which('upx')``."""

    name = "upx"
    binary = "upx"

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def pack(self, input_path: Path, output_path: Path) -> Tuple[bool, str]:
        if not self.available():
            return False, "upx not on PATH"
        # UPX refuses to overwrite -- clear the target first so re-runs work.
        try:
            if output_path.exists():
                output_path.unlink()
        except OSError as exc:
            return False, f"cannot clear output: {exc}"
        cmd = [self.binary, "--best", str(input_path), "-o", str(output_path)]
        try:
            res = subprocess.run(cmd, capture_output=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"upx failed: {exc}"
        if res.returncode != 0:
            err = (res.stderr or res.stdout or b"").decode("latin-1", "replace").strip()
            return False, f"upx exit {res.returncode}: {err[:200]}"
        if not output_path.exists():
            return False, "upx produced no output"
        return True, ""


# ===========================================================================
# MPRESS -- Windows-only shareware, common in older malware
# ===========================================================================
class MpressPacker(Packer):
    """``mpress -s <in>`` (writes back into ``in``; we stage a copy at ``out``
    and pack that in place). Availability = ``shutil.which('mpress')`` -- on
    non-Windows hosts, or when the binary isn't installed, this is simply
    False."""

    name = "mpress"
    binary = "mpress"

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def pack(self, input_path: Path, output_path: Path) -> Tuple[bool, str]:
        if not self.available():
            return False, "mpress not on PATH"
        # mpress packs in place. Stage a copy at output_path and pack that.
        try:
            shutil.copyfile(str(input_path), str(output_path))
        except OSError as exc:
            return False, f"cannot stage output: {exc}"
        cmd = [self.binary, "-s", str(output_path)]
        try:
            res = subprocess.run(cmd, capture_output=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"mpress failed: {exc}"
        if res.returncode != 0:
            err = (res.stderr or res.stdout or b"").decode("latin-1", "replace").strip()
            return False, f"mpress exit {res.returncode}: {err[:200]}"
        return True, ""


# ===========================================================================
# Themida demo -- shipped DISABLED on purpose (no scriptable CLI)
# ===========================================================================
class ThemidaDemoPacker(Packer):
    """Themida's demo GUI has no automation surface. Kept present so the API is
    complete and the README can point to the "pack manually, drop the file into
    samples/, re-run the harness pointing at that file" workflow."""

    name = "themida-demo"
    binary = ""

    def available(self) -> bool:
        return False

    def pack(self, input_path: Path, output_path: Path) -> Tuple[bool, str]:
        return False, "themida demo has no scriptable CLI (pack manually and re-run)"


# ===========================================================================
# Lethe -- this author's own packer, opt-in via env var
# ===========================================================================
class LethePacker(Packer):
    """Runs ``python <LETHE_BIN> pack <in> <out>`` when ``LETHE_BIN`` points at
    a Lethe CLI script (typically ``lethe.py``). Absent env var -> unavailable."""

    name = "lethe"
    binary = "lethe"

    def _script(self) -> str:
        return os.environ.get("LETHE_BIN", "")

    def available(self) -> bool:
        p = self._script()
        return bool(p) and Path(p).exists()

    def pack(self, input_path: Path, output_path: Path) -> Tuple[bool, str]:
        script = self._script()
        if not script:
            return False, "LETHE_BIN not set"
        if not Path(script).exists():
            return False, f"LETHE_BIN points at missing file: {script}"
        cmd = ["python", script, "pack", str(input_path), str(output_path)]
        try:
            res = subprocess.run(cmd, capture_output=True, timeout=180)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"lethe failed: {exc}"
        if res.returncode != 0:
            err = (res.stderr or res.stdout or b"").decode("latin-1", "replace").strip()
            return False, f"lethe exit {res.returncode}: {err[:200]}"
        if not output_path.exists():
            return False, "lethe produced no output"
        return True, ""


# ===========================================================================
# registry: name -> class. Order here is for --packers=all iteration order.
# ===========================================================================
ALL_PACKERS = {
    RawPasser.name: RawPasser,
    UpxPacker.name: UpxPacker,
    MpressPacker.name: MpressPacker,
    ThemidaDemoPacker.name: ThemidaDemoPacker,
    LethePacker.name: LethePacker,
}


def get_packer(name: str) -> Packer:
    """Look up a packer by name. Raises ``KeyError`` on an unknown name so the
    runner surfaces a typo instead of silently ignoring it."""
    cls = ALL_PACKERS[name]
    return cls()


__all__ = [
    "Packer",
    "RawPasser",
    "UpxPacker",
    "MpressPacker",
    "ThemidaDemoPacker",
    "LethePacker",
    "ALL_PACKERS",
    "get_packer",
]
