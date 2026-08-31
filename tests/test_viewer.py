"""Static structural checks for viewer/index.html + its bundled sample project.

Deliberately NO headless browser / JS execution: the viewer is a zero-dependency
single HTML file, so these tests pin (1) that the file exists and is a real page,
not a stub, (2) that it is fully offline (no external script/style/img refs),
(3) that the bundled sample JSON still loads through ``Project.from_json`` (the
schema-compatibility proof), and (4) that the HTML names the top-level Project
JSON keys it consumes, so a rename in ``project.to_json`` breaks a test here
instead of silently breaking the viewer.
"""
import json
import sys
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aletheia.project import Project  # noqa: E402

VIEWER = ROOT / "viewer" / "index.html"
SAMPLE = ROOT / "viewer" / "sample_project.json"


# ---------------------------------------------------------------------------
# 1. the file exists and is substantial (a stub would fail)
# ---------------------------------------------------------------------------
def test_viewer_html_exists_and_is_substantial():
    assert VIEWER.is_file(), "viewer/index.html is missing"
    assert VIEWER.stat().st_size > 5 * 1024, "viewer/index.html looks like a stub"


# ---------------------------------------------------------------------------
# 2. parses as HTML; has <title>/<script>/<style>; nothing external (offline)
# ---------------------------------------------------------------------------
class _Walker(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []                  # (tag, {attr: value})
        self.title_text = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, {k: (v or "") for k, v in attrs}))
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title_text += data


def test_viewer_html_structure_and_offline_enforcement():
    w = _Walker()
    w.feed(VIEWER.read_text(encoding="utf-8"))

    names = [t for t, _ in w.tags]
    assert "title" in names and w.title_text.strip(), "no <title>"
    assert names.count("script") >= 1, "no inline <script>"
    assert names.count("style") >= 1, "no inline <style>"

    for tag, attrs in w.tags:
        if tag == "script":
            assert "src" not in attrs, f"<script src={attrs['src']!r}> — scripts must be inline"
        # offline enforcement: no src/href on ANY tag may reach the network
        for attr in ("src", "href"):
            val = attrs.get(attr, "").strip().lower()
            assert not val.startswith(("http:", "https:", "//")), \
                f"external reference <{tag} {attr}={attrs[attr]!r}>"


# ---------------------------------------------------------------------------
# 3. the bundled sample loads via Project.from_json (schema compatibility)
# ---------------------------------------------------------------------------
def test_sample_project_json_loads_via_project():
    assert SAMPLE.is_file(), "viewer/sample_project.json is missing"
    text = SAMPLE.read_text(encoding="utf-8")
    d = json.loads(text)                      # clean JSON
    assert d["schema_version"] == 1

    proj = Project.from_json(text)            # the real loader accepts it
    assert proj.functions, "sample project carries no functions"
    assert proj.path and proj.binary_sha256
    # the viewer-extension keys must stay invisible to the Python loader
    assert proj.pe is None and proj.verdict is None


# ---------------------------------------------------------------------------
# 4. schema-drift sentinel: the viewer names the top-level keys it consumes
# ---------------------------------------------------------------------------
def test_viewer_mentions_core_schema_keys():
    html_text = VIEWER.read_text(encoding="utf-8")
    for key in ("functions", "strings", "signatures", "imports",
                "labels", "comments", "path", "binary_sha256"):
        assert f'"{key}"' in html_text, \
            f'viewer/index.html no longer mentions the "{key}" project key'
