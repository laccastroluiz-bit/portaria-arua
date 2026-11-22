#!/usr/bin/env python3
"""Read-only inspection of external script versions and SRI in Portaria HTML.
No network calls, no changes to personal records or HTML, no remote code execution.
Developed by: Eng. Luiz Alberto Castro.
"""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse
import re
import sys

MINIMUM_JSPDF = (4, 2, 1)
SRI_PATTERN = re.compile(r"^sha(?:384|512)-[A-Za-z0-9+/=]{40,}$")
JSPDF_VERSION = re.compile(r"(?:/jspdf/|/jspdf@)(\d+)\.(\d+)\.(\d+)(?:/|$)", re.I)

class ScriptInspection(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.errors = []
        self.external_scripts = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "script":
            return
        props = {str(k).lower(): v for k, v in attrs if k}
        src = props.get("src", "")
        if not src:
            return
        parsed = urlparse(src)
        if not parsed.scheme and not parsed.netloc:
            return  # Bundled, same-origin scripts are not external CDN content.
        self.external_scripts += 1
        if parsed.scheme != "https":
            self.errors.append("EXTERNAL_SCRIPT_NOT_HTTPS")
        integrity = props.get("integrity", "")
        if not SRI_PATTERN.fullmatch(integrity or ""):
            self.errors.append("EXTERNAL_SCRIPT_MISSING_SRI")
        if props.get("crossorigin", "").lower() != "anonymous":
            self.errors.append("EXTERNAL_SCRIPT_MISSING_CORS")
        if re.search(r"(?:/jspdf/|/jspdf@)", parsed.path, re.I):
            m = JSPDF_VERSION.search(parsed.path)
            if not m:
                self.errors.append("JSPDF_UNPINNED")
            elif tuple(int(x) for x in m.groups()) < MINIMUM_JSPDF:
                self.errors.append("JSPDF_KNOWN_VULNERABLE_VERSION")

def inspect_html(source: str):
    parser = ScriptInspection()
    parser.feed(source)
    parser.close()
    return parser.errors, parser.external_scripts

def audit_directory(root: Path) -> tuple[int, int, int]:
    files = 0
    scripts = 0
    violations = 0
    for path in sorted(root.rglob("*.html")):
        if any(part in (".git", "node_modules", "dist", "build") for part in path.parts):
            continue
        files += 1
        errors, count = inspect_html(path.read_text(encoding="utf-8"))
        scripts += count
        for error in errors:
            # Never log external URL queries; they may contain personal identifiers or tokens.
            print(f"LAC_HTML_CDN_FINDING {path.name}: {error}")
        violations += len(errors)
    print(f"LAC_HTML_CDN_SUMMARY html_files={files} external_scripts={scripts} violations={violations}")
    return files, scripts, violations

if __name__ == "__main__":
    try:
        _, _, issues = audit_directory(Path(sys.argv[1] if len(sys.argv) > 1 else "."))
        sys.exit(1 if issues else 0)
    except (OSError, ValueError) as exc:
        print(f"LAC_HTML_CDN_ERROR {type(exc).__name__}: audit incomplete", file=sys.stderr)
        sys.exit(2)
