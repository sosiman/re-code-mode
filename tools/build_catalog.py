#!/usr/bin/env python3
"""
Build data/re-catalog.json from public "awesome" lists.

Sources (fetched at build time, NOT redistributed in this repository):
  * https://github.com/zhuyansen/awesome-ai-reverse-engineering
  * https://github.com/morluto/awesome-reverse-engineering

Usage:  python3 tools/build_catalog.py [--out PATH]
"""
import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "data" / "re-catalog.json"

SOURCES = [
    ("awesome-ai-reverse-engineering",
     "https://raw.githubusercontent.com/zhuyansen/awesome-ai-reverse-engineering/main/README.md"),
    ("awesome-reverse-engineering",
     "https://raw.githubusercontent.com/morluto/awesome-reverse-engineering/main/README.md"),
]

SKIP_SECTIONS = {"contents", "start here", "related lists", "related collections",
                 "contributing and maintenance", "license", "add a repo", "how a repo gets on the list"}


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "re-code-mode-catalog/1.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parse_stars(cell: str) -> int:
    cell = cell.strip().lower().replace(",", "")
    try:
        if cell.endswith("k"):
            return int(float(cell[:-1]) * 1000)
        return int(re.sub(r"[^\d]", "", cell) or "0")
    except ValueError:
        return 0


def classify(section: str, name: str) -> str:
    s, n = section.lower(), name.lower()
    if "learning" in s or "books" in s or "practice" in s:
        return "reference"
    if "mcp" in s or "mcp" in n:
        return "mcp"
    if "skill" in s or "skill" in n:
        return "skill"
    return "tool"


def parse_table_list(md: str, source: str):
    """Table rows: | [owner/repo](url) | 1.2k | description | ..."""
    section = "General"
    for line in md.splitlines():
        s = line.strip()
        if s.startswith("## "):
            section = re.sub(r"^#+\s+", "", s)
        elif s.startswith("| ["):
            cells = [c.strip() for c in s.strip("|").split("|")]
            m = re.search(r"\[([^\]]+)\]\((https://github\.com/[^)\s]+)\)", cells[0]) if cells else None
            if m and len(cells) >= 3:
                yield {"name": m.group(1), "url": m.group(2), "source": source, "category": section,
                       "stars": parse_stars(cells[1]), "description": cells[2][:300],
                       "type": classify(section, m.group(1))}


def parse_bullet_list(md: str, source: str):
    """Bullets: - [name](url) - description"""
    section = "General"
    for line in md.splitlines():
        s = line.strip()
        if s.startswith("## ") or s.startswith("### "):
            section = re.sub(r"^#+\s+", "", s)
        elif s.startswith("- ["):
            if section.lower() in SKIP_SECTIONS:
                continue
            m = re.search(r"-\s+\[([^\]]+)\]\((https?://[^)\s]+)\)\s*[-—:]?\s*(.*)", s)
            if m:
                yield {"name": m.group(1), "url": m.group(2), "source": source, "category": section,
                       "stars": 0, "description": m.group(3).strip()[:300],
                       "type": classify(section, m.group(1))}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    out = Path(ap.parse_args().out)

    items, seen = [], set()
    for source, url in SOURCES:
        try:
            md = fetch(url)
        except Exception as exc:  # network failure must not wipe an existing catalog
            print(f"ERROR fetching {url}: {exc}", file=sys.stderr)
            return 1
        parsed = list(parse_table_list(md, source)) + list(parse_bullet_list(md, source))
        print(f"{source}: {len(parsed)} entries")
        for it in parsed:
            key = it["url"].rstrip("/").lower()
            if key not in seen:
                seen.add(key)
                items.append(it)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"total": len(items), "items": items}, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(f"wrote {out} ({len(items)} unique entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
