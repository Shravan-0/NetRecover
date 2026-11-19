import os
import json
from pathlib import Path

ROOT = Path.cwd()
OUTPUT_TXT = ROOT / "ACN_PROJECT_KNOWLEDGE.txt"
OUTPUT_JSON = ROOT / "ACN_PROJECT_KNOWLEDGE.json"

EXCLUDE_DIRS = {
    "venv", ".venv", ".ryu39", ".git",
    "__pycache__", "node_modules", ".pytest_cache",
    ".mypy_cache", "dist", "build", "site-packages",
    "logs", "datasets", "data", "uploads"
}

EXCLUDE_FILES = {
    ".env", ".env.local", ".env.production",
    "export_project.py",
    "ACN_PROJECT_KNOWLEDGE.txt",
    "ACN_PROJECT_KNOWLEDGE.json"
}

ALLOWED_EXTENSIONS = {
    ".py", ".md", ".txt", ".json", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf", ".sh",
    ".service", ".html", ".css", ".js", ".xml",
    ".csv", ".sql"
}

MAX_FILE_SIZE = 500_000

files = []
tree = []

for path in sorted(ROOT.rglob("*")):
    if not path.is_file():
        continue

    rel = path.relative_to(ROOT)

    if any(part in EXCLUDE_DIRS for part in rel.parts):
        continue

    if path.name in EXCLUDE_FILES:
        continue

    if path.suffix.lower() not in ALLOWED_EXTENSIONS:
        continue

    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            tree.append(str(rel) + " [SKIPPED: large file]")
            continue

        content = path.read_text(encoding="utf-8", errors="replace")

        files.append({
            "path": str(rel),
            "content": content
        })

        tree.append(str(rel))

    except Exception as e:
        tree.append(str(rel) + " [READ ERROR: " + str(e) + "]")

project = {
    "project": "ACN - SDN Fault Detection and Recovery",
    "description": "Complete source-code knowledge export. Third-party libraries and virtual environments excluded.",
    "root": str(ROOT),
    "file_count": len(files),
    "project_tree": tree,
    "files": files
}

OUTPUT_JSON.write_text(
    json.dumps(project, ensure_ascii=False, separators=(",", ":")),
    encoding="utf-8"
)

with OUTPUT_TXT.open("w", encoding="utf-8") as out:
    out.write("ACN PROJECT - COMPLETE SOURCE KNOWLEDGE\n")
    out.write("=" * 65 + "\n")
    out.write("Files included: " + str(len(files)) + "\n\n")

    out.write("PROJECT FILE TREE\n")
    out.write("-" * 65 + "\n")

    for item in tree:
        out.write(item + "\n")

    out.write("\nCOMPLETE SOURCE CONTENTS\n")
    out.write("=" * 65 + "\n")

    for item in files:
        out.write("\n\n")
        out.write("=" * 65 + "\n")
        out.write("FILE: " + item["path"] + "\n")
        out.write("=" * 65 + "\n")
        out.write(item["content"])

print("EXPORT COMPLETE")
print("Files included:", len(files))
print("TXT:", OUTPUT_TXT)
print("JSON:", OUTPUT_JSON)
print("TXT size:", round(OUTPUT_TXT.stat().st_size / 1024, 2), "KB")
print("JSON size:", round(OUTPUT_JSON.stat().st_size / 1024, 2), "KB")
