#!/bin/sh
# Assemble the GitHub Pages site into $1 (default: _site): site/ plus a generated llms-full.txt.
set -eu
out=${1:-_site}
rm -rf "$out"
mkdir -p "$out"
cp site/* "$out"/
go run ./cmd/opnsense-docs -out "$out/docs"
{
  echo "# opnsense-agentic-toolkit: full documentation"
  echo
  echo "Source: https://github.com/SmuliS/opnsense-agentic-toolkit (relative links below refer to files in that repository)."
  for f in README.md docs/DESIGN.md gen/README.md .claude/skills/opnsense-agentic-toolkit/SKILL.md docs/TODO.md; do
    printf '\n\n---\n\n<!-- %s -->\n\n' "$f"
    cat "$f"
  done
  printf '\n\n---\n\n'
  cat "$out/docs/reference.md"
} > "$out/llms-full.txt"
