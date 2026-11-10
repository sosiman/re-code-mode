#!/usr/bin/env bash
# fetch-skills.sh — clone third-party agent-skill repositories into ./skills-repos
#
# These projects are NOT part of this repository and keep their own licenses.
# They are cloned (shallow) on your machine so that `skill_list` / `skill_read`
# can serve their documentation to your agent.
#
# By default the offensive-security modules of reverse-skill are pruned to keep the
# collection focused on analysis. Set RE_KEEP_ALL_SKILLS=1 to keep everything.
set -euo pipefail

HOME_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$HOME_DIR/skills-repos"
mkdir -p "$DEST"
cd "$DEST"

REPOS=(
  "aicodeking/leanrea"
  "SimoneAvogadro/android-reverse-engineering-skill"
  "zhaoxuya520/reverse-skill"
)

for repo in "${REPOS[@]}"; do
  name="$(basename "$repo")"
  if [ -d "$name/.git" ]; then
    echo "update  $repo"
    git -C "$name" pull --ff-only --depth 1 --quiet || echo "  (skipped, could not fast-forward)"
  else
    echo "clone   $repo"
    git clone --depth 1 --no-tags --quiet -- "https://github.com/$repo.git" "$name"
  fi
done

if [ "${RE_KEEP_ALL_SKILLS:-0}" != "1" ] && [ -d reverse-skill ]; then
  for sub in skills/pwn-chain skills/edr-bypass-re skills/patch-diff-exploit \
             skills/attack-chain skills/pentest-tools CTF-Sandbox-Orchestrator; do
    rm -rf "reverse-skill/$sub"
  done
  echo "pruned offensive modules from reverse-skill (RE_KEEP_ALL_SKILLS=1 to keep)"
fi

echo "done: $(find . -name SKILL.md -not -path './*/.git/*' | wc -l) SKILL.md files in $DEST"
