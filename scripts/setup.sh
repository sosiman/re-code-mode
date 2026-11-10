#!/usr/bin/env bash
# setup.sh — one-shot installer for re-code-mode.
#
#   bash scripts/setup.sh                    npm deps + UTCP configs + catalog
#   bash scripts/setup.sh --with-skills      also clone the third-party agent skills
#   bash scripts/setup.sh --with-rea         also install the optional REA engine (npm: rea-agents)
#   bash scripts/setup.sh --install-system-deps   apt-get install radare2 binwalk upx ... (needs sudo/root)
#
# Nothing here touches files outside this repository unless --install-system-deps is used.
set -euo pipefail

HOME_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HOME_DIR"

WITH_SKILLS=0; WITH_REA=0; SYS_DEPS=0
for arg in "$@"; do
  case "$arg" in
    --with-skills) WITH_SKILLS=1 ;;
    --with-rea) WITH_REA=1 ;;
    --install-system-deps) SYS_DEPS=1 ;;
    -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }

command -v node >/dev/null || { echo "Node.js >= 18 is required." >&2; exit 1; }
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
[ "$NODE_MAJOR" -ge 18 ] || { echo "Node.js >= 18 is required (found $(node -v))." >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required (catalog builder)." >&2; exit 1; }

if [ "$SYS_DEPS" -eq 1 ]; then
  say "Installing system packages (apt)"
  command -v apt-get >/dev/null || { echo "--install-system-deps supports apt-based systems only." >&2; exit 1; }
  SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo"
  $SUDO apt-get update -qq
  $SUDO apt-get install -y radare2 binwalk upx-ucl unzip binutils file git
fi

say "Installing npm dependencies"
npm install --no-audit --no-fund

if [ "$WITH_REA" -eq 1 ]; then
  say "Installing optional REA engine"
  npm install --no-save --no-audit --no-fund rea-agents
fi

say "Generating UTCP configs (local paths, git-ignored)"
node - "$HOME_DIR" "$WITH_REA" <<'EOF'
const fs = require("fs"), path = require("path");
const [, , root, withRea] = process.argv;
const manual = (name, args, timeout, env = {}) => ({
  manual_call_templates: [{
    name,
    call_template_type: "mcp",
    config: { mcpServers: { [name]: { transport: "stdio", command: process.execPath, args, cwd: root, env, timeout } } }
  }]
});
fs.writeFileSync(path.join(root, ".utcp_config.json"),
  JSON.stringify(manual("re", [path.join(root, "src", "server.mjs")], 60000), null, 2) + "\n");
const rea = path.join(root, "node_modules", "rea-agents", "scripts", "rea.mjs");
if (withRea === "1" && fs.existsSync(rea)) {
  fs.writeFileSync(path.join(root, ".utcp_rea_full.json"),
    JSON.stringify(manual("rea", [rea, "--mcp"], 90000), null, 2) + "\n");
}
EOF

say "Building the tool catalog"
python3 tools/build_catalog.py || echo "(catalog build failed — retry later with: npm run catalog)"

if [ "$WITH_SKILLS" -eq 1 ]; then
  say "Fetching third-party agent skills"
  bash scripts/fetch-skills.sh
fi

say "Checking external programs"
missing=0
for tool in r2 rabin2 binwalk upx unzip file git; do
  if command -v "$tool" >/dev/null; then printf '  ok       %s\n' "$tool"
  else printf '  MISSING  %s\n' "$tool"; missing=1; fi
done
for tool in jadx apktool gdb frida; do
  if command -v "$tool" >/dev/null; then printf '  ok       %s (optional)\n' "$tool"
  else printf '  absent   %s (optional)\n' "$tool"; fi
done
[ "$missing" -eq 0 ] || echo "Install the missing programs, e.g.: bash scripts/setup.sh --install-system-deps  (Debian/Ubuntu)  |  brew install radare2 binwalk upx  (macOS)"

say "Done. Try:  bin/re-run.sh list"
