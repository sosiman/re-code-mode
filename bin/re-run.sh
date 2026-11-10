#!/usr/bin/env bash
# re-run.sh — thin wrapper around the UTCP Code Mode CLI for re-code-mode.
#
# Every user-controlled argument is converted to a JSON string literal before it is
# placed in the generated TypeScript, so file names / patterns cannot inject code.
#
#   re-run.sh list
#   re-run.sh categories
#   re-run.sh catalog "<query>" [limit]
#   re-run.sh playbook [elf_linux|pe_windows|android_apk|electron_js|firmware_iot|go_rust_packed|all]
#   re-run.sh skills [filter]            re-run.sh skill-read <name> [regex]
#   re-run.sh fetch <owner/repo|query>
#   re-run.sh triage <file>              re-run.sh imports <file> [regex]
#   re-run.sh strings <file> [regex]     re-run.sh funcs <file> [regex]
#   re-run.sh decompile <file> <func|0xaddr>
#   re-run.sh apk <file> [triage|apis]   re-run.sh firmware <file>
#   re-run.sh rea-mcp <utcp args...>     (optional full REA mode, needs setup --with-rea)
#   re-run.sh run '<TypeScript>'         (or pipe TypeScript on stdin)
set -euo pipefail

HOME_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HOME_DIR"

if [ -x "$HOME_DIR/node_modules/.bin/utcp" ]; then
  UTCP=("$HOME_DIR/node_modules/.bin/utcp")
elif command -v utcp >/dev/null 2>&1; then
  UTCP=(utcp)
else
  echo "utcp CLI not found. Run: bash scripts/setup.sh" >&2
  exit 1
fi

if [ ! -f "$HOME_DIR/.utcp_config.json" ]; then
  echo ".utcp_config.json missing. Run: bash scripts/setup.sh" >&2
  exit 1
fi

# JSON-encode an arbitrary string as a safe TypeScript string literal.
js() { node -p 'JSON.stringify(process.argv[1])' -- "${1-}"; }
# Validate that a value is a non-negative integer, else fall back to a default.
int() { case "${1-}" in ''|*[!0-9]*) echo "$2" ;; *) echo "$1" ;; esac; }

run_ts() { "${UTCP[@]}" run; }   # TypeScript is read from stdin
CMD="${1:-}"

case "$CMD" in
  catalog)
    run_ts <<EOF
return await re.re_catalog_search({ query: $(js "${2:-}"), limit: $(int "${3:-}" 15) });
EOF
    ;;
  categories)
    run_ts <<< 'return await re.re_catalog_categories({});'
    ;;
  playbook)
    run_ts <<EOF
return await re.re_get_playbook({ scenario: $(js "${2:-all}") });
EOF
    ;;
  skills)
    run_ts <<EOF
return await re.re_skill_list({ filter: $(js "${2:-}") });
EOF
    ;;
  skill-read)
    : "${2:?usage: re-run.sh skill-read <name> [regex]}"
    run_ts <<EOF
return await re.re_skill_read({ target: $(js "$2"), grep: $(js "${3:-}"), max_lines: 150 });
EOF
    ;;
  fetch)
    : "${2:?usage: re-run.sh fetch <owner/repo|query>}"
    run_ts <<EOF
return await re.re_fetch_tool({ repo_or_query: $(js "$2"), mode: "clone" });
EOF
    ;;
  triage)
    : "${2:?usage: re-run.sh triage <file>}"
    run_ts <<EOF
return await re.re_triage_binary({ path: $(js "$2") });
EOF
    ;;
  imports)
    : "${2:?usage: re-run.sh imports <file> [regex]}"
    run_ts <<EOF
return await re.re_imports_exports({ path: $(js "$2"), filter: $(js "${3:-}"), limit: 40 });
EOF
    ;;
  strings)
    : "${2:?usage: re-run.sh strings <file> [regex]}"
    run_ts <<EOF
return await re.re_extract_strings({ path: $(js "$2"), regex: $(js "${3:-}"), limit: 40 });
EOF
    ;;
  funcs)
    : "${2:?usage: re-run.sh funcs <file> [regex]}"
    run_ts <<EOF
return await re.re_list_functions({ path: $(js "$2"), filter: $(js "${3:-}"), limit: 40 });
EOF
    ;;
  decompile)
    : "${2:?usage: re-run.sh decompile <file> <func|0xaddr>}"
    run_ts <<EOF
return await re.re_disassemble_function({ path: $(js "$2"), target: $(js "${3:-main}"), mode: "both" });
EOF
    ;;
  apk)
    : "${2:?usage: re-run.sh apk <file> [triage|apis]}"
    run_ts <<EOF
return await re.re_apk_inspect({ path: $(js "$2"), mode: $(js "${3:-triage}") });
EOF
    ;;
  firmware)
    : "${2:?usage: re-run.sh firmware <file>}"
    run_ts <<EOF
return await re.re_firmware_scan({ path: $(js "$2") });
EOF
    ;;
  rea-mcp)
    shift
    if [ ! -f "$HOME_DIR/.utcp_rea_full.json" ]; then
      echo "Full REA mode not configured. Run: bash scripts/setup.sh --with-rea" >&2
      exit 1
    fi
    "${UTCP[@]}" "$@" --config "$HOME_DIR/.utcp_rea_full.json"
    ;;
  list|validate|prompt|search|info)
    "${UTCP[@]}" "$@"
    ;;
  run)
    shift
    "${UTCP[@]}" run "$@"
    ;;
  "")
    if [ -t 0 ]; then
      sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
      exit 1
    fi
    run_ts
    ;;
  *)
    "${UTCP[@]}" "$@"
    ;;
esac
