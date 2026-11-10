# Security policy

## Threat model

`re-code-mode` is a **local developer tool**. The MCP server runs with the privileges of the user who starts it and executes external programs (radare2, binwalk, upx, unzip, git) on files that user points it at. It is **not** designed to be exposed to untrusted users or networks.

### Built-in protections

* No shell is ever used: external programs are launched with `execFile` and an argument vector.
* File arguments are resolved to real regular files (`realpath`); `RE_ALLOWED_DIRS` can restrict them to an allow-list.
* radare2 receives `-N` (no user rc/scripts). Function names/addresses interpolated into radare2 commands are validated against a strict pattern, so `;`, `|`, `` ` ``, `!`, newlines and `@` are rejected.
* User regexes are length-limited and rejected when they contain nested quantifiers (basic ReDoS guard).
* `fetch_tool` only accepts `github.com` HTTPS repositories matching a strict slug pattern, uses `--` before positional arguments, performs a shallow **clone only** and never builds or runs the cloned code.
* `skill_list`/`skill_read` never follow symlinks and are confined to `./skills-repos`.
* `bin/re-run.sh` JSON-encodes every argument before placing it in generated TypeScript.
* The free-form `rea_exec` tool is **disabled by default** (`RE_ENABLE_REA_EXEC=1` to enable).

### Residual risks — please read

* **Hostile samples.** Disassemblers and unpackers have had memory-safety bugs. Analyse untrusted malware inside a disposable VM or container with no credentials and restricted network.
* **Third-party code.** Anything cloned by `fetch_tool` or `fetch-skills.sh` is third-party; review before building or running it.
* **Optional REA engine.** In full mode (`rea-mcp`) all REA tools are reachable, including debugger and device commands. Enable it only where that is acceptable.
* **Prompt injection.** Strings extracted from a binary are attacker-controlled text that will be read by your model. Treat them as untrusted data.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** (Security tab → *Report a vulnerability*). Do not open a public issue for security problems. We aim to acknowledge reports within a few days.

## Secrets

This repository must never contain credentials. `.gitignore` excludes `.env*`, keys and machine-local UTCP configs. If you find a secret in the history, report it as above.
