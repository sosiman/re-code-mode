# Contributing

Thanks for helping! Useful contributions: new playbooks, new local-engine tools, parsers for more catalog sources, fixes, docs.

## Dev loop

```bash
bash scripts/setup.sh        # deps + configs + catalog
npm test                     # must stay green (needs radare2 and a C compiler)
```

## Guidelines

* **No shell strings.** Spawn programs with `execFileSync(cmd, [args])`; never concatenate user input into a command line.
* **Validate at the boundary.** Paths go through `resolveFile`, regexes through `safeRegex`, radare2 targets through `checkR2Target`. New tools that interpolate input into another tool's command language need an allow-list pattern **and** a regression test in `test/smoke.mjs`.
* **Keep outputs small.** Every tool needs a `limit`/filter parameter; the point is to avoid flooding the model.
* **No machine-specific data.** No absolute home paths, hostnames, IPs, tokens or personal e-mails in code, docs, fixtures or commit metadata.
* **Third-party content is fetched, not vendored.** Don't commit cloned repositories or generated catalogs.
* Playbooks live in `data/playbooks.json` and should reference tools by their Code Mode name (`re.re_...`).

## Pull requests

Describe the change, mention the security impact of any new input path, and include/adjust tests.
