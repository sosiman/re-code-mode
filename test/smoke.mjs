// Smoke + security regression tests. Spawns the MCP server over stdio and calls its tools.
// Requires: radare2 (rabin2/r2), a C compiler (gcc/cc). Run with: npm test
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "re-code-mode-test-"));
const src = path.join(tmp, "hello.c");
const bin = path.join(tmp, "hello");
fs.writeFileSync(src, '#include <stdio.h>\nint secret(int x){return x*42;}\nint main(void){puts("https://example.test/api/v1");return secret(1);}\n');
const cc = ["cc", "gcc"].find((c) => { try { execFileSync(c, ["--version"], { stdio: "ignore" }); return true; } catch { return false; } });
assert.ok(cc, "a C compiler is required for the tests");
execFileSync(cc, ["-O0", "-o", bin, src]);

const client = new Client({ name: "smoke", version: "1.0.0" });
await client.connect(new StdioClientTransport({
  command: process.execPath,
  args: [path.join(root, "src", "server.mjs")],
  env: { ...process.env, RE_CODE_MODE_HOME: root }
}));

const call = async (name, args) => JSON.parse((await client.callTool({ name, arguments: args })).content[0].text);
let passed = 0;
const test = async (label, fn) => { await fn(); passed++; console.log(`ok - ${label}`); };

await test("exposes the expected tools (rea_exec hidden by default)", async () => {
  const names = (await client.listTools()).tools.map((t) => t.name).sort();
  for (const n of ["catalog_search", "catalog_categories", "get_playbook", "skill_list", "skill_read", "fetch_tool",
    "triage_binary", "imports_exports", "extract_strings", "list_functions", "disassemble_function",
    "apk_inspect", "firmware_scan"]) assert.ok(names.includes(n), `missing tool ${n}`);
  assert.ok(!names.includes("rea_exec"), "rea_exec must be opt-in");
});

await test("playbooks load", async () => {
  const r = await call("get_playbook", { scenario: "elf_linux" });
  assert.ok(Array.isArray(r.fast_triage_steps) && r.fast_triage_steps.length >= 3);
});

await test("triage_binary fingerprints an ELF", async () => {
  const r = await call("triage_binary", { path: bin });
  assert.equal(r.ok, true);
  assert.match(r.sha256, /^[0-9a-f]{64}$/);
  assert.ok(r.binary_info.arch);
});

await test("imports_exports filters by regex", async () => {
  const r = await call("imports_exports", { path: bin, filter: "puts", kind: "imports" });
  assert.ok(r.imports_matched >= 1);
});

await test("extract_strings finds the URL", async () => {
  const r = await call("extract_strings", { path: bin, preset: "urls" });
  assert.ok(r.strings.some((s) => s.string.includes("example.test")));
});

await test("list_functions + disassemble_function work", async () => {
  const f = await call("list_functions", { path: bin, filter: "main|secret" });
  assert.ok(f.matched_functions >= 1);
  const d = await call("disassemble_function", { path: bin, target: "main", mode: "disasm" });
  assert.match(d.disasm, /ret|call/);
});

await test("SECURITY: radare2 command injection via target is rejected", async () => {
  const marker = path.join(tmp, "PWNED");
  for (const target of [`main; !touch ${marker}`, "main | !id", "main`id`", "main\n!id"]) {
    const r = await call("disassemble_function", { path: bin, target });
    assert.equal(r.ok, false, `target accepted: ${JSON.stringify(target)}`);
  }
  assert.equal(fs.existsSync(marker), false, "injection executed a command");
});

await test("SECURITY: missing / non-regular paths are rejected cleanly", async () => {
  assert.equal((await call("triage_binary", { path: path.join(tmp, "nope") })).ok, false);
  assert.equal((await call("triage_binary", { path: tmp })).ok, false);
  assert.equal((await call("triage_binary", { path: "bad\0path" })).ok, false);
});

await test("SECURITY: nested-quantifier regex (ReDoS) is rejected", async () => {
  assert.equal((await call("extract_strings", { path: bin, regex: "(a+)+$" })).ok, false);
});

await test("SECURITY: fetch_tool refuses option-injection and traversal", async () => {
  for (const q of ["--upload-pack=touch /tmp/x/y", "../../etc", "owner/../x", "https://evil.example/o/r", "-oProxyCommand=x/y"]) {
    const r = await call("fetch_tool", { repo_or_query: q });
    assert.equal(r.ok, false, `fetch_tool accepted ${JSON.stringify(q)}`);
  }
});

await test("catalog tools answer (built or with a helpful error)", async () => {
  const r = await call("catalog_categories", {});
  assert.ok(r.total_tools > 0 || r.ok === false);
});

await client.close();
fs.rmSync(tmp, { recursive: true, force: true });
console.log(`\n${passed} tests passed`);
