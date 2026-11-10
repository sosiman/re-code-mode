#!/usr/bin/env node
/**
 * re-code-mode — MCP server (stdio) exposing a layered reverse-engineering toolbox.
 *
 *   Layer 1  Local engines : radare2/rabin2, binwalk, upx, unzip (+ optional REA CLI)
 *   Layer 2  Catalog       : searchable index of community RE tools + on-demand clone
 *   Layer 3  Playbooks     : per-target-type methodology + locally cloned agent skills
 *
 * Designed to be mounted behind UTCP Code Mode so that large outputs are filtered
 * inside a sandbox (TypeScript) instead of being streamed into an LLM context.
 *
 * NOTE: UTCP prefixes every tool with the manual name, so the tool declared here as
 * `triage_binary` is called from Code Mode as `re.re_triage_binary(...)`.
 *
 * Security model: this server is meant to run LOCALLY, for a user you trust.
 * Read SECURITY.md before exposing it to anything else.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(process.env.RE_CODE_MODE_HOME || path.join(__dirname, ".."));

const CATALOG_PATH = path.join(ROOT, "data", "re-catalog.json");
const PLAYBOOKS_PATH = path.join(ROOT, "data", "playbooks.json");
const SKILLS_DIR = path.join(ROOT, "skills-repos");
const TOOLS_CACHE_DIR = path.join(ROOT, "tools-cache");
const REA_BIN = path.join(ROOT, "node_modules", "rea-agents", "scripts", "rea.mjs");

// Optional hardening knobs (all opt-in via environment):
//   RE_ALLOWED_DIRS=/path/a:/path/b   only analyse files under these directories
//   RE_ENABLE_REA_EXEC=1              expose the free-form `rea_exec` tool
const ALLOWED_DIRS = (process.env.RE_ALLOWED_DIRS || "")
  .split(path.delimiter)
  .filter(Boolean)
  .map((d) => {
    try { return fs.realpathSync(path.resolve(d)); } catch { return path.resolve(d); }
  });
const ENABLE_REA_EXEC = process.env.RE_ENABLE_REA_EXEC === "1";

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

function runCmd(cmd, args = [], timeoutMs = 25000, asBuffer = false) {
  try {
    const out = execFileSync(cmd, args, {
      encoding: asBuffer ? "buffer" : "utf-8",
      timeout: timeoutMs,
      maxBuffer: 128 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0" }
    });
    return { ok: true, stdout: asBuffer ? out : out.trim() };
  } catch (err) {
    return {
      ok: false,
      error: err.code === "ENOENT" ? `required program not found in PATH: ${cmd}` : err.message,
      stdout: asBuffer ? Buffer.alloc(0) : (err.stdout || "").toString().trim(),
      stderr: (err.stderr || "").toString().trim()
    };
  }
}

function safeJsonParse(str, fallback = null) {
  try { return JSON.parse(str); } catch { return fallback; }
}

function jsonResponse(data) {
  return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
}

/** Wrap a handler so thrown validation errors become structured tool results. */
function guarded(fn) {
  return async (args) => {
    try {
      return await fn(args);
    } catch (err) {
      return jsonResponse({ ok: false, error: String(err && err.message ? err.message : err) });
    }
  };
}

/** Resolve a user supplied path to a real, existing regular file. */
function resolveFile(p) {
  if (typeof p !== "string" || !p || p.includes("\0")) throw new Error("invalid path");
  let abs;
  try {
    abs = fs.realpathSync(path.resolve(p));
  } catch {
    throw new Error(`file does not exist: ${p}`);
  }
  if (!fs.statSync(abs).isFile()) throw new Error(`not a regular file: ${p}`);
  if (ALLOWED_DIRS.length && !ALLOWED_DIRS.some((d) => abs === d || abs.startsWith(d + path.sep))) {
    throw new Error("path is outside RE_ALLOWED_DIRS");
  }
  return abs;
}

/** Compile a user supplied regex with basic ReDoS guards. */
function safeRegex(pattern) {
  if (!pattern) return null;
  if (pattern.length > 200) throw new Error("regex too long (max 200 chars)");
  if (/\([^)]*[+*][^)]*\)[+*{]/.test(pattern)) throw new Error("regex rejected: nested quantifiers");
  try {
    return new RegExp(pattern, "i");
  } catch (e) {
    throw new Error(`invalid regex: ${e.message}`);
  }
}

/** Function names / addresses are interpolated into a radare2 command line. */
const R2_TARGET_RE = /^(0x[0-9a-fA-F]{1,16}|[A-Za-z_][A-Za-z0-9_.:+-]{0,199})$/;
function checkR2Target(t) {
  if (!R2_TARGET_RE.test(t)) {
    throw new Error("invalid target: use a function name (letters, digits, _ . : + -) or a 0x... address");
  }
  return t;
}

function r2(file, commands, timeoutMs) {
  // -N: do not load user rc files / scripts. -q: quit after running commands.
  return runCmd(
    "r2",
    ["-N", "-q", "-e", "scr.color=0", "-e", "scr.interactive=false", "-c", commands, file],
    timeoutMs
  );
}

function sha256File(file, maxBytes = 512 * 1024 * 1024) {
  const st = fs.statSync(file);
  if (st.size > maxBytes) return null;
  const hash = crypto.createHash("sha256");
  const fd = fs.openSync(file, "r");
  try {
    const buf = Buffer.alloc(1024 * 1024);
    let n;
    while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) hash.update(buf.subarray(0, n));
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest("hex");
}

function printableStrings(buf, minLen = 8) {
  const out = [];
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const c = i < buf.length ? buf[i] : 0;
    if (c >= 0x20 && c < 0x7f) {
      if (start < 0) start = i;
    } else if (start >= 0) {
      if (i - start >= minLen) out.push(buf.toString("latin1", start, i));
      start = -1;
    }
  }
  return out;
}

function loadCatalog() {
  if (!fs.existsSync(CATALOG_PATH)) {
    throw new Error("catalog not built yet — run `npm run catalog` (or scripts/setup.sh) first");
  }
  return safeJsonParse(fs.readFileSync(CATALOG_PATH, "utf-8"), { items: [] });
}

function walkFiles(dir, base, acc = []) {
  if (!fs.existsSync(dir)) return acc;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === ".git" || entry.name === "node_modules") continue;
    const full = path.join(dir, entry.name);
    if (entry.isSymbolicLink()) continue; // never follow links out of the sandbox dir
    if (entry.isDirectory()) walkFiles(full, base, acc);
    else if (/\.(md|sh|py|json)$/i.test(entry.name)) acc.push(path.relative(base, full));
  }
  return acc;
}

const server = new McpServer({ name: "re-code-mode", version: "1.0.0" });

// ============================================================================
// LAYER 2 — catalog
// ============================================================================

server.tool(
  "catalog_search",
  "Search the indexed catalog of community reverse-engineering tools, MCP servers and agent skills.",
  {
    query: z.string().optional().describe("Free text, e.g. ghidra, android, firmware, unpacker, flutter, electron"),
    category: z.string().optional().describe("Category substring filter, e.g. Mobile, Firmware, Debuggers"),
    type: z.enum(["all", "mcp", "skill", "tool", "reference"]).optional().default("all"),
    min_stars: z.number().optional().default(0),
    limit: z.number().optional().default(20)
  },
  guarded(async ({ query = "", category = "", type = "all", min_stars = 0, limit = 20 }) => {
    const raw = loadCatalog();
    const q = query.toLowerCase().trim();
    const cat = category.toLowerCase().trim();
    const filtered = raw.items.filter((item) => {
      if (type !== "all" && item.type !== type) return false;
      if (min_stars > 0 && (item.stars || 0) < min_stars) return false;
      if (cat && !(item.category || "").toLowerCase().includes(cat)) return false;
      if (q) {
        return `${item.name} ${item.description} ${item.category} ${item.url}`.toLowerCase().includes(q);
      }
      return true;
    });
    filtered.sort((a, b) => (b.stars || 0) - (a.stars || 0));
    return jsonResponse({
      total_matches: filtered.length,
      returned: Math.min(limit, filtered.length),
      results: filtered.slice(0, limit)
    });
  })
);

server.tool(
  "catalog_categories",
  "List catalog categories and counts.",
  {},
  guarded(async () => {
    const raw = loadCatalog();
    const byCategory = {};
    const byType = {};
    for (const item of raw.items) {
      byCategory[item.category] = (byCategory[item.category] || 0) + 1;
      byType[item.type] = (byType[item.type] || 0) + 1;
    }
    return jsonResponse({
      total_tools: raw.items.length,
      by_type: byType,
      categories: Object.entries(byCategory)
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count)
    });
  })
);

// ============================================================================
// LAYER 3 — playbooks and skills
// ============================================================================

server.tool(
  "get_playbook",
  "Get the step-by-step triage playbook for a target type.",
  {
    scenario: z
      .enum(["all", "elf_linux", "pe_windows", "android_apk", "electron_js", "firmware_iot", "go_rust_packed"])
      .default("all")
  },
  guarded(async ({ scenario = "all" }) => {
    const playbooks = safeJsonParse(fs.readFileSync(PLAYBOOKS_PATH, "utf-8"), {});
    if (scenario === "all") return jsonResponse({ available_scenarios: Object.keys(playbooks), playbooks });
    return jsonResponse(playbooks[scenario] || { ok: false, error: "unknown scenario" });
  })
);

server.tool(
  "skill_list",
  "List markdown/scripts of the agent-skill repositories cloned into ./skills-repos (see scripts/fetch-skills.sh).",
  { filter: z.string().optional().default("").describe("Substring filter on the relative path") },
  guarded(async ({ filter = "" }) => {
    if (!fs.existsSync(SKILLS_DIR)) {
      return jsonResponse({ ok: false, error: "skills-repos/ not found — run scripts/fetch-skills.sh" });
    }
    const all = walkFiles(SKILLS_DIR, SKILLS_DIR);
    const q = filter.toLowerCase().trim();
    const matched = all.filter((f) => !q || f.toLowerCase().includes(q));
    return jsonResponse({ total_files: all.length, matched_count: matched.length, files: matched });
  })
);

server.tool(
  "skill_read",
  "Read a file from ./skills-repos by (partial) relative path, optionally filtering lines with a regex.",
  {
    target: z.string().describe("Relative path or distinctive fragment, e.g. 'leanrea', 'apk-reverse', 'MASTER-ROUTING.md'"),
    grep: z.string().optional().default(""),
    max_lines: z.number().optional().default(200)
  },
  guarded(async ({ target, grep = "", max_lines = 200 }) => {
    const all = walkFiles(SKILLS_DIR, SKILLS_DIR);
    const t = target.toLowerCase().trim();
    const hit =
      all.find((f) => f.toLowerCase() === t) ||
      all.find((f) => f.toLowerCase().endsWith(`/${t}/skill.md`)) ||
      all.find((f) => f.toLowerCase().includes(t) && f.toLowerCase().endsWith("skill.md")) ||
      all.find((f) => f.toLowerCase().includes(t));
    if (!hit) return jsonResponse({ ok: false, error: `no file matches '${target}'` });

    const full = path.join(SKILLS_DIR, hit);
    if (fs.statSync(full).size > 2 * 1024 * 1024) return jsonResponse({ ok: false, error: "file too large" });
    let lines = fs.readFileSync(full, "utf-8").split("\n");
    const re = safeRegex(grep);
    if (re) lines = lines.filter((l) => re.test(l));
    return jsonResponse({
      ok: true,
      relative_path: hit,
      total_lines: lines.length,
      content: lines.slice(0, max_lines).join("\n")
    });
  })
);

server.tool(
  "fetch_tool",
  "Shallow-clone a GitHub repository (from the catalog, 'owner/repo' or a github.com URL) into ./tools-cache. Clone only: nothing is built or executed.",
  {
    repo_or_query: z.string().describe("'owner/repo', a https://github.com/... URL, or a catalog name"),
    mode: z.enum(["clone", "status"]).optional().default("clone")
  },
  guarded(async ({ repo_or_query, mode = "clone" }) => {
    fs.mkdirSync(TOOLS_CACHE_DIR, { recursive: true });
    if (mode === "status") return jsonResponse({ cached_repos: fs.readdirSync(TOOLS_CACHE_DIR) });

    const SLUG = /^([A-Za-z0-9_.-]{1,100})\/([A-Za-z0-9_.-]{1,100})$/;
    const input = repo_or_query.trim();
    let owner, repo;
    const urlMatch = input.match(/^https:\/\/github\.com\/([A-Za-z0-9_.-]{1,100})\/([A-Za-z0-9_.-]{1,100})(?:\.git)?\/?$/);
    if (urlMatch) {
      [, owner, repo] = urlMatch;
    } else if (SLUG.test(input)) {
      [, owner, repo] = input.match(SLUG);
    } else {
      const q = input.toLowerCase();
      const found = loadCatalog().items.find((i) => i.name.toLowerCase() === q) ||
        loadCatalog().items.find((i) => i.name.toLowerCase().includes(q));
      const m = found && found.url.match(/^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)/);
      if (m) [, owner, repo] = m;
    }
    if (!owner || !repo) return jsonResponse({ ok: false, error: `cannot resolve a GitHub repository from: ${repo_or_query}` });
    repo = repo.replace(/\.git$/, "");
    if (owner.startsWith("-") || repo.startsWith("-") || repo === "." || repo === "..") {
      return jsonResponse({ ok: false, error: "invalid repository name" });
    }

    const dest = path.join(TOOLS_CACHE_DIR, `${owner}__${repo}`);
    if (!fs.existsSync(dest)) {
      const res = runCmd(
        "git",
        ["clone", "--depth", "1", "--no-tags", "--single-branch", "--", `https://github.com/${owner}/${repo}.git`, dest],
        120000
      );
      if (!res.ok) return jsonResponse({ ok: false, error: `clone failed for ${owner}/${repo}`, details: res.stderr || res.error });
    }
    return jsonResponse({
      ok: true,
      repo: `${owner}/${repo}`,
      local_path: dest,
      files: fs.readdirSync(dest).filter((f) => f !== ".git"),
      notice: "Third-party code. Review it before building or running anything."
    });
  })
);

// ============================================================================
// LAYER 1 — local engines
// ============================================================================

server.tool(
  "triage_binary",
  "Fast static triage of ELF/PE/Mach-O/DEX: arch, bits, language, hardening flags, linked libs, sections, SHA-256.",
  { path: z.string().describe("Path to the file") },
  guarded(async ({ path: p }) => {
    const file = resolveFile(p);
    const stat = fs.statSync(file);
    const magic = runCmd("file", ["-b", "--", file]);
    const info = safeJsonParse(runCmd("rabin2", ["-Ij", file]).stdout, {}).info || {};
    const libs = safeJsonParse(runCmd("rabin2", ["-lj", file]).stdout, {}).libs || [];
    const sections = (safeJsonParse(runCmd("rabin2", ["-Sj", file]).stdout, {}).sections || []).map((s) => ({
      name: s.name, size: s.size, vsize: s.vsize, perm: s.perm
    }));
    return jsonResponse({
      ok: true,
      file,
      size_bytes: stat.size,
      sha256: sha256File(file),
      file_magic: magic.stdout,
      binary_info: {
        arch: info.arch, bits: info.bits, os: info.os, class: info.class, lang: info.lang,
        compiler: info.compiler, machine: info.machine, stripped: info.stripped, static: info.static,
        security: { nx: info.nx, pic_pie: info.pic, canary: info.canary, relro: info.relro, crypto: info.crypto }
      },
      linked_libraries: libs,
      sections_summary: sections.slice(0, 25)
    });
  })
);

server.tool(
  "imports_exports",
  "List imports/exports of a binary, filtered with a regex (done in-process so only matches reach the caller).",
  {
    path: z.string(),
    filter: z.string().optional().default("").describe("Regex on symbol names, e.g. 'socket|ssl|crypt|exec'"),
    kind: z.enum(["both", "imports", "exports"]).optional().default("both"),
    limit: z.number().optional().default(50)
  },
  guarded(async ({ path: p, filter = "", kind = "both", limit = 50 }) => {
    const file = resolveFile(p);
    const re = safeRegex(filter);
    const out = { file, filter: filter || null };
    if (kind === "both" || kind === "imports") {
      const all = safeJsonParse(runCmd("rabin2", ["-ij", file]).stdout, {}).imports || [];
      const matched = all
        .filter((i) => !re || re.test(i.name || "") || re.test(i.libname || ""))
        .map((i) => ({ name: i.name, type: i.type, bind: i.bind, plt: i.plt }));
      Object.assign(out, { imports_total: all.length, imports_matched: matched.length, imports: matched.slice(0, limit) });
    }
    if (kind === "both" || kind === "exports") {
      const all = safeJsonParse(runCmd("rabin2", ["-ej", file]).stdout, {}).exports || [];
      const matched = all
        .filter((e) => !re || re.test(e.name || "") || re.test(e.demangled || ""))
        .map((e) => ({ name: e.demangled || e.name, raw_name: e.name, size: e.size, vaddr: e.vaddr, type: e.type }));
      Object.assign(out, { exports_total: all.length, exports_matched: matched.length, exports: matched.slice(0, limit) });
    }
    return jsonResponse(out);
  })
);

server.tool(
  "extract_strings",
  "Extract strings from a binary (rabin2 -zzj) and filter by regex or preset before returning them.",
  {
    path: z.string(),
    regex: z.string().optional().default(""),
    preset: z.enum(["none", "urls", "paths", "network", "secrets"]).optional().default("none"),
    min_length: z.number().optional().default(5),
    limit: z.number().optional().default(60)
  },
  guarded(async ({ path: p, regex = "", preset = "none", min_length = 5, limit = 60 }) => {
    const file = resolveFile(p);
    const presets = {
      urls: "https?://|wss?://|ftp://",
      paths: "/(etc|proc|sys|dev|var|tmp|home|usr|opt|bin)/|[A-Za-z]:\\\\",
      network: "https?://|\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b|socket|connect|bind|listen|bearer|user-agent",
      secrets: "api[_-]?key|secret|token|password|passwd|private[_-]?key|begin rsa|hmac|authorization"
    };
    const re = safeRegex(regex || (preset !== "none" ? presets[preset] : ""));
    const all = safeJsonParse(runCmd("rabin2", ["-zzj", file], 30000).stdout, {}).strings || [];
    const matched = [];
    for (const s of all) {
      const val = s.string || "";
      if (val.length < min_length) continue;
      if (re && !re.test(val)) continue;
      matched.push({ string: val.slice(0, 300), section: s.section, vaddr: s.vaddr, length: s.length });
    }
    return jsonResponse({
      file,
      total_strings_in_binary: all.length,
      matched_count: matched.length,
      returned: Math.min(limit, matched.length),
      strings: matched.slice(0, limit)
    });
  })
);

server.tool(
  "list_functions",
  "Run radare2 analysis (aa; aflj) and return a filtered function list. only_leaf=true gives call-graph leaves for bottom-up review.",
  {
    path: z.string(),
    filter: z.string().optional().default("").describe("Regex on function names"),
    min_size: z.number().optional().default(0),
    only_leaf: z.boolean().optional().default(false),
    limit: z.number().optional().default(40)
  },
  guarded(async ({ path: p, filter = "", min_size = 0, only_leaf = false, limit = 40 }) => {
    const file = resolveFile(p);
    const re = safeRegex(filter);
    const funcs = safeJsonParse(r2(file, "aa; aflj", 60000).stdout, []) || [];
    const matched = funcs
      .filter((f) => (f.size || 0) >= min_size && (!only_leaf || !(f.outdegree > 0)) && (!re || re.test(f.name || "")))
      .map((f) => ({
        name: f.name,
        offset: `0x${(f.offset || 0).toString(16)}`,
        size: f.size, nbbs: f.nbbs,
        indegree_xrefs: f.indegree, outdegree_calls: f.outdegree, cc_complexity: f.cc
      }));
    return jsonResponse({
      file,
      total_functions: funcs.length,
      matched_functions: matched.length,
      functions: matched.slice(0, limit)
    });
  })
);

server.tool(
  "disassemble_function",
  "Disassemble (pdf) and/or pseudo-decompile (pdc) one function by name or 0x address using radare2.",
  {
    path: z.string(),
    target: z.string().describe("Function name (e.g. main, sym.check) or 0x address"),
    mode: z.enum(["decompile", "disasm", "both"]).optional().default("decompile"),
    max_lines: z.number().optional().default(120)
  },
  guarded(async ({ path: p, target, mode = "decompile", max_lines = 120 }) => {
    const file = resolveFile(p);
    checkR2Target(target);
    const out = { file, target, mode };
    if (mode === "decompile" || mode === "both") {
      const lines = (r2(file, `aa; s ${target}; pdc`, 60000).stdout || "").split("\n");
      Object.assign(out, { decompiled_total_lines: lines.length, decompiled: lines.slice(0, max_lines).join("\n") });
    }
    if (mode === "disasm" || mode === "both") {
      const lines = (r2(file, `aa; s ${target}; pdf`, 60000).stdout || "").split("\n");
      Object.assign(out, { disasm_total_lines: lines.length, disasm: lines.slice(0, max_lines).join("\n") });
    }
    return jsonResponse(out);
  })
);

server.tool(
  "apk_inspect",
  "Fingerprint an APK/AAR (Flutter, React Native, Hermes, Unity IL2CPP, Kotlin, native libs) and optionally harvest URLs / API routes from its DEX files.",
  {
    path: z.string(),
    mode: z.enum(["triage", "apis"]).optional().default("triage")
  },
  guarded(async ({ path: p, mode = "triage" }) => {
    const file = resolveFile(p);
    const listing = runCmd("unzip", ["-Z1", "--", file], 20000);
    if (!listing.ok) return jsonResponse({ ok: false, error: "not a readable zip/APK", details: listing.stderr || listing.error });
    const names = listing.stdout.split("\n").filter(Boolean);
    const has = (needle) => names.some((n) => n.includes(needle));
    const dexFiles = names.filter((n) => /^classes\d*\.dex$/.test(n));
    const frameworks = {
      flutter: has("libflutter.so") || has("libapp.so"),
      react_native: has("index.android.bundle") || has("libreactnativejni.so"),
      hermes: has("libhermes.so"),
      unity_il2cpp: has("libil2cpp.so") || has("global-metadata.dat"),
      kotlin: has("kotlin/") || has("kotlinx"),
      native_libs: names.filter((n) => /^lib\/.+\.so$/.test(n)).slice(0, 40)
    };
    if (mode === "triage") {
      return jsonResponse({ ok: true, apk: file, detected_frameworks: frameworks, dex_files: dexFiles });
    }

    const urls = new Set();
    const routes = new Set();
    for (const dex of dexFiles.slice(0, 8)) {
      const buf = runCmd("unzip", ["-p", "--", file, dex], 60000, true);
      if (!buf.ok) continue;
      for (const s of printableStrings(buf.stdout, 8)) {
        if (/^https?:\/\/[^\s"'<>]+/i.test(s)) urls.add(s.slice(0, 200));
        else if (/^\/(api|v\d+|graphql|auth|oauth|user|login)\/[^\s"'<>]+/i.test(s)) routes.add(s.slice(0, 150));
      }
    }
    return jsonResponse({
      ok: true,
      apk: file,
      detected_frameworks: frameworks,
      extracted_urls_count: urls.size,
      extracted_urls: [...urls].slice(0, 60),
      extracted_api_routes_count: routes.size,
      extracted_api_routes: [...routes].slice(0, 60)
    });
  })
);

server.tool(
  "firmware_scan",
  "Scan a firmware image or packed binary for embedded files/filesystems (binwalk) and UPX packing.",
  { path: z.string() },
  guarded(async ({ path: p }) => {
    const file = resolveFile(p);
    const bw = runCmd("binwalk", [file], 60000);
    const upx = runCmd("upx", ["-t", file], 15000);
    return jsonResponse({
      file,
      upx_packed: upx.ok,
      upx_output: upx.stdout || upx.stderr,
      binwalk_signatures: (bw.stdout || bw.stderr || "").split("\n").filter(Boolean).slice(0, 60)
    });
  })
);

// Free-form access to the optional REA CLI. Disabled unless explicitly enabled,
// because REA includes debugger / device / process-capture commands.
if (ENABLE_REA_EXEC) {
  server.tool(
    "rea_exec",
    "Run the optional REA CLI (npm: rea-agents) with arbitrary arguments. Only available when RE_ENABLE_REA_EXEC=1.",
    { args: z.array(z.string()).max(64).describe("CLI arguments, e.g. ['--help']") },
    guarded(async ({ args = ["--help"] }) => {
      if (!fs.existsSync(REA_BIN)) {
        return jsonResponse({ ok: false, error: "rea-agents not installed — run scripts/setup.sh --with-rea" });
      }
      const res = runCmd("node", [REA_BIN, ...args], 60000);
      return jsonResponse({
        ok: res.ok,
        stdout: res.stdout.slice(0, 12000),
        stderr: res.stderr ? res.stderr.slice(0, 4000) : undefined
      });
    })
  );
}

await server.connect(new StdioServerTransport());
