// ──────────────────────────────────────────────────────────────────────────────
// ILAS — the documentation, checked against the code.
//   npx ts-node src/docs.test.ts
//
// 1. Every ```ts (or ```typescript) block of README.md, docs/S4-WIRE-SPEC.md,
//    docs/INSTALL-FOR-AGENTS.md, packages/clerk/README.md and
//    packages/witness/README.md is type-checked with the TypeScript compiler
//    API, under the repository's own compiler options (tsconfig.json; only the
//    emit options are dropped), as a module of its own at the repository root,
//    so `import … from "./src"` resolves as it does for a reader who saves the
//    block there. Everything happens in memory: nothing is written into the
//    repository. A block that is meant not to compile is marked in the
//    markdown with a comment on the line before its opening fence:
//      <!-- docs-test: skip -->   or   <!-- docs-test: skip: <reason> -->
//    The test reports how many blocks it skipped, and refuses a marker that
//    does not stand right before a ts block.
// 2. The install guide's ilas-clerk.service: its ExecStartPost readiness check
//    is run as systemd would run it (a bare environment with MAINPID set, "$$"
//    read as "$"), against a socket file left by a killed process, then
//    against a real clerkd started on that path, and once more with the main
//    process gone.
// 3. A few sentences that were once wrong stay corrected.
//
// Every child is killed and every temporary directory removed when this file
// ends, also when it is stopped by SIGINT, SIGTERM or SIGHUP.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { spawn } from "child_process";
import type { ChildProcess } from "child_process";
import { generateKeyPairSync } from "crypto";
import { existsSync, lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { connect } from "net";
import { constants as osConstants, tmpdir } from "os";
import { join, resolve } from "path";
import ts from "typescript";

let passed = 0;
let failed = 0;
let skipped = 0;
async function check(name: string, fn: () => void | Promise<void>): Promise<void> {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${String((err as Error)?.message ?? err).split("\n").join("\n    ")}`);
    failed++;
  }
}
function skip(name: string, why: string): void {
  console.log(`  - ${name}: skipped (${why})`);
  skipped++;
}

const REPO = resolve(__dirname, "..");
const DOCS = [
  "README.md",
  "docs/S4-WIRE-SPEC.md",
  "docs/INSTALL-FOR-AGENTS.md",
  "packages/clerk/README.md",
  "packages/witness/README.md",
] as const;
const text = (doc: string): string => readFileSync(join(REPO, doc), "utf8");

// ── clean-up: children, process groups and temporary directories ─────────────

const children = new Set<ChildProcess>();
const groups = new Set<number>();
const temps: string[] = [];
function cleanUp(): void {
  for (const pgid of groups) {
    try {
      process.kill(-pgid, "SIGKILL");
    } catch {
      // the group is gone
    }
  }
  for (const c of children) {
    if (c.exitCode === null && c.signalCode === null) {
      try {
        c.kill("SIGKILL");
      } catch {
        // gone
      }
    }
  }
  for (const d of temps) rmSync(d, { recursive: true, force: true });
}
process.on("exit", cleanUp);
for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
  process.once(sig, () => process.exit(128 + (osConstants.signals[sig] ?? 0)));
}
// Nothing here may hang: whatever is still running after this long is a failure.
const WATCHDOG_MS = 240_000;
setTimeout(() => {
  console.error(`  ✗ the test did not finish within ${WATCHDOG_MS} ms; its children were killed`);
  process.exit(1);
}, WATCHDOG_MS).unref();

function tempDir(prefix: string): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  temps.push(d);
  return d;
}

function track(c: ChildProcess, group = false): ChildProcess {
  children.add(c);
  if (group && c.pid !== undefined) groups.add(c.pid);
  c.on("exit", () => {
    children.delete(c);
    if (group && c.pid !== undefined) groups.delete(c.pid);
  });
  return c;
}

/** Resolves with the exit code (or the signal's name) once `c` has exited, or null after `ms`. */
function exitWithin(c: ChildProcess, ms: number): Promise<number | string | null> {
  if (c.exitCode !== null) return Promise.resolve(c.exitCode);
  if (c.signalCode !== null) return Promise.resolve(c.signalCode);
  return new Promise((done) => {
    const timer = setTimeout(() => done(null), ms);
    c.once("exit", (code, signal) => {
      clearTimeout(timer);
      done(code ?? signal ?? null);
    });
  });
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Resolves once `c` has written a line containing `needle` on stdout or stderr, or rejects after `ms`. */
function outputLine(c: ChildProcess, needle: string, ms: number): Promise<void> {
  return new Promise((done, fail) => {
    let seen = "";
    const timer = setTimeout(() => fail(new Error(`no "${needle}" within ${ms} ms; output: ${seen.slice(-800)}`)), ms);
    const onData = (chunk: Buffer): void => {
      seen += chunk.toString("utf8");
      if (seen.includes(needle)) {
        clearTimeout(timer);
        done();
      }
    };
    c.stdout?.on("data", onData);
    c.stderr?.on("data", onData);
    c.once("exit", (code, signal) => {
      if (seen.includes(needle)) return;
      clearTimeout(timer);
      fail(new Error(`exited (${code ?? signal}) before "${needle}"; output: ${seen.slice(-800)}`));
    });
  });
}

// ── markdown: fenced blocks and sections ─────────────────────────────────────

interface Block {
  doc: string;
  /** 1-based line of the opening fence. */
  line: number;
  /** The info string's first word, lower case ("" for none). */
  lang: string;
  body: string;
  /** The skip marker on the line before the fence: its reason, "" for none given; null without a marker. */
  skip: string | null;
}

const SKIP_MARKER = /^\s*<!--\s*docs-test:\s*skip(?::\s*(.*?))?\s*-->\s*$/;
const TS_LANGS = new Set(["ts", "typescript"]);

/** Every fenced block of `doc` (``` or ~~~, indented ones too), with the skip marker before it. */
function blocks(doc: string): Block[] {
  const lines = text(doc).split("\n");
  const out: Block[] = [];
  for (let i = 0; i < lines.length; i++) {
    const open = /^(\s*)(`{3,}|~{3,})\s*([^\s`]*)/.exec(lines[i]);
    if (open === null) continue;
    const [, indent, fence, info] = open;
    let j = i + 1;
    const body: string[] = [];
    for (; j < lines.length; j++) {
      const close = /^(\s*)(`{3,}|~{3,})\s*$/.exec(lines[j]);
      if (close !== null && close[2][0] === fence[0] && close[2].length >= fence.length) break;
      body.push(lines[j].startsWith(indent) ? lines[j].slice(indent.length) : lines[j].trimStart());
    }
    let k = i - 1;
    while (k >= 0 && lines[k].trim() === "") k--;
    const marker = k >= 0 ? SKIP_MARKER.exec(lines[k]) : null;
    out.push({
      doc,
      line: i + 1,
      lang: info.toLowerCase(),
      body: body.join("\n"),
      skip: marker === null ? null : (marker[1] ?? ""),
    });
    i = j;
  }
  return out;
}

/** The lines of a skip marker that does not stand right before a ts block. */
function strayMarkers(doc: string): number[] {
  const lines = text(doc).split("\n");
  const marked = new Set(
    blocks(doc)
      .filter((b) => b.skip !== null && TS_LANGS.has(b.lang))
      .map((b) => b.line)
  );
  const stray: number[] = [];
  lines.forEach((l, i) => {
    if (!SKIP_MARKER.test(l)) return;
    let k = i + 1;
    while (k < lines.length && lines[k].trim() === "") k++;
    if (!marked.has(k + 1)) stray.push(i + 1);
  });
  return stray;
}

/**
 * A section of `doc`, from the heading that matches to the next heading of the
 * same or a higher level. A "#" line inside a fenced block (a comment in a
 * unit file, say) is not a heading.
 */
function section(doc: string, heading: RegExp): string {
  const lines = text(doc).split("\n");
  let fence: string | null = null;
  const isHeading = lines.map((l) => {
    const f = /^\s*(`{3,}|~{3,})/.exec(l);
    if (f !== null) {
      if (fence === null) fence = f[1];
      else if (f[1][0] === fence[0] && f[1].length >= fence.length && /^\s*(`{3,}|~{3,})\s*$/.test(l)) fence = null;
      return false;
    }
    return fence === null && /^#+ /.test(l);
  });
  const start = lines.findIndex((l, i) => isHeading[i] && heading.test(l));
  assert.ok(start >= 0, `${doc} has no heading matching ${heading}`);
  const level = /^(#+)/.exec(lines[start])![1].length;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (isHeading[i] && /^(#+)/.exec(lines[i])![1].length <= level) {
      end = i;
      break;
    }
  }
  return lines.slice(start, end).join("\n");
}

/** Whitespace folded to single spaces, so a sentence matches across line breaks. */
const flat = (s: string): string => s.replace(/\s+/g, " ");

// ── 1. the ts blocks ─────────────────────────────────────────────────────────

interface Snippet {
  block: Block;
  file: string;
  code: string;
}

/** Type-check every snippet in one program; the diagnostics for each snippet's own file. */
function typecheckAll(snippets: readonly Snippet[]): { global: string[]; perFile: Map<string, string[]> } {
  const configPath = join(REPO, "tsconfig.json");
  const read = ts.readConfigFile(configPath, ts.sys.readFile);
  assert.ok(read.error === undefined, "tsconfig.json reads");
  const parsed = ts.parseJsonConfigFileContent(read.config, ts.sys, REPO, undefined, configPath);
  const options: ts.CompilerOptions = {
    ...parsed.options,
    // A snippet sits at the repository root, outside rootDir, and is never emitted.
    noEmit: true,
    rootDir: undefined,
    outDir: undefined,
    declaration: false,
    declarationMap: false,
    sourceMap: false,
  };
  const virtual = new Map(snippets.map((s) => [s.file, s.code]));
  const host = ts.createCompilerHost(options);
  const getSourceFile = host.getSourceFile.bind(host);
  const fileExists = host.fileExists.bind(host);
  const readFile = host.readFile.bind(host);
  host.getSourceFile = (fileName, languageVersion, onError, shouldCreate) => {
    const code = virtual.get(fileName);
    return code !== undefined
      ? ts.createSourceFile(fileName, code, languageVersion, true)
      : getSourceFile(fileName, languageVersion, onError, shouldCreate);
  };
  host.fileExists = (fileName) => virtual.has(fileName) || fileExists(fileName);
  host.readFile = (fileName) => virtual.get(fileName) ?? readFile(fileName);
  host.writeFile = () => {
    throw new Error("the docs test writes nothing");
  };
  const program = ts.createProgram([...virtual.keys()], options, host);
  const show = (d: ts.Diagnostic): string => {
    const where =
      d.file !== undefined && d.start !== undefined
        ? (() => {
            const p = d.file.getLineAndCharacterOfPosition(d.start);
            return `line ${p.line + 1}: `;
          })()
        : "";
    return `${where}TS${d.code}: ${ts.flattenDiagnosticMessageText(d.messageText, " ")}`;
  };
  const global = [...program.getOptionsDiagnostics(), ...program.getGlobalDiagnostics()].map(show);
  const perFile = new Map<string, string[]>();
  for (const file of virtual.keys()) {
    const source = program.getSourceFile(file);
    assert.ok(source !== undefined, `${file} was not loaded`);
    perFile.set(
      file,
      [...program.getSyntacticDiagnostics(source), ...program.getSemanticDiagnostics(source)].map(show)
    );
  }
  return { global, perFile };
}

async function tsBlocks(): Promise<void> {
  console.log("── the ts blocks of the documents ──");
  const all = DOCS.flatMap((doc) => blocks(doc)).filter((b) => TS_LANGS.has(b.lang));
  const toCheck = all.filter((b) => b.skip === null);
  const marked = all.filter((b) => b.skip !== null);

  await check("every docs-test skip marker stands right before a ts block", () => {
    const stray = DOCS.flatMap((doc) => strayMarkers(doc).map((line) => `${doc}:${line}`));
    assert.deepEqual(stray, [], `markers before no ts block: ${stray.join(", ")}`);
  });

  await check("the READMEs and the install guide each have ts blocks to check (the fence parser finds them)", () => {
    for (const doc of DOCS.filter((d) => d !== "docs/S4-WIRE-SPEC.md")) {
      assert.ok(
        toCheck.some((b) => b.doc === doc),
        `${doc}: no ts block found to type-check`
      );
    }
  });

  const snippets: Snippet[] = toCheck.map((block, n) => ({
    block,
    file: join(REPO, `__docs_test_${block.doc.replace(/[^A-Za-z0-9]+/g, "_")}_${n}.ts`),
    // Its own module: a block without import or export would otherwise be a
    // script sharing one global scope with every other.
    code: `${block.body}\nexport {};\n`,
  }));
  let result: { global: string[]; perFile: Map<string, string[]> } | null = null;
  await check("the compiler options load and the program builds without global errors", () => {
    result = typecheckAll(snippets);
    assert.deepEqual(result.global, []);
  });
  for (const s of snippets) {
    await check(`${s.block.doc}:${s.block.line} (\`\`\`${s.block.lang}) type-checks as a module at the repository root`, () => {
      assert.ok(result !== null, "the program was not built");
      const diagnostics = result.perFile.get(s.file) ?? ["not checked"];
      assert.deepEqual(diagnostics, [], diagnostics.join("\n"));
    });
  }
  for (const b of marked) {
    console.log(`  - ${b.doc}:${b.line} (\`\`\`${b.lang}) not type-checked: marked docs-test skip${b.skip ? ` (${b.skip})` : ""}`);
  }
  console.log(
    `  ts blocks: ${all.length} in ${DOCS.length} documents, ${toCheck.length} type-checked, ` +
      `${marked.length} skipped (marked <!-- docs-test: skip -->)`
  );
}

// ── 2. the clerk unit's readiness check ──────────────────────────────────────

const GUIDE = "docs/INSTALL-FOR-AGENTS.md";
const TS_NODE_BIN = join(REPO, "node_modules", "ts-node", "dist", "bin.js");
/** A word the guide's single-quoted shell script can carry unquoted. */
const PLAIN_WORD = /^[A-Za-z0-9_@%+=:,./-]+$/;

interface ReadinessCheck {
  /** The seconds /usr/bin/timeout gives the loop. */
  timeoutS: string;
  /** The script /bin/sh -c runs, after systemd's own processing of the line. */
  script: string;
}

/** The ExecStartPost of the guide's ilas-clerk.service, as systemd hands it to /usr/bin/timeout. */
function readinessCheck(): ReadinessCheck {
  const unit = blocks(GUIDE).find((b) => b.lang === "ini" && b.body.includes("packages/clerk/src/cli.ts run"));
  assert.ok(unit !== undefined, "the guide has an ilas-clerk.service block (```ini, running packages/clerk/src/cli.ts run)");
  const posts = unit.body.split("\n").filter((l) => l.startsWith("ExecStartPost="));
  assert.equal(posts.length, 1, "the clerk unit has one ExecStartPost line");
  const m = /^ExecStartPost=\/usr\/bin\/timeout (\d+) \/bin\/sh -c '([^']*)'$/.exec(posts[0]);
  assert.ok(m !== null, `ExecStartPost is "/usr/bin/timeout <s> /bin/sh -c '<script>'": ${posts[0]}`);
  // What systemd does to the line before it runs it, as far as this test copies
  // it: "$$" is a literal "$". Anything else systemd would rewrite (a lone "$"
  // is a variable, "%" a specifier, "\" an escape) is refused here, so the
  // script run below is exactly the one systemd runs.
  const held = m[2].replace(/\$\$/g, "\u0000");
  assert.doesNotMatch(held, /[$%\\]/, "the script holds no systemd variable, specifier or escape except $$");
  return { timeoutS: m[1], script: held.replace(/\u0000/g, "$") };
}

function fill(script: string, socketPath: string): string {
  for (const p of [process.execPath, REPO, socketPath]) {
    assert.match(p, PLAIN_WORD, `the path ${p} cannot be put into the guide's script unquoted`);
  }
  const filled = script
    .split("<node>").join(process.execPath)
    .split("<repo>").join(REPO)
    .split("<absolute socket_path>").join(socketPath);
  assert.doesNotMatch(filled, /<[^<>\s]+(?: [^<>]+)*>/, `a placeholder is left in the script: ${filled}`);
  return filled;
}

/** A Unix socket file at `path` with nothing listening on it: the listener was killed. */
async function staleSocket(path: string): Promise<void> {
  const listener = track(
    spawn(
      process.execPath,
      ["-e", "require('net').createServer().listen(process.argv[1], () => process.stdout.write('up\\n'))", path],
      { stdio: ["ignore", "pipe", "pipe"], cwd: tempDir("ilas-docs-cwd-") }
    )
  );
  await outputLine(listener, "up", 15_000);
  listener.kill("SIGKILL");
  assert.notEqual(await exitWithin(listener, 10_000), null, "the listener exited after SIGKILL");
  assert.ok(lstatSync(path).isSocket(), "a socket file is left behind");
}

/** A process that stands in for clerkd as the unit's main process (MAINPID). */
function mainStandIn(): ChildProcess {
  return track(spawn("/bin/sleep", ["600"], { stdio: "ignore" }));
}

/** Run the readiness check as systemd runs it: in its own process group, a bare environment, MAINPID set. */
function runReadiness(check: ReadinessCheck, socketPath: string, mainPid: number): ChildProcess {
  return track(
    spawn("/usr/bin/timeout", [check.timeoutS, "/bin/sh", "-c", fill(check.script, socketPath)], {
      cwd: tempDir("ilas-docs-cwd-"),
      env: { PATH: "/usr/bin:/bin", MAINPID: String(mainPid) },
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
    }),
    true
  );
}

/** One request line to the socket; resolves with the answer line. */
function ask(path: string, line: string, ms: number): Promise<string> {
  return new Promise((done, fail) => {
    let got = "";
    const s = connect(path);
    const timer = setTimeout(() => {
      s.destroy();
      fail(new Error(`no answer on ${path} within ${ms} ms`));
    }, ms);
    s.on("connect", () => s.write(line + "\n"));
    s.on("data", (b: Buffer) => {
      got += b.toString("utf8");
      const nl = got.indexOf("\n");
      if (nl !== -1) {
        clearTimeout(timer);
        s.destroy();
        done(got.slice(0, nl));
      }
    });
    s.on("error", (err) => {
      clearTimeout(timer);
      fail(err);
    });
  });
}

/** A clerkd started on `socketPath` with a new key and book, as its own process. */
function startClerkd(socketPath: string): ChildProcess {
  const dir = tempDir("ilas-docs-clerk-");
  const { privateKey } = generateKeyPairSync("ed25519");
  const keyPath = join(dir, "clerk.key");
  writeFileSync(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }) as string, { mode: 0o600 });
  const configPath = join(dir, "clerk.json");
  writeFileSync(
    configPath,
    JSON.stringify({
      clerk_id: "docs-test-clerk",
      private_key_path: keyPath,
      book_path: join(dir, "book", "receipts.jsonl"),
      socket_path: socketPath,
      socket_mode: "0600",
    })
  );
  const env: NodeJS.ProcessEnv = { ...process.env, TS_NODE_TRANSPILE_ONLY: "true" };
  delete env.npm_command;
  delete env.npm_lifecycle_event;
  return track(
    spawn(process.execPath, [TS_NODE_BIN, join(REPO, "packages", "clerk", "src", "cli.ts"), "run", "--config", configPath], {
      cwd: tempDir("ilas-docs-cwd-"),
      env,
      stdio: ["ignore", "pipe", "pipe"],
    })
  );
}

async function clerkUnit(): Promise<void> {
  console.log("── the install guide's clerk unit: is it active only once clerkd answers? ──");
  const name = "the guide's ilas-clerk.service";
  if (process.platform !== "linux" || !existsSync("/usr/bin/timeout") || !existsSync("/bin/sh") || !existsSync("/bin/sleep")) {
    skip(name, "needs Linux with /usr/bin/timeout, /bin/sh and /bin/sleep");
    return;
  }
  if (!existsSync(TS_NODE_BIN)) {
    skip(name, `needs ${TS_NODE_BIN} (npm install)`);
    return;
  }

  let found: ReadinessCheck | null = null;
  await check("its ExecStartPost is a shell loop systemd runs unchanged, with only <node>, <repo> and <absolute socket_path> to fill in", () => {
    const r = readinessCheck();
    fill(r.script, "/tmp/x.sock");
    found = r;
  });
  // (read back through a cast: the assignment above happens inside a callback)
  const readiness = found as ReadinessCheck | null;
  if (readiness === null) return;

  await check(
    "with a socket file left by a killed clerkd, the check keeps waiting; it finishes (exit 0) only once a clerkd started on that path answers",
    async () => {
      const sock = join(tempDir("ilas-docs-sock-"), "clerk.sock");
      await staleSocket(sock);
      const main = mainStandIn();
      const post = runReadiness(readiness, sock, main.pid!);
      const early = await exitWithin(post, 4_000);
      assert.equal(
        early,
        null,
        `the readiness check finished (exit ${early}) although nothing answered on the socket (a socket file left by a killed process)`
      );
      const clerkd = startClerkd(sock);
      const code = await exitWithin(post, 60_000);
      assert.equal(code, 0, `the readiness check should finish with exit 0 once clerkd answers; it gave ${code}`);
      // At that moment clerkd answers on the socket, as a node ordered after the unit needs.
      const answer = JSON.parse(await ask(sock, "{}", 5_000)) as { ok?: unknown; error?: unknown };
      assert.equal(answer.ok, false, "clerkd refuses the probe");
      assert.equal(typeof answer.error, "string");
      clerkd.kill("SIGTERM");
      assert.equal(await exitWithin(clerkd, 15_000), 0, "clerkd stops cleanly on SIGTERM");
      main.kill("SIGKILL");
    }
  );

  await check("when the main process (clerkd) has exited, the check gives up at once instead of waiting for its timeout", async () => {
    const sock = join(tempDir("ilas-docs-sock-"), "clerk.sock");
    const main = mainStandIn();
    const post = runReadiness(readiness, sock, main.pid!);
    const early = await exitWithin(post, 2_500);
    assert.equal(early, null, `the readiness check finished (exit ${early}) while clerkd ran and nothing answered`);
    main.kill("SIGKILL");
    assert.notEqual(await exitWithin(main, 5_000), null, "the stand-in exited");
    // One more ping try (a ts-node start) at most, then the MAINPID check; well
    // inside the unit's own timeout, which is what this tells apart.
    const code = await exitWithin(post, 30_000);
    assert.notEqual(code, null, "the readiness check kept waiting after the clerk's main process had exited");
    assert.notEqual(code, 0, "the readiness check reported success with no clerkd");
  });
}

// ── 3. sentences that were once wrong ────────────────────────────────────────

async function statements(): Promise<void> {
  console.log("── statements that were once wrong stay corrected ──");
  await check("guide step 9: reconcile matches the receipts of a log passed with --log, and lists them only when that log is left out", () => {
    const step9 = flat(section(GUIDE, /^## 9\./));
    assert.doesNotMatch(
      step9,
      /lists the receipts of the old file \(pass it with a second `--log`\)/,
      "step 9 still says reconcile lists the old file's receipts when that file is passed with --log"
    );
    assert.match(
      step9,
      /Pass the old file with a second `--log` so that its receipts are matched; left out, they are listed there too\./,
      "step 9 does not say that a log passed with --log has its receipts matched"
    );
  });
  await check("guide step 8: the clerk unit counts clerkd as started only once it answers, not once a socket file exists", () => {
    const step8 = flat(section(GUIDE, /^## 8\./));
    assert.doesNotMatch(step8, /\[ -S /, "the readiness check still tests only that a socket file exists");
    assert.doesNotMatch(step8, /starts only once the socket is there/, "step 8 still says the node starts once the socket is there");
    assert.match(step8, /starts only once clerkd answers on its socket/, "step 8 does not say the node starts only once clerkd answers");
  });
}

async function main(): Promise<void> {
  await tsBlocks();
  await clerkUnit();
  await statements();
  console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed${skipped > 0 ? ` (${skipped} skipped)` : ""}`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
