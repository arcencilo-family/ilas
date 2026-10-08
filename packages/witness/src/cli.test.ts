// ──────────────────────────────────────────────────────────────────────────────
// Reference witness — the CLI, run as separate child processes.
//   npx ts-node packages/witness/src/cli.test.ts
//
// `run` is started as its own process and left polling for a few seconds. The
// node side (ILAS core's FileDropWitness client) drops a commit into the intake
// and waits for a receipt it can verify. Then the child gets SIGTERM.
//
// Never hangs: every child has a timeout, the long-running child is killed in a
// finally block, and a watchdog ends the whole file if anything stalls. Never
// leaves anything behind: the children and the temp dir are registered with
// test-support, which kills and removes them however the process ends,
// SIGINT, SIGTERM and SIGHUP included. Never writes into the repository: every
// file is under the temp dir, and every child but npx (which needs the
// repository root to find ts-node) runs with the temp dir as its working
// directory.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { generateKeyPairSync } from "crypto";
import { spawn, spawnSync } from "child_process";
import type { ChildProcess, SpawnSyncReturns } from "child_process";
import {
  appendFileSync,
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "fs";
import { createServer } from "net";
import { isAbsolute, join, relative } from "path";

import { LockedEvidenceLog } from "../../../src/l0";
import { publicKeyFingerprint as ilasFingerprint } from "../../../src/l0/fingerprint";
import { ContinuityVerifier, FileDropWitness, HeadCommitEmitter } from "../../../src/s4";
import { GENESIS_HASH } from "./commit";
import { recordHash } from "./store";
import type { UnhashedRecord } from "./store";
import {
  betweenTests,
  cleanUp,
  tempDir,
  trackChild,
  trackPid,
  untrackChild,
  untrackPid,
} from "./test-support";

let passed = 0;
let failed = 0;
const pending: Array<() => Promise<void>> = [];

function checkAsync(name: string, fn: () => void | Promise<void>): void {
  pending.push(async () => {
    try {
      await fn();
      console.log(`  ✓ ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✗ ${name}`);
      console.error(`    ${(err as Error).message}`);
      failed++;
    }
  });
}

const REPO = join(__dirname, "..", "..", "..");
const CLI = join(__dirname, "cli.ts");
const TS_NODE_REGISTER = require.resolve("ts-node/register");
const CHILD_ENV: NodeJS.ProcessEnv = {
  ...process.env,
  // The package is type-checked by `npx tsc -p packages/witness`; the children
  // only need to run it.
  TS_NODE_TRANSPILE_ONLY: "true",
  TS_NODE_PROJECT: join(__dirname, "..", "tsconfig.json"),
};
// The children are started directly, whether or not this file was started by
// npm (`npm test`, `npx ts-node`): they must not inherit npm's launch markers.
delete CHILD_ENV.npm_command;
delete CHILD_ENV.npm_lifecycle_event;

/** The npm/npx warning lines `run` wrote to stderr. */
function npmWarnings(stderr: string): string[] {
  return stderr.split("\n").filter((l) => l.startsWith("warning: ") && l.includes("npm/npx"));
}

/** The direct command a warning line names, as the shell would split it into words. */
function directCommandWords(warning: string): string[] {
  const m = /start it directly: (.*)$/.exec(warning);
  assert.ok(m !== null, `no direct command in: ${warning}`);
  const words: string[] = [];
  let word: string | null = null;
  const line = m[1];
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === " ") {
      if (word !== null) words.push(word);
      word = null;
    } else if (c === "'") {
      const end = line.indexOf("'", i + 1);
      assert.ok(end > i, `unterminated quote in: ${line}`);
      word = (word ?? "") + line.slice(i + 1, end);
      i = end;
    } else if (c === "\\") {
      word = (word ?? "") + (line[++i] ?? "");
    } else {
      word = (word ?? "") + c;
    }
  }
  if (word !== null) words.push(word);
  return words;
}

/**
 * The checks every direct command must pass: node, ts-node's bin.js and this
 * cli.ts by absolute paths that exist, then `run --config <absolute config>`.
 */
function assertDirectCommand(warning: string, config: string): void {
  const words = directCommandWords(warning);
  assert.equal(words.length, 6, `node, ts-node, cli.ts, run, --config, the config: ${warning}`);
  const [node, tsNode, cliPath, ...rest] = words;
  for (const [what, path] of [["node", node], ["ts-node's bin.js", tsNode], ["cli.ts", cliPath]]) {
    assert.ok(isAbsolute(path), `${what} is named by an absolute path: ${path} (in ${warning})`);
    assert.ok(existsSync(path), `${what}, named in the warning, exists: ${path}`);
  }
  assert.match(tsNode, /[\\/]ts-node[\\/]dist[\\/]bin\.js$/, "ts-node's own bin.js");
  assert.equal(cliPath, CLI, "the cli.ts in use");
  assert.deepEqual(rest, ["run", "--config", config]);
}

const ROOT = tempDir("ilas-witness-cli-");

const watchdog = setTimeout(() => {
  console.error("  ✗ watchdog: the CLI test did not finish in 240 s");
  // The exit handler (test-support) kills the children and removes ROOT.
  process.exit(1);
}, 240_000);
watchdog.unref();

function cli(args: string[], timeout = 90_000): SpawnSyncReturns<string> {
  const result = spawnSync(process.execPath, ["-r", TS_NODE_REGISTER, CLI, ...args], {
    cwd: ROOT,
    env: CHILD_ENV,
    encoding: "utf8",
    timeout,
    killSignal: "SIGKILL",
  });
  if (result.error) throw result.error;
  return result;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(what: string, predicate: () => boolean, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error(`timed out after ${timeoutMs} ms waiting for ${what}`);
    await sleep(50);
  }
}

function entry(n: number) {
  return {
    timestamp: 1_700_000_000_000 + n,
    moduleId: "test",
    eventType: "unit",
    provenanceTag: "LaneA" as const,
    parameters: { n },
    outcome: "ok",
  };
}

type RunEvent = { event: string; [k: string]: unknown };

interface Running {
  readonly child: ChildProcess;
  events(): RunEvent[];
  stderr(): string;
  exit(): { code: number | null; signal: NodeJS.Signals | null } | null;
  spawnError(): Error | null;
}

/** Start a long-running child and collect its stdout events and stderr. */
function startChild(command: string, args: string[], env: NodeJS.ProcessEnv = CHILD_ENV, cwd = ROOT): Running {
  const lines: string[] = [];
  let stderr = "";
  let exit: { code: number | null; signal: NodeJS.Signals | null } | null = null;
  let spawnError: Error | null = null;
  const child = trackChild(spawn(command, args, { cwd, env, stdio: ["ignore", "pipe", "pipe"] }));
  child.on("error", (error) => {
    spawnError = error;
  });
  child.on("exit", (code, signal) => {
    exit = { code, signal };
  });
  let buffered = "";
  child.stdout!.setEncoding("utf8");
  child.stdout!.on("data", (chunk: string) => {
    buffered += chunk;
    const parts = buffered.split("\n");
    buffered = parts.pop()!;
    lines.push(...parts.filter((l) => l.startsWith("{")));
  });
  child.stderr!.setEncoding("utf8");
  child.stderr!.on("data", (chunk: string) => {
    stderr += chunk;
  });
  return {
    child,
    events: () => lines.map((l) => JSON.parse(l) as RunEvent),
    stderr: () => stderr,
    exit: () => exit,
    spawnError: () => spawnError,
  };
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

/** A separate witness layout under ROOT/<name>, sharing the generated key. Returns its config path. */
function layout(name: string): { dir: string; intake: string; outbox: string; store: string; config: string } {
  const dir = join(ROOT, name);
  const l = {
    dir,
    intake: join(dir, "intake"),
    outbox: join(dir, "outbox", "node-a"),
    store: join(dir, "store", "witness-store.jsonl"),
    config: join(dir, "witness.json"),
  };
  mkdirSync(l.intake, { recursive: true });
  mkdirSync(l.outbox, { recursive: true });
  mkdirSync(join(dir, "store"), { recursive: true });
  writeFileSync(
    l.config,
    JSON.stringify({
      witnessSetId: "set-a",
      intakeDir: l.intake,
      storePath: l.store,
      privateKeyPath: keyPath,
      submitters: [{ id: "node-a", outboxDir: l.outbox }],
      pollIntervalMs: 100,
    })
  );
  return l;
}

// ── layout shared by the steps below ──────────────────────────────────────────

const keysDir = join(ROOT, "keys");
const keyPath = join(keysDir, "witness.key");
const pubPath = join(keysDir, "witness.pub.pem");
const intake = join(ROOT, "intake");
const outbox = join(ROOT, "outbox", "node-a");
const storePath = join(ROOT, "store", "witness-store.jsonl");
const configPath = join(ROOT, "witness.json");

console.log("── the CLI, as child processes ──");

/** The fingerprint keygen printed for the shared key; every later print must equal it. */
let keygenFingerprint = "";

checkAsync("keygen writes witness.key (0600) and witness.pub.pem, prints the fingerprint in ILAS's format, and will not overwrite them", () => {
  const first = cli(["keygen", "--out", keysDir]);
  assert.equal(first.status, 0, first.stderr);
  assert.equal(statSync(keyPath).mode & 0o777, 0o600);
  assert.match(first.stdout, /witness\.key \(private, mode 0600\)/);
  assert.ok(existsSync(pubPath));
  // The line the clerk's keygen prints too: "sha256:" + hex SHA-256 of the SPKI DER.
  const printed = /^public key fingerprint: (sha256:[0-9a-f]{64})$/m.exec(first.stdout);
  assert.ok(printed !== null, `no fingerprint line in ILAS's format: ${first.stdout}`);
  assert.equal(printed[1], ilasFingerprint(readFileSync(pubPath, "utf8")), "the fingerprint of the key it wrote");
  keygenFingerprint = printed[1];

  const again = cli(["keygen", "--out", keysDir]);
  assert.equal(again.status, 1);
  assert.match(again.stderr, /refusing to overwrite/);
});

checkAsync("keygen on a file system that does not keep the 0600 mode exits 1, says so, and never claims 0600", () => {
  // Preloaded into the child: chmod that sets 0644 whatever it is asked, as a
  // Windows drive under WSL without metadata effectively does.
  const preload = join(ROOT, "chmod-does-not-stick.js");
  writeFileSync(
    preload,
    'const fs = require("fs"); const real = fs.chmodSync;\n' +
      "fs.chmodSync = (path) => real(path, 0o644);\n"
  );
  const out = join(ROOT, "keys-no-posix");
  const result = spawnSync(
    process.execPath,
    ["-r", preload, "-r", TS_NODE_REGISTER, CLI, "keygen", "--out", out],
    { cwd: ROOT, env: CHILD_ENV, encoding: "utf8", timeout: 90_000, killSignal: "SIGKILL" }
  );
  if (result.error) throw result.error;
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stderr, /mode reads back as 0644, not 0600/);
  assert.doesNotMatch(result.stdout, /0600/, "nothing on stdout claims the key is 0600");
  assert.equal(existsSync(join(out, "witness.key")), false, "no exposed key left behind");
});

checkAsync("keygen where chmod is refused (EPERM) exits 1 with the reason, not a bare EPERM, and leaves no key", () => {
  // Preloaded into the child: chmod refused, as on a FAT/exFAT mount owned by another account.
  const preload = join(ROOT, "chmod-refused.js");
  writeFileSync(
    preload,
    'const fs = require("fs");\n' +
      "fs.chmodSync = (path) => { const e = new Error(`EPERM: operation not permitted, chmod '${path}'`);\n" +
      '  e.code = "EPERM"; e.syscall = "chmod"; throw e; };\n'
  );
  const out = join(ROOT, "keys-chmod-refused");
  const result = spawnSync(
    process.execPath,
    ["-r", preload, "-r", TS_NODE_REGISTER, CLI, "keygen", "--out", out],
    { cwd: ROOT, env: CHILD_ENV, encoding: "utf8", timeout: 90_000, killSignal: "SIGKILL" }
  );
  if (result.error) throw result.error;
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stderr, /setting its mode to 0600 failed \(EPERM/);
  assert.match(result.stderr, /removed again/);
  assert.deepEqual(readdirSync(out), [], "no key file of either half left behind");
});

checkAsync("usage errors exit 2", () => {
  assert.equal(cli([]).status, 2);
  assert.equal(cli(["run"]).status, 2, "run without --config");
  assert.equal(cli(["verify", "--store", storePath]).status, 2, "verify without --pub");
  assert.equal(cli(["frobnicate"]).status, 2);
});

checkAsync("run refuses a private key the group can read, and says how to fix it", () => {
  mkdirSync(intake, { recursive: true });
  mkdirSync(outbox, { recursive: true });
  mkdirSync(join(ROOT, "store"), { recursive: true });
  // Relative paths resolve against the config file's own directory.
  writeFileSync(
    configPath,
    JSON.stringify(
      {
        witnessSetId: "set-a",
        intakeDir: "intake",
        storePath: "store/witness-store.jsonl",
        privateKeyPath: "keys/witness.key",
        submitters: [{ id: "node-a", outboxDir: "outbox/node-a" }],
        pollIntervalMs: 100,
      },
      null,
      2
    )
  );
  chmodSync(keyPath, 0o640);
  try {
    const r = cli(["run", "--config", configPath, "--once"]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /mode is 0640/);
    assert.match(r.stderr, /chmod 600/);
    assert.equal(existsSync(storePath), false, "nothing was started");
  } finally {
    chmodSync(keyPath, 0o600);
  }
});

checkAsync("run polls as its own process; the ILAS client verifies the receipt; SIGTERM stops it", async () => {
  const lines: string[] = [];
  let stderr = "";
  const child = trackChild(
    spawn(process.execPath, ["-r", TS_NODE_REGISTER, CLI, "run", "--config", configPath], {
      cwd: ROOT,
      env: CHILD_ENV,
      stdio: ["ignore", "pipe", "pipe"],
    })
  );
  let exit: { code: number | null; signal: NodeJS.Signals | null } | null = null;
  child.on("exit", (code, signal) => {
    exit = { code, signal };
  });
  let buffered = "";
  child.stdout!.setEncoding("utf8");
  child.stdout!.on("data", (chunk: string) => {
    buffered += chunk;
    const parts = buffered.split("\n");
    buffered = parts.pop()!;
    lines.push(...parts.filter((l) => l.length > 0));
  });
  child.stderr!.setEncoding("utf8");
  child.stderr!.on("data", (chunk: string) => {
    stderr += chunk;
  });
  const events = () => lines.map((l) => JSON.parse(l) as { event: string; [k: string]: unknown });

  try {
    await waitFor("the STARTED line", () => events().some((e) => e.event === "STARTED") || exit !== null, 90_000);
    assert.equal(exit, null, `the witness exited early: ${stderr}`);
    const started = events().find((e) => e.event === "STARTED")!;
    assert.equal(started.storeCreated, true);
    assert.deepEqual(started.submitters, ["node-a"]);
    assert.equal(started.publicKeyFingerprint, keygenFingerprint, "STARTED names its key as keygen did");
    assert.deepEqual(npmWarnings(stderr), [], "started directly: no npm/npx warning");

    // Let it idle through a few polls with nothing to do.
    await sleep(500);

    // The node side: ILAS core, unchanged.
    const log = new LockedEvidenceLog();
    for (let i = 0; i < 3; i++) await log.append(entry(i));
    const client = new FileDropWitness({
      id: "set-a",
      intakeDir: intake,
      outboxDir: outbox,
      submitterId: "node-a",
      publicKeyPath: pubPath,
    });
    const commit = new HeadCommitEmitter(log, client).emit();
    assert.equal(client.getSubmitDiagnostics().written, 1);

    await waitFor("a receipt in the outbox", () => readdirSync(outbox).some((n) => n.startsWith("receipt-")), 20_000);
    await waitFor("the intake file to be consumed", () => !existsSync(join(intake, "node-a")), 20_000);

    const receipts = client.retrieveReceipts();
    assert.equal(receipts.length, 1, JSON.stringify(client.getLastFetchDiagnostics()));
    assert.equal(receipts[0].seq_no, commit.seq_no);
    assert.equal(receipts[0].head_hash, commit.head_hash);
    const report = new ContinuityVerifier(log, client).verify();
    assert.equal(report.status, "VERIFIED_HISTORICAL");
    assert.equal(report.receiptsChecked, 1);
    const retained = events().find((e) => e.event === "RETAINED");
    assert.ok(retained !== undefined, "the child logged the retention");
    assert.equal(retained!.submitterId, "node-a");

    child.kill("SIGTERM");
    await waitFor("the child to exit after SIGTERM", () => exit !== null, 15_000);
    assert.deepEqual(exit, { code: 0, signal: null }, `clean shutdown expected; stderr: ${stderr}`);
    const last = events()[events().length - 1];
    assert.equal(last.event, "STOPPED");
    assert.equal(last.signal, "SIGTERM");
  } finally {
    if (exit === null) child.kill("SIGKILL");
    untrackChild(child);
  }
});

checkAsync("verify accepts the store the child wrote, under the witness public key", () => {
  const r = cli(["verify", "--store", storePath, "--pub", pubPath]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /^OK: 1 record\(s\) verify/);
  assert.match(r.stdout, /submitter "node-a": 1 record\(s\)/);
});

checkAsync("verify fails under another public key (signatures are checked)", () => {
  const otherDir = join(ROOT, "other-keys");
  assert.equal(cli(["keygen", "--out", otherDir]).status, 0);
  const r = cli(["verify", "--store", storePath, "--pub", join(otherDir, "witness.pub.pem")]);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /FAIL: .*witness_sig does not verify/);
});

checkAsync("a tampered store: verify exits non-zero, and run refuses to start", () => {
  const original = readFileSync(storePath, "utf8");
  const record = JSON.parse(original.trim());
  record.commit.ts += 1;
  writeFileSync(storePath, JSON.stringify(record) + "\n");
  try {
    const v = cli(["verify", "--store", storePath, "--pub", pubPath]);
    assert.equal(v.status, 1);
    assert.match(v.stdout, /FAIL: .*line 1: hash does not match/);

    const run = cli(["run", "--config", configPath, "--once"]);
    assert.equal(run.status, 1);
    assert.match(run.stderr, /does not verify/);
    assert.match(run.stderr, /Refusing to run/);
  } finally {
    writeFileSync(storePath, original);
  }
  assert.equal(cli(["verify", "--store", storePath, "--pub", pubPath]).status, 0, "restored");
});

checkAsync("verify of a missing store exits non-zero", () => {
  const r = cli(["verify", "--store", join(ROOT, "nope.jsonl"), "--pub", pubPath]);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /FAIL: no store/);
});

checkAsync("verify refuses a PRIVATE key given as --pub, and says to give only the public key", () => {
  const r = cli(["verify", "--store", storePath, "--pub", keyPath]);
  assert.equal(r.status, 1, r.stdout);
  assert.match(r.stderr, /holds a PRIVATE key/);
  assert.match(r.stderr, /PUBLIC key file/);
  assert.doesNotMatch(r.stdout, /^OK/);
});

checkAsync("fingerprint --pub prints, for the node's copy of the key, exactly what keygen printed (exit 0); verify prints the same", () => {
  assert.match(keygenFingerprint, /^sha256:[0-9a-f]{64}$/, "keygen ran first");
  const copy = join(ROOT, "node-copy.pub.pem");
  copyFileSync(pubPath, copy);
  const r = cli(["fingerprint", "--pub", copy]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, `${keygenFingerprint}\n`, "the fingerprint alone, on one line");
  const other = cli(["fingerprint", "--pub", join(ROOT, "other-keys", "witness.pub.pem")]);
  assert.equal(other.status, 0, other.stderr);
  assert.match(other.stdout, /^sha256:[0-9a-f]{64}\n$/);
  assert.notEqual(other.stdout, r.stdout, "two keys, one fingerprint");
  const v = cli(["verify", "--store", storePath, "--pub", copy]);
  assert.equal(v.status, 0, v.stdout + v.stderr);
  assert.ok(v.stdout.split("\n").includes(`public key fingerprint: ${keygenFingerprint}`), v.stdout);
});

checkAsync("fingerprint refuses a private key, a missing file, a file that is no key and a non-ed25519 key (exit 1, nothing on stdout)", () => {
  const notAKey = join(ROOT, "not-a-key.pem");
  writeFileSync(notAKey, "not a key\n");
  const rsa = join(ROOT, "rsa.pub.pem");
  writeFileSync(
    rsa,
    generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ type: "spki", format: "pem" })
  );
  const cases: Array<[string, string, RegExp]> = [
    ["the private key", keyPath, /holds a PRIVATE key/],
    ["a missing file", join(ROOT, "nope.pub.pem"), /cannot read public key file/],
    ["a file that is no key", notAKey, /cannot read public key file/],
    ["an RSA key", rsa, /not ed25519/],
  ];
  for (const [label, path, why] of cases) {
    const r = cli(["fingerprint", "--pub", path]);
    assert.equal(r.status, 1, `${label}: ${r.stdout}${r.stderr}`);
    assert.equal(r.stdout, "", `${label}: nothing on stdout`);
    assert.match(r.stderr, why, label);
  }
});

checkAsync("fingerprint usage errors exit 2: no --pub, --pub twice", () => {
  for (const args of [["fingerprint"], ["fingerprint", "--pub", pubPath, "--pub", pubPath]]) {
    const r = cli(args);
    assert.equal(r.status, 2, `${args.join(" ")}: ${r.stdout}${r.stderr}`);
    assert.equal(r.stdout, "");
  }
});

checkAsync("verify fails a store rewritten without the key, hashes recomputed (record_sig)", () => {
  const copy = join(ROOT, "rewritten-store.jsonl");
  const rec = JSON.parse(readFileSync(storePath, "utf8").trim()) as Record<string, unknown>;
  (rec.commit as { ts: number }).ts = 42;
  rec.prev_hash = GENESIS_HASH;
  rec.hash = recordHash(rec as unknown as UnhashedRecord);
  writeFileSync(copy, JSON.stringify(rec) + "\n");
  const r = cli(["verify", "--store", copy, "--pub", pubPath]);
  assert.equal(r.status, 1, r.stdout);
  assert.match(r.stdout, /FAIL: .*line 1: record_sig does not verify/);
});

checkAsync("a witness that halts exits 1 and gives the reason on stderr as well as in the HALTED line", async () => {
  const l = layout("halt");
  const run = startChild(process.execPath, ["-r", TS_NODE_REGISTER, CLI, "run", "--config", l.config]);
  try {
    await waitFor("STARTED", () => run.events().some((e) => e.event === "STARTED") || run.exit() !== null, 90_000);
    assert.equal(run.exit(), null, `exited early: ${run.stderr()}`);
    const log = new LockedEvidenceLog();
    for (let i = 0; i < 3; i++) await log.append(entry(i));
    const client = new FileDropWitness({
      id: "set-a",
      intakeDir: l.intake,
      outboxDir: l.outbox,
      submitterId: "node-a",
      publicKeyPath: pubPath,
    });
    const emitter = new HeadCommitEmitter(log, client);
    emitter.emit();
    await waitFor("RETAINED", () => run.events().some((e) => e.event === "RETAINED"), 20_000);
    // Something else writes to the store; the next retention must halt.
    appendFileSync(l.store, "x");
    await log.append(entry(3));
    emitter.emit();
    await waitFor("the child to exit", () => run.exit() !== null, 20_000);
    assert.deepEqual(run.exit(), { code: 1, signal: null });
    const last = run.events()[run.events().length - 1];
    assert.equal(last.event, "HALTED");
    assert.match(String(last.detail), /last left it at/);
    assert.match(run.stderr(), /^error: the witness halted: .*last left it at/m);
  } finally {
    if (run.exit() === null) run.child.kill("SIGKILL");
    untrackChild(run.child);
  }
});

checkAsync("started through npx, run warns once on stderr (signals to npx may not reach it; the direct command) and never stops itself", async () => {
  const l = layout("npx");
  // npm's default script shell, so that the tree is npm → sh -c → node.
  const env: NodeJS.ProcessEnv = { ...CHILD_ENV };
  delete env.npm_config_script_shell;
  // From the repository root, as its README says: npx finds ts-node there.
  const run = startChild("npx", ["ts-node", relative(REPO, CLI), "run", "--config", l.config], env, REPO);
  let witnessPid: number | null = null;
  try {
    await waitFor(
      "STARTED",
      () => run.events().some((e) => e.event === "STARTED") || run.exit() !== null || run.spawnError() !== null,
      90_000
    );
    if (run.spawnError() !== null) {
      console.log(`    (npx unavailable: ${String(run.spawnError())}; skipped)`);
      return;
    }
    assert.equal(run.exit(), null, `exited early: ${run.stderr()}`);
    witnessPid = run.events().find((e) => e.event === "STARTED")!.pid as number;
    trackPid(witnessPid);
    assert.notEqual(witnessPid, run.child.pid, "npx is not the witness process itself");

    // Written before STARTED, but on another pipe.
    await waitFor("the warning line", () => npmWarnings(run.stderr()).length > 0, 5_000).catch(() => undefined);
    const warnings = npmWarnings(run.stderr());
    assert.equal(warnings.length, 1, `exactly one warning line: ${JSON.stringify(run.stderr())}`);
    assert.match(warnings[0], /a signal sent to npx may not reach it/);
    assert.ok(warnings[0].includes(`pid ${witnessPid}`), "it names the pid to signal");
    // npx was given cli.ts relative to the repository; the command names it absolutely.
    assertDirectCommand(warnings[0], l.config);

    // Is the witness npm's direct child, or behind a shell that will not pass the signal on?
    let behindShell = true;
    try {
      const stat = readFileSync(`/proc/${witnessPid}/stat`, "utf8");
      behindShell = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1]) !== run.child.pid;
    } catch {
      // no /proc: assume the default npm layout
    }

    run.child.kill("SIGTERM");
    await waitFor("npx to exit", () => run.exit() !== null, 20_000);
    const pid = witnessPid;
    if (behindShell) {
      // The signal did not reach the witness, and it does not take npx's exit as one.
      await sleep(1500);
      assert.ok(alive(pid), "the witness stopped itself when npx went away");
      assert.equal(run.events().some((e) => e.event === "STOPPED"), false);
      process.kill(pid, "SIGTERM");
    }
    await waitFor("the STOPPED line", () => run.events().some((e) => e.event === "STOPPED"), 20_000);
    const stopped = run.events().find((e) => e.event === "STOPPED")!;
    assert.equal(stopped.signal, "SIGTERM", "stopped by a signal, never by itself");
    assert.equal(stopped.detail, undefined);
    await waitFor("the witness process to be gone", () => !alive(pid), 20_000);
  } finally {
    if (witnessPid !== null) {
      if (alive(witnessPid)) process.kill(witnessPid, "SIGKILL");
      untrackPid(witnessPid);
    }
    if (run.exit() === null) run.child.kill("SIGKILL");
    untrackChild(run.child);
  }
});

checkAsync("run does not stop itself when its launcher exits, whatever npm variables it inherited", async () => {
  const l = layout("orphan");
  const outPath = join(l.dir, "witness.out");
  const errPath = join(l.dir, "witness.err");
  // A launcher that starts the witness detached, with npx's markers in its
  // environment, waits until it has started, and exits normally: the running
  // witness loses its parent and is reparented.
  const launcher = [
    'const { spawn } = require("child_process");',
    'const { openSync, readFileSync } = require("fs");',
    "const a = JSON.parse(process.argv[1]);",
    'const c = spawn(process.execPath, ["-r", a.register, a.cli, "run", "--config", a.config], {',
    '  cwd: a.cwd, env: a.env, detached: true, stdio: ["ignore", openSync(a.out, "w"), openSync(a.err, "w")],',
    "});",
    "c.unref();",
    "console.log(c.pid);",
    "const deadline = Date.now() + 80000;",
    "const tick = () => {",
    '  let text = ""; try { text = readFileSync(a.out, "utf8"); } catch {}',
    '  if (!text.includes(\'"event":"STARTED"\') && Date.now() < deadline) setTimeout(tick, 50);',
    "};",
    "tick();",
  ].join("\n");
  const args = JSON.stringify({
    register: TS_NODE_REGISTER,
    cli: CLI,
    config: l.config,
    cwd: ROOT,
    env: { ...CHILD_ENV, npm_command: "exec", npm_lifecycle_event: "npx" },
    out: outPath,
    err: errPath,
  });
  const launched = spawnSync(process.execPath, ["-e", launcher, args], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 90_000,
    killSignal: "SIGKILL",
  });
  // The pid is the launcher's first line, printed before it waits.
  const pid = Number(launched.stdout.split("\n")[0].trim());
  const pidPrinted = Number.isSafeInteger(pid) && pid > 0;
  if (pidPrinted) trackPid(pid);
  if (launched.error) {
    if (pidPrinted) {
      untrackPid(pid);
      if (alive(pid)) process.kill(pid, "SIGKILL");
    }
    throw launched.error;
  }
  assert.ok(pidPrinted, `the launcher printed the witness pid: ${launched.stdout}${launched.stderr}`);
  const events = (): RunEvent[] =>
    readFileSync(outPath, "utf8")
      .split("\n")
      .filter((line) => line.startsWith("{"))
      .map((line) => JSON.parse(line) as RunEvent);
  try {
    await waitFor("STARTED", () => events().some((e) => e.event === "STARTED") || !alive(pid), 90_000);
    assert.ok(alive(pid), `exited early: ${readFileSync(errPath, "utf8")}`);
    // The launcher has exited, after STARTED. Give a launcher watch, were
    // there one, several chances to fire.
    await sleep(2000);
    assert.ok(alive(pid), `the witness stopped itself: ${JSON.stringify(events())}`);
    assert.equal(events().some((e) => e.event === "STOPPED"), false);
    assert.equal(npmWarnings(readFileSync(errPath, "utf8")).length, 1, "it warned, once, instead");
    process.kill(pid, "SIGTERM");
    await waitFor("STOPPED", () => events().some((e) => e.event === "STOPPED"), 20_000);
    assert.equal(events().find((e) => e.event === "STOPPED")!.signal, "SIGTERM");
    await waitFor("the witness process to be gone", () => !alive(pid), 20_000);
  } finally {
    if (alive(pid)) process.kill(pid, "SIGKILL");
    untrackPid(pid);
  }
});

checkAsync("run --once under npm's markers writes no warning (it is not a daemon)", () => {
  const l = layout("once-npm");
  const result = spawnSync(process.execPath, ["-r", TS_NODE_REGISTER, CLI, "run", "--config", l.config, "--once"], {
    cwd: ROOT,
    env: { ...CHILD_ENV, npm_command: "exec", npm_lifecycle_event: "npx" },
    encoding: "utf8",
    timeout: 90_000,
    killSignal: "SIGKILL",
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(npmWarnings(result.stderr), []);
});

checkAsync("started with npm's markers from outside the repository with a relative --config, run's warning names a direct command that works from any other directory", async () => {
  const l = layout("elsewhere");
  // The config is given relative to the directory run starts in, which is not the repository.
  const run = startChild(
    process.execPath,
    [require.resolve("ts-node/dist/bin.js"), CLI, "run", "--config", "witness.json"],
    { ...CHILD_ENV, npm_command: "exec" },
    l.dir
  );
  let warning = "";
  try {
    await waitFor(
      "STARTED and the warning",
      () =>
        (run.events().some((e) => e.event === "STARTED") && npmWarnings(run.stderr()).length > 0) ||
        run.exit() !== null ||
        run.spawnError() !== null,
      90_000
    );
    assert.equal(run.exit(), null, `exited early: ${run.stderr()}`);
    const warnings = npmWarnings(run.stderr());
    assert.equal(warnings.length, 1, run.stderr());
    warning = warnings[0];
    run.child.kill("SIGTERM");
    await waitFor("the witness to stop", () => run.exit() !== null, 20_000);
  } finally {
    if (run.exit() === null) run.child.kill("SIGKILL");
    untrackChild(run.child);
  }
  assertDirectCommand(warning, l.config);

  // The operator pastes it into a shell somewhere else; --once so that it ends by itself.
  const somewhereElse = join(ROOT, "somewhere-else");
  mkdirSync(somewhereElse, { recursive: true });
  const command = /start it directly: (.*)$/.exec(warning)![1];
  const direct = spawnSync("sh", ["-c", `${command} --once`], {
    cwd: somewhereElse,
    env: CHILD_ENV,
    encoding: "utf8",
    timeout: 90_000,
    killSignal: "SIGKILL",
  });
  if (direct.error) throw direct.error;
  assert.equal(direct.status, 0, `the direct command, run from ${somewhereElse}: ${direct.stdout}${direct.stderr}`);
  assert.ok(direct.stdout.includes('"event":"STARTED"'), direct.stdout);
});

/** Make a FIFO; false (and a note) where mkfifo is unavailable. */
function mkfifo(path: string): boolean {
  const made = spawnSync("mkfifo", [path], { timeout: 5_000 });
  if (made.status !== 0) console.log("    (mkfifo unavailable; skipped)");
  return made.status === 0;
}

/**
 * A FIFO that nothing ever writes to: open() for reading without O_NONBLOCK
 * waits on it for ever. Each command below gets 20 s, and a hang fails the test.
 */
const fifo = join(ROOT, "nobody-writes.fifo");

/** cli(), killed after 20 s; a hang fails with what hung. */
function cliNoHang(label: string, args: string[]): SpawnSyncReturns<string> {
  try {
    return cli(args, 20_000);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ETIMEDOUT") {
      throw new Error(`${label}: hung on the FIFO and was killed after 20 s`);
    }
    throw error;
  }
}

/** A copy of layout(name) whose config names `privateKeyPath` as the private key. */
function layoutWithKey(name: string, privateKeyPath: string): { config: string; store: string } {
  const l = layout(name);
  const config = JSON.parse(readFileSync(l.config, "utf8")) as Record<string, unknown>;
  writeFileSync(l.config, JSON.stringify({ ...config, privateKeyPath }));
  return l;
}

checkAsync("a FIFO, a directory or a socket as a key file is refused at once (exit 1, the reason on stderr), never waited on: fingerprint --pub, verify --pub, run's privateKeyPath", async () => {
  if (!mkfifo(fifo)) return;
  const fifoKey = layoutWithKey("fifo-key", fifo);
  const socket = join(ROOT, "key.sock");
  const socketKey = layoutWithKey("socket-key", socket);
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socket, resolve);
  });
  try {
    const cases: Array<[string, string[], RegExp]> = [
      ["fingerprint --pub <FIFO>", ["fingerprint", "--pub", fifo], /cannot read public key file .* is not a regular file \(it is a FIFO\)/],
      ["fingerprint --pub <directory>", ["fingerprint", "--pub", keysDir], /cannot read public key file .* is not a regular file \(it is a directory\)/],
      ["fingerprint --pub <socket>", ["fingerprint", "--pub", socket], /cannot read public key file .* is not a regular file \(it is a socket\)/],
      ["verify --pub <FIFO>", ["verify", "--store", storePath, "--pub", fifo], /cannot read public key file .* is not a regular file \(it is a FIFO\)/],
      ["run, privateKeyPath a FIFO", ["run", "--config", fifoKey.config, "--once"], /private key path .* is not a regular file \(it is a FIFO\)/],
      ["run, privateKeyPath a socket", ["run", "--config", socketKey.config, "--once"], /private key path .* is not a regular file \(it is a socket\)/],
    ];
    for (const [label, args, why] of cases) {
      const r = cliNoHang(label, args);
      assert.equal(r.status, 1, `${label}: ${r.stdout}${r.stderr}`);
      assert.equal(r.stdout, "", `${label}: nothing on stdout`);
      assert.match(r.stderr, why, label);
    }
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  assert.equal(existsSync(fifoKey.store) || existsSync(socketKey.store), false, "run started nothing");
});

checkAsync("a FIFO as the store (verify --store, the config's storePath) or as --config is refused at once (exit 1), never waited on", () => {
  if (!existsSync(fifo) && !mkfifo(fifo)) return;
  const v = cliNoHang("verify --store <FIFO>", ["verify", "--store", fifo, "--pub", pubPath]);
  assert.equal(v.status, 1, v.stdout + v.stderr);
  assert.match(v.stdout, /^FAIL: .* does not verify: cannot read store .* is not a regular file \(it is a FIFO\)/);

  const fifoStore = layout("fifo-store");
  const config = JSON.parse(readFileSync(fifoStore.config, "utf8")) as Record<string, unknown>;
  writeFileSync(fifoStore.config, JSON.stringify({ ...config, storePath: fifo }));
  const r = cliNoHang("run, storePath a FIFO", ["run", "--config", fifoStore.config, "--once"]);
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stderr, /cannot read store .* is not a regular file \(it is a FIFO\)/);

  const c = cliNoHang("run --config <FIFO>", ["run", "--config", fifo, "--once"]);
  assert.equal(c.status, 1, c.stdout + c.stderr);
  assert.equal(c.stdout, "");
  assert.match(c.stderr, /cannot read config file .* is not a regular file \(it is a FIFO\)/);
});

// ── run ──────────────────────────────────────────────────────────────────────

void (async () => {
  try {
    for (const t of pending) {
      await t();
      // A signal that arrived during a synchronous test is handled here.
      await betweenTests();
    }
  } finally {
    cleanUp();
    clearTimeout(watchdog);
  }
  console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
})();
