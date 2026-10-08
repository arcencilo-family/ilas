// ──────────────────────────────────────────────────────────────────────────────
// ILAS — the durable L0 file: opened once, regular files only, every entry one
// whole line written in full and fsynced, a failed write taken back, a missing
// final newline repaired, a torn final line refused, and a file that changes
// under a running log noticed.
// House style: standalone ts-node script, custom check() harness.
//   npx ts-node src/l0/l0.file.test.ts
// Anything that could block (a FIFO at the log path) or needs a file-size limit
// runs in a child process (log-child.fixture.ts) with a timeout and SIGKILL.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { spawnSync } from "child_process";
import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { createServer } from "net";
import { tmpdir } from "os";
import { join, resolve } from "path";
import { LockedEvidenceLog, L0WriteError } from "./index";
import { ILASKillStack } from "../index";

// The fs module object itself, so a fault can be injected where L0 calls it.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const realFs = require("fs") as typeof import("fs");

let passed = 0;
let failed = 0;
const pending: Array<() => Promise<void>> = [];

function check(name: string, fn: () => void | Promise<void>): void {
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

function section(title: string): void {
  pending.push(async () => console.log(`── ${title} ──`));
}

const root = mkdtempSync(join(tmpdir(), "ilas-l0-file-"));
let counter = 0;
const freshPath = (): string => join(root, `log-${counter++}.jsonl`);
const REPO_ROOT = resolve(__dirname, "..", "..");
const FIXTURE = join(__dirname, "log-child.fixture.ts");
const asRoot = process.getuid?.() === 0;

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

/** A durable log (fsync off: these checks are about what lands, not when) with `n` entries. */
function seeded(n: number, p = freshPath()): { p: string; log: LockedEvidenceLog } {
  const log = new LockedEvidenceLog({ path: p, fsync: false });
  for (let i = 0; i < n; i++) void log.append(entry(i));
  return { p, log };
}

/** Run the fixture in a child; never longer than the timeout; parse its one JSON line. */
function child(args: string[], shellPrefix?: string): Record<string, any> {
  const node = [process.execPath, "-r", "ts-node/register", FIXTURE, ...args];
  const quoted = node.map((a) => `'${a.replace(/'/g, `'\\''`)}'`).join(" ");
  const run =
    shellPrefix === undefined
      ? spawnSync(node[0], node.slice(1), opts())
      : spawnSync("bash", ["-c", `${shellPrefix} && exec ${quoted}`], opts());
  assert.equal(run.signal, null, `the child was killed (${run.signal}): it blocked. stderr: ${run.stderr}`);
  assert.equal(run.status, 0, `the child failed: ${run.stderr}`);
  const line = run.stdout.trim().split("\n").pop() ?? "";
  const out = JSON.parse(line);
  assert.equal(out.setupFailed, undefined, String(out.setupFailed));
  return out;
}

function opts() {
  return {
    cwd: REPO_ROOT,
    env: { ...process.env, TS_NODE_TRANSPILE_ONLY: "true" },
    encoding: "utf8" as const,
    timeout: 30_000,
    killSignal: "SIGKILL" as const,
  };
}

/** Replace one fs function for the length of `fn`, then put the real one back. */
function withFs<K extends "writeSync" | "fsyncSync" | "ftruncateSync">(
  name: K,
  replacement: (typeof realFs)[K],
  fn: () => void
): void {
  const original = realFs[name];
  (realFs as unknown as Record<string, unknown>)[name] = replacement;
  try {
    fn();
  } finally {
    (realFs as unknown as Record<string, unknown>)[name] = original;
  }
}

/** A write that lands the first half of what it is given and then fails, as a full disk does. */
function halfThenFail(code: string): typeof realFs.writeSync {
  const real = realFs.writeSync;
  return ((fd: number, buffer: Buffer, offset: number, length: number) => {
    if (length > 1) real(fd, buffer, offset, Math.floor(length / 2));
    throw Object.assign(new Error(`${code}: injected short write`), { code });
  }) as unknown as typeof realFs.writeSync;
}

function failing(code: string): (...args: unknown[]) => never {
  return () => {
    throw Object.assign(new Error(`${code}: injected`), { code });
  };
}

/** The real fsync, except that its first call fails. */
function fsyncFailingOnce(code: string): typeof realFs.fsyncSync {
  const real = realFs.fsyncSync;
  let calls = 0;
  return ((fd: number) => {
    if (calls++ === 0) throw Object.assign(new Error(`${code}: injected`), { code });
    real(fd);
  }) as typeof realFs.fsyncSync;
}

function lines(p: string): string[] {
  return readFileSync(p, "utf8").split("\n").filter((l) => l.trim());
}

function hashes(log: LockedEvidenceLog): string[] {
  return log.getAll().map((e) => e.hash);
}

// ── 1 · opened once, regular files only ──────────────────────────────────────

section("1: the log path must hold a regular file; nothing at it can block the node");

check("1a: a FIFO at the log path ⇒ CANNOT_VERIFY at load with lastError, never a hang", () => {
  const p = freshPath();
  const mk = spawnSync("mkfifo", [p], { encoding: "utf8" });
  assert.equal(mk.status, 0, `mkfifo is needed for this test: ${mk.stderr ?? String(mk.error)}`);
  const out = child(["load", p]);
  assert.equal(out.info.loadState, "CANNOT_VERIFY");
  assert.equal(out.info.persisting, false);
  assert.equal(out.info.clean, false);
  assert.match(out.info.lastError, /not a regular file \(a FIFO\)/);
});

check("1b: the file replaced by a FIFO while the log runs ⇒ the next append throws L0WriteError, never a hang", () => {
  const p = freshPath();
  const out = child(["swap-fifo", p]);
  assert.equal(out.second.ok, false, "the append onto a FIFO was accepted");
  assert.equal(out.second.name, "L0WriteError");
  assert.equal(out.length, 1, "the refused entry was committed in memory");
  assert.equal(out.info.writeHealthy, false);
  assert.equal(out.info.persisting, false);
  assert.match(out.info.lastError, /no longer the file this log opened/);
});

check("1c: a symbolic link at the log path is not followed: CANNOT_VERIFY, and its target is never written", () => {
  const { p: target } = seeded(2);
  const before = readFileSync(target);
  const link = freshPath();
  symlinkSync(target, link);
  const log = new LockedEvidenceLog({ path: link, fsync: false });
  const d = log.getDurabilityInfo();
  assert.equal(d.loadState, "CANNOT_VERIFY", "a log was loaded through a symbolic link");
  assert.equal(d.persisting, false);
  assert.match(d.lastError ?? "", /symbolic link/);
  void log.append(entry(9)); // memory only
  assert.deepEqual(readFileSync(target), before, "the link's target was written");
});

check("1d: a directory at the log path ⇒ CANNOT_VERIFY with lastError; nothing is created in it", () => {
  const p = freshPath();
  mkdirSync(p);
  const log = new LockedEvidenceLog({ path: p, fsync: false });
  const d = log.getDurabilityInfo();
  assert.equal(d.loadState, "CANNOT_VERIFY");
  assert.equal(d.persisting, false);
  assert.ok(d.lastError, "no lastError");
  void log.append(entry(0));
  assert.equal(realFs.readdirSync(p).length, 0);
});

check("1e: a socket at the log path ⇒ CANNOT_VERIFY with lastError", async () => {
  const p = freshPath();
  const server = createServer();
  await new Promise<void>((ok, fail) => {
    server.once("error", fail);
    server.listen(p, () => ok());
  });
  try {
    const d = new LockedEvidenceLog({ path: p, fsync: false }).getDurabilityInfo();
    assert.equal(d.loadState, "CANNOT_VERIFY");
    assert.equal(d.persisting, false);
    assert.ok(d.lastError, "no lastError");
  } finally {
    await new Promise<void>((ok) => server.close(() => ok()));
  }
});

check("1f: a valid history this process may read but not write ⇒ LOADED_VERIFIED, every append refused, the file unchanged", () => {
  if (asRoot) return; // root writes a 0444 file; nothing to test
  const { p } = seeded(3);
  chmodSync(p, 0o444);
  try {
    const before = readFileSync(p);
    const log = new LockedEvidenceLog({ path: p, fsync: false });
    const d = log.getDurabilityInfo();
    assert.equal(d.loadState, "LOADED_VERIFIED", "a readable history was not loaded");
    assert.equal(log.length, 3);
    assert.equal(d.persisting, false);
    assert.equal(d.writeHealthy, false);
    assert.match(d.lastError ?? "", /not writable/);
    assert.throws(() => log.append(entry(3)), L0WriteError);
    assert.equal(log.length, 3, "memory ran ahead of disk");
    assert.deepEqual(readFileSync(p), before);
  } finally {
    chmodSync(p, 0o644);
  }
});

// ── 2 · a failed write is taken back ─────────────────────────────────────────

section("2: a write that fails part-way leaves no partial line");

check("2a: half a line written, then ENOSPC ⇒ L0WriteError, the file cut back; the next append and the reload are clean", () => {
  const { p, log } = seeded(2);
  const before = readFileSync(p);
  withFs("writeSync", halfThenFail("ENOSPC"), () => {
    assert.throws(() => log.append(entry(2)), L0WriteError);
  });
  assert.deepEqual(readFileSync(p), before, "the partial line stayed in the file");
  assert.equal(log.length, 2);
  const d = log.getDurabilityInfo();
  assert.equal(d.writeHealthy, false);
  assert.equal(d.persisting, true, "a write that was taken back stops nothing");
  assert.match(d.lastError ?? "", /cut back/);
  void log.append(entry(3));
  const reloaded = new LockedEvidenceLog({ path: p, fsync: false });
  assert.equal(reloaded.getLoadState(), "LOADED_VERIFIED", String(reloaded.getDurabilityInfo().lastError));
  assert.deepEqual(hashes(reloaded), hashes(log));
});

check("2b: the line written in full but fsync fails (EIO) ⇒ cut back; the entry is not committed", () => {
  const p = freshPath();
  const log = new LockedEvidenceLog({ path: p }); // fsync on
  void log.append(entry(0));
  const before = readFileSync(p);
  withFs("fsyncSync", fsyncFailingOnce("EIO"), () => {
    assert.throws(() => log.append(entry(1)), L0WriteError);
  });
  assert.deepEqual(readFileSync(p), before, "an entry whose fsync failed stayed in the file");
  assert.equal(log.length, 1);
  assert.equal(log.getDurabilityInfo().persisting, true);
  void log.append(entry(2));
  const reloaded = new LockedEvidenceLog({ path: p, fsync: false });
  assert.equal(reloaded.getLoadState(), "LOADED_VERIFIED");
  assert.deepEqual(hashes(reloaded), hashes(log));
});

check("2c: the cut-back fails too ⇒ this and every later append throws, nothing more is written; the reload names the torn line", () => {
  const { p, log } = seeded(2);
  withFs("ftruncateSync", failing("EIO") as typeof realFs.ftruncateSync, () => {
    withFs("writeSync", halfThenFail("ENOSPC"), () => {
      assert.throws(() => log.append(entry(2)), L0WriteError);
    });
  });
  const d = log.getDurabilityInfo();
  assert.equal(d.persisting, false);
  assert.equal(d.writeHealthy, false);
  assert.match(d.lastError ?? "", /torn line/);
  const torn = readFileSync(p);
  assert.throws(() => log.append(entry(3)), L0WriteError, "an append after a torn line was accepted");
  assert.equal(log.length, 2, "memory ran ahead of disk");
  assert.deepEqual(readFileSync(p), torn, "something was written after the torn line");
  const reloaded = new LockedEvidenceLog({ path: p, fsync: false });
  const r = reloaded.getDurabilityInfo();
  assert.equal(r.loadState, "CANNOT_VERIFY");
  assert.equal(r.brokenAt, 2);
  assert.match(r.lastError ?? "", /^torn final line at index 2/);
  assert.deepEqual(readFileSync(p), torn, "the load cut history off");
});

check("2d: a real short write (file-size limit, EFBIG) in a child ⇒ taken back; the refused entry never loads", () => {
  for (const past of [1, 40]) {
    const { p, log } = seeded(3);
    const seedBytes = statSync(p).size;
    // The big line's length without its padding, measured on an identical entry.
    const probe = JSON.stringify({
      sequenceNumber: 3,
      hash: "0".repeat(64),
      previousHash: "0".repeat(64),
      timestamp: 1_700_000_000_100,
      moduleId: "child",
      eventType: "unit",
      provenanceTag: "LaneA",
      parameters: { pad: "" },
      outcome: "ok",
    });
    const limit = 2048; // ulimit -f 2: 2 blocks of 1024 bytes
    const pad = limit - seedBytes - (Buffer.byteLength(probe) + 1) + past;
    assert.ok(pad > 0, "precondition: the seed leaves room");
    log.close(); // release the writer lock: the child is another process
    const out = child(["append-big", p, String(pad)], "ulimit -f 2");
    assert.equal(out.loadState, "LOADED_VERIFIED", "precondition: the child loaded the seed");
    assert.equal(out.big.ok, false, `${past} past the limit: the oversized append was accepted`);
    assert.equal(out.big.name, "L0WriteError");
    assert.equal(out.afterBig.length, 3);
    assert.equal(out.small.ok, true, `the next append failed: ${out.small.message}`);
    assert.equal(out.length, 4);
    const reloaded = new LockedEvidenceLog({ path: p, fsync: false });
    assert.equal(reloaded.getLoadState(), "LOADED_VERIFIED", `${past} past: ${reloaded.getDurabilityInfo().lastError}`);
    assert.equal(reloaded.length, 4, `${past} past: the refused entry loaded`);
    assert.deepEqual(hashes(reloaded), out.hashes);
    assert.equal(lines(p).length, 4);
  }
});

// ── 3 · the end of the file ──────────────────────────────────────────────────

section("3: a last line without its newline; a torn final line");

check("3a: a whole last line without its newline loads, and the next append does not join onto it", () => {
  const { p } = seeded(3);
  writeFileSync(p, readFileSync(p, "utf8").slice(0, -1));
  const b = new LockedEvidenceLog({ path: p, fsync: false });
  assert.equal(b.getLoadState(), "LOADED_VERIFIED");
  assert.equal(b.length, 3);
  void b.append(entry(3));
  assert.equal(b.getDurabilityInfo().writeHealthy, true);
  const c = new LockedEvidenceLog({ path: p, fsync: false });
  assert.equal(c.getLoadState(), "LOADED_VERIFIED", `reload: ${c.getDurabilityInfo().lastError}`);
  assert.equal(c.length, 4);
  assert.deepEqual(hashes(c), hashes(b));
  assert.ok(readFileSync(p, "utf8").endsWith("}\n"));
  assert.equal(lines(p).length, 4);
});

check("3b: a torn final line ⇒ CANNOT_VERIFY 'torn final line at index i'; nothing is cut off, now or after an append", () => {
  const { p } = seeded(3);
  const next = JSON.stringify({ ...entry(3), sequenceNumber: 3, hash: "a".repeat(64), previousHash: "b".repeat(64) });
  writeFileSync(p, readFileSync(p, "utf8") + next.slice(0, 40));
  const before = readFileSync(p);
  const b = new LockedEvidenceLog({ path: p, fsync: false });
  const d = b.getDurabilityInfo();
  assert.equal(d.loadState, "CANNOT_VERIFY");
  assert.equal(d.brokenAt, 3);
  assert.equal(d.persisting, false);
  assert.match(d.lastError ?? "", /^torn final line at index 3/);
  void b.append(entry(9)); // memory only, as on any CANNOT_VERIFY load
  assert.deepEqual(readFileSync(p), before);
});

check("3c: a broken line with whole lines after it is malformed JSON, not a torn final line", () => {
  const { p } = seeded(2);
  writeFileSync(p, readFileSync(p, "utf8") + '{"sequenceNumber":2,"ha\n' + lines(p)[0] + "\n");
  const d = new LockedEvidenceLog({ path: p, fsync: false }).getDurabilityInfo();
  assert.equal(d.loadState, "CANNOT_VERIFY");
  assert.equal(d.brokenAt, 2);
  assert.match(d.lastError ?? "", /^malformed JSON at line 2/);
});

// ── 4 · the file must still be the one this log opened ──────────────────────

section("4: a file removed, replaced or written by someone else stops the log");

check("4a: removed while running ⇒ the append throws L0WriteError and the file is not recreated", () => {
  const { p, log } = seeded(2);
  unlinkSync(p);
  assert.throws(() => log.append(entry(2)), L0WriteError);
  assert.equal(existsSync(p), false, "the removed log was recreated at seq 2");
  assert.throws(() => log.append(entry(3)), L0WriteError, "a later append was accepted");
  assert.equal(log.length, 2);
  const d = log.getDurabilityInfo();
  assert.equal(d.persisting, false);
  assert.equal(d.writeHealthy, false);
  assert.match(d.lastError ?? "", /removed/);
});

check("4b: replaced (another file renamed onto the path) ⇒ the append throws; the new file is not written", () => {
  const { p, log } = seeded(2);
  const other = freshPath();
  writeFileSync(other, "");
  renameSync(other, p);
  assert.throws(() => log.append(entry(2)), L0WriteError);
  assert.equal(readFileSync(p, "utf8"), "", "an entry was written into the replacement");
  assert.match(log.getDurabilityInfo().lastError ?? "", /no longer the file this log opened/);
});

check("4c: another writer appended to the file ⇒ the append throws, naming both sizes; nothing of ours is added", () => {
  const { p, log } = seeded(2);
  appendFileSync(p, lines(p)[1] + "\n");
  const before = readFileSync(p);
  assert.throws(() => log.append(entry(2)), L0WriteError);
  assert.deepEqual(readFileSync(p), before);
  assert.match(log.getDurabilityInfo().lastError ?? "", /bytes; this log left it at/);
});

// ── 5 · fsync ────────────────────────────────────────────────────────────────

section("5: every entry is fsynced before it counts, unless fsync: false is asked for");

function countFsyncs(fn: () => void): number {
  let n = 0;
  const real = realFs.fsyncSync;
  withFs("fsyncSync", ((fd: number) => {
    n++;
    real(fd);
  }) as typeof realFs.fsyncSync, fn);
  return n;
}

check("5a: default ⇒ at least one fsync per append; fsync: false ⇒ none", () => {
  const synced = new LockedEvidenceLog({ path: freshPath() });
  assert.ok(countFsyncs(() => { for (let i = 0; i < 3; i++) void synced.append(entry(i)); }) >= 3, "an append committed without a sync");
  const unsynced = new LockedEvidenceLog({ path: freshPath(), fsync: false });
  assert.equal(countFsyncs(() => { for (let i = 0; i < 3; i++) void unsynced.append(entry(i)); }), 0);
  assert.equal(unsynced.length, 3);
});

check("5b: ILASKillStack passes fsync through to L0", () => {
  assert.ok(countFsyncs(() => new ILASKillStack({ logPath: freshPath() })) >= 10, "the ten bootstrap entries were not synced");
  assert.equal(countFsyncs(() => new ILASKillStack({ logPath: freshPath(), fsync: false })), 0);
});

// ── 6 · a relative path ──────────────────────────────────────────────────────

section("6: a relative log path is anchored when the log is built");

check("6a: process.chdir() after construction ⇒ appends still land in the file it opened; close() removes its lock; the next start is no takeover", () => {
  const a = freshPath();
  const b = freshPath();
  mkdirSync(a);
  mkdirSync(b);
  const cwd = process.cwd();
  try {
    process.chdir(a);
    const log = new LockedEvidenceLog({ path: "l0.jsonl", fsync: false });
    void log.append(entry(0));
    process.chdir(b);
    let err: unknown = null;
    try {
      void log.append(entry(1));
    } catch (e) {
      err = e;
    }
    assert.equal(err, null, `the append after chdir was refused: ${String(err)}`);
    const d = log.getDurabilityInfo();
    assert.equal(d.writeHealthy, true, String(d.lastError));
    assert.equal(d.persisting, true);
    assert.equal(d.path, "l0.jsonl", "the path is reported as it was given");
    log.close();
    assert.equal(existsSync(join(a, "l0.jsonl.lock")), false, "close() left the lock behind");
    assert.deepEqual(realFs.readdirSync(b), [], "something was created in the new working directory");
  } finally {
    process.chdir(cwd);
  }
  assert.equal(lines(join(a, "l0.jsonl")).length, 2);
  const next = new LockedEvidenceLog({ path: join(a, "l0.jsonl"), fsync: false });
  assert.equal(next.getLoadState(), "LOADED_VERIFIED");
  assert.equal(next.getDurabilityInfo().lockTakenOver, false, "a clean close() read as a crash");
  next.close();
});

check("6b: a relative path while the working directory is gone ⇒ CANNOT_VERIFY with lastError, never a throw", () => {
  if (process.platform === "win32") return; // the working directory cannot be removed there
  const gone = freshPath();
  mkdirSync(gone);
  const cwd = process.cwd();
  let d: ReturnType<LockedEvidenceLog["getDurabilityInfo"]> | null = null;
  let thrown: unknown = null;
  try {
    process.chdir(gone);
    rmSync(gone, { recursive: true });
    try {
      const log = new LockedEvidenceLog({ path: "l0.jsonl", fsync: false });
      d = log.getDurabilityInfo();
      log.close();
    } catch (err) {
      thrown = err;
    }
  } finally {
    process.chdir(cwd);
  }
  assert.equal(thrown, null, `the constructor threw: ${String(thrown)}`);
  assert.ok(d !== null);
  assert.equal(d.loadState, "CANNOT_VERIFY");
  assert.equal(d.persisting, false);
  assert.match(d.lastError ?? "", /working directory/);
  assert.equal(existsSync(gone), false, "the removed directory was created again");
});

// ── run ──────────────────────────────────────────────────────────────────────

void (async () => {
  try {
    for (const step of pending) await step();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
  console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
})();
