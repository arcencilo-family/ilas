// ──────────────────────────────────────────────────────────────────────────────
// ILAS — one writer per L0 file: the writer lock "<path>.lock".
// House style: standalone ts-node script, custom check() harness.
//   npx ts-node src/l0/l0.lock.test.ts
//
// Another live process holding the lock is a deployment error: construction
// throws L0WriteError naming its pid; so is another thread of this process (a
// worker thread). A stale lock (its process gone, or this pid with another
// process start) is taken over and reported. The lock appears whole or not at
// all, so a start killed while taking it leaves nothing that blocks the next.
// Within one thread the newest log on a path owns it; older ones refuse every
// append. close() and process exit release the lock. Every child process and
// worker thread this script starts is killed or ends before it finishes.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { spawn, spawnSync } from "child_process";
import type { ChildProcessWithoutNullStreams } from "child_process";
import { generateKeyPairSync, randomBytes } from "crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join, resolve } from "path";
import { Worker } from "worker_threads";
import { LockedEvidenceLog, L0WriteError } from "./index";
import type { ClerkSubmitClient } from "./index";
import { ILASKillStack } from "../index";

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

const root = mkdtempSync(join(tmpdir(), "ilas-l0-lock-"));
let counter = 0;
const freshPath = (): string => join(root, `log-${counter++}.jsonl`);
const REPO_ROOT = resolve(__dirname, "..", "..");
const FIXTURE = join(__dirname, "log-child.fixture.ts");
const asRoot = process.getuid?.() === 0;
const children = new Set<ChildProcessWithoutNullStreams>();

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

function seeded(n: number, p = freshPath()): { p: string; log: LockedEvidenceLog } {
  const log = new LockedEvidenceLog({ path: p, fsync: false });
  for (let i = 0; i < n; i++) void log.append(entry(i));
  return { p, log };
}

function lockOf(p: string): { pid: number; instance: string; processStart: string; started: unknown } {
  return JSON.parse(readFileSync(`${p}.lock`, "utf8"));
}

/** A child process that holds the log at `p` until its stdin closes. */
async function holder(p: string): Promise<{ child: ChildProcessWithoutNullStreams; pid: number }> {
  const child = spawn(process.execPath, ["-r", "ts-node/register", FIXTURE, "hold", p], {
    cwd: REPO_ROOT,
    env: { ...process.env, TS_NODE_TRANSPILE_ONLY: "true" },
  });
  children.add(child);
  child.on("exit", () => children.delete(child));
  let out = "";
  let err = "";
  child.stderr.on("data", (d) => (err += String(d)));
  const pid = await new Promise<number>((ok, fail) => {
    const timer = setTimeout(() => fail(new Error(`the holder did not start: ${err}`)), 30_000);
    child.stdout.on("data", (d) => {
      out += String(d);
      if (out.includes("\n")) {
        clearTimeout(timer);
        ok(JSON.parse(out.split("\n")[0]).pid);
      }
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      fail(new Error(`the holder exited (${code}) before holding: ${err}`));
    });
  });
  return { child, pid };
}

function exited(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((ok) => child.once("exit", () => ok()));
}

/** A pid that belonged to a process that has ended. */
function deadPid(): number {
  const run = spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"], {
    encoding: "utf8",
    timeout: 30_000,
    killSignal: "SIGKILL",
  });
  return Number(run.stdout);
}

/** A lock file written by hand; without `processStart`, in the form written before it was recorded. */
function writeLock(p: string, pid: number, instance = randomBytes(16).toString("hex"), processStart?: string): void {
  const lock = processStart === undefined ? { pid, instance } : { pid, instance, processStart };
  writeFileSync(`${p}.lock`, JSON.stringify({ ...lock, started: new Date().toISOString() }) + "\n");
}

/** This process's start as L0 records it in a lock: read from a lock L0 wrote. */
function ownProcessStart(): string {
  const { p, log } = seeded(0);
  const start = lockOf(p).processStart;
  log.close();
  return start;
}

/** A process start that is not this process's (an earlier process that had this pid). */
function otherProcessStart(): string {
  const m = /^(proc|uptime):(\d+)$/.exec(ownProcessStart());
  assert.ok(m !== null, "precondition: L0 records a processStart");
  const n = Number(m[2]);
  return `${m[1]}:${n > 1000 ? n - 1000 : n + 1000}`;
}

/** Staged lock files (".ilas-lock-<instance>") left in `dir`. */
function stagedFiles(dir: string): string[] {
  return readdirSync(dir).filter((name) => name.startsWith(".ilas-lock-"));
}

function thrown(fn: () => unknown): unknown {
  try {
    fn();
  } catch (err) {
    return err;
  }
  return null;
}

// ── 1 · another process ──────────────────────────────────────────────────────

section("1: another live process on the same log fails at startup");

check("1a: a second process opening a held log ⇒ the constructor throws L0WriteError naming the holder's pid", async () => {
  const { p, log } = seeded(2);
  log.close();
  const { child, pid } = await holder(p);
  try {
    const before = readFileSync(p);
    const err = thrown(() => new LockedEvidenceLog({ path: p, fsync: false }));
    assert.ok(err instanceof L0WriteError, `got ${String(err)}`);
    assert.match((err as Error).message, new RegExp(`process ${pid}\\b`));
    const stackErr = thrown(() => new ILASKillStack({ logPath: p, fsync: false }));
    assert.ok(stackErr instanceof L0WriteError, `the assembly started on a held log: ${String(stackErr)}`);
    assert.deepEqual(readFileSync(p), before, "the file was written by a second writer");
    assert.equal(lockOf(p).pid, pid, "the holder's lock was replaced");
  } finally {
    child.kill("SIGKILL");
    await exited(child);
  }
});

check("1b: the holder exits normally ⇒ its lock is removed; the next log takes the path without a takeover", async () => {
  const { p, log } = seeded(1);
  log.close();
  const { child } = await holder(p);
  child.stdin.end();
  await exited(child);
  assert.equal(existsSync(`${p}.lock`), false, "process exit left the lock behind");
  const next = new LockedEvidenceLog({ path: p, fsync: false });
  assert.equal(next.getLoadState(), "LOADED_VERIFIED");
  assert.equal(next.getDurabilityInfo().lockTakenOver, false);
});

check("1c: the holder killed (SIGKILL) ⇒ its stale lock is taken over and reported", async () => {
  const { p, log } = seeded(2);
  log.close();
  const { child, pid } = await holder(p);
  child.kill("SIGKILL");
  await exited(child);
  assert.equal(lockOf(p).pid, pid, "precondition: the killed holder's lock is still there");
  const next = new LockedEvidenceLog({ path: p, fsync: false });
  const d = next.getDurabilityInfo();
  assert.equal(d.lockTakenOver, true);
  assert.equal(d.loadState, "LOADED_VERIFIED");
  assert.equal(d.persisting, true);
  assert.equal(lockOf(p).pid, process.pid);
  void next.append(entry(2));
  assert.equal(new LockedEvidenceLog({ path: p, fsync: false }).length, 3);
});

// ── 2 · stale and unreadable locks ───────────────────────────────────────────

section("2: stale locks are taken over; a lock that names no process is refused");

check("2a: a lock naming a dead pid ⇒ taken over (lockTakenOver: true)", () => {
  const { p, log } = seeded(1);
  log.close();
  writeLock(p, deadPid());
  const next = new LockedEvidenceLog({ path: p, fsync: false });
  assert.equal(next.getDurabilityInfo().lockTakenOver, true);
  assert.equal(next.getDurabilityInfo().persisting, true);
});

check("2b: a lock naming THIS pid with ANOTHER process start, or none, ⇒ an earlier process: stale, taken over", () => {
  for (const start of [otherProcessStart(), undefined]) {
    const label = start === undefined ? "no processStart" : start;
    const { p, log } = seeded(1);
    log.close();
    const foreign = randomBytes(16).toString("hex");
    writeLock(p, process.pid, foreign, start); // an earlier process that had this pid
    const next = new LockedEvidenceLog({ path: p, fsync: false });
    assert.equal(next.getDurabilityInfo().lockTakenOver, true, label);
    assert.equal(next.getDurabilityInfo().persisting, true, label);
    assert.equal(lockOf(p).pid, process.pid);
    assert.notEqual(lockOf(p).instance, foreign, `${label}: the stale lock was kept as if it were this process's`);
    next.close();
  }
});

check("2c: a lock file that cannot be parsed (text, empty, a bad processStart) ⇒ L0WriteError saying how to check and remove it; the lock is left for a human", () => {
  const bad = [
    "not a lock\n",
    "",
    JSON.stringify({ pid: process.pid, instance: randomBytes(16).toString("hex"), processStart: 42 }) + "\n",
  ];
  for (const text of bad) {
    const { p, log } = seeded(1);
    log.close();
    writeFileSync(`${p}.lock`, text);
    const err = thrown(() => new LockedEvidenceLog({ path: p, fsync: false }));
    assert.ok(err instanceof L0WriteError, `${JSON.stringify(text)}: got ${String(err)}`);
    assert.match((err as Error).message, /names no process/);
    assert.match((err as Error).message, /lsof .*then remove .* by hand/);
    assert.equal(readFileSync(`${p}.lock`, "utf8"), text);
  }
});

check("2d: a lock naming THIS pid and THIS process start with an instance this thread never created ⇒ another thread holds it: refused", () => {
  const { p, log } = seeded(1);
  log.close();
  writeLock(p, process.pid, randomBytes(16).toString("hex"), ownProcessStart());
  const before = readFileSync(`${p}.lock`);
  const err = thrown(() => new LockedEvidenceLog({ path: p, fsync: false }));
  assert.ok(err instanceof L0WriteError, `a live thread's lock was taken over: ${String(err)}`);
  assert.match((err as Error).message, /another thread of this process/);
  assert.match((err as Error).message, /remove the lock file by hand/);
  assert.deepEqual(readFileSync(`${p}.lock`), before, "the lock was changed");
  const stackErr = thrown(() => new ILASKillStack({ logPath: p, fsync: false }));
  assert.ok(stackErr instanceof L0WriteError, `the assembly started: ${String(stackErr)}`);
});

check("2d2: THIS pid with a process start of the OTHER kind ⇒ not proof of another process: refused, never taken over", () => {
  const own = ownProcessStart();
  const other = own.startsWith("proc:") ? "uptime:123" : "proc:123";
  const { p, log } = seeded(1);
  log.close();
  writeLock(p, process.pid, randomBytes(16).toString("hex"), other);
  const before = readFileSync(`${p}.lock`);
  const err = thrown(() => new LockedEvidenceLog({ path: p, fsync: false }));
  assert.ok(err instanceof L0WriteError, `a lock with a mixed-kind start was taken over: ${String(err)}`);
  assert.deepEqual(readFileSync(`${p}.lock`), before, "the lock was changed");
});

check("2d3: THIS pid with a clearly different process start of the SAME kind ⇒ an earlier process: taken over", () => {
  const own = ownProcessStart();
  const m = /^(proc|uptime):(\d+)$/.exec(own)!;
  const earlier = `${m[1]}:${Math.max(0, Number(m[2]) - 1000)}`;
  const { p, log } = seeded(1);
  log.close();
  writeLock(p, process.pid, randomBytes(16).toString("hex"), earlier);
  const again = new LockedEvidenceLog({ path: p, fsync: false });
  try {
    assert.equal(again.getDurabilityInfo().lockTakenOver, true);
  } finally {
    again.close();
  }
});

check("2e: the lock records pid, instance, processStart (on Linux: proc:<field 22 of /proc/self/stat>) and started", () => {
  const { p, log } = seeded(0);
  const lock = lockOf(p);
  log.close();
  assert.equal(lock.pid, process.pid);
  assert.match(lock.instance, /^[0-9a-f]{32}$/);
  assert.equal(typeof lock.started, "string");
  if (process.platform === "linux") {
    const stat = readFileSync("/proc/self/stat", "utf8");
    const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
    assert.equal(lock.processStart, `proc:${fields[22 - 3]}`);
  } else {
    assert.match(lock.processStart, /^uptime:\d+$/);
    const estimate = Math.round(Number(process.hrtime.bigint() / 1_000_000n) / 1000 - process.uptime());
    assert.ok(Math.abs(Number(lock.processStart.slice(7)) - estimate) <= 2, lock.processStart);
  }
});

// ── 3 · one process, several logs on one path ────────────────────────────────

section("3: within one process the newest log on a path owns it");

check("3a: reopening a path supersedes the older log: it refuses every append; the file holds only the owner's", () => {
  const { p, log: a } = seeded(2);
  const b = new LockedEvidenceLog({ path: p, fsync: false });
  assert.equal(b.getDurabilityInfo().lockTakenOver, false, "a reopen in the same process is not a takeover");
  assert.equal(a.getDurabilityInfo().persisting, false);
  const err = thrown(() => a.append(entry(9)));
  assert.ok(err instanceof L0WriteError, `the superseded log appended: ${String(err)}`);
  assert.match((err as Error).message, /superseded/);
  assert.equal(a.length, 2);
  void b.append(entry(2));
  const c = new LockedEvidenceLog({ path: p, fsync: false });
  assert.equal(c.getLoadState(), "LOADED_VERIFIED");
  assert.deepEqual(c.getAll().map((e) => e.parameters.n), [0, 1, 2]);
});

check("3b: a superseded log with a clerk route refuses BEFORE submitting", async () => {
  const { publicKey } = generateKeyPairSync("ed25519");
  let submitted = 0;
  const client: ClerkSubmitClient = {
    submit: async () => {
      submitted++;
      throw new Error("never reached");
    },
  };
  const route = {
    client,
    submitterId: "node-a",
    channel: "l0",
    clerkPublicKeyPem: publicKey.export({ type: "spki", format: "pem" }) as string,
  };
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p, clerk: route, fsync: false });
  new LockedEvidenceLog({ path: p, clerk: route, fsync: false });
  let err: unknown = null;
  try {
    await a.append(entry(0));
  } catch (e) {
    err = e;
  }
  assert.ok(err instanceof L0WriteError, `got ${String(err)}`);
  assert.match((err as Error).message, /superseded/);
  assert.equal(submitted, 0, "a frame was submitted for a log that can never commit it");
});

// ── 4 · close() ──────────────────────────────────────────────────────────────

section("4: close() releases the lock; a closed log refuses appends");

check("4a: close() removes the lock file; later appends throw; the next log takes the path cleanly", () => {
  const { p, log } = seeded(2);
  assert.equal(lockOf(p).pid, process.pid);
  log.close();
  assert.equal(existsSync(`${p}.lock`), false, "close() left the lock");
  const err = thrown(() => log.append(entry(2)));
  assert.ok(err instanceof L0WriteError, `a closed log appended: ${String(err)}`);
  assert.match((err as Error).message, /closed/);
  log.close(); // twice is harmless
  const next = new LockedEvidenceLog({ path: p, fsync: false });
  assert.equal(next.getDurabilityInfo().lockTakenOver, false);
  assert.equal(next.length, 2);
});

check("4b: closing a superseded log does not release the owner's lock", () => {
  const { p, log: a } = seeded(1);
  const b = new LockedEvidenceLog({ path: p, fsync: false });
  a.close();
  assert.ok(existsSync(`${p}.lock`), "the owner's lock was removed by an older log");
  void b.append(entry(1));
  b.close();
  assert.equal(existsSync(`${p}.lock`), false);
});

check("4c: ILASKillStack.close() releases the lock", () => {
  const p = freshPath();
  const s = new ILASKillStack({ logPath: p, fsync: false });
  assert.ok(existsSync(`${p}.lock`));
  s.close();
  assert.equal(existsSync(`${p}.lock`), false);
});

check("4d: a log without a path takes no lock, and close() leaves it working", () => {
  const log = new LockedEvidenceLog();
  assert.equal(log.getDurabilityInfo().lockTakenOver, false);
  log.close();
  void log.append(entry(0));
  assert.equal(log.length, 1);
});

// ── 5 · a lock that cannot be taken ──────────────────────────────────────────

section("5: without the lock, nothing is written");

check("5a: a directory where the lock cannot be created ⇒ the history loads, every append is refused, the file unchanged", () => {
  if (asRoot) return; // root creates files in a 0555 directory; nothing to test
  const dir = freshPath();
  mkdirSync(dir);
  const p = join(dir, "l0.jsonl");
  const { log: seed } = seeded(2, p);
  seed.close();
  const before = readFileSync(p);
  chmodSync(dir, 0o555);
  try {
    const log = new LockedEvidenceLog({ path: p, fsync: false });
    const d = log.getDurabilityInfo();
    assert.equal(d.loadState, "LOADED_VERIFIED");
    assert.equal(d.persisting, false);
    assert.equal(d.writeHealthy, false);
    assert.match(d.lastError ?? "", /writer lock/);
    assert.throws(() => log.append(entry(2)), L0WriteError);
    assert.equal(log.length, 2, "memory ran ahead of disk");
  } finally {
    chmodSync(dir, 0o755);
  }
  assert.deepEqual(readFileSync(p), before);
});

// ── 6 · worker threads ───────────────────────────────────────────────────────

section("6: another thread of this process on the same log fails at startup");

const workers = new Set<Worker>();

/**
 * A worker thread of THIS process (same pid, its own module registry) that
 * opens a durable log at `path`, appends one entry, reports, and closes the
 * log and ends when told "close".
 */
function logWorker(path: string): Worker {
  const source = `
    const { parentPort, workerData } = require("worker_threads");
    require(workerData.register);
    const { LockedEvidenceLog } = require(workerData.l0);
    let log = null;
    try {
      log = new LockedEvidenceLog({ path: workerData.path, fsync: false });
      log.append({ timestamp: 1, moduleId: "worker", eventType: "unit", provenanceTag: "LaneA", parameters: { n: 0 }, outcome: "ok" });
      parentPort.postMessage({ ok: true, info: log.getDurabilityInfo() });
    } catch (err) {
      parentPort.postMessage({ ok: false, name: err && err.name, message: err && err.message });
    }
    parentPort.on("message", (m) => {
      if (m === "close") {
        if (log !== null) log.close();
        parentPort.close();
      }
    });
  `;
  const w = new Worker(source, {
    eval: true,
    workerData: { register: require.resolve("ts-node/register"), l0: join(__dirname, "index.ts"), path },
    env: { ...process.env, TS_NODE_TRANSPILE_ONLY: "true" },
  });
  workers.add(w);
  w.on("exit", () => workers.delete(w));
  w.on("error", () => undefined); // reported through nextMessage / workerExited
  return w;
}

function nextMessage(w: Worker): Promise<Record<string, any>> {
  return new Promise((ok, fail) => {
    const done = (): void => {
      clearTimeout(timer);
      w.off("message", onMessage);
      w.off("error", onError);
      w.off("exit", onExit);
    };
    const onMessage = (m: Record<string, any>): void => (done(), ok(m));
    const onError = (e: Error): void => (done(), fail(e));
    const onExit = (code: number): void => (done(), fail(new Error(`the worker exited (${code}) without answering`)));
    const timer = setTimeout(() => (done(), fail(new Error("the worker did not answer in 60 s"))), 60_000);
    w.on("message", onMessage);
    w.on("error", onError);
    w.on("exit", onExit);
  });
}

function workerExited(w: Worker): Promise<void> {
  if (!workers.has(w)) return Promise.resolve();
  return new Promise((ok) => w.once("exit", () => ok()));
}

check("6a: a worker thread opening a log the main thread holds ⇒ L0WriteError in the worker; the holder keeps its lock and keeps writing", async () => {
  const { p, log } = seeded(2);
  const lockBefore = readFileSync(`${p}.lock`);
  const w = logWorker(p);
  try {
    const out = await nextMessage(w);
    assert.equal(out.ok, false, `the worker took the live lock over (lockTakenOver: ${out.info?.lockTakenOver})`);
    assert.equal(out.name, "L0WriteError");
    assert.match(out.message, /another thread of this process/);
    assert.deepEqual(readFileSync(`${p}.lock`), lockBefore, "the holder's lock was replaced");
    void log.append(entry(2));
    assert.equal(log.getDurabilityInfo().writeHealthy, true, String(log.getDurabilityInfo().lastError));
  } finally {
    w.postMessage("close");
    await workerExited(w);
    log.close();
  }
  assert.deepEqual(new LockedEvidenceLog({ path: p, fsync: false }).getAll().map((e) => e.parameters.n), [0, 1, 2]);
});

check("6b: the main thread opening a log a live worker thread holds ⇒ L0WriteError; the worker's lock stays; once it closes, the path is free", async () => {
  const p = freshPath();
  const w = logWorker(p);
  try {
    const out = await nextMessage(w);
    assert.equal(out.ok, true, `the worker could not open the log: ${out.message}`);
    const lockBefore = readFileSync(`${p}.lock`);
    const err = thrown(() => new LockedEvidenceLog({ path: p, fsync: false }));
    assert.ok(err instanceof L0WriteError, `the main thread took the worker's live lock over: ${String(err)}`);
    assert.match((err as Error).message, /another thread of this process/);
    assert.deepEqual(readFileSync(`${p}.lock`), lockBefore, "the worker's lock was replaced");
  } finally {
    w.postMessage("close");
    await workerExited(w);
  }
  assert.equal(existsSync(`${p}.lock`), false, "the worker's close() left its lock");
  const next = new LockedEvidenceLog({ path: p, fsync: false });
  assert.equal(next.getLoadState(), "LOADED_VERIFIED");
  assert.equal(next.length, 1);
  assert.equal(next.getDurabilityInfo().lockTakenOver, false);
  next.close();
});

// ── 7 · the lock appears whole or not at all ────────────────────────────────

section("7: a start killed while taking the lock leaves nothing that blocks the next start");

/** A preload that SIGKILLs the process the moment it writes a writer lock's text. */
function killOnLockWrite(): string {
  const preload = join(root, "kill-on-lock-write.js");
  if (!existsSync(preload)) {
    writeFileSync(
      preload,
      [
        'const fs = require("fs");',
        "const real = fs.writeSync;",
        "fs.writeSync = function (fd, buffer, ...rest) {",
        "  if (Buffer.isBuffer(buffer) && buffer.includes('\"instance\":\"')) process.kill(process.pid, \"SIGKILL\");",
        "  return real.call(this, fd, buffer, ...rest);",
        "};",
        "",
      ].join("\n")
    );
  }
  return preload;
}

check("7a: killed while writing the lock ⇒ no lock is left; the next LockedEvidenceLog and ILASKillStack start, without a takeover", () => {
  for (const assembly of [false, true]) {
    const dir = freshPath();
    mkdirSync(dir);
    const p = join(dir, "l0.jsonl");
    const { log } = seeded(2, p);
    log.close();
    const run = spawnSync(process.execPath, ["-r", killOnLockWrite(), "-r", "ts-node/register", FIXTURE, "load", p], {
      cwd: REPO_ROOT,
      env: { ...process.env, TS_NODE_TRANSPILE_ONLY: "true" },
      encoding: "utf8",
      timeout: 60_000,
      killSignal: "SIGTERM",
    });
    assert.equal(run.signal, "SIGKILL", `precondition: the child was killed while writing its lock (status ${run.status}, signal ${run.signal}): ${run.stderr}`);
    if (existsSync(`${p}.lock`)) {
      assert.fail(`a lock without its text was left: ${JSON.stringify(readFileSync(`${p}.lock`, "utf8"))}`);
    }
    for (const name of stagedFiles(dir)) assert.match(name, /^\.ilas-lock-[0-9a-f]{32}$/);
    const err = thrown(() => {
      if (assembly) {
        const s = new ILASKillStack({ logPath: p, fsync: false });
        assert.equal(s.status().logDurability.persisting, true);
        assert.equal(s.status().logDurability.lockTakenOver, false);
        s.close();
      } else {
        const next = new LockedEvidenceLog({ path: p, fsync: false });
        assert.equal(next.getLoadState(), "LOADED_VERIFIED");
        assert.equal(next.getDurabilityInfo().persisting, true);
        assert.equal(next.getDurabilityInfo().lockTakenOver, false);
        next.close();
      }
    });
    assert.equal(err, null, `${assembly ? "ILASKillStack" : "LockedEvidenceLog"}: the next start was refused: ${String(err)}`);
  }
});

check("7b: a lock taken normally leaves no staged file; the lock holds its whole text", () => {
  const dir = freshPath();
  mkdirSync(dir);
  const p = join(dir, "l0.jsonl");
  const { log } = seeded(1, p);
  assert.deepEqual(stagedFiles(dir), []);
  assert.equal(lockOf(p).pid, process.pid);
  log.close();
  assert.deepEqual(readdirSync(dir), ["l0.jsonl"]);
});

check("7c: a file system without hard links (link fails EPERM) ⇒ the lock is created in place, whole; any other link failure ⇒ no lock, nothing written, no staged file", () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const fs = require("fs") as typeof import("fs");
  const realLink = fs.linkSync;
  const withLink = (code: string, fn: () => void): void => {
    (fs as { linkSync: unknown }).linkSync = () => {
      throw Object.assign(new Error(`${code}: injected`), { code });
    };
    try {
      fn();
    } finally {
      (fs as { linkSync: unknown }).linkSync = realLink;
    }
  };
  const dir = freshPath();
  mkdirSync(dir);
  const p = join(dir, "l0.jsonl");
  withLink("EPERM", () => {
    const log = new LockedEvidenceLog({ path: p, fsync: false });
    assert.equal(log.getDurabilityInfo().persisting, true, String(log.getDurabilityInfo().lastError));
    void log.append(entry(0));
    assert.equal(lockOf(p).pid, process.pid);
    assert.match(lockOf(p).processStart, /^(proc|uptime):\d+$/);
    assert.deepEqual(stagedFiles(dir), []);
    log.close();
  });
  withLink("EIO", () => {
    const log = new LockedEvidenceLog({ path: p, fsync: false });
    const d = log.getDurabilityInfo();
    assert.equal(d.persisting, false);
    assert.match(d.lastError ?? "", /writer lock/);
    assert.throws(() => log.append(entry(1)), L0WriteError);
    assert.equal(existsSync(`${p}.lock`), false);
    assert.deepEqual(stagedFiles(dir), []);
  });
  assert.equal(new LockedEvidenceLog({ path: p, fsync: false }).length, 1);
});

// ── run ──────────────────────────────────────────────────────────────────────

void (async () => {
  try {
    for (const step of pending) await step();
  } finally {
    for (const c of children) {
      c.kill("SIGKILL");
      await exited(c);
    }
    for (const w of workers) await w.terminate();
    rmSync(root, { recursive: true, force: true });
  }
  console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
})();
