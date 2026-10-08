// ──────────────────────────────────────────────────────────────────────────────
// Reference witness — a test run stopped by a signal leaves nothing behind.
//   npx ts-node packages/witness/src/harness-signal.test.ts
//
// A test process stopped by SIGINT, SIGTERM or SIGHUP must still kill the
// children it started and remove its temp dirs (test-support.ts). Checked on a
// fixture (harness-child.fixture.ts) for each signal, for a signal that arrives
// during a synchronous test, and on cli.test.ts itself while its `run` child is
// polling.
//
// Each process under test is started detached, in a process group of its own,
// and the signal is sent to that process alone, as `kill <pid>` or a CI runner
// that signals only the top process does. A signal to the whole group would
// stop the children by itself and hide a harness that does not.
//
// Never hangs: every wait has a deadline, every group started here is
// SIGKILLed in a finally block, and a watchdog ends the file.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { spawn } from "child_process";
import type { ChildProcess } from "child_process";
import { existsSync, readFileSync, readdirSync, rmSync } from "fs";
import { constants as osConstants } from "os";
import { dirname, join } from "path";

import { betweenTests, cleanUp, removeOnExit, tempDir, trackPid, untrackPid } from "./test-support";

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

/** The working directory of every process started here: never the repository. */
const CWD = tempDir("ilas-witness-signal-cwd-");
const FIXTURE = join(__dirname, "harness-child.fixture.ts");
const CLI_TEST = join(__dirname, "cli.test.ts");
const TS_NODE_REGISTER = require.resolve("ts-node/register");
const CHILD_ENV: NodeJS.ProcessEnv = {
  ...process.env,
  TS_NODE_TRANSPILE_ONLY: "true",
  TS_NODE_PROJECT: join(__dirname, "..", "tsconfig.json"),
};
const HAVE_PROC = existsSync("/proc/self/stat");

const watchdog = setTimeout(() => {
  console.error("  ✗ watchdog: the harness-signal test did not finish in 240 s");
  process.exit(1);
}, 240_000);
watchdog.unref();

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(what: string, predicate: () => boolean, timeoutMs: number, everyMs = 50): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error(`timed out after ${timeoutMs} ms waiting for ${what}`);
    await sleep(everyMs);
  }
}

/** True while `pid` runs: it exists and is not a zombie waiting to be reaped. */
function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
  if (!HAVE_PROC) return true;
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    return stat[stat.lastIndexOf(")") + 2] !== "Z";
  } catch {
    return false; // gone between the two looks
  }
}

interface Detached {
  readonly child: ChildProcess;
  readonly pid: number;
  lines(): string[];
  output(): string;
  exit(): { code: number | null; signal: NodeJS.Signals | null } | null;
}

/**
 * Run a ts-node script in a process group of its own. The group is SIGKILLed
 * when this file exits, unless stopGroup() did it first.
 */
function startDetached(script: string, args: string[]): Detached {
  const child = spawn(process.execPath, ["-r", TS_NODE_REGISTER, script, ...args], {
    cwd: CWD,
    env: CHILD_ENV,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const pid = child.pid;
  if (pid === undefined) throw new Error(`could not start ${script}`);
  trackPid(-pid);
  let out = "";
  let err = "";
  let exit: { code: number | null; signal: NodeJS.Signals | null } | null = null;
  child.on("error", (error) => {
    err += String(error);
  });
  child.on("exit", (code, signal) => {
    exit = { code, signal };
  });
  child.stdout!.setEncoding("utf8");
  child.stdout!.on("data", (chunk: string) => {
    out += chunk;
  });
  child.stderr!.setEncoding("utf8");
  child.stderr!.on("data", (chunk: string) => {
    err += chunk;
  });
  return {
    child,
    pid,
    lines: () => out.split("\n").filter((l) => l.length > 0),
    output: () => `stdout: ${out.slice(-2000)} | stderr: ${err.slice(-2000)}`,
    exit: () => exit,
  };
}

function stopGroup(d: Detached): void {
  try {
    process.kill(-d.pid, "SIGKILL");
  } catch {
    // the group is empty: nothing left in it
  }
  untrackPid(-d.pid);
}

/** After a run, wait up to 5 s for the processes to be gone and the dirs removed; say what is left. */
async function leftBehind(pids: Array<[string, number]>, dirs: string[]): Promise<string[]> {
  const left = (): string[] => [
    ...pids.filter(([, pid]) => alive(pid)).map(([what, pid]) => `${what} ${pid} is still running`),
    ...dirs.filter((dir) => existsSync(dir)).map((dir) => `${dir} is still there`),
  ];
  await waitFor("the children to be gone and the temp dirs removed", () => left().length === 0, 5_000).catch(
    () => undefined
  );
  return left();
}

function kill(pid: number): void {
  if (alive(pid)) process.kill(pid, "SIGKILL");
}

interface FixtureReport {
  child: number;
  stray: number;
  dir: string;
}

/** The fixture's first line; from then on its pids and dir are also cleaned up if this file exits. */
async function fixtureReport(f: Detached): Promise<FixtureReport> {
  await waitFor("the fixture's report", () => f.lines().length > 0 || f.exit() !== null, 60_000);
  assert.equal(f.exit(), null, `the fixture exited early: ${f.output()}`);
  const report = JSON.parse(f.lines()[0]) as FixtureReport;
  trackPid(report.stray);
  removeOnExit(report.dir);
  assert.ok(alive(report.child) && alive(report.stray) && existsSync(report.dir), "precondition: all there");
  return report;
}

function discard(report: FixtureReport | null): void {
  if (report === null) return;
  kill(report.child);
  kill(report.stray);
  untrackPid(report.stray);
  rmSync(report.dir, { recursive: true, force: true });
}

console.log("── a test process stopped by a signal kills its children and removes its temp dirs ──");

for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
  const code = 128 + osConstants.signals[signal];
  checkAsync(`${signal} to the test process alone: its child and its detached process are killed, its temp dir removed; it exits ${code}`, async () => {
    const f = startDetached(FIXTURE, []);
    let report: FixtureReport | null = null;
    try {
      report = await fixtureReport(f);
      process.kill(f.pid, signal);
      await waitFor("the fixture to exit", () => f.exit() !== null, 10_000);
      const left = await leftBehind(
        [
          ["its child", report.child],
          ["its detached process", report.stray],
        ],
        [report.dir]
      );
      assert.deepEqual(left, [], `after ${signal}: ${left.join("; ")}`);
      assert.deepEqual(f.exit(), { code, signal: null }, `the signal became an exit: ${f.output()}`);
    } finally {
      stopGroup(f);
      discard(report);
    }
  });
}

checkAsync("a signal that arrives during a synchronous test is handled before the next test starts, not lost", async () => {
  const f = startDetached(FIXTURE, ["busy"]);
  let report: FixtureReport | null = null;
  const steps = (): number => f.lines().filter((l) => l.startsWith("step ")).length;
  try {
    report = await fixtureReport(f);
    await waitFor("two tests", () => steps() >= 2 || f.exit() !== null, 30_000);
    const stepsAtSignal = steps();
    process.kill(f.pid, "SIGTERM");
    await waitFor("the fixture to exit", () => f.exit() !== null, 30_000);
    assert.equal(f.lines().includes("done"), false, "the signal was lost: the run went on to its end");
    // The test running when the signal came finishes; the next one does not
    // start. (One more line may have been on its way through the pipe.)
    assert.ok(steps() <= stepsAtSignal + 2, `${steps() - stepsAtSignal} more tests ran after the signal`);
    const left = await leftBehind([["its child", report.child]], [report.dir]);
    assert.deepEqual(left, [], left.join("; "));
    assert.deepEqual(f.exit(), { code: 128 + osConstants.signals.SIGTERM, signal: null }, f.output());
  } finally {
    stopGroup(f);
    discard(report);
  }
});

interface RunChild {
  readonly pid: number;
  /** cli.test.ts's temp dir. */
  readonly root: string;
  /** The store this witness creates when it has opened. */
  readonly store: string;
}

/** The long-running `run` child (no --once) of `ppid`, and the cli.test.ts temp dir its config is in. */
function runChildOf(ppid: number): RunChild | null {
  for (const name of readdirSync("/proc")) {
    if (!/^\d+$/.test(name)) continue;
    try {
      const stat = readFileSync(`/proc/${name}/stat`, "utf8");
      if (Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1]) !== ppid) continue;
      const argv = readFileSync(`/proc/${name}/cmdline`, "utf8").split("\0");
      const at = argv.indexOf("run");
      if (at < 0 || argv[at + 1] !== "--config" || argv.includes("--once")) continue;
      const config = argv[at + 2] ?? "";
      const root = /^(.*\/ilas-witness-cli-[^/]+)\//.exec(config);
      if (root !== null) {
        // Every config cli.test.ts writes keeps its store at store/witness-store.jsonl beside it.
        return { pid: Number(name), root: root[1], store: join(dirname(config), "store", "witness-store.jsonl") };
      }
    } catch {
      // that process ended while it was being read
    }
  }
  return null;
}

checkAsync("cli.test.ts, stopped by SIGTERM while its `run` child polls: the child is killed and its temp dir removed", async () => {
  if (!HAVE_PROC) {
    console.log("    (no /proc to find the run child; skipped)");
    return;
  }
  const t = startDetached(CLI_TEST, []);
  const found: { run: RunChild | null } = { run: null };
  try {
    await waitFor(
      "cli.test.ts to start a `run` child",
      () => (found.run = runChildOf(t.pid)) !== null || t.exit() !== null,
      150_000,
      200
    );
    const run = found.run;
    assert.ok(run !== null, `cli.test.ts ended before it started a run child: ${t.output()}`);
    trackPid(run.pid);
    removeOnExit(run.root);
    // Signal once the witness has opened and is polling, as a run stopped
    // midway finds it: it then writes nothing until a commit arrives, so
    // nothing but the harness would stop it.
    await waitFor("the witness to open its store", () => existsSync(run.store) || !alive(run.pid), 60_000);
    await sleep(200);
    process.kill(t.pid, "SIGTERM");
    await waitFor("cli.test.ts to exit", () => t.exit() !== null, 30_000);
    const left = await leftBehind([["its run child", run.pid]], [run.root]);
    assert.deepEqual(left, [], `after SIGTERM: ${left.join("; ")}`);
    assert.deepEqual(t.exit(), { code: 128 + osConstants.signals.SIGTERM, signal: null }, t.output());
  } finally {
    stopGroup(t);
    const run = found.run;
    if (run !== null) {
      kill(run.pid);
      untrackPid(run.pid);
      rmSync(run.root, { recursive: true, force: true });
    }
  }
});

// ── run ──────────────────────────────────────────────────────────────────────

void (async () => {
  try {
    for (const t of pending) {
      await t();
      await betweenTests();
    }
  } finally {
    cleanUp();
    clearTimeout(watchdog);
  }
  console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
})();
