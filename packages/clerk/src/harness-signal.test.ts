// ──────────────────────────────────────────────────────────────────────────────
// Reference clerk — the test harness cleans up after a run that is stopped by
// a signal.
//   npx ts-node packages/clerk/src/harness-signal.test.ts
//
// A test file that has clerkd children and temp directories is stopped with
// SIGTERM, SIGHUP or SIGINT (kill <pid>, a CI cancel, Ctrl-C). Its clerkd
// children must not outlive it, holding their sockets and book locks, and its
// temp directories (with test keys) must not stay behind.
//
// The stand-in test file is harness-child.fixture.ts. It is started in its own
// process group, so the signal reaches it alone and not clerkd as well: the
// fixture has to do the cleaning up itself.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { spawn } from "child_process";
import type { ChildProcess } from "child_process";
import { existsSync, readFileSync, rmSync } from "fs";
import { constants as osConstants } from "os";
import { resolve } from "path";
import { checkAsync, childCwd, runAll, section } from "./test-support";

const FIXTURE = resolve(__dirname, "harness-child.fixture.ts");

/** Is `pid` a running process? A zombie (exited, not yet reaped) is not. */
function running(pid: number): boolean {
  try {
    process.kill(pid, 0);
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
  try {
    // Linux: the state is the field after the parenthesised command name.
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    return stat.slice(stat.lastIndexOf(")") + 2, stat.lastIndexOf(")") + 3) !== "Z";
  } catch {
    return true; // no /proc here: kill(pid, 0) said it exists
  }
}

async function until(cond: () => boolean, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) return false;
    await new Promise((res) => setTimeout(res, 50));
  }
  return true;
}

function startFixture(): { child: ChildProcess; ready: Promise<{ clerkd: number; dir: string }>; exited: Promise<{ code: number | null; signal: NodeJS.Signals | null }> } {
  const childEnv: NodeJS.ProcessEnv = { ...process.env, TS_NODE_TRANSPILE_ONLY: "true" };
  delete childEnv.npm_command;
  delete childEnv.npm_lifecycle_event;
  const child = spawn(process.execPath, [require.resolve("ts-node/dist/bin.js"), FIXTURE], {
    cwd: childCwd(), // a temp directory: nothing a child writes lands in the working copy
    env: childEnv,
    stdio: ["ignore", "pipe", "pipe"],
    detached: true,
  });
  let out = "";
  let err = "";
  child.stdout!.setEncoding("utf8");
  child.stderr!.setEncoding("utf8");
  child.stderr!.on("data", (s: string) => (err += s));
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((res) =>
    child.once("exit", (code, signal) => res({ code, signal }))
  );
  const ready = new Promise<{ clerkd: number; dir: string }>((res, rej) => {
    const timer = setTimeout(() => rej(new Error(`fixture not ready after 90 s; stderr: ${err}`)), 90_000);
    child.stdout!.on("data", (s: string) => {
      out += s;
      const nl = out.indexOf("\n");
      if (nl === -1) return;
      clearTimeout(timer);
      res(JSON.parse(out.slice(0, nl)) as { clerkd: number; dir: string });
    });
    void exited.then(({ code, signal }) => {
      clearTimeout(timer);
      rej(new Error(`fixture exited before it was ready (code ${code}, signal ${signal}); stderr: ${err}`));
    });
  });
  return { child, ready, exited };
}

section("A test run stopped by a signal leaves no clerkd and no temp directory");

for (const signal of ["SIGTERM", "SIGHUP", "SIGINT"] as const) {
  checkAsync(`${signal} to the test process: its clerkd child is stopped and its temp directory removed`, async () => {
    const fixture = startFixture();
    let clerkd: number | null = null;
    let dir: string | null = null;
    try {
      ({ clerkd, dir } = await fixture.ready);
      assert.ok(running(clerkd), "precondition: clerkd runs");
      assert.ok(existsSync(dir), "precondition: the temp directory exists");
      process.kill(fixture.child.pid!, signal);
      const done = await Promise.race([
        fixture.exited,
        new Promise<null>((res) => setTimeout(() => res(null), 15_000).unref()),
      ]);
      assert.ok(done !== null, `the test process still runs 15 s after ${signal}`);
      const pid = clerkd;
      assert.ok(
        await until(() => !running(pid), 4000),
        `clerkd ${pid} is still running after its test process was stopped by ${signal}`
      );
      const d = dir;
      assert.ok(
        await until(() => !existsSync(d), 4000),
        `temp directory ${d} is still there after its test process was stopped by ${signal}`
      );
      assert.equal(done.code, 128 + osConstants.signals[signal], `exit ${done.code} ${done.signal}`);
    } finally {
      if (clerkd !== null && running(clerkd)) process.kill(clerkd, "SIGKILL");
      if (fixture.child.exitCode === null && fixture.child.signalCode === null) fixture.child.kill("SIGKILL");
      if (dir !== null) rmSync(dir, { recursive: true, force: true });
    }
  }, 120_000);
}

runAll();
