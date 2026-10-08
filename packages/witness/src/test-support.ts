// ──────────────────────────────────────────────────────────────────────────────
// Reference witness — test support: temp dirs and child processes that are
// cleaned up however the test process ends.
//
// A test file registers here the temp dirs it makes and the children it starts.
// They are killed (SIGKILL) and removed when the process exits: normally, by
// process.exit(), or by SIGINT, SIGTERM or SIGHUP. Each of those signals is
// turned into process.exit(128 + its number), so that the exit handlers run
// (this one, and any other, such as L0's removal of its writer lock). Without
// that, a run stopped by a signal sent to the test process alone (kill <pid>, a
// CI cancel, timeout --foreground) leaves its `run` children polling,
// reparented, and its temp dirs, test keys included, behind. Nothing can be
// done about SIGKILL.
//
// Node runs a signal listener only when its event loop turns. Synchronous code,
// and awaits that resolve without I/O or a timer, give it no turn: the signal
// waits, and if the run ends first it is lost. So a file that imports this
// module calls betweenTests() after each test, and the signal is handled before
// the next test starts. A test file that is synchronous throughout must not
// import it: there the listener would only swallow the signal.
// ──────────────────────────────────────────────────────────────────────────────

import type { ChildProcess } from "child_process";
import { mkdtempSync, rmSync } from "fs";
import { constants as osConstants, tmpdir } from "os";
import { join } from "path";

const dirs = new Set<string>();
const children = new Set<ChildProcess>();
const pids = new Set<number>();

/** A new directory under the OS temp dir, removed when the process exits. */
export function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  dirs.add(dir);
  return dir;
}

/** Remove `dir` when the process exits: a directory this process did not make itself. */
export function removeOnExit(dir: string): void {
  dirs.add(dir);
}

/** SIGKILL `child` when the process exits, unless it was untracked first. */
export function trackChild(child: ChildProcess): ChildProcess {
  children.add(child);
  return child;
}

export function untrackChild(child: ChildProcess): void {
  children.delete(child);
}

/**
 * SIGKILL `pid` when the process exits, unless it was untracked first: a
 * process this file did not spawn itself (behind npx, or started detached by a
 * launcher). A negative pid names a process group, as for process.kill.
 */
export function trackPid(pid: number): void {
  pids.add(pid);
}

export function untrackPid(pid: number): void {
  pids.delete(pid);
}

/** Kill every tracked child and pid, then remove every tracked dir. Safe to call again. */
export function cleanUp(): void {
  for (const child of children) {
    try {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    } catch {
      // already gone
    }
  }
  children.clear();
  for (const pid of pids) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // already gone
    }
  }
  pids.clear();
  for (const dir of dirs) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch (error) {
      process.stderr.write(`could not remove ${dir}: ${error instanceof Error ? error.message : String(error)}\n`);
    }
  }
  dirs.clear();
}

/** One turn of the event loop, so that a pending SIGINT, SIGTERM or SIGHUP is handled now. */
export function betweenTests(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

process.on("exit", cleanUp);
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
  process.once(signal, () => {
    process.stderr.write(`\n  stopped by ${signal}: killing this file's children, removing its temp dirs\n`);
    process.exit(128 + osConstants.signals[signal]);
  });
}
