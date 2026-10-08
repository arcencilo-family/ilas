// ──────────────────────────────────────────────────────────────────────────────
// Reference clerk — shared test support (not a test file itself).
//
// · a queued check()/checkAsync() harness that runs in declaration order and
//   prints "N tests: P passed, F failed", exiting 1 on any failure;
// · temp directories under os.tmpdir(), removed when the process exits;
// · clerkd child processes that are always killed when the process exits,
//   including an exit forced by SIGINT, SIGTERM or SIGHUP;
// · a watchdog so a hung test fails instead of hanging.
// ──────────────────────────────────────────────────────────────────────────────

import { spawn } from "child_process";
import type { ChildProcess } from "child_process";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { constants as osConstants, tmpdir } from "os";
import { join, resolve } from "path";
import { generateClerkKeyFiles } from "./keys";

// ── harness ──────────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const queue: Array<() => Promise<void>> = [];

export function section(title: string): void {
  queue.push(async () => {
    console.log(`\n── ${title} ──`);
  });
}

export function checkAsync(name: string, fn: () => void | Promise<void>, timeoutMs = 60_000): void {
  queue.push(async () => {
    let timer: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        Promise.resolve().then(fn),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error(`timed out after ${timeoutMs} ms`)), timeoutMs);
        }),
      ]);
      console.log(`  ✓ ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✗ ${name}`);
      console.error(`    ${(err as Error).stack ?? String(err)}`);
      failed++;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  });
}

/** Synchronous test; queued like the rest. */
export function check(name: string, fn: () => void): void {
  checkAsync(name, fn);
}

/** Run every queued test in order, print the tally, and exit. */
export function runAll(watchdogMs = 300_000): void {
  const watchdog = setTimeout(() => {
    console.error(`\nwatchdog: test file still running after ${watchdogMs} ms`);
    process.exit(1);
  }, watchdogMs);
  watchdog.unref();
  void (async () => {
    for (const t of queue) await t();
    console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
    process.exit(failed > 0 ? 1 : 0);
  })();
}

export async function rejects(p: Promise<unknown>): Promise<Error> {
  try {
    await p;
  } catch (err) {
    return err as Error;
  }
  throw new Error("expected a rejection; the promise resolved");
}

export function throws(fn: () => unknown): Error {
  try {
    fn();
  } catch (err) {
    return err as Error;
  }
  throw new Error("expected a throw; the call returned");
}

// ── cleanup on exit ──────────────────────────────────────────────────────────

const tempDirs: string[] = [];
const children = new Set<ChildProcess>();

process.on("exit", () => {
  for (const c of children) {
    if (c.exitCode === null && c.signalCode === null) c.kill("SIGKILL");
  }
  for (const d of tempDirs) {
    try {
      rmSync(d, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
    } catch {
      /* best effort */
    }
  }
});

// A process ended by a signal does not run "exit" handlers. A test run stopped
// with Ctrl-C, kill <pid>, a CI cancel or timeout(1) would otherwise leave its
// clerkd children running (holding their sockets and book locks) and its temp
// directories (with test keys) behind. Exit instead, with the status a shell
// reports for that signal, so the handler above runs.
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
  process.once(signal, () => process.exit(128 + osConstants.signals[signal]));
}

/** A fresh directory under os.tmpdir() (mode 0700), removed at exit. */
export function tempDir(prefix = "ilas-clerk-"): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(d);
  return d;
}

// ── fixtures ─────────────────────────────────────────────────────────────────

export function entry(n: number) {
  return {
    timestamp: 1_700_000_000_000 + n,
    moduleId: "test",
    eventType: "unit",
    provenanceTag: "LaneA" as const,
    parameters: { n },
    outcome: "ok",
  };
}

export interface ClerkFixture {
  dir: string;
  configPath: string;
  privateKeyPath: string;
  publicKeyPath: string;
  publicKeyPem: string;
  bookPath: string;
  socketPath: string;
}

/** Keys + config in a new temp directory. Extra config keys may be given. */
export function makeClerkFixture(extra: Record<string, unknown> = {}): ClerkFixture {
  const dir = tempDir();
  const keys = generateClerkKeyFiles(join(dir, "keys"));
  const bookPath = join(dir, "book", "receipts.jsonl");
  const socketPath = join(dir, "run", "clerk.sock");
  const configPath = join(dir, "clerk.json");
  writeFileSync(
    configPath,
    JSON.stringify(
      {
        clerk_id: "test-clerk",
        private_key_path: "keys/clerk.key",
        book_path: "book/receipts.jsonl",
        socket_path: "run/clerk.sock",
        ...extra,
      },
      null,
      2
    )
  );
  return {
    dir,
    configPath,
    privateKeyPath: keys.privateKeyPath,
    publicKeyPath: keys.publicKeyPath,
    publicKeyPem: keys.publicKeyPem,
    bookPath,
    socketPath,
  };
}

// ── clerkd as a child process ────────────────────────────────────────────────

export const CLI_PATH = resolve(__dirname, "cli.ts");
export const REPO_ROOT = resolve(__dirname, "..", "..", "..");

let defaultChildCwd: string | null = null;

/**
 * The working directory child processes start in unless a test names one: a
 * temp directory, never the repository, so a relative path a child writes to
 * cannot land in the working copy.
 */
export function childCwd(): string {
  return (defaultChildCwd ??= tempDir("ilas-clerk-cwd-"));
}

/** Kill `child` (SIGKILL) when this process exits, if it is still running then. */
export function trackChild(child: ChildProcess): ChildProcess {
  children.add(child);
  child.once("exit", () => children.delete(child));
  return child;
}

export interface ChildRun {
  child: ChildProcess;
  stdout: string[];
  stderr: string[];
  /** Resolves with the exit code (null if killed by a signal). */
  exited: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
}

/**
 * Spawn the CLI with ts-node (transpile-only, for start-up speed), directly
 * with node, in `cwd` (default: childCwd(), a temp directory). The variables
 * npm and npx set (npm_command, npm_lifecycle_event) are removed, since this
 * is not an npm launch even when the tests run under `npm test`; `env` sets
 * variables on top, including those.
 */
export function spawnCli(
  args: readonly string[],
  env: Record<string, string> = {},
  cwd: string = childCwd()
): ChildRun {
  const tsNode = require.resolve("ts-node/dist/bin.js");
  const childEnv: NodeJS.ProcessEnv = { ...process.env, TS_NODE_TRANSPILE_ONLY: "true" };
  delete childEnv.npm_command;
  delete childEnv.npm_lifecycle_event;
  const child = spawn(process.execPath, [tsNode, CLI_PATH, ...args], {
    cwd,
    env: { ...childEnv, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  children.add(child);
  const stdout: string[] = [];
  const stderr: string[] = [];
  child.stdout!.setEncoding("utf8");
  child.stderr!.setEncoding("utf8");
  child.stdout!.on("data", (s: string) => stdout.push(s));
  child.stderr!.on("data", (s: string) => stderr.push(s));
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((res) => {
    child.once("exit", (code, signal) => {
      children.delete(child);
      res({ code, signal });
    });
  });
  return { child, stdout, stderr, exited };
}

export interface ChildClerkd extends ChildRun {
  /** Send `signal` and wait for exit; SIGKILL after `graceMs`. */
  stop(signal?: NodeJS.Signals, graceMs?: number): Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
}

/** Start `cli.ts run --config <file>` (in `cwd`) and wait until it says it is listening. */
export async function startChildClerkd(
  configPath: string,
  readyTimeoutMs = 45_000,
  env: Record<string, string> = {},
  cwd: string = childCwd()
): Promise<ChildClerkd> {
  const run = spawnCli(["run", "--config", configPath], env, cwd);
  const stop = async (signal: NodeJS.Signals = "SIGTERM", graceMs = 10_000) => {
    if (run.child.exitCode === null && run.child.signalCode === null) run.child.kill(signal);
    let timer: NodeJS.Timeout | undefined;
    const killed = new Promise<void>((res) => {
      timer = setTimeout(() => {
        run.child.kill("SIGKILL");
        res();
      }, graceMs);
    });
    await Promise.race([run.exited, killed]);
    clearTimeout(timer);
    return run.exited;
  };
  try {
    await new Promise<void>((res, rej) => {
      const timer = setTimeout(
        () => rej(new Error(`clerkd not ready after ${readyTimeoutMs} ms; stderr: ${run.stderr.join("")}`)),
        readyTimeoutMs
      );
      const poll = setInterval(() => {
        if (run.stdout.join("").includes("listening on")) {
          clearInterval(poll);
          clearTimeout(timer);
          res();
        }
      }, 25);
      void run.exited.then(({ code, signal }) => {
        clearInterval(poll);
        clearTimeout(timer);
        rej(
          new Error(
            `clerkd exited before it was ready (code ${code}, signal ${signal}); ` +
              `stderr: ${run.stderr.join("")}`
          )
        );
      });
    });
  } catch (err) {
    run.child.kill("SIGKILL");
    throw err;
  }
  return { ...run, stop };
}
