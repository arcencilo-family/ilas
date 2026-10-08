// ──────────────────────────────────────────────────────────────────────────────
// ILAS — the v0 staleness timer (deprecated, still supported) across the
// stack's lifecycle. ILASKillStack.close() stops it, and nothing it does is
// thrown out of the timer, where no caller could catch it: an append that
// fails there is kept in the log, and settle() (settleEvidence()) throws it.
// House style: standalone ts-node script, custom check() harness.
//   npx ts-node src/v0/v0.staleness.test.ts
// An uncaughtException listener records what a timer throws, so the run reports
// it instead of dying. Every log lives in a temporary directory removed at the end.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { ILASKillStack } from "../index";
import { LockedEvidenceLog, L0WriteError } from "../l0";
import { IntegrityState } from "../types";
import type { ModuleSignal } from "../types";
import { VerdictEngine } from "./index";

let passed = 0;
let failed = 0;
const pending: Array<() => Promise<void>> = [];

function checkAsync(name: string, fn: () => Promise<void>): void {
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

const uncaught: unknown[] = [];
process.on("uncaughtException", (err) => {
  uncaught.push(err);
});

const root = mkdtempSync(join(tmpdir(), "ilas-v0-staleness-"));
let counter = 0;
const freshPath = (): string => join(root, `log-${counter++}.jsonl`);
const sleep = (ms: number): Promise<void> => new Promise((ok) => setTimeout(ok, ms));

function clean(): ModuleSignal[] {
  return [{ moduleId: "x", severity: "clean", message: "ok", timestamp: Date.now() }];
}

/** Run `fn`, then fail if anything was thrown out of a timer meanwhile. */
async function noUncaught(fn: () => Promise<void>): Promise<void> {
  const before = uncaught.length;
  await fn();
  if (uncaught.length > before) {
    const err = uncaught[before] as Error;
    throw new Error(`the staleness timer threw: ${err?.name}: ${err?.message}`);
  }
}

console.log("── The staleness timer and the stack's lifecycle ──");

checkAsync("ILASKillStack.close() stops the staleness timer: the state stays, nothing is thrown", async () => {
  const s = new ILASKillStack({ logPath: freshPath(), fsync: false });
  s.verdict.runVerificationCycle(clean());
  assert.equal(s.verdict.getState(), IntegrityState.DEGRADED, "precondition");
  s.verdict.setStalenessTimeout(30);
  s.close();
  await noUncaught(() => sleep(150));
  assert.equal(s.verdict.getState(), IntegrityState.DEGRADED, "the timer of a closed stack still moved its state");
});

checkAsync("an in-process restart supersedes the old stack's log: its timer's failed append is kept, not thrown; the old settleEvidence() throws it; the new stack is unharmed", async () => {
  const p = freshPath();
  const one = new ILASKillStack({ logPath: p, fsync: false });
  one.verdict.runVerificationCycle(clean());
  await one.settleEvidence();
  one.verdict.setStalenessTimeout(30);
  const two = new ILASKillStack({ logPath: p, fsync: false });
  try {
    await noUncaught(() => sleep(150));
    assert.equal(one.verdict.getState(), IntegrityState.UNVERIFIED, "precondition: the old timer ran");
    await assert.rejects(one.settleEvidence(), (err: unknown) => err instanceof L0WriteError && /superseded/.test((err as Error).message));
    await two.settleEvidence();
    const d = two.status().logDurability;
    assert.equal(d.writeHealthy, true, String(d.lastError));
    assert.equal(d.persisting, true);
  } finally {
    one.verdict.clearStalenessTimeout();
    two.close();
  }
});

checkAsync("a VerdictEngine whose log refuses the append (closed, no clerk route): the timer keeps the failure in the log; settle() throws it", async () => {
  const log = new LockedEvidenceLog({ path: freshPath(), fsync: false });
  const engine = new VerdictEngine(log);
  engine.runVerificationCycle(clean());
  engine.runVerificationCycle(clean());
  assert.equal(engine.getState(), IntegrityState.VERIFIED, "precondition");
  engine.setStalenessTimeout(30);
  log.close();
  try {
    await noUncaught(() => sleep(150));
    assert.equal(engine.getState(), IntegrityState.UNVERIFIED, "precondition: the timer ran");
    await assert.rejects(log.settle(), (err: unknown) => err instanceof L0WriteError && /closed/.test((err as Error).message));
    await assert.rejects(log.settle(), L0WriteError, "a failure that stops the log is thrown on every later settle()");
  } finally {
    engine.clearStalenessTimeout();
  }
});

checkAsync("keepFailure() keeps any value, never throws, and never replaces a failure that stopped the log", async () => {
  const log = new LockedEvidenceLog();
  log.keepFailure(Object.create(null)); // no string form
  await assert.rejects(log.settle(), L0WriteError);
  const first = new L0WriteError("first");
  const other = new LockedEvidenceLog();
  other.keepFailure(first);
  other.keepFailure(new Error("second"));
  await assert.rejects(other.settle(), (err: unknown) => err === first);
});

void (async () => {
  try {
    for (const step of pending) await step();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
  console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
})();
