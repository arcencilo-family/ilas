// ──────────────────────────────────────────────────────────────────────────────
// ILAS — V0 confidence-decay tests
// Added: 2026-06-13 (CEST) — Uncle Frank + AI colleagues
// Deterministic: uses an injected clock, so no real waiting.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { LockedEvidenceLog } from "../l0";
import { DriftMonitor } from "../m5";
import { VerdictEngine } from ".";
import { IntegrityState } from "../types";
import type { ModuleSignal } from "../types";

let passed = 0;
let failed = 0;

function test(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`  \u2713 ${name}`);
    passed++;
  } catch (err) {
    console.error(`  \u2717 ${name}`);
    console.error(`    ${(err as Error).message}`);
    failed++;
  }
}

// Mutable fake clock
function fakeClock() {
  let t = 1_000_000;
  return {
    now: () => t,
    advance: (ms: number) => { t += ms; },
    set: (ms: number) => { t = ms; },
  };
}

function clean(moduleId = "m3"): ModuleSignal {
  return { moduleId, severity: "clean", message: "clean", timestamp: Date.now() };
}
function reachVerified(engine: VerdictEngine): void {
  engine.runVerificationCycle([clean("m3"), clean("m5")]);
  engine.runVerificationCycle([clean("m3"), clean("m5")]);
}

const LN2 = Math.log(2);

console.log("\nV0 Confidence-Decay Tests\n");

// 1. Disabled by default → confidence is 1.0
test("decay disabled by default: confidence = 1", () => {
  const engine = new VerdictEngine(new LockedEvidenceLog());
  assert.strictEqual(engine.confidence(), 1);
  assert.strictEqual(engine.getFreshness().decayEnabled, false);
});

// 2. Half-life: at t = ln2/lambda, confidence ≈ 0.5
test("confidence follows e^(-lambda t): half-life check", () => {
  const c = fakeClock();
  const lambda = 1e-3; // per ms
  const engine = new VerdictEngine(new LockedEvidenceLog(), c.now);
  engine.setDecayRate(lambda);            // resets clock to now
  c.advance(LN2 / lambda);                // exactly one half-life
  assert.ok(Math.abs(engine.confidence() - 0.5) < 1e-9, `got ${engine.confidence()}`);
});

// 3. Monotonic decrease between resets (DeepSeek-flagged invariant)
test("confidence is strictly monotonic-decreasing between resets", () => {
  const c = fakeClock();
  const engine = new VerdictEngine(new LockedEvidenceLog(), c.now);
  engine.setDecayRate(1e-3);
  let prev = engine.confidence();
  for (let i = 0; i < 50; i++) {
    c.advance(10);
    const cur = engine.confidence();
    assert.ok(cur < prev, `not decreasing at step ${i}: ${cur} >= ${prev}`);
    prev = cur;
  }
});

// 4. A clean verification cycle is a freshness event → resets confidence to ~1
test("clean verification cycle resets confidence upward to ~1", () => {
  const c = fakeClock();
  const engine = new VerdictEngine(new LockedEvidenceLog(), c.now);
  engine.setDecayRate(1e-3);
  c.advance(2000);
  assert.ok(engine.confidence() < 0.2, `pre-reset ${engine.confidence()}`);
  engine.runVerificationCycle([clean("m3"), clean("m5")]); // fresh evidence
  assert.ok(Math.abs(engine.confidence() - 1) < 1e-9, `post-reset ${engine.confidence()}`);
});

// 5. evaluateFreshness degrades exactly ONE step at floor cross, then re-arms
test("evaluateFreshness: VERIFIED -> DEGRADED -> UNVERIFIED, one step per cross", () => {
  const c = fakeClock();
  const engine = new VerdictEngine(new LockedEvidenceLog(), c.now);
  reachVerified(engine);
  engine.setDecayRate(1e-3, 0.5); // floor 0.5; reset happened on setDecayRate
  assert.strictEqual(engine.getState(), IntegrityState.VERIFIED);

  // below floor after one half-life + epsilon
  c.advance(LN2 / 1e-3 + 1);
  assert.strictEqual(engine.evaluateFreshness(), IntegrityState.DEGRADED);
  // re-armed → confidence back ~1, no further degrade yet
  assert.strictEqual(engine.evaluateFreshness(), IntegrityState.DEGRADED);

  c.advance(LN2 / 1e-3 + 1);
  assert.strictEqual(engine.evaluateFreshness(), IntegrityState.UNVERIFIED);
  // UNVERIFIED is the floor of the degrade path — decay cannot go lower
  c.advance(LN2 / 1e-3 + 1);
  assert.strictEqual(engine.evaluateFreshness(), IntegrityState.UNVERIFIED);
});

// 6. Decay NEVER upgrades
test("decay never upgrades (UNVERIFIED stays put no matter how 'fresh')", () => {
  const c = fakeClock();
  const engine = new VerdictEngine(new LockedEvidenceLog(), c.now);
  engine.setDecayRate(1e-3);
  // brand new / full confidence, but still UNVERIFIED
  assert.strictEqual(engine.evaluateFreshness(), IntegrityState.UNVERIFIED);
});

// 7. QUARANTINED is untouched by decay (one-way trap preserved)
test("QUARANTINED: confidence pinned 0, evaluateFreshness is a no-op", () => {
  const c = fakeClock();
  const engine = new VerdictEngine(new LockedEvidenceLog(), c.now);
  reachVerified(engine);
  engine.setDecayRate(1e-3, 0.5);
  engine.processSignal({ moduleId: "m3", severity: "hard_alarm", message: "x", timestamp: c.now() });
  assert.strictEqual(engine.getState(), IntegrityState.QUARANTINED);
  assert.strictEqual(engine.confidence(), 0);
  c.advance(10_000_000);
  assert.strictEqual(engine.evaluateFreshness(), IntegrityState.QUARANTINED);
});

// 8. Deployment pattern: lambda registered with M5; suppression -> hard_alarm -> QUARANTINE
//    (V0 does not own M5; this is the wiring a deployer does.)
test("lambda-as-M5-parameter: suppressing lambda->0 trips M5 'material' -> V0 QUARANTINES", () => {
  const log = new LockedEvidenceLog();
  const c = fakeClock();
  const engine = new VerdictEngine(log, c.now);
  const drift = new DriftMonitor(log);

  const LAMBDA = 1e-3;
  reachVerified(engine);
  engine.setDecayRate(LAMBDA);
  drift.registerParameter("v0_decay_lambda", LAMBDA, true); // structural

  // Attacker tries to freeze confidence high by killing decay:
  const res = drift.recordChange("v0_decay_lambda", 0);
  assert.strictEqual(res.status, "material"); // near-zero suppression

  // Deployer maps a material drift verdict to a hard_alarm into V0:
  if (res.status === "material") {
    engine.processSignal({
      moduleId: "m5",
      severity: "hard_alarm",
      message: "decay lambda suppressed to near-zero",
      timestamp: c.now(),
    });
  }
  assert.strictEqual(engine.getState(), IntegrityState.QUARANTINED);
});

// 9. L0 chain stays valid through decay-driven transitions
test("L0 chain valid after decay transitions", () => {
  const log = new LockedEvidenceLog();
  const c = fakeClock();
  const engine = new VerdictEngine(log, c.now);
  reachVerified(engine);
  engine.setDecayRate(1e-3, 0.5);
  c.advance(LN2 / 1e-3 + 1);
  engine.evaluateFreshness();
  c.advance(LN2 / 1e-3 + 1);
  engine.evaluateFreshness();
  assert.deepStrictEqual(log.verify(), { valid: true });
});

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
