import assert from "assert";
import { LockedEvidenceLog } from "../l0";
import { VerdictEngine } from ".";
import { IntegrityState } from "../types";
import type { ModuleSignal } from "../types";

let passed = 0;
let failed = 0;

function test(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${(err as Error).message}`);
    failed++;
  }
}

function signal(
  severity: ModuleSignal["severity"],
  moduleId = "test"
): ModuleSignal {
  return { moduleId, severity, message: `${severity} event`, timestamp: Date.now() };
}

function cleanCycle(engine: VerdictEngine, reviewComplete = false): IntegrityState {
  return engine.runVerificationCycle(
    [signal("clean", "m3"), signal("clean", "m5")],
    reviewComplete
  );
}

// ── Test suite ────────────────────────────────────────────────────────────────

console.log("\nV0 Verdict Engine Tests\n");

// 1. Initial state
test("starts UNVERIFIED", () => {
  const engine = new VerdictEngine(new LockedEvidenceLog());
  assert.strictEqual(engine.getState(), IntegrityState.UNVERIFIED);
});

// 2–3. Clean cycles climb the ladder
test("clean cycle: UNVERIFIED → DEGRADED", () => {
  const engine = new VerdictEngine(new LockedEvidenceLog());
  const next = cleanCycle(engine);
  assert.strictEqual(next, IntegrityState.DEGRADED);
});

test("two clean cycles: UNVERIFIED → DEGRADED → VERIFIED", () => {
  const engine = new VerdictEngine(new LockedEvidenceLog());
  cleanCycle(engine);
  const next = cleanCycle(engine);
  assert.strictEqual(next, IntegrityState.VERIFIED);
});

test("clean cycle at VERIFIED stays VERIFIED (no over-upgrade)", () => {
  const engine = new VerdictEngine(new LockedEvidenceLog());
  cleanCycle(engine); cleanCycle(engine); // reach VERIFIED
  const next = cleanCycle(engine);
  assert.strictEqual(next, IntegrityState.VERIFIED);
});

// 4. hard_alarm → QUARANTINED from any state
test("hard_alarm from UNVERIFIED → QUARANTINED", () => {
  const engine = new VerdictEngine(new LockedEvidenceLog());
  const next = engine.processSignal(signal("hard_alarm"));
  assert.strictEqual(next, IntegrityState.QUARANTINED);
});

test("hard_alarm from VERIFIED → QUARANTINED", () => {
  const engine = new VerdictEngine(new LockedEvidenceLog());
  cleanCycle(engine); cleanCycle(engine); // reach VERIFIED
  const next = engine.processSignal(signal("hard_alarm"));
  assert.strictEqual(next, IntegrityState.QUARANTINED);
});

// 5. soft_alarm → DEGRADED (from VERIFIED or UNVERIFIED)
test("soft_alarm from UNVERIFIED → DEGRADED", () => {
  const engine = new VerdictEngine(new LockedEvidenceLog());
  const next = engine.processSignal(signal("soft_alarm"));
  assert.strictEqual(next, IntegrityState.DEGRADED);
});

test("soft_alarm from VERIFIED → DEGRADED", () => {
  const engine = new VerdictEngine(new LockedEvidenceLog());
  cleanCycle(engine); cleanCycle(engine);
  const next = engine.processSignal(signal("soft_alarm"));
  assert.strictEqual(next, IntegrityState.DEGRADED);
});

// 6. soft_alarm when QUARANTINED → stays QUARANTINED (no upgrade, no double-degrade)
test("soft_alarm when QUARANTINED stays QUARANTINED", () => {
  const engine = new VerdictEngine(new LockedEvidenceLog());
  engine.processSignal(signal("hard_alarm"));
  const next = engine.processSignal(signal("soft_alarm"));
  assert.strictEqual(next, IntegrityState.QUARANTINED);
});

// 7. clean cycle when QUARANTINED — without review flag stays QUARANTINED
test("clean cycle without independentReview stays QUARANTINED", () => {
  const engine = new VerdictEngine(new LockedEvidenceLog());
  cleanCycle(engine); cleanCycle(engine); // reach VERIFIED
  engine.processSignal(signal("hard_alarm"));
  const next = cleanCycle(engine, false);
  assert.strictEqual(next, IntegrityState.QUARANTINED);
});

// 8. clean cycle when QUARANTINED with review flag → DEGRADED (not VERIFIED)
test("clean cycle with independentReview: QUARANTINED → DEGRADED", () => {
  const engine = new VerdictEngine(new LockedEvidenceLog());
  engine.processSignal(signal("hard_alarm"));
  const next = cleanCycle(engine, true);
  assert.strictEqual(next, IntegrityState.DEGRADED);
});

test("QUARANTINED with review → DEGRADED, not VERIFIED in one step", () => {
  const engine = new VerdictEngine(new LockedEvidenceLog());
  engine.processSignal(signal("hard_alarm"));
  cleanCycle(engine, true); // → DEGRADED
  assert.strictEqual(engine.getState(), IntegrityState.DEGRADED);
  // second clean cycle (no quarantine, no review needed) → VERIFIED
  const next = cleanCycle(engine);
  assert.strictEqual(next, IntegrityState.VERIFIED);
});

// 9. dirty cycle applies non-clean signals
test("verification cycle with non-clean signals applies them", () => {
  const engine = new VerdictEngine(new LockedEvidenceLog());
  engine.runVerificationCycle([signal("clean"), signal("hard_alarm")]);
  assert.strictEqual(engine.getState(), IntegrityState.QUARANTINED);
});

// 10. L0 chain remains valid after all transitions
test("L0 chain is valid after all transitions", () => {
  const log = new LockedEvidenceLog();
  const engine = new VerdictEngine(log);
  cleanCycle(engine);
  cleanCycle(engine);
  engine.processSignal(signal("hard_alarm"));
  cleanCycle(engine, true);
  assert.deepStrictEqual(log.verify(), { valid: true });
});

// 11. history records every transition
test("getHistory records initial state and all transitions", () => {
  const engine = new VerdictEngine(new LockedEvidenceLog());
  cleanCycle(engine);
  engine.processSignal(signal("hard_alarm"));
  const h = engine.getHistory();
  assert.strictEqual(h[0].state, IntegrityState.UNVERIFIED);
  assert.strictEqual(h[1].state, IntegrityState.DEGRADED);
  assert.strictEqual(h[2].state, IntegrityState.QUARANTINED);
});

// 12. Staleness timeout (async — must use real timer)
// Check at 70 ms: first firing at 50 ms degrades VERIFIED→DEGRADED.
// Second firing would be at 100 ms; we read before that.
async function runStalenessTest(): Promise<void> {
  return new Promise((resolve) => {
    const engine = new VerdictEngine(new LockedEvidenceLog());
    cleanCycle(engine); cleanCycle(engine); // VERIFIED
    engine.setStalenessTimeout(50);
    setTimeout(() => {
      try {
        assert.strictEqual(engine.getState(), IntegrityState.DEGRADED);
        console.log("  ✓ staleness timeout: VERIFIED → DEGRADED after 50 ms");
        passed++;
      } catch (err) {
        console.error("  ✗ staleness timeout: VERIFIED → DEGRADED after 50 ms");
        console.error(`    ${(err as Error).message}`);
        failed++;
      }
      resolve();
    }, 70);
  });
}

runStalenessTest().then(() => {
  console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
});
