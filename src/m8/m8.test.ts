// ──────────────────────────────────────────────────────────────────────────────
// ILAS / M8 Conservation Auditor tests
// 2026-06-13 (CEST), Uncle Frank + AI colleagues
// Hand-rolled to match the other modules' test style. Deterministic via an
// injected fake clock where time matters.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { LockedEvidenceLog } from "../l0";
import { ConservationAuditor } from ".";

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

function fakeClock() {
  let t = 1_000_000;
  return {
    now: () => t,
    advance: (ms: number) => { t += ms; },
    set: (ms: number) => { t = ms; },
  };
}

console.log("\nM8 Conservation Auditor Tests\n");

// 1. clean pair: call -> result -> close, no alarm anywhere
test("clean pair: call -> result -> close emits no alarm", () => {
  const audit = new ConservationAuditor(new LockedEvidenceLog());
  const i = audit.ingestCall("c1", "s1", "a1", "bash");
  assert.strictEqual(i.status, "ok");
  assert.strictEqual(i.signal, undefined);

  const r = audit.ingestResult("c1", "s1", "a1", "bash");
  assert.strictEqual(r.status, "matched");
  assert.strictEqual(r.signal, undefined);

  const c = audit.closeSession("s1", "a1");
  assert.strictEqual(c.status, "clean");
  assert.strictEqual(c.danglingCallIds.length, 0);
  assert.strictEqual(c.signal, undefined);
});

// 2. ORPHAN: result without a prior matching call -> hard_alarm (strict W1)
test("orphan: result with no prior call -> hard_alarm", () => {
  const audit = new ConservationAuditor(new LockedEvidenceLog());
  const r = audit.ingestResult("ghost-1", "s1", "a1", "bash");
  assert.strictEqual(r.status, "orphan_alarm");
  assert.ok(r.signal);
  assert.strictEqual(r.signal!.severity, "hard_alarm");
  assert.strictEqual(r.signal!.moduleId, "m8");
  assert.ok(r.signal!.message.includes("ghost-1"));
});

// 3. DANGLING AT CLOSE: call without result, session closes -> soft_alarm
test("dangling at session close -> soft_alarm with the dangling callIds listed", () => {
  const audit = new ConservationAuditor(new LockedEvidenceLog());
  audit.ingestCall("c1", "s1", "a1", "bash");
  audit.ingestCall("c2", "s1", "a1", "bash");
  audit.ingestResult("c1", "s1", "a1", "bash");
  const c = audit.closeSession("s1", "a1");
  assert.strictEqual(c.status, "dangling_alarm");
  assert.deepStrictEqual(c.danglingCallIds, ["c2"]);
  assert.ok(c.signal);
  assert.strictEqual(c.signal!.severity, "soft_alarm");
});

// 4. DANGLING MID-SESSION past threshold = INFORMATIONAL, NOT an alarm.
//    This test asserts the explicit Frank ruling: do not grade a liveness
//    budget as a security signal.
test("dangling mid-session past threshold is liveness info, NOT a signal", () => {
  const c = fakeClock();
  const audit = new ConservationAuditor(new LockedEvidenceLog(), c.now);
  audit.setDanglingThresholdMs(5000);
  audit.ingestCall("c1", "s1", "a1");
  c.advance(7000);
  const report = audit.evaluateLiveness();
  assert.strictEqual(report.pending.length, 1);
  assert.strictEqual(report.pending[0].callId, "c1");
  assert.ok(report.pending[0].ageMs >= 7000);
  // Critical: evaluateLiveness has no ModuleSignal in its return type.
  // The shape itself enforces "this is information, not detection."
  assert.ok(!("signal" in report));
});

// 5. AUDITS-THE-BOOK BOUND: a fabricated clean pair produces NO alarm.
//    This is documented as CORRECT BEHAVIOUR, not a missed detection.
test("audits-the-book bound: fabricated clean pair produces NO alarm (correct)", () => {
  const audit = new ConservationAuditor(new LockedEvidenceLog());
  // Threat model: an attacker injects a perfectly paired call+result for an
  // action that was never executed. Both halves land in the stream and look
  // clean. M8 is defined to NOT alarm on this -- it audits the book, not the
  // world. The whole-system answer to this threat lives elsewhere (M7
  // provenance, seam-integrity monitoring), not in the pairing invariant.
  audit.ingestCall("forged-1", "s-forged", "attacker", "bash");
  const r = audit.ingestResult("forged-1", "s-forged", "attacker", "bash");
  assert.strictEqual(r.status, "matched");
  assert.strictEqual(r.signal, undefined);
  const close = audit.closeSession("s-forged", "attacker");
  assert.strictEqual(close.status, "clean");
  assert.strictEqual(close.signal, undefined);
});

// 6. Sessions are tracked independently
test("multiple concurrent sessions are independent", () => {
  const audit = new ConservationAuditor(new LockedEvidenceLog());
  audit.ingestCall("c1", "sA", "agent-1");
  audit.ingestCall("c2", "sB", "agent-2");
  audit.ingestResult("c1", "sA", "agent-1");

  const cA = audit.closeSession("sA", "agent-1");
  assert.strictEqual(cA.status, "clean");

  // sB still open with c2 dangling
  assert.strictEqual(audit.getOpenSessions(), 1);
  assert.strictEqual(audit.getPendingCount(), 1);

  const cB = audit.closeSession("sB", "agent-2");
  assert.strictEqual(cB.status, "dangling_alarm");
  assert.deepStrictEqual(cB.danglingCallIds, ["c2"]);
});

// 7. ingestCall is idempotent (duplicate POST does not false-orphan)
test("ingestCall is idempotent for duplicate callId", () => {
  const audit = new ConservationAuditor(new LockedEvidenceLog());
  audit.ingestCall("c1", "s1", "a1");
  audit.ingestCall("c1", "s1", "a1");
  const r = audit.ingestResult("c1", "s1", "a1");
  assert.strictEqual(r.status, "matched");
  const c = audit.closeSession("s1", "a1");
  assert.strictEqual(c.status, "clean");
});

// 8. session_close evicts state; reopening a sessionId starts fresh
test("session_close evicts state, no carryover", () => {
  const audit = new ConservationAuditor(new LockedEvidenceLog());
  audit.ingestCall("c1", "s1", "a1");
  audit.ingestResult("c1", "s1", "a1");
  audit.closeSession("s1", "a1");
  assert.strictEqual(audit.getOpenSessions(), 0);
  assert.strictEqual(audit.getPendingCount(), 0);

  // Closing again is a no-op clean
  const c = audit.closeSession("s1", "a1");
  assert.strictEqual(c.status, "clean");
});

// 9. Late result after session_close is treated as orphan (W1 strict semantics
//    at the live layer; L0 replay can disambiguate post-hoc).
test("late result after session_close is orphan in live view", () => {
  const audit = new ConservationAuditor(new LockedEvidenceLog());
  audit.ingestCall("c1", "s1", "a1");
  audit.closeSession("s1", "a1");                  // dangling soft_alarm, c1 evicted
  const r = audit.ingestResult("c1", "s1", "a1"); // late arrival
  assert.strictEqual(r.status, "orphan_alarm");
  assert.strictEqual(r.signal!.severity, "hard_alarm");
});

// 10. L0 chain valid after mixed orphan + clean + dangling activity
test("L0 chain valid after mixed orphan + clean + dangling sequence", () => {
  const log = new LockedEvidenceLog();
  const audit = new ConservationAuditor(log);
  audit.ingestResult("ghost", "s-orph", "a1");     // orphan hard_alarm
  audit.ingestCall("c1", "s1", "a1");
  audit.ingestResult("c1", "s1", "a1");
  audit.closeSession("s1", "a1");                   // clean
  audit.ingestCall("c2", "s2", "a1");
  audit.closeSession("s2", "a1");                   // dangling soft_alarm
  assert.deepStrictEqual(log.verify(), { valid: true });
});

// 11. liveness threshold honoured: call younger than threshold is NOT pending
test("evaluateLiveness ignores calls younger than danglingThresholdMs", () => {
  const c = fakeClock();
  const audit = new ConservationAuditor(new LockedEvidenceLog(), c.now);
  audit.setDanglingThresholdMs(5000);
  audit.ingestCall("c1", "s1", "a1");
  c.advance(2000);
  assert.strictEqual(audit.evaluateLiveness().pending.length, 0);
  c.advance(4000);
  assert.strictEqual(audit.evaluateLiveness().pending.length, 1);
});

// 12. Missing sessionId on call/result still tracked, doesn't false-orphan
test("call/result without sessionId fall under sentinel session, still pair", () => {
  const audit = new ConservationAuditor(new LockedEvidenceLog());
  audit.ingestCall("c1", null, "a1");
  audit.ingestCall("c2", undefined, "a1");
  const r1 = audit.ingestResult("c1", null, "a1");
  const r2 = audit.ingestResult("c2", undefined, "a1");
  assert.strictEqual(r1.status, "matched");
  assert.strictEqual(r2.status, "matched");
});

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
