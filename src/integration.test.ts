import assert from "assert";
import { ILASKillStack } from "./index";
import { IntegrityState } from "./types";
import type { ModuleSignal } from "./types";

let passed = 0;
let failed = 0;

function check(name: string, fn: () => void): void {
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

function sig(
  severity: ModuleSignal["severity"],
  moduleId: string,
  message: string
): ModuleSignal {
  return { moduleId, severity, message, timestamp: Date.now() };
}

console.log("\nILAS Integration Test\n");

// ── Bootstrap ─────────────────────────────────────────────────────────────────

const ilas = new ILASKillStack();

check("initial state is UNVERIFIED", () => {
  assert.strictEqual(ilas.verdict.getState(), IntegrityState.UNVERIFIED);
});

// ── M3: Plant canaries ────────────────────────────────────────────────────────

const shallow = ilas.canary.plantCanary("shallow");
const medium  = ilas.canary.plantCanary("medium");
const deep    = ilas.canary.plantCanary("deep");

check("3 canaries planted (one per depth)", () => {
  const active = ilas.canary.getActiveCanaries();
  assert.strictEqual(active.length, 3);
  assert.ok(active.some((t) => t.depth === "shallow"));
  assert.ok(active.some((t) => t.depth === "medium"));
  assert.ok(active.some((t) => t.depth === "deep"));
});

check("L0 logged canary_planted events", () => {
  const entries = ilas.log.getAll();
  const plantedEvents = entries.filter((e) => e.eventType === "canary_planted");
  assert.strictEqual(plantedEvents.length, 3);
});

// ── M5: Register parameters ───────────────────────────────────────────────────

ilas.drift.registerParameter("temperature", 100);
ilas.drift.registerParameter("threshold", 200, true); // structural

check("2 parameters registered", () => {
  assert.ok(ilas.drift.getParameter("temperature"));
  assert.ok(ilas.drift.getParameter("threshold"));
});

check("L0 logged parameter_registered events", () => {
  const entries = ilas.log.getAll();
  const regEvents = entries.filter((e) => e.eventType === "parameter_registered");
  assert.strictEqual(regEvents.length, 2);
});

// ── V0: Clean verification cycles ────────────────────────────────────────────

const cleanSignals: ModuleSignal[] = [
  sig("clean", "m3", "no canary hits"),
  sig("clean", "m5", "all params within bounds"),
];

const afterFirstCycle = ilas.verdict.runVerificationCycle(cleanSignals);
check("first clean cycle: UNVERIFIED → DEGRADED", () => {
  assert.strictEqual(afterFirstCycle, IntegrityState.DEGRADED);
});

const afterSecondCycle = ilas.verdict.runVerificationCycle(cleanSignals);
check("second clean cycle: DEGRADED → VERIFIED", () => {
  assert.strictEqual(afterSecondCycle, IntegrityState.VERIFIED);
});

// ── M3: Canary hit → alarm signal ─────────────────────────────────────────────

const hitContent = `outbound payload containing canary: ${shallow.value}`;
const checkResult = ilas.canary.checkOutbound(hitContent);

check("canary hit detected on shallow token", () => {
  assert.strictEqual(checkResult.hit, true);
  assert.ok(checkResult.tokens?.some((t) => t.id === shallow.id));
});

check("canary hit severity is alarm (first hit)", () => {
  assert.strictEqual(checkResult.severity, "alarm");
});

check("L0 logged canary_hit event", () => {
  const entries = ilas.log.getAll();
  assert.ok(entries.some((e) => e.eventType === "canary_hit"));
});

// Feed canary alarm to verdict engine
const canaryAlarmSignal = sig("soft_alarm", "m3", `canary hit: depth=shallow id=${shallow.id}`);
const stateAfterCanaryAlarm = ilas.verdict.processSignal(canaryAlarmSignal);

check("soft_alarm from M3: VERIFIED → DEGRADED", () => {
  assert.strictEqual(stateAfterCanaryAlarm, IntegrityState.DEGRADED);
});

// ── M5: Drift breach → material signal ───────────────────────────────────────

// temperature baseline=100, threshold baseline=200 → totalBaseline=300
// Push temperature way up: cumulative change must exceed 10% of 300 = 30
// Change temperature by 31 in one step
const driftResult = ilas.drift.recordChange("temperature", 131);

check("drift change triggers material status", () => {
  assert.strictEqual(driftResult.status, "material");
});

check("drift snapshot captures correct delta", () => {
  assert.strictEqual(driftResult.snapshot.absoluteChange, 31);
  assert.strictEqual(driftResult.snapshot.previousValue, 100);
  assert.strictEqual(driftResult.snapshot.currentValue, 131);
});

check("L0 logged parameter_changed event with material outcome", () => {
  const entries = ilas.log.getAll();
  const changeEvents = entries.filter((e) => e.eventType === "parameter_changed");
  assert.ok(changeEvents.some((e) => e.outcome === "material"));
});

// Feed drift material signal to verdict engine
const driftMaterialSignal = sig("hard_alarm", "m5", `material drift on temperature: Δ31`);
const stateAfterDrift = ilas.verdict.processSignal(driftMaterialSignal);

check("hard_alarm from M5: → QUARANTINED", () => {
  assert.strictEqual(stateAfterDrift, IntegrityState.QUARANTINED);
});

// ── Chain integrity ───────────────────────────────────────────────────────────

const verifyResult = ilas.log.verify();

check("L0 Merkle chain is valid after all operations", () => {
  assert.deepStrictEqual(verifyResult, { valid: true });
});

check("L0 contains events from all four modules (l0 init, m3, m5, v0)", () => {
  const entries = ilas.log.getAll();
  const moduleIds = new Set(entries.map((e) => e.moduleId));
  assert.ok(moduleIds.has("m3"), "missing m3 entries");
  assert.ok(moduleIds.has("m5"), "missing m5 entries");
  assert.ok(moduleIds.has("v0"), "missing v0 entries");
});

// ── Final status ──────────────────────────────────────────────────────────────

const finalStatus = ilas.status();

check("status() reports QUARANTINED", () => {
  assert.strictEqual(finalStatus.state, IntegrityState.QUARANTINED);
});

check("status() reports 3 active canaries", () => {
  assert.strictEqual(finalStatus.activeCanaries, 3);
});

check("status() reports non-zero cumulativeDrift", () => {
  assert.ok(finalStatus.cumulativeDrift > 0);
});

check("status() logSize matches actual chain length", () => {
  assert.strictEqual(finalStatus.logSize, ilas.log.length);
});

// ── Summary ───────────────────────────────────────────────────────────────────

console.log("\n── Final status() ──────────────────────────────────────────────");
console.log(JSON.stringify(finalStatus, null, 2));
console.log("\n── State history ───────────────────────────────────────────────");
for (const h of ilas.verdict.getHistory()) {
  console.log(`  [${h.state.padEnd(12)}] ${h.reason}`);
}
console.log(`\n── L0 chain: ${ilas.log.length} entries, valid=${verifyResult.valid} ──`);

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
