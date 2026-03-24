import assert from "assert";
import { ProvenanceTracker } from "./index";
import { LockedEvidenceLog } from "../l0";

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

console.log("\nM7 — ProvenanceTracker Test\n");

const log = new LockedEvidenceLog();
const tracker = new ProvenanceTracker(log);

// ── checkPermission ───────────────────────────────────────────────────────────

check("memory_write is permitted on LaneA", () => {
  const r = tracker.checkPermission("memory_write", "LaneA");
  assert.strictEqual(r.permitted, true);
});

check("memory_write is NOT permitted on LaneC", () => {
  const r = tracker.checkPermission("memory_write", "LaneC");
  assert.strictEqual(r.permitted, false);
  assert.deepStrictEqual(r.expectedLanes, ["LaneA"]);
});

check("canary_plant is permitted on LaneB", () => {
  const r = tracker.checkPermission("canary_plant", "LaneB");
  assert.strictEqual(r.permitted, true);
});

check("config_change is permitted on LaneC only", () => {
  const r = tracker.checkPermission("config_change", "LaneA");
  assert.strictEqual(r.permitted, false);
  assert.deepStrictEqual(r.expectedLanes, ["LaneC"]);
});

check("memory_read is permitted on LaneA and LaneB", () => {
  const rA = tracker.checkPermission("memory_read", "LaneA");
  const rB = tracker.checkPermission("memory_read", "LaneB");
  assert.strictEqual(rA.permitted, true);
  assert.strictEqual(rB.permitted, true);
});

// ── tagAction — permitted ─────────────────────────────────────────────────────

check("tagAction(external_call, LaneA) logs permitted", () => {
  const r = tracker.tagAction("external_call", "LaneA");
  assert.strictEqual(r.permitted, true);
  const entries = log.getAll();
  const last = entries[entries.length - 1];
  assert.strictEqual(last.eventType, "action_tagged");
  assert.strictEqual(last.outcome, "permitted");
});

// ── tagAction — mismatch ──────────────────────────────────────────────────────

check("mismatch count starts at 0", () => {
  // Create fresh tracker so mismatch count is clean
  const t = new ProvenanceTracker();
  assert.strictEqual(t.getMismatchCount(), 0);
  assert.strictEqual(t.shouldAlarm(), false);
});

check("tagAction(file_op, LaneA) is a mismatch, increments count", () => {
  const t = new ProvenanceTracker();
  const r = t.tagAction("file_op", "LaneA");
  assert.strictEqual(r.permitted, false);
  assert.strictEqual(t.getMismatchCount(), 1);
  assert.strictEqual(t.shouldAlarm(), false); // threshold is 2
});

check("two mismatches trigger shouldAlarm()", () => {
  const t = new ProvenanceTracker();
  t.tagAction("file_op", "LaneA");
  t.tagAction("config_change", "LaneB");
  assert.strictEqual(t.getMismatchCount(), 2);
  assert.strictEqual(t.shouldAlarm(), true);
});

check("L0 logs mismatch outcome", () => {
  const l = new LockedEvidenceLog();
  const t = new ProvenanceTracker(l);
  t.tagAction("canary_plant", "LaneA"); // wrong lane
  const mismatches = l.getAll().filter((e) => e.outcome === "mismatch");
  assert.strictEqual(mismatches.length, 1);
  assert.strictEqual(mismatches[0].moduleId, "m7");
});

// ── L0 chain integrity ────────────────────────────────────────────────────────

check("L0 chain valid after all operations", () => {
  const verify = log.verify();
  assert.deepStrictEqual(verify, { valid: true });
});

// ── Summary ───────────────────────────────────────────────────────────────────

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
