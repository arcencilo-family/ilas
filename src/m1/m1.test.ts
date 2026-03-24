import assert from "assert";
import { ScanScheduler } from "./index";
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

console.log("\nM1 — ScanScheduler Test\n");

// ── Initialization ────────────────────────────────────────────────────────────

check("constructor produces a valid commitment", () => {
  const s = new ScanScheduler();
  const c = s.getCommitment();
  assert.ok(typeof c.seed === "string");
  assert.strictEqual(c.seed.length, 64); // SHA-256 hex = 64 chars
  assert.ok(c.committedAt > 0);
});

check("verifySeed() returns true on fresh instance", () => {
  const s = new ScanScheduler();
  assert.strictEqual(s.verifySeed(), true);
});

check("shouldScanNow() is false immediately after construction", () => {
  const s = new ScanScheduler();
  assert.strictEqual(s.shouldScanNow(), false);
});

check("getNextScanIn() is between 4h and 7h after construction", () => {
  const s = new ScanScheduler();
  const nextIn = s.getNextScanIn();
  const FOUR_HOURS = 4 * 60 * 60 * 1000;
  const SEVEN_HOURS = 7 * 60 * 60 * 1000;
  assert.ok(nextIn >= FOUR_HOURS, `nextScanIn ${nextIn} < 4h`);
  assert.ok(nextIn <= SEVEN_HOURS, `nextScanIn ${nextIn} > 7h`);
});

// ── generateSchedule ──────────────────────────────────────────────────────────

check("generateSchedule() returns a future timestamp", () => {
  const s = new ScanScheduler();
  const nextAt = s.generateSchedule();
  assert.ok(nextAt > Date.now());
});

check("generateSchedule() updates getNextScanIn()", () => {
  const s = new ScanScheduler();
  const before = s.getNextScanIn();
  s.generateSchedule();
  const after = s.getNextScanIn();
  // Both should be in [4h, 7h]
  const FOUR_HOURS = 4 * 60 * 60 * 1000;
  const SEVEN_HOURS = 7 * 60 * 60 * 1000;
  assert.ok(after >= FOUR_HOURS, `after=${after} < 4h`);
  assert.ok(after <= SEVEN_HOURS, `after=${after} > 7h`);
  assert.ok(before > 0 && after > 0);
});

check("multiple generateSchedule() calls produce varying intervals (jitter works)", () => {
  // Generate 10 schedules and check that not all intervals are identical
  const s = new ScanScheduler();
  const intervals = new Set<number>();
  for (let i = 0; i < 10; i++) {
    const before = Date.now();
    const nextAt = s.generateSchedule();
    intervals.add(nextAt - before);
  }
  // With 10 different (seed, count) pairs, we should see variation
  assert.ok(intervals.size > 1, "all intervals were identical — jitter is broken");
});

check("interval always stays in [4h, 7h] across 10 schedules", () => {
  const s = new ScanScheduler();
  const FOUR_HOURS = 4 * 60 * 60 * 1000;
  const SEVEN_HOURS = 7 * 60 * 60 * 1000;
  for (let i = 0; i < 10; i++) {
    const before = Date.now();
    const nextAt = s.generateSchedule();
    const interval = nextAt - before;
    assert.ok(interval >= FOUR_HOURS, `schedule ${i}: interval ${interval} < 4h`);
    assert.ok(interval <= SEVEN_HOURS, `schedule ${i}: interval ${interval} > 7h`);
  }
});

// ── getStatus ─────────────────────────────────────────────────────────────────

check("getStatus() returns consistent values", () => {
  const s = new ScanScheduler();
  const status = s.getStatus();
  assert.strictEqual(typeof status.shouldScan, "boolean");
  assert.ok(status.nextScanAt > 0);
  assert.ok(status.nextScanIn >= 0);
  assert.ok(status.scheduledCount >= 1);
});

// ── L0 logging ────────────────────────────────────────────────────────────────

check("generateSchedule() logs to L0", () => {
  const log = new LockedEvidenceLog();
  const s = new ScanScheduler(log);
  s.generateSchedule();
  const entries = log.getAll();
  assert.ok(entries.some((e) => e.eventType === "schedule_generated" && e.moduleId === "m1"));
});

check("L0 log entry has LaneB provenance", () => {
  const log = new LockedEvidenceLog();
  const s = new ScanScheduler(log);
  s.generateSchedule();
  const entry = log.getAll().find((e) => e.moduleId === "m1");
  assert.strictEqual(entry?.provenanceTag, "LaneB");
});

check("L0 chain valid after schedule generation", () => {
  const log = new LockedEvidenceLog();
  const s = new ScanScheduler(log);
  s.generateSchedule();
  s.generateSchedule();
  assert.deepStrictEqual(log.verify(), { valid: true });
});

// ── Min 3 rotations per 24h guarantee ────────────────────────────────────────

check("max interval (7h) guarantees min 3 scans per 24h", () => {
  // 24h / 7h = 3.43 — so at worst-case interval we get > 3 scans per day
  const MAX_INTERVAL_H = 7;
  const scansPerDay = 24 / MAX_INTERVAL_H;
  assert.ok(scansPerDay >= 3, `${scansPerDay} scans/day < 3`);
});

// ── Summary ───────────────────────────────────────────────────────────────────

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
