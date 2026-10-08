import assert from "assert";
import { DetectionRotator } from "./index";
import { LockedEvidenceLog } from "../l0";
import type { ModuleSignal } from "../types";

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

function cleanSignal(moduleId: string): ModuleSignal {
  return { moduleId, severity: "clean", message: "ok", timestamp: Date.now() };
}

function alarmSignal(moduleId: string): ModuleSignal {
  return { moduleId, severity: "soft_alarm", message: "alarm", timestamp: Date.now() };
}

console.log("\nM2 — DetectionRotator Test\n");

// ── Rejection with fewer than 4 families ──────────────────────────────────────

check("rotate() throws when fewer than 4 families registered", () => {
  const r = new DetectionRotator();
  r.registerFamily("f1", "Family 1", () => cleanSignal("f1"));
  r.registerFamily("f2", "Family 2", () => cleanSignal("f2"));
  r.registerFamily("f3", "Family 3", () => cleanSignal("f3"));
  assert.throws(() => r.rotate(), /at least 4 families/);
});

// ── Setup ─────────────────────────────────────────────────────────────────────

const log = new LockedEvidenceLog();
const rot = new DetectionRotator(log);

rot.registerFamily("canary",     "Canary Tripwire",    () => cleanSignal("m3"));
rot.registerFamily("drift",      "Config Drift",        () => cleanSignal("m5"));
rot.registerFamily("provenance", "Provenance Tagging",  () => cleanSignal("m7"));
rot.registerFamily("privilege",  "Privilege Escalation",() => cleanSignal("m6"));

check("4 families registered without error", () => {
  // If we got here, registerFamily did not throw
  assert.ok(true);
});

check("L0 logged 4 family_registered events", () => {
  const entries = log.getAll().filter((e) => e.eventType === "family_registered");
  assert.strictEqual(entries.length, 4);
});

// ── rotate() — selection count and bounds ─────────────────────────────────────

const r1 = rot.rotate();

check("rotate() returns 2 or 3 families", () => {
  assert.ok(r1.selectedFamilies.length >= 2 && r1.selectedFamilies.length <= 3,
    `got ${r1.selectedFamilies.length}`);
});

check("rotate() returns rotationIndex 0 on first call", () => {
  assert.strictEqual(r1.rotationIndex, 0);
});

check("rotate() returns non-empty seed and commitment (64-char hex each)", () => {
  assert.strictEqual(r1.seed.length, 64);
  assert.strictEqual(r1.commitment.length, 64);
});

check("selected families are a subset of registered families", () => {
  const known = new Set(["canary", "drift", "provenance", "privilege"]);
  for (const id of r1.selectedFamilies) {
    assert.ok(known.has(id), `unknown family id: "${id}"`);
  }
});

// ── getActiveFamilies() ───────────────────────────────────────────────────────

check("getActiveFamilies() matches rotate() output", () => {
  assert.deepStrictEqual(rot.getActiveFamilies(), r1.selectedFamilies);
});

// ── Different selections across rotations (jitter) ───────────────────────────

check("multiple rotations produce different selections (crypto randomness)", () => {
  const seen = new Set<string>();
  seen.add(r1.selectedFamilies.slice().sort().join(","));
  for (let i = 0; i < 10; i++) {
    const rx = rot.rotate();
    seen.add(rx.selectedFamilies.slice().sort().join(","));
  }
  // With 10 random rotations over 4 families choosing 2–3, we must see >1 distinct selection
  assert.ok(seen.size > 1, `all rotations produced identical selections`);
});

// ── verifySeed() ──────────────────────────────────────────────────────────────

check("verifySeed() returns true for seed+commitment from rotate()", () => {
  assert.strictEqual(rot.verifySeed(r1.seed, r1.commitment), true);
});

check("verifySeed() returns false when seed is tampered", () => {
  const tampered = r1.seed.slice(0, -1) + (r1.seed.endsWith("0") ? "1" : "0");
  assert.strictEqual(rot.verifySeed(tampered, r1.commitment), false);
});

// ── runActiveFamilies() ───────────────────────────────────────────────────────

check("runActiveFamilies() returns one signal per active family", () => {
  // Rotate to get a known active set
  const rotFresh = new DetectionRotator();
  rotFresh.registerFamily("a", "A", () => cleanSignal("a"));
  rotFresh.registerFamily("b", "B", () => cleanSignal("b"));
  rotFresh.registerFamily("c", "C", () => cleanSignal("c"));
  rotFresh.registerFamily("d", "D", () => cleanSignal("d"));
  rotFresh.rotate();
  const signals = rotFresh.runActiveFamilies();
  const activeCount = rotFresh.getActiveFamilies().length;
  assert.strictEqual(signals.length, activeCount);
});

check("runActiveFamilies() captures exception from a throwing family as soft_alarm", () => {
  const rotBad = new DetectionRotator();
  rotBad.registerFamily("ok1",  "OK1",  () => cleanSignal("ok1"));
  rotBad.registerFamily("ok2",  "OK2",  () => cleanSignal("ok2"));
  rotBad.registerFamily("ok3",  "OK3",  () => cleanSignal("ok3"));
  rotBad.registerFamily("boom", "BOOM", () => { throw new Error("exploded"); });
  // Force boom into active set by running many rotations until it appears
  let foundBoom = false;
  for (let i = 0; i < 20 && !foundBoom; i++) {
    rotBad.rotate();
    if (rotBad.getActiveFamilies().includes("boom")) foundBoom = true;
  }
  if (!foundBoom) {
    // Skip gracefully if random didn't select it
    console.log("      (boom not selected in 20 rotations — skip)");
    return;
  }
  const signals = rotBad.runActiveFamilies();
  assert.ok(signals.some((s) => s.severity === "soft_alarm" && s.message.includes("boom")));
});

// ── trackRotationResults() + getPassCondition() ───────────────────────────────

check("getPassCondition() returns met=false before any results tracked", () => {
  const fresh = new DetectionRotator();
  fresh.registerFamily("a","A",()=>cleanSignal("a"));
  fresh.registerFamily("b","B",()=>cleanSignal("b"));
  fresh.registerFamily("c","C",()=>cleanSignal("c"));
  fresh.registerFamily("d","D",()=>cleanSignal("d"));
  const pc = fresh.getPassCondition();
  assert.strictEqual(pc.met, false);
  assert.strictEqual(pc.rotationsTested, 0);
});

check("pass condition met after 2 non-adjacent clean rotations (with 1 alarm between)", () => {
  // Build: rotation 0 (clean), rotation 1 (alarm), rotation 2 (clean)
  // Non-adjacent pair: (0, 2) — gap = 2 > 1 → nonAdjacentPasses = 1
  // rotationsTested = 3 >= MIN_ROTATIONS_PER_CYCLE(3) → met = true
  const fresh = new DetectionRotator();
  fresh.registerFamily("a","A",()=>cleanSignal("a"));
  fresh.registerFamily("b","B",()=>cleanSignal("b"));
  fresh.registerFamily("c","C",()=>cleanSignal("c"));
  fresh.registerFamily("d","D",()=>cleanSignal("d"));
  fresh.rotate(); fresh.trackRotationResults(0, [cleanSignal("a")]);
  fresh.rotate(); fresh.trackRotationResults(1, [alarmSignal("a")]);
  fresh.rotate(); fresh.trackRotationResults(2, [cleanSignal("a")]);
  const pc = fresh.getPassCondition();
  assert.strictEqual(pc.rotationsTested, 3);
  assert.ok(pc.nonAdjacentPasses >= 1, `expected nonAdjacentPasses >= 1, got ${pc.nonAdjacentPasses}`);
  assert.strictEqual(pc.met, true);
});

check("pass condition NOT met when only adjacent clean rotations exist", () => {
  const fresh = new DetectionRotator();
  fresh.registerFamily("a","A",()=>cleanSignal("a"));
  fresh.registerFamily("b","B",()=>cleanSignal("b"));
  fresh.registerFamily("c","C",()=>cleanSignal("c"));
  fresh.registerFamily("d","D",()=>cleanSignal("d"));
  // Rotation 0 and 1 both clean — but adjacent (gap = 1, not > 1)
  fresh.rotate(); fresh.trackRotationResults(0, [cleanSignal("a")]);
  fresh.rotate(); fresh.trackRotationResults(1, [cleanSignal("a")]);
  fresh.rotate(); fresh.trackRotationResults(2, [alarmSignal("a")]);
  const pc = fresh.getPassCondition();
  assert.strictEqual(pc.nonAdjacentPasses, 0);
  assert.strictEqual(pc.met, false);
});

check("pass condition NOT met with only 2 rotations tested (< 3 minimum)", () => {
  const fresh = new DetectionRotator();
  fresh.registerFamily("a","A",()=>cleanSignal("a"));
  fresh.registerFamily("b","B",()=>cleanSignal("b"));
  fresh.registerFamily("c","C",()=>cleanSignal("c"));
  fresh.registerFamily("d","D",()=>cleanSignal("d"));
  fresh.rotate(); fresh.trackRotationResults(0, [cleanSignal("a")]);
  fresh.rotate(); fresh.rotate();
  fresh.trackRotationResults(2, [cleanSignal("a")]);
  // Only 2 tracked (0 and 2) even though gap > 1 — rotationsTested < 3
  const pc = fresh.getPassCondition();
  assert.strictEqual(pc.rotationsTested, 2);
  assert.strictEqual(pc.met, false);
});

// ── getRotationCount() ────────────────────────────────────────────────────────

check("getRotationCount() increases with each rotate() call", () => {
  const fresh = new DetectionRotator();
  fresh.registerFamily("a","A",()=>cleanSignal("a"));
  fresh.registerFamily("b","B",()=>cleanSignal("b"));
  fresh.registerFamily("c","C",()=>cleanSignal("c"));
  fresh.registerFamily("d","D",()=>cleanSignal("d"));
  assert.strictEqual(fresh.getRotationCount(), 0);
  fresh.rotate();
  assert.strictEqual(fresh.getRotationCount(), 1);
  fresh.rotate();
  assert.strictEqual(fresh.getRotationCount(), 2);
});

// ── a caller's edits to a rotate() result change nothing inside ───────────────

check("editing rotate().selectedFamilies leaves the active set and the logged rotation alone", () => {
  const l = new LockedEvidenceLog();
  const r2 = new DetectionRotator(l);
  for (const id of ["a", "b", "c", "d"]) r2.registerFamily(id, id, () => cleanSignal(id));
  const result = r2.rotate();
  const active = r2.getActiveFamilies();
  const logged = [...(l.getAll().find((e) => e.eventType === "rotation")!.parameters.selectedFamilies as string[])];
  result.selectedFamilies.sort().reverse();
  result.selectedFamilies.push("zzz");
  assert.deepStrictEqual(r2.getActiveFamilies(), active, "the caller changed which families run");
  assert.ok(!r2.getActiveFamilies().includes("zzz"));
  assert.deepStrictEqual(
    l.getAll().find((e) => e.eventType === "rotation")!.parameters.selectedFamilies,
    logged
  );
  assert.deepStrictEqual(l.verify(), { valid: true });
});

// ── L0 chain integrity ────────────────────────────────────────────────────────

check("L0 chain valid after all operations", () => {
  assert.deepStrictEqual(log.verify(), { valid: true });
});

check("L0 contains rotation events with commitment logged", () => {
  const entries = log.getAll().filter((e) => e.eventType === "rotation");
  assert.ok(entries.length >= 1);
  assert.ok(typeof entries[0].parameters["commitment"] === "string");
});

// ── Summary ───────────────────────────────────────────────────────────────────

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
