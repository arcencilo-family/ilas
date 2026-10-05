// ──────────────────────────────────────────────────────────────────────────────
// ILAS — L0 durability acceptance tests
// House style: standalone ts-node script, custom check() harness.
//   npx ts-node src/l0/l0.durability.test.ts
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { chmodSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { LockedEvidenceLog, L0WriteError } from "./index";
import { ILASKillStack } from "../index";

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

const root = mkdtempSync(join(tmpdir(), "ilas-l0-dura-"));
let counter = 0;
const freshPath = (): string => join(root, `log-${counter++}.jsonl`);

function entry(n: number) {
  return {
    timestamp: 1_700_000_000_000 + n,
    moduleId: "test",
    eventType: "unit",
    provenanceTag: "LaneA" as const,
    parameters: { n },
    outcome: "ok",
  };
}

console.log("── Regression: in-memory default is unchanged ──");

check("no path ⇒ IN_MEMORY, not durable, append works, no file", () => {
  const log = new LockedEvidenceLog();
  assert.equal(log.getLoadState(), "IN_MEMORY");
  assert.equal(log.getDurabilityInfo().durable, false);
  log.append(entry(1));
  assert.equal(log.length, 1);
  assert.equal(log.verify().valid, true);
});

console.log("── T1: durable append survives a fresh construction ──");

check("T1: append 3 → reload same path → length 3, verify valid, LOADED_VERIFIED", () => {
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p });
  a.append(entry(1));
  a.append(entry(2));
  a.append(entry(3));
  assert.equal(a.length, 3);

  const b = new LockedEvidenceLog({ path: p });
  assert.equal(b.length, 3, "reloaded length");
  assert.equal(b.verify().valid, true, "reloaded chain verifies");
  assert.equal(b.getLoadState(), "LOADED_VERIFIED");
  assert.equal(b.isClean(), true);
  // continues to append coherently after reload
  b.append(entry(4));
  assert.equal(b.length, 4);
  assert.equal(b.verify().valid, true);
});

console.log("── T2: a missing log file MUST NOT produce a clean start ──");

check("T2: absent file ⇒ FIRST_BOOT_OR_ERASED, NOT clean", () => {
  const p = freshPath();
  const log = new LockedEvidenceLog({ path: p });
  assert.equal(log.getLoadState(), "FIRST_BOOT_OR_ERASED");
  assert.equal(log.isClean(), false, "must not be clean");
});

check("T2: rm after writing ⇒ next construction is FIRST_BOOT_OR_ERASED, not clean", () => {
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p });
  a.append(entry(1));
  a.append(entry(2));
  unlinkSync(p); // simulate rm of the log
  const b = new LockedEvidenceLog({ path: p });
  assert.equal(b.getLoadState(), "FIRST_BOOT_OR_ERASED");
  assert.equal(b.isClean(), false);
  assert.equal(b.length, 0, "erased history does not resurrect");
});

console.log("── T3: truncation verifies internally (needs an external anchor to catch) ──");

check("T3: drop last K lines ⇒ reload verify() VALID (a valid prefix)", () => {
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p });
  for (let i = 0; i < 8; i++) a.append(entry(i));

  // Truncate on disk: keep only the first 4 lines (seq 0..3).
  const kept = readFileSync(p, "utf8").split("\n").filter((l) => l.trim()).slice(0, 4);
  writeFileSync(p, kept.join("\n") + "\n");

  const b = new LockedEvidenceLog({ path: p });
  assert.equal(b.getLoadState(), "LOADED_VERIFIED", "truncated prefix still loads clean");
  assert.equal(b.verify().valid, true, "verify() alone CANNOT see truncation");
  assert.equal(b.length, 4);
});

console.log("── T4: a corrupt middle entry ⇒ CANNOT_VERIFY, fail closed ──");

check("T4: corrupt a middle entry ⇒ load reports the break, brokenAt correct", () => {
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p });
  for (let i = 0; i < 5; i++) a.append(entry(i));

  const lines = readFileSync(p, "utf8").split("\n").filter((l) => l.trim());
  const mid = JSON.parse(lines[2]);
  mid.outcome = "TAMPERED";
  lines[2] = JSON.stringify(mid);
  writeFileSync(p, lines.join("\n") + "\n");

  const b = new LockedEvidenceLog({ path: p });
  const info = b.getDurabilityInfo();
  assert.equal(b.getLoadState(), "CANNOT_VERIFY", "corrupt load must be cannot-verify");
  assert.equal(b.isClean(), false);
  assert.equal(info.brokenAt, 2, "brokenAt points at the tampered entry");
  assert.equal(info.persisting, false, "fail closed: does not persist onto an unverified chain");
});

check("T4b: malformed JSON line ⇒ CANNOT_VERIFY", () => {
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p });
  a.append(entry(1));
  a.append(entry(2));
  writeFileSync(p, readFileSync(p, "utf8") + "{not json}\n");
  const b = new LockedEvidenceLog({ path: p });
  assert.equal(b.getLoadState(), "CANNOT_VERIFY");
  assert.equal(b.getDurabilityInfo().persisting, false);
});

console.log("── T5: a write failure MUST surface, not be swallowed ──");

check("T5: file made read-only mid-run ⇒ append throws L0WriteError, writeHealthy false", () => {
  const p = freshPath();
  const log = new LockedEvidenceLog({ path: p });
  log.append(entry(1)); // creates the file
  chmodSync(p, 0o444); // read-only
  let threw = false;
  try {
    log.append(entry(2));
  } catch (e) {
    threw = e instanceof L0WriteError;
  } finally {
    chmodSync(p, 0o644); // restore so cleanup can remove it
  }
  assert.equal(threw, true, "append must throw on write failure");
  assert.equal(log.getDurabilityInfo().writeHealthy, false, "durability marked unhealthy");
  assert.equal(log.length, 1, "memory did not diverge from disk (entry not committed)");
});

console.log("── T6: bootstrap does not inflate across restarts ──");

check("T6: ILASKillStack restarts 3× ⇒ no bootstrap inflation, length stable", () => {
  const p = freshPath();
  const first = new ILASKillStack({ logPath: p });
  const bootstrap = first.log.length; // probe_registered seeds
  assert.equal(bootstrap, 10, "fresh boot seeds exactly 10 bootstrap entries");
  first.log.append(entry(100));
  first.log.append(entry(101));
  const expected = bootstrap + 2; // 12

  for (let r = 0; r < 3; r++) {
    const s = new ILASKillStack({ logPath: p });
    assert.equal(s.log.length, expected, `restart ${r + 1}: length must equal ${expected}, not inflate`);
    assert.equal(s.log.verify().valid, true, `restart ${r + 1}: chain still valid`);
    assert.equal(s.log.getLoadState(), "LOADED_VERIFIED");
    assert.equal(s.status().logDurability.clean, true, `restart ${r + 1}: status reports clean`);
  }
});

// ── cleanup ─────────────────────────────────────────────────────────────────
rmSync(root, { recursive: true, force: true });

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
