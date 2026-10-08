// ──────────────────────────────────────────────────────────────────────────────
// ILAS — a RELATIVE log path is anchored at the real working directory, not at
// Node's cached process.cwd().
//   npx ts-node src/l0/l0.cwd.test.ts
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { existsSync, mkdirSync, mkdtempSync, renameSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { LockedEvidenceLog } from "./index";

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

const home = process.cwd();
const root = mkdtempSync(join(tmpdir(), "ilas-l0-cwd-"));

function entry(n: number) {
  return { timestamp: 1_700_000_000_000 + n, moduleId: "t", eventType: "e", provenanceTag: "LaneA" as const, parameters: { n }, outcome: "ok" };
}

console.log("── Relative log paths follow the real working directory ──");

check("working directory removed after Node cached it ⇒ CANNOT_VERIFY, and the directory is NOT recreated", () => {
  const d = mkdtempSync(join(root, "gone-"));
  process.chdir(d);
  try {
    process.cwd(); // fill Node's cache with the soon-stale name
    rmSync(d, { recursive: true, force: true });
    const log = new LockedEvidenceLog({ path: "l0.jsonl", fsync: false });
    try {
      assert.equal(log.getLoadState(), "CANNOT_VERIFY", log.getDurabilityInfo().lastError ?? "");
      assert.equal(existsSync(d), false, "the removed working directory was created again");
    } finally {
      log.close();
    }
  } finally {
    process.chdir(home);
  }
});

check("working directory renamed and a new one made at the old name ⇒ the history where the process really is loads", () => {
  const a = join(root, "a");
  const b = join(root, "b");
  mkdirSync(a);
  const first = new LockedEvidenceLog({ path: join(a, "l0.jsonl"), fsync: false });
  for (let i = 0; i < 3; i++) first.append(entry(i));
  first.close();
  process.chdir(a);
  try {
    process.cwd(); // cache "a"
    renameSync(a, b); // the process now sits in "b"
    mkdirSync(a); // a fresh, empty directory at the old name
    const log = new LockedEvidenceLog({ path: "l0.jsonl", fsync: false });
    try {
      assert.equal(log.getLoadState(), "LOADED_VERIFIED", log.getDurabilityInfo().lastError ?? "");
      assert.equal(log.length, 3, "a second chain was started beside the real history");
      assert.equal(existsSync(join(a, "l0.jsonl")), false, "a log was created in the directory at the old name");
    } finally {
      log.close();
    }
  } finally {
    process.chdir(home);
  }
});

rmSync(root, { recursive: true, force: true });
console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
