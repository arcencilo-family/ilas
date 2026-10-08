// ──────────────────────────────────────────────────────────────────────────────
// ILAS — L0 durability + S-4 continuity acceptance tests
// (durable chain: README "L0 durability"; continuity: docs/S4-WIRE-SPEC.md §6)
// House style: standalone ts-node script, custom check() harness.
//   npx ts-node src/l0/l0.durability.test.ts
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { createHash } from "crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { LockedEvidenceLog, L0PayloadError, L0WriteError, recomputeHeadHashAt } from "./index";
import type { DurabilityInfo } from "./index";
import type { LogEntry } from "../types";
import { ILASKillStack } from "../index";
import { ContinuityVerifier, GENESIS_HEAD_HASH } from "../s4";
import type { Witness, WitnessReceipt, HeadCommit } from "../s4";

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

/** The file's lines, parsed. */
function readLines(p: string): Array<Record<string, unknown>> {
  return readFileSync(p, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l));
}

function writeLines(p: string, lines: unknown[]): void {
  writeFileSync(p, lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
}

/** An entry's own hash, exactly as docs/S4-WIRE-SPEC.md §5 defines it. */
function ownHash(e: Record<string, unknown>): string {
  return createHash("sha256")
    .update(
      JSON.stringify({
        sequenceNumber: e.sequenceNumber,
        previousHash: e.previousHash,
        timestamp: e.timestamp,
        moduleId: e.moduleId,
        eventType: e.eventType,
        provenanceTag: e.provenanceTag,
        parameters: e.parameters,
        outcome: e.outcome,
        clerkReceipt: e.clerkReceipt,
      })
    )
    .digest("hex");
}

/** The load surface must say the same thing through isClean() and the status field. */
function assertCleanAgrees(log: LockedEvidenceLog, expected: boolean): void {
  assert.equal(log.isClean(), expected, "isClean()");
  assert.equal(log.getDurabilityInfo().clean, expected, "getDurabilityInfo().clean must agree with isClean()");
}

/** A witness that returns whatever receipts we inject — for continuity tests. */
class TestWitness implements Witness {
  readonly id = "test-witness";
  private readonly receipts: WitnessReceipt[] = [];
  submit(_c: HeadCommit): void {}
  inject(r: WitnessReceipt): void {
    this.receipts.push(r);
  }
  retrieveReceipts(): WitnessReceipt[] {
    return this.receipts;
  }
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

console.log("── Durable append survives a fresh construction ──");

check("append 3 → reload same path → length 3, verify valid, LOADED_VERIFIED", () => {
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
  assertCleanAgrees(b, true);
  assert.equal(b.getDurabilityInfo().entriesLoaded, 3);
  // The reload owns the file now: the first log can no longer fork it.
  assert.throws(() => a.append(entry(9)), (err: unknown) => err instanceof L0WriteError && /superseded/.test((err as Error).message));
  assert.equal(a.length, 3);
  // continues to append coherently after reload
  b.append(entry(4));
  assert.equal(b.length, 4);
  assert.equal(b.verify().valid, true);
  assert.equal(b.getDurabilityInfo().entriesLoaded, 3, "entriesLoaded is fixed at load, not the live length");
  assert.equal(readLines(p).length, 4, "the file holds exactly the owner's chain");
});

console.log("── A missing log file MUST NOT produce a clean start ──");

check("absent file ⇒ FIRST_BOOT_OR_ERASED, NOT clean, NOT verified", () => {
  const p = freshPath();
  const log = new LockedEvidenceLog({ path: p });
  assert.equal(log.getLoadState(), "FIRST_BOOT_OR_ERASED");
  assertCleanAgrees(log, false);
});

check("EMPTY but present file ⇒ FIRST_BOOT_OR_ERASED, NOT clean, persists onward", () => {
  const p = freshPath();
  writeFileSync(p, "");
  const log = new LockedEvidenceLog({ path: p });
  assert.equal(log.getLoadState(), "FIRST_BOOT_OR_ERASED");
  assertCleanAgrees(log, false);
  assert.equal(log.loadedExisting(), false);
  assert.equal(log.getDurabilityInfo().persisting, true);
  log.append(entry(1));
  assert.equal(readLines(p).length, 1);
});

check("UNREADABLE file ⇒ CANNOT_VERIFY, not clean, not persisting, and nothing is written to it", () => {
  if (process.getuid?.() === 0) return; // root reads mode 0200 files; nothing to test
  const p = freshPath();
  writeFileSync(p, "{}\n");
  chmodSync(p, 0o200);
  try {
    const log = new LockedEvidenceLog({ path: p });
    assert.equal(log.getLoadState(), "CANNOT_VERIFY");
    assertCleanAgrees(log, false);
    const info = log.getDurabilityInfo();
    assert.equal(info.persisting, false);
    assert.ok(info.lastError, "the read failure is not reported");
    log.append(entry(1));
  } finally {
    chmodSync(p, 0o644);
  }
  assert.equal(readFileSync(p, "utf8"), "{}\n", "an append was written onto a file that could not be read");
});

/**
 * A log path whose file is absent (ENOENT) but whose directory cannot be
 * created: the parent is a dangling symlink. Works the same as root.
 */
function uncreatableDirPath(): string {
  const dangling = freshPath();
  symlinkSync(join(root, `nowhere-${counter++}`), dangling);
  return join(dangling, "l0.jsonl");
}

check("log directory cannot be created ⇒ append THROWS L0WriteError; memory does not run ahead of disk", () => {
  const p = uncreatableDirPath();
  const log = new LockedEvidenceLog({ path: p });
  assert.equal(log.getLoadState(), "FIRST_BOOT_OR_ERASED");
  assert.equal(log.getDurabilityInfo().writeHealthy, false);
  assert.throws(() => log.append(entry(1)), L0WriteError);
  assert.throws(() => log.append(entry(2)), L0WriteError);
  assert.equal(log.length, 0, "an entry committed in memory only");
  assert.equal(existsSync(p), false);
  const info = log.getDurabilityInfo();
  assert.equal(info.persisting, false);
  assert.match(info.lastError ?? "", /log directory/);
  // The assembly fails at start-up, as it does for any durable write failure.
  assert.throws(() => new ILASKillStack({ logPath: p }), L0WriteError);
});

check("history that cannot be reached (directory not searchable, EACCES) ⇒ CANNOT_VERIFY, not FIRST_BOOT_OR_ERASED; nothing written", () => {
  if (process.getuid?.() === 0) return; // root searches a 0600 directory; nothing to test
  const dir = freshPath();
  mkdirSync(dir);
  const p = join(dir, "l0.jsonl");
  new LockedEvidenceLog({ path: p }).append(entry(0));
  const before = readFileSync(p);
  chmodSync(dir, 0o600);
  let info: DurabilityInfo | null = null;
  let lengthAfterAppend = -1;
  try {
    const log = new LockedEvidenceLog({ path: p });
    info = log.getDurabilityInfo();
    log.append(entry(1)); // memory only: nothing may be written where we cannot read
    lengthAfterAppend = log.length;
  } finally {
    chmodSync(dir, 0o700);
  }
  assert.ok(info !== null);
  assert.equal(info.loadState, "CANNOT_VERIFY", "an unreachable history was reported as absent");
  assert.equal(info.clean, false);
  assert.equal(info.persisting, false);
  assert.match(info.lastError ?? "", /cannot read log file.*EACCES/);
  assert.equal(lengthAfterAppend, 1);
  assert.deepEqual(readFileSync(p), before, "the file changed");
});

check("a log path that runs through a file (ENOTDIR) ⇒ CANNOT_VERIFY, not FIRST_BOOT_OR_ERASED", () => {
  // A trailing slash on an existing log file: the history IS there.
  const p = freshPath();
  new LockedEvidenceLog({ path: p }).append(entry(0));
  const before = readFileSync(p);
  const slashed = new LockedEvidenceLog({ path: `${p}/` }).getDurabilityInfo();
  assert.equal(slashed.loadState, "CANNOT_VERIFY", "existing history was reported as absent");
  assert.equal(slashed.persisting, false);
  assert.match(slashed.lastError ?? "", /ENOTDIR/);
  assert.deepEqual(readFileSync(p), before);
  // A path under a regular file, through the assembly: the node starts non-clean.
  const blocker = freshPath();
  writeFileSync(blocker, "a regular file, not a directory\n");
  const s = new ILASKillStack({ logPath: join(blocker, "l0.jsonl") });
  const d = s.status().logDurability;
  assert.equal(d.loadState, "CANNOT_VERIFY");
  assert.equal(d.clean, false);
  assert.equal(d.persisting, false);
  assert.equal(readFileSync(blocker, "utf8"), "a regular file, not a directory\n");
});

check("rm after writing ⇒ next construction is FIRST_BOOT_OR_ERASED, not clean", () => {
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p });
  a.append(entry(1));
  a.append(entry(2));
  unlinkSync(p); // simulate `rm` of the deployed log
  const b = new LockedEvidenceLog({ path: p });
  assert.equal(b.getLoadState(), "FIRST_BOOT_OR_ERASED");
  assert.equal(b.isClean(), false);
  assert.equal(b.length, 0, "erased history does not resurrect");
});

console.log("── Truncation verifies internally; the receipt predicate catches it ──");

check("drop last K lines ⇒ reload verify() VALID (a valid prefix)", () => {
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p });
  for (let i = 0; i < 8; i++) a.append(entry(i));
  const headAt2 = a.getEntry(2)!.hash;
  const headAt5 = a.getEntry(5)!.hash;

  // Truncate on disk: keep only the first 4 lines (seq 0..3).
  const kept = readFileSync(p, "utf8").split("\n").filter((l) => l.trim()).slice(0, 4);
  writeFileSync(p, kept.join("\n") + "\n");

  const b = new LockedEvidenceLog({ path: p });
  assert.equal(b.getLoadState(), "LOADED_VERIFIED", "truncated prefix still loads clean");
  assert.equal(b.verify().valid, true, "verify() alone CANNOT see truncation");
  assert.equal(b.length, 4);

  // The predicate is the thing that catches it, once receipts exist.
  const w = new TestWitness();
  w.inject({ seq_no: 2, head_hash: headAt2, witness_ts: 1, witness_sig: "sig" });
  w.inject({ seq_no: 5, head_hash: headAt5, witness_ts: 2, witness_sig: "sig" });
  const report = new ContinuityVerifier(b, w).verify();
  assert.equal(report.status, "MISMATCH", "continuity catches the truncation");
  assert.equal(report.mismatches.length, 1, "seq 5 is the missing one");
  assert.equal(report.mismatches[0].seq_no, 5);
  assert.equal(report.mismatches[0].recomputed_head_hash, null, "seq 5 absent from live chain");
});

console.log("── A corrupt middle entry ⇒ CANNOT_VERIFY, fail closed ──");

check("corrupt a middle entry ⇒ verify()/load reports the break, brokenAt correct", () => {
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
  assertCleanAgrees(b, false);
  assert.equal(info.brokenAt, 2, "brokenAt points at the tampered entry");
  assert.equal(info.persisting, false, "fail closed: does not persist onto an unverified chain");
  assert.equal(info.entriesLoaded, 5);
});

check("malformed JSON line ⇒ CANNOT_VERIFY", () => {
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p });
  a.append(entry(1));
  a.append(entry(2));
  writeFileSync(p, readFileSync(p, "utf8") + "{not json}\n");
  const b = new LockedEvidenceLog({ path: p });
  assert.equal(b.getLoadState(), "CANNOT_VERIFY");
  assertCleanAgrees(b, false);
  assert.equal(b.getDurabilityInfo().persisting, false);
});

check("a stored sequenceNumber that is not the entry's position ⇒ CANNOT_VERIFY at the first wrong line", () => {
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p });
  for (let i = 0; i < 4; i++) a.append(entry(i));
  const lines = readLines(p);
  lines[1].sequenceNumber = 3; // the hash covers the position, not this field,
  lines[3].sequenceNumber = 1; // so only a direct check can see the swap
  writeLines(p, lines);
  const b = new LockedEvidenceLog({ path: p });
  assert.equal(b.getLoadState(), "CANNOT_VERIFY");
  assertCleanAgrees(b, false);
  assert.equal(b.getDurabilityInfo().brokenAt, 1);
  assert.equal(b.getDurabilityInfo().persisting, false);
});

check("a field the entry does not have, injected into a line ⇒ CANNOT_VERIFY naming the field", () => {
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p });
  for (let i = 0; i < 3; i++) a.append(entry(i));
  const lines = readLines(p);
  lines[1].approvedBy = "security department"; // outside the hash: nothing else can see it
  writeLines(p, lines);
  const b = new LockedEvidenceLog({ path: p });
  assert.equal(b.getLoadState(), "CANNOT_VERIFY");
  assertCleanAgrees(b, false);
  const info = b.getDurabilityInfo();
  assert.equal(info.brokenAt, 1);
  assert.match(info.lastError ?? "", /approvedBy/);
  assert.equal(info.persisting, false);
});

/** A log of `n` entries, closed, and the text of its lines. */
function closedLog(n: number): { p: string; lines: string[] } {
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p, fsync: false });
  for (let i = 0; i < n; i++) a.append(entry(i));
  a.close();
  return { p, lines: readFileSync(p, "utf8").split("\n").filter((l) => l.length > 0) };
}

/** Reload `p` and expect CANNOT_VERIFY at line `at`, with a lastError naming that line. */
function assertNotStoredAsWritten(p: string, at: number, label: string): void {
  const log = new LockedEvidenceLog({ path: p, fsync: false });
  const d = log.getDurabilityInfo();
  log.close();
  assert.equal(d.loadState, "CANNOT_VERIFY", `${label}: loaded as ${d.loadState}`);
  assert.equal(d.clean, false);
  assert.equal(d.persisting, false, `${label}: persisting onto a file it refused`);
  assert.equal(d.brokenAt, at, `${label}: brokenAt ${d.brokenAt} (${d.lastError})`);
  assert.match(d.lastError ?? "", new RegExp(`^line ${at} is not stored as L0 writes it`), label);
}

check("a repeated key in a stored line (top level or nested) ⇒ CANNOT_VERIFY at that line", () => {
  // JSON.parse keeps the LAST value: the hash, and everything after it, sees
  // only that one, while a reader of the file sees the first.
  const edits: Array<[string, number, (l: string) => string]> = [
    ["outcome", 1, (l) => l.replace('"outcome":"ok"', '"outcome":"approved by security","outcome":"ok"')],
    ["parameters.n", 2, (l) => l.replace('"parameters":{"n":2}', '"parameters":{"n":99,"n":2}')],
  ];
  for (const [label, at, edit] of edits) {
    const { p, lines } = closedLog(4);
    const edited = edit(lines[at]);
    assert.notEqual(edited, lines[at], `${label}: precondition: the edit applies`);
    assert.deepEqual(JSON.parse(edited), JSON.parse(lines[at]), `${label}: precondition: it parses to the same entry`);
    lines[at] = edited;
    writeFileSync(p, lines.join("\n") + "\n");
    assertNotStoredAsWritten(p, at, label);
  }
});

check("extra whitespace, another escape, CRLF or bytes that are not UTF-8 in a line ⇒ CANNOT_VERIFY at it", () => {
  const edits: Array<[string, (l: string) => string | Buffer]> = [
    ["a space after a colon", (l) => l.replace('"moduleId":"test"', '"moduleId": "test"')],
    ["a trailing space", (l) => `${l} `],
    ["an escaped letter", (l) => l.replace('"moduleId":"test"', '"moduleId":"t\\u0065st"')],
    ["an escaped slash", (l) => l.replace('"eventType":"unit"', '"eventType":"un\\/it"')],
    ["a carriage return before the newline", (l) => `${l}\r`],
    ["an invalid UTF-8 byte (read as U+FFFD)", (l) => {
      const at = l.indexOf('"outcome":"ok"') + '"outcome":"'.length;
      return Buffer.concat([Buffer.from(l.slice(0, at)), Buffer.from([0xff]), Buffer.from(l.slice(at))]);
    }],
  ];
  for (const [label, edit] of edits) {
    const { p, lines } = closedLog(3);
    const parts: Buffer[] = lines.map((l) => Buffer.from(l));
    const edited = edit(lines[1]);
    parts[1] = typeof edited === "string" ? Buffer.from(edited) : edited;
    writeFileSync(p, Buffer.concat(parts.flatMap((b) => [b, Buffer.from("\n")])));
    assertNotStoredAsWritten(p, 1, label);
  }
});

check("every line L0 writes loads back: unusual strings and numbers, a last line without its newline", () => {
  // No false refusal: each of these is stored as JSON.stringify writes it.
  const odd = {
    separators: "  ",
    loneSurrogates: "\ud800 \udfff",
    controls: "\u0000\u0001\u001f\u007f\t\n\r",
    quotes: "\"\\/'",
    emoji: "😀 é € 中",
    numbers: [1e21, 5e-324, -0, 0.1 + 0.2, -1.5e-7, Number.MAX_SAFE_INTEGER],
    keys: { b: 1, "10": 2, "2": 3, a: 4, "": 5 },
    empty: [{}, [], ""],
  };
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p, fsync: false });
  a.append(entry(0));
  a.append({ ...entry(1), parameters: odd, outcome: " " });
  a.append(entry(2));
  const hashes = a.getAll().map((e) => e.hash);
  a.close();
  writeFileSync(p, readFileSync(p).subarray(0, -1)); // drop the final newline
  const b = new LockedEvidenceLog({ path: p, fsync: false });
  const d = b.getDurabilityInfo();
  assert.equal(d.loadState, "LOADED_VERIFIED", `refused: ${d.lastError}`);
  assert.deepEqual(b.getAll().map((e) => e.hash), hashes);
  b.append(entry(3));
  b.close();
  const c = new LockedEvidenceLog({ path: p, fsync: false });
  assert.equal(c.getLoadState(), "LOADED_VERIFIED", `after an append: ${c.getDurabilityInfo().lastError}`);
  assert.equal(c.length, 4);
  c.close();
});

check("a blank line between entries ⇒ CANNOT_VERIFY at it: L0 never writes one", () => {
  for (const blank of ["", "   ", "\t"]) {
    const { p, lines } = closedLog(3);
    writeFileSync(p, [lines[0], lines[1], blank, lines[2]].join("\n") + "\n");
    const d = new LockedEvidenceLog({ path: p, fsync: false }).getDurabilityInfo();
    assert.equal(d.loadState, "CANNOT_VERIFY", `${JSON.stringify(blank)}: loaded as ${d.loadState}`);
    assert.equal(d.brokenAt, 2);
    assert.match(d.lastError ?? "", /^malformed JSON at line 2/);
  }
});

check("the file is never decoded as one string: a log whose whole text exceeds the longest string the runtime makes still loads", () => {
  // The ceiling here is the runtime's maximum string length (512 MiB on V8),
  // scaled down: any decode of more than LIMIT bytes in one string fails, as a
  // decode past the real ceiling does. Each line fits; the file does not.
  const LIMIT = 16 * 1024;
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p, fsync: false });
  for (let i = 0; i < 400; i++) a.append({ ...entry(i), parameters: { n: i, pad: "x".repeat(100) } });
  const hashes = a.getAll().map((e) => e.hash);
  a.close();
  assert.ok(readFileSync(p).length > 4 * LIMIT, "precondition: the file exceeds the scaled-down ceiling");
  const toString = Buffer.prototype.toString;
  Buffer.prototype.toString = function (this: Buffer, encoding?: BufferEncoding, start?: number, end?: number) {
    const from = Math.max(0, start ?? 0);
    const to = Math.min(this.length, end ?? this.length);
    if (to - from > LIMIT) throw new RangeError(`Cannot create a string longer than ${LIMIT} characters`);
    return toString.call(this, encoding, start, end);
  } as typeof toString;
  let d: DurabilityInfo;
  let loaded: string[];
  try {
    const b = new LockedEvidenceLog({ path: p, fsync: false });
    d = b.getDurabilityInfo();
    loaded = b.getAll().map((e) => e.hash);
    b.close();
  } finally {
    Buffer.prototype.toString = toString;
  }
  assert.equal(d.loadState, "LOADED_VERIFIED", `refused: ${d.lastError}`);
  assert.equal(d.persisting, true);
  assert.deepEqual(loaded, hashes);
});

check("lines longer than the read size, and characters split across reads, load exactly", () => {
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p, fsync: false });
  a.append(entry(0));
  // 3 MiB of 1- to 4-byte characters: line 1 spans several reads, and reads
  // end inside characters.
  a.append({ ...entry(1), parameters: { pad: "a€é😀".repeat(300_000) } });
  a.append(entry(2));
  a.append({ ...entry(3), parameters: { pad: "😀".repeat(400_001) } });
  const hashes = a.getAll().map((e) => e.hash);
  a.close();
  writeFileSync(p, readFileSync(p).subarray(0, -1)); // and the last of them without its newline
  const b = new LockedEvidenceLog({ path: p, fsync: false });
  const d = b.getDurabilityInfo();
  assert.equal(d.loadState, "LOADED_VERIFIED", `refused: ${d.lastError}`);
  assert.deepEqual(b.getAll().map((e) => e.hash), hashes);
  b.append(entry(4));
  b.close();
  assert.equal(new LockedEvidenceLog({ path: p, fsync: false }).length, 5);
});

check("a line that is valid JSON but not an object ⇒ CANNOT_VERIFY", () => {
  for (const junk of ["null", "[]", "42", '"text"']) {
    const p = freshPath();
    const a = new LockedEvidenceLog({ path: p });
    a.append(entry(1));
    writeFileSync(p, readFileSync(p, "utf8") + junk + "\n");
    const b = new LockedEvidenceLog({ path: p });
    assert.equal(b.getLoadState(), "CANNOT_VERIFY", `accepted a line reading ${junk}`);
    assert.equal(b.getDurabilityInfo().brokenAt, 1);
  }
});

/** One stored line whose parameters nest `depth` arrays deep. */
function deepLine(depth: number, previousHash: string): string {
  return (
    `{"sequenceNumber":0,"hash":"x","previousHash":"${previousHash}","timestamp":1,` +
    `"moduleId":"m","eventType":"e","provenanceTag":"LaneA",` +
    `"parameters":{"a":${"[".repeat(depth)}${"]".repeat(depth)}},"outcome":"ok"}\n`
  );
}

check("a line nested deeper than the stack allows ⇒ CANNOT_VERIFY, never a throw from the constructor", () => {
  // JSON.parse copes with all of these. Deeper ones defeat the recursive freeze;
  // shallower ones (with the genesis link, so the hash IS recomputed) defeat
  // the hash recomputation in verify(). Every one must load CANNOT_VERIFY.
  for (const previousHash of ["y", "0".repeat(64)]) {
    for (const depth of [3_000, 5_000, 7_000, 20_000, 50_000]) {
      const label = `depth ${depth}, previousHash ${previousHash.slice(0, 4)}`;
      const p = freshPath();
      writeFileSync(p, deepLine(depth, previousHash));
      let log: LockedEvidenceLog;
      try {
        log = new LockedEvidenceLog({ path: p });
      } catch (err) {
        throw new Error(`${label}: the constructor threw ${(err as Error).name}: ${(err as Error).message}`);
      }
      const d = log.getDurabilityInfo();
      assert.equal(d.loadState, "CANNOT_VERIFY", `${label}: ${d.loadState}`);
      assert.equal(d.clean, false);
      assert.equal(d.persisting, false, `${label}: persisting onto an unverified file`);
      assert.equal(d.brokenAt, 0, `${label}: brokenAt ${d.brokenAt}`);
      assert.ok(d.lastError, `${label}: no lastError`);
      const v = log.verify(); // must not throw either
      assert.equal(v.valid, log.length === 0, `${label}: verify() ${JSON.stringify(v)}`);
      let status: DurabilityInfo;
      try {
        status = new ILASKillStack({ logPath: p }).status().logDurability;
      } catch (err) {
        throw new Error(`${label}: ILASKillStack threw ${(err as Error).name}: ${(err as Error).message}`);
      }
      assert.equal(status.loadState, "CANNOT_VERIFY", `${label}: the assembly`);
    }
  }
});

check("a kept entry too deep to hash, with a witness receipt at or past it ⇒ status() and continuity report MISMATCH, never a throw", () => {
  // Depths the recursive freeze can finish but the hash cannot: the entry is
  // kept (CANNOT_VERIFY), and recomputing any head from it on cannot be done.
  let exercised = 0;
  for (const depth of [2_000, 3_000, 5_000, 7_000, 10_000]) {
    const label = `depth ${depth}`;
    const p = freshPath();
    writeFileSync(p, deepLine(depth, "0".repeat(64)));
    const log = new LockedEvidenceLog({ path: p });
    if (log.length === 0) continue; // not kept at this depth: nothing to recompute
    const w = new TestWitness();
    w.inject({ seq_no: 0, head_hash: "a".repeat(64), witness_ts: 1, witness_sig: "s" });
    let report;
    try {
      report = new ContinuityVerifier(log, w).verify();
    } catch (err) {
      throw new Error(`${label}: verify() threw ${(err as Error).name}: ${(err as Error).message}`);
    }
    assert.equal(report.status, "MISMATCH", `${label}: ${report.status}`);
    let status;
    try {
      status = new ILASKillStack({ logPath: p, witness: w }).status();
    } catch (err) {
      throw new Error(`${label}: status() threw ${(err as Error).name}: ${(err as Error).message}`);
    }
    assert.equal(status.continuity, "MISMATCH", `${label}: status().continuity`);
    assert.equal(status.logDurability.loadState, "CANNOT_VERIFY");
    if (report.mismatches[0].recomputed_head_hash === null) {
      assert.match(report.mismatches[0].reason, /cannot be recomputed: an entry up to it cannot be hashed/, label);
      exercised++;
    }
  }
  assert.ok(exercised > 0, "no depth produced a kept entry the hash could not cover; the check proved nothing");
});

check("a no-clerk append nested too deeply ⇒ L0PayloadError (never a raw RangeError); nothing written or committed", () => {
  let refused = 0;
  for (const depth of [1_000, 2_000, 3_000, 4_000, 5_000, 8_000, 20_000]) {
    const p = freshPath();
    const log = new LockedEvidenceLog({ path: p, fsync: false });
    log.append(entry(0));
    const before = readFileSync(p);
    let deep: unknown = 1;
    for (let i = 0; i < depth; i++) deep = [deep];
    let err: unknown = null;
    try {
      log.append({ ...entry(1), parameters: { deep } });
    } catch (e) {
      err = e;
    }
    if (err === null) {
      assert.equal(log.length, 2, `depth ${depth}`);
      continue;
    }
    assert.ok(err instanceof L0PayloadError, `depth ${depth}: ${(err as Error).name}: ${(err as Error).message}`);
    assert.equal(log.length, 1, `depth ${depth}: committed in memory`);
    assert.deepEqual(readFileSync(p), before, `depth ${depth}: written`);
    log.append(entry(2)); // the log goes on
    assert.equal(log.length, 2);
    refused++;
  }
  assert.ok(refused > 0, "no depth was refused; the check proved nothing");
});

check("ANY fault while loading (here an injected one) ⇒ CANNOT_VERIFY with lastError, never a throw", () => {
  const p = freshPath();
  new LockedEvidenceLog({ path: p }).append(entry(0));
  const equals = Buffer.prototype.equals;
  let log: LockedEvidenceLog | null = null;
  let thrown: unknown = null;
  // The fault: comparing a stored line with the form L0 writes throws a value
  // that has no string form.
  Buffer.prototype.equals = function () {
    throw Object.create(null);
  } as unknown as typeof equals;
  try {
    log = new LockedEvidenceLog({ path: p });
  } catch (err) {
    thrown = err;
  } finally {
    Buffer.prototype.equals = equals;
  }
  assert.equal(thrown, null, "the constructor threw");
  assert.ok(log !== null);
  const d = log.getDurabilityInfo();
  assert.equal(d.loadState, "CANNOT_VERIFY");
  assert.equal(d.clean, false);
  assert.equal(d.persisting, false);
  assert.match(d.lastError ?? "", /could not be loaded/);
  assert.equal(readLines(p).length, 1);
});

check("one middle entry rewritten with ITS OWN hash recomputed ⇒ the stale link on the next entry breaks", () => {
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p });
  for (let i = 0; i < 5; i++) a.append(entry(i));
  const lines = readLines(p);
  lines[2].outcome = "REWRITTEN";
  lines[2].hash = ownHash(lines[2]); // entry 2 is now self-consistent
  writeLines(p, lines);
  const b = new LockedEvidenceLog({ path: p });
  assert.equal(b.getLoadState(), "CANNOT_VERIFY");
  assertCleanAgrees(b, false);
  assert.equal(b.getDurabilityInfo().brokenAt, 3, "entry 3 still links to the old hash of entry 2");
  assert.equal(b.getDurabilityInfo().persisting, false);
});

check("one entry re-linked to a forged previousHash, own hash recomputed ⇒ broken AT that entry", () => {
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p });
  for (let i = 0; i < 5; i++) a.append(entry(i));
  const lines = readLines(p);
  lines[2].outcome = "REWRITTEN";
  lines[2].previousHash = "f".repeat(64);
  lines[2].hash = ownHash(lines[2]);
  writeLines(p, lines);
  const b = new LockedEvidenceLog({ path: p });
  assert.equal(b.getLoadState(), "CANNOT_VERIFY");
  assert.equal(b.getDurabilityInfo().brokenAt, 2);
  assert.deepEqual(b.verify(), { valid: false, brokenAt: 2 });
});

check("EACH hashed field, tampered on disk ⇒ CANNOT_VERIFY at that line", () => {
  const tampers: Array<[string, (e: Record<string, unknown>) => void]> = [
    ["timestamp", (e) => { e.timestamp = 1; }],
    ["moduleId", (e) => { e.moduleId = "m-forged"; }],
    ["eventType", (e) => { e.eventType = "forged"; }],
    ["provenanceTag", (e) => { e.provenanceTag = "LaneC"; }],
    ["parameters", (e) => { e.parameters = { n: 1_000_000 }; }],
    ["outcome", (e) => { e.outcome = "TAMPERED"; }],
    ["clerkReceipt", (e) => { e.clerkReceipt = { clerk_seq: 0 }; }],
  ];
  for (const [field, tamper] of tampers) {
    const p = freshPath();
    const a = new LockedEvidenceLog({ path: p });
    for (let i = 0; i < 4; i++) a.append(entry(i));
    const lines = readLines(p);
    tamper(lines[1]);
    writeLines(p, lines);
    const b = new LockedEvidenceLog({ path: p });
    assert.equal(b.getLoadState(), "CANNOT_VERIFY", `a tampered ${field} loaded as ${b.getLoadState()}`);
    assert.equal(b.getDurabilityInfo().brokenAt, 1, `${field}: brokenAt`);
    assert.notEqual(recomputeHeadHashAt(b.getAll(), 3), a.getEntry(3)!.hash, `${field}: the head did not move`);
  }
});

check("entriesLoaded counts what was read from disk: a malformed FIRST line loads 0", () => {
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p });
  for (let i = 0; i < 3; i++) a.append(entry(i));
  writeFileSync(p, "{not json}\n" + readFileSync(p, "utf8"));
  const s = new ILASKillStack({ logPath: p });
  const d = s.status().logDurability;
  assert.equal(d.loadState, "CANNOT_VERIFY");
  assert.equal(d.clean, false);
  assert.equal(d.entriesLoaded, 0, "nothing was loaded, whatever the stack appended since");
});

check("a tampered file under ILASKillStack: status() says clean:false and counts only the loaded entries", () => {
  const p = freshPath();
  const first = new ILASKillStack({ logPath: p });
  first.canary.plantCanary("shallow");
  first.canary.plantCanary("deep");
  const onDisk = readLines(p).length;
  const lines = readLines(p);
  lines[2].outcome = "TAMPERED";
  writeLines(p, lines);
  const s = new ILASKillStack({ logPath: p });
  const d = s.status().logDurability;
  assert.equal(d.loadState, "CANNOT_VERIFY");
  assert.equal(d.clean, false, "the status surface reported a tampered log as clean");
  assert.equal(d.brokenAt, 2);
  assert.equal(d.entriesLoaded, onDisk, `entriesLoaded ${d.entriesLoaded}, file holds ${onDisk}`);
  assert.ok(s.status().logSize > onDisk, "precondition: the stack appended after the load");
});

console.log("── What a caller does with its objects afterwards changes nothing ──");

check("parameters changed after a durable append: verify valid, head unchanged, memory equals the reload", () => {
  const p = freshPath();
  const log = new LockedEvidenceLog({ path: p });
  const params = { tags: ["a", "b"] };
  log.append({ ...entry(1), parameters: params });
  const head = log.getEntry(0)!.hash;
  params.tags.reverse();
  params.tags.push("zzz");
  assert.deepEqual(log.verify(), { valid: true });
  assert.equal(recomputeHeadHashAt(log.getAll(), 0), head);
  assert.deepEqual(log.getEntry(0)!.parameters, new LockedEvidenceLog({ path: p }).getEntry(0)!.parameters);
  assert.ok(Object.isFrozen(log.getEntry(0)!.parameters), "a committed entry is not frozen");
});

check("getAll() cannot change the chain: truncate, reorder or replace throws; memory, disk and reload agree", () => {
  const p = freshPath();
  const log = new LockedEvidenceLog({ path: p });
  for (let i = 0; i < 3; i++) log.append(entry(i));
  const hashes = log.getAll().map((e) => e.hash);
  const all = log.getAll() as LogEntry[];
  assert.ok(Object.isFrozen(all), "getAll() handed out a mutable array");
  const forged = { ...all[2], sequenceNumber: 1, previousHash: all[0].hash };
  const attempts: Array<[string, () => unknown]> = [
    ["length = 1", () => { all.length = 1; }],
    ["pop()", () => all.pop()],
    ["splice(1, 1)", () => all.splice(1, 1)],
    ["reverse()", () => all.reverse()],
    ["sort()", () => all.sort((a, b) => b.sequenceNumber - a.sequenceNumber)],
    ["[1] = forged", () => { all[1] = forged; }],
  ];
  for (const [label, attempt] of attempts) assert.throws(attempt, TypeError, `${label} did not throw`);
  assert.equal(log.length, 3, "the chain was changed through getAll()");
  assert.deepEqual(log.getAll().map((e) => e.hash), hashes);
  assert.deepEqual(log.verify(), { valid: true });
  log.append(entry(9));
  assert.equal(log.getEntry(3)!.sequenceNumber, 3, "the next append reused a sequence number already on disk");
  assert.equal(all.length, 3, "an array handed out earlier is a live view");
  assert.equal(readLines(p).length, 4);
  assertCleanAgrees(new LockedEvidenceLog({ path: p }), true);
});

check("rotate() result edited by the caller: no false MISMATCH, and the active families stay", () => {
  const p = freshPath();
  const w = new TestWitness();
  const s = new ILASKillStack({ logPath: p, witness: w });
  for (const id of ["a", "b", "c", "d"]) {
    s.rotation.registerFamily(id, id, () => ({ moduleId: "x", severity: "clean", message: "", timestamp: 0 }));
  }
  const r = s.rotation.rotate();
  const active = s.rotation.getActiveFamilies();
  const last = s.log.length - 1;
  w.inject({ seq_no: last, head_hash: s.log.getEntry(last)!.hash, witness_ts: 1, witness_sig: "s" });
  assert.equal(s.verifyContinuity().status, "VERIFIED_HISTORICAL");
  r.selectedFamilies.sort().reverse();
  r.selectedFamilies.push("zzz");
  assert.deepEqual(s.log.verify(), { valid: true });
  assert.equal(s.verifyContinuity().status, "VERIFIED_HISTORICAL", "a caller's edit read as tampering");
  assert.deepEqual(s.rotation.getActiveFamilies(), active, "the caller changed which families run");
});

console.log("── A write failure MUST surface, not be swallowed ──");

check("file made read-only mid-run ⇒ the running log writes through the descriptor it opened; the next start loads it read-only and every append throws L0WriteError", () => {
  if (process.getuid?.() === 0) return; // root writes a 0444 file; nothing to test
  const p = freshPath();
  const log = new LockedEvidenceLog({ path: p });
  log.append(entry(1)); // creates the file
  chmodSync(p, 0o444); // read-only
  let restarted: LockedEvidenceLog | null = null;
  let threw = false;
  try {
    log.append(entry(2)); // the file was opened once, at load
    restarted = new LockedEvidenceLog({ path: p });
    try {
      restarted.append(entry(3));
    } catch (e) {
      threw = e instanceof L0WriteError;
    }
  } finally {
    chmodSync(p, 0o644); // restore so cleanup can remove it
  }
  assert.equal(log.length, 2);
  assert.ok(restarted !== null);
  assert.equal(restarted.getLoadState(), "LOADED_VERIFIED");
  assert.equal(threw, true, "append must throw on write failure");
  assert.equal(restarted.getDurabilityInfo().writeHealthy, false, "durability marked unhealthy");
  assert.equal(restarted.length, 2, "memory did not diverge from disk (entry not committed)");
  assert.equal(readLines(p).length, 2);
});

check("a write that fails part-way (injected: half the line, then ENOSPC) ⇒ L0WriteError, the file unchanged, memory did not diverge", () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const fs = require("fs") as typeof import("fs");
  const p = freshPath();
  const log = new LockedEvidenceLog({ path: p });
  log.append(entry(1));
  const before = readFileSync(p);
  const real = fs.writeSync;
  (fs as { writeSync: unknown }).writeSync = (fd: number, buf: Buffer, off: number, len: number) => {
    real(fd, buf, off, Math.floor(len / 2));
    throw Object.assign(new Error("ENOSPC: injected"), { code: "ENOSPC" });
  };
  try {
    assert.throws(() => log.append(entry(2)), L0WriteError);
  } finally {
    (fs as { writeSync: unknown }).writeSync = real;
  }
  assert.equal(log.getDurabilityInfo().writeHealthy, false);
  assert.equal(log.length, 1);
  assert.deepEqual(readFileSync(p), before, "a partial line was left in the file");
});

console.log("── Bootstrap does not inflate across restarts ──");

check("ILASKillStack restarts 3× ⇒ no +10 bootstrap inflation, length stable", () => {
  const p = freshPath();
  const first = new ILASKillStack({ logPath: p });
  const bootstrap = first.log.length; // 10 probe_registered seeds
  assert.equal(bootstrap, 10, "fresh boot seeds exactly 10 bootstrap entries");
  first.log.append(entry(100));
  first.log.append(entry(101));
  const expected = bootstrap + 2; // 12

  let len = 0;
  for (let r = 0; r < 3; r++) {
    const s = new ILASKillStack({ logPath: p });
    len = s.log.length;
    assert.equal(len, expected, `restart ${r + 1}: length ${len} must equal ${expected}, not inflate`);
    assert.equal(s.log.verify().valid, true, `restart ${r + 1}: chain still valid`);
    assert.equal(s.log.getLoadState(), "LOADED_VERIFIED");
  }
});

check("a bootstrap cut short (4 of 10 on disk) is COMPLETED on restart; a second restart adds nothing", () => {
  const p = freshPath();
  const first = new ILASKillStack({ logPath: p });
  assert.equal(first.log.length, 10);
  // The process died after four bootstrap entries reached the disk.
  writeFileSync(p, readFileSync(p, "utf8").split("\n").filter((l) => l.trim()).slice(0, 4).join("\n") + "\n");

  const registered = (s: ILASKillStack) =>
    s.log
      .getAll()
      .filter((e) => e.eventType === "probe_registered")
      .map((e) => e.parameters.id as string);

  const second = new ILASKillStack({ logPath: p });
  assert.equal(second.log.getLoadState(), "LOADED_VERIFIED");
  const ids = registered(second);
  assert.equal(ids.length, 10, `registrations on the chain: ${ids.join(",")}`);
  assert.equal(new Set(ids).size, 10, "a probe was registered twice");
  assert.equal(second.log.verify().valid, true);
  assert.equal(readLines(p).length, 10, "the completed bootstrap did not reach the disk");

  const third = new ILASKillStack({ logPath: p });
  assert.equal(third.log.length, 10, "a restart after the repair inflated the chain");
});

console.log("── Continuity states (docs/S4-WIRE-SPEC.md §6) ──");

check("NullWitness (no receipts) ⇒ CANNOT_VERIFY_CONTINUITY", () => {
  const s = new ILASKillStack(); // default NullWitness
  assert.equal(s.verifyContinuity().status, "CANNOT_VERIFY_CONTINUITY");
});

check("all receipts reproduce ⇒ VERIFIED_HISTORICAL", () => {
  const p = freshPath();
  const log = new LockedEvidenceLog({ path: p });
  for (let i = 0; i < 6; i++) log.append(entry(i));
  const w = new TestWitness();
  w.inject({ seq_no: 1, head_hash: log.getEntry(1)!.hash, witness_ts: 1, witness_sig: "s" });
  w.inject({ seq_no: 4, head_hash: log.getEntry(4)!.hash, witness_ts: 2, witness_sig: "s" });
  const report = new ContinuityVerifier(log, w).verify();
  assert.equal(report.status, "VERIFIED_HISTORICAL");
  assert.equal(report.receiptsChecked, 2);
});

check("a wrong witnessed head ⇒ MISMATCH (hard finding)", () => {
  const p = freshPath();
  const log = new LockedEvidenceLog({ path: p });
  for (let i = 0; i < 4; i++) log.append(entry(i));
  const w = new TestWitness();
  w.inject({ seq_no: 2, head_hash: "deadbeef".repeat(8), witness_ts: 1, witness_sig: "s" });
  const report = new ContinuityVerifier(log, w).verify();
  assert.equal(report.status, "MISMATCH");
  assert.equal(report.mismatches[0].seq_no, 2);
});

check("empty-chain receipt (seq -1, genesis hash) on an EMPTY chain ⇒ VERIFIED_HISTORICAL", () => {
  const log = new LockedEvidenceLog();
  const w = new TestWitness();
  w.inject({ seq_no: -1, head_hash: GENESIS_HEAD_HASH, witness_ts: 1, witness_sig: "s" });
  const report = new ContinuityVerifier(log, w).verify();
  assert.equal(report.status, "VERIFIED_HISTORICAL");
  assert.equal(report.receiptsChecked, 1);
});

check("empty-chain receipt still reproduces after the chain has grown", () => {
  const log = new LockedEvidenceLog();
  for (let i = 0; i < 3; i++) log.append(entry(i));
  const w = new TestWitness();
  w.inject({ seq_no: -1, head_hash: GENESIS_HEAD_HASH, witness_ts: 1, witness_sig: "s" });
  w.inject({ seq_no: 2, head_hash: log.getEntry(2)!.hash, witness_ts: 2, witness_sig: "s" });
  assert.equal(new ContinuityVerifier(log, w).verify().status, "VERIFIED_HISTORICAL");
});

check("seq -1 with a NON-genesis hash ⇒ MISMATCH", () => {
  const w = new TestWitness();
  w.inject({ seq_no: -1, head_hash: "ab".repeat(32), witness_ts: 1, witness_sig: "s" });
  const report = new ContinuityVerifier(new LockedEvidenceLog(), w).verify();
  assert.equal(report.status, "MISMATCH");
  assert.equal(report.mismatches[0].recomputed_head_hash, GENESIS_HEAD_HASH);
});

check("seq below -1 names no prefix ⇒ MISMATCH", () => {
  const w = new TestWitness();
  w.inject({ seq_no: -2, head_hash: GENESIS_HEAD_HASH, witness_ts: 1, witness_sig: "s" });
  assert.equal(new ContinuityVerifier(new LockedEvidenceLog(), w).verify().status, "MISMATCH");
});

check("a clean continuity result upgrades NOTHING (v0 state untouched)", () => {
  const s = new ILASKillStack();
  const before = s.verdict.getState();
  s.verifyContinuity(); // even when it would be clean, must not move state
  assert.equal(s.verdict.getState(), before, "continuity must not upgrade v0 state");
});

// ── cleanup ─────────────────────────────────────────────────────────────────
rmSync(root, { recursive: true, force: true });

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
