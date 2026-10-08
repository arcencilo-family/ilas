// ──────────────────────────────────────────────────────────────────────────────
// ILAS — S-4 continuity predicate: cost, equivalence, odd sequence numbers, and
// the verdict precedence for rejected receipts.
// House style: standalone ts-node script, custom check() harness.
//   npx ts-node src/s4/continuity.test.ts
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";

import { LockedEvidenceLog, recomputeHeadHashAt, recomputeHeadHashes } from "../l0";
import type { LogEntry } from "../types";
import { ContinuityVerifier, GENESIS_HEAD_HASH } from "./index";
import type { ContinuityMismatch, HeadCommit, Witness, WitnessReceipt } from "./index";

let passed = 0;
let failed = 0;
const pending: Array<() => Promise<void>> = [];

function check(name: string, fn: () => void | Promise<void>): void {
  pending.push(async () => {
    try {
      await fn();
      console.log(`  ✓ ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✗ ${name}`);
      console.error(`    ${(err as Error).message}`);
      failed++;
    }
  });
}

function section(title: string): void {
  pending.push(async () => console.log(`── ${title} ──`));
}

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

async function chain(n: number): Promise<LockedEvidenceLog> {
  const log = new LockedEvidenceLog();
  for (let i = 0; i < n; i++) await log.append(entry(i));
  return log;
}

/** A Witness that hands over fixed receipts and, optionally, a rejection report. */
function witnessOf(
  receipts: WitnessReceipt[],
  issues?: { rejected: number; reasons: readonly string[] }
): Witness {
  const w: Witness = {
    id: "stub",
    submit(_c: HeadCommit): void {},
    retrieveReceipts: () => [...receipts],
  };
  if (issues !== undefined) w.retrievalIssues = () => issues;
  return w;
}

function receipt(seq_no: number, head_hash: string): WitnessReceipt {
  return { seq_no, head_hash, witness_ts: 1, witness_sig: "unchecked-here" };
}

/**
 * A stand-in log over `entries` that counts how many entry reads the verifier
 * makes. ContinuityVerifier only reads getAll().
 */
function countingLog(entries: readonly LogEntry[]): { log: LockedEvidenceLog; reads: () => number } {
  let reads = 0;
  const proxy = new Proxy(entries as LogEntry[], {
    get(target, prop, receiver) {
      if (typeof prop === "string" && /^\d+$/.test(prop)) reads++;
      return Reflect.get(target, prop, receiver);
    },
  });
  const log = { getAll: () => proxy } as unknown as LockedEvidenceLog;
  return { log, reads: () => reads };
}

/**
 * The predicate as it was specified per receipt: each receipt recomputed on its
 * own from genesis with recomputeHeadHashAt. Used as the oracle the one-pass
 * verifier must agree with.
 */
function perReceiptOracle(entries: readonly LogEntry[], receipts: WitnessReceipt[]) {
  const out: Array<Pick<ContinuityMismatch, "seq_no" | "expected_head_hash" | "recomputed_head_hash">> = [];
  for (const r of receipts) {
    if (!Number.isSafeInteger(r.seq_no)) {
      out.push({ seq_no: r.seq_no, expected_head_hash: r.head_hash, recomputed_head_hash: null });
      continue;
    }
    if (r.seq_no < 0) {
      if (!(r.seq_no === -1 && r.head_hash === GENESIS_HEAD_HASH)) {
        out.push({
          seq_no: r.seq_no,
          expected_head_hash: r.head_hash,
          recomputed_head_hash: r.seq_no === -1 ? GENESIS_HEAD_HASH : null,
        });
      }
      continue;
    }
    const recomputed = recomputeHeadHashAt(entries, r.seq_no);
    if (recomputed !== r.head_hash) {
      out.push({ seq_no: r.seq_no, expected_head_hash: r.head_hash, recomputed_head_hash: recomputed });
    }
  }
  return out;
}

function strip(ms: ContinuityMismatch[]) {
  return ms.map(({ seq_no, expected_head_hash, recomputed_head_hash }) => ({
    seq_no,
    expected_head_hash,
    recomputed_head_hash,
  }));
}

/** Entries with entry `at` rewritten — new objects, the originals stay frozen. */
function rewrittenAt(entries: readonly LogEntry[], at: number): LogEntry[] {
  return entries.map((e, i) => (i === at ? ({ ...e, outcome: "REWRITTEN" } as LogEntry) : e));
}

// ── 1 · cost: one pass, not one replay per receipt ──────────────────────────

section("1: the predicate's cost is linear in chain + receipts");

const N = 20_000;
const RECEIPTS = 200;
let big: readonly LogEntry[] = [];

check(`1a: ${N} entries, ${RECEIPTS} receipts ⇒ VERIFIED_HISTORICAL in well under a few seconds`, async () => {
  big = (await chain(N)).getAll();
  const receipts: WitnessReceipt[] = [];
  for (let k = 0; k < RECEIPTS; k++) {
    const seq = k * (N / RECEIPTS) + (N / RECEIPTS - 1); // 99, 199, …, 19999
    receipts.push(receipt(seq, big[seq].hash));
  }
  const { log, reads } = countingLog(big);
  const started = process.hrtime.bigint();
  const report = new ContinuityVerifier(log, witnessOf(receipts)).verify();
  const ms = Number(process.hrtime.bigint() - started) / 1e6;

  assert.equal(report.status, "VERIFIED_HISTORICAL");
  assert.equal(report.receiptsChecked, RECEIPTS);
  // Deterministic, load-independent: each entry is read at most once. A replay
  // from genesis per receipt reads ~2,000,000 entries here.
  assert.ok(reads() <= N, `the verifier read ${reads()} entries for a ${N}-entry chain`);
  assert.ok(ms < 2_500, `verify() took ${ms.toFixed(0)} ms`);
});

check("1b: on the same chain, rewritten at 15000, the mismatches equal the per-receipt recomputation", () => {
  assert.equal(big.length, N, "precondition: 1a built the chain");
  const live = rewrittenAt(big, 15_000);
  const receipts: WitnessReceipt[] = [];
  for (let k = 0; k < RECEIPTS; k++) {
    const seq = k * (N / RECEIPTS) + (N / RECEIPTS - 1);
    receipts.push(receipt(seq, big[seq].hash));
  }
  const report = new ContinuityVerifier(countingLog(live).log, witnessOf(receipts)).verify();
  assert.equal(report.status, "MISMATCH");
  const expectedSeqs = receipts.map((r) => r.seq_no).filter((s) => s >= 15_000);
  assert.deepEqual(report.mismatches.map((m) => m.seq_no), expectedSeqs);
  // The oracle replays from genesis per receipt, so check it on a sample that
  // straddles the rewrite (each replay costs up to 20000 hashes).
  const sample = receipts.filter((r) => [99, 199, 14_899, 14_999, 15_099, 19_999].includes(r.seq_no));
  assert.equal(sample.length, 6);
  const sampled = new Set(sample.map((r) => r.seq_no));
  assert.deepEqual(
    strip(report.mismatches.filter((m) => sampled.has(m.seq_no))),
    perReceiptOracle(live, sample)
  );
});

check("1c: differential — 300 mixed receipts on a rewritten chain agree with the per-receipt oracle", async () => {
  const entries = (await chain(800)).getAll();
  const live = rewrittenAt(entries, 517);
  // Deterministic pseudo-random receipts: right heads, wrong heads, beyond the
  // end, the empty prefix (right and wrong), below -1, and non-integers.
  let seed = 12345;
  const rand = (m: number) => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; // 32-bit LCG
    return (seed >>> 8) % m;
  };
  const receipts: WitnessReceipt[] = [];
  for (let i = 0; i < 300; i++) {
    const kind = rand(8);
    const seq = rand(820) - 2; // -2 … 817: some below -1, some past the end
    if (kind === 0) receipts.push(receipt(seq, "f".repeat(64)));
    else if (kind === 1) receipts.push(receipt(-1, GENESIS_HEAD_HASH));
    else if (kind === 2) receipts.push(receipt(seq + 0.5, "e".repeat(64)));
    else {
      const head = seq >= 0 && seq < entries.length ? entries[seq].hash : GENESIS_HEAD_HASH;
      receipts.push(receipt(seq, head));
    }
  }
  const report = new ContinuityVerifier(countingLog(live).log, witnessOf(receipts)).verify();
  const oracle = perReceiptOracle(live, receipts);
  assert.ok(oracle.length > 50 && oracle.length < 300, `a mix, not all one way (${oracle.length})`);
  assert.deepEqual(strip(report.mismatches), oracle);
  assert.equal(report.status, oracle.length > 0 ? "MISMATCH" : "VERIFIED_HISTORICAL");
  assert.equal(report.receiptsChecked, 300);
});

// ── 2 · sequence numbers that name no prefix ────────────────────────────────

section("2: a seq_no that is not an integer ≥ -1 names no prefix ⇒ MISMATCH");

check("2a: NaN, 1.5, -2, -0.5, Infinity and the string '2' are MISMATCH, never reproduced", async () => {
  const log = await chain(3);
  const e = log.getAll();
  const cases: Array<[string, WitnessReceipt]> = [
    ["NaN + genesis hash", receipt(NaN, GENESIS_HEAD_HASH)],
    ["NaN + head(0)", receipt(NaN, e[0].hash)],
    ["1.5 + head(1)", receipt(1.5, e[1].hash)],
    ["2.5 + head(2)", receipt(2.5, e[2].hash)],
    ["-0.5 + genesis hash", receipt(-0.5, GENESIS_HEAD_HASH)],
    ["-2 + genesis hash", receipt(-2, GENESIS_HEAD_HASH)],
    ["Infinity + head(2)", receipt(Infinity, e[2].hash)],
    ["'2' + head(2)", receipt("2" as unknown as number, e[2].hash)],
  ];
  for (const [label, r] of cases) {
    const report = new ContinuityVerifier(log, witnessOf([r])).verify();
    assert.equal(report.status, "MISMATCH", label);
    assert.equal(report.mismatches.length, 1, label);
    assert.equal(report.mismatches[0].recomputed_head_hash, null, label);
  }
});

check("2b: the integer controls beside them still reproduce", async () => {
  const log = await chain(3);
  const e = log.getAll();
  const report = new ContinuityVerifier(
    log,
    witnessOf([receipt(-1, GENESIS_HEAD_HASH), receipt(0, e[0].hash), receipt(2, e[2].hash)])
  ).verify();
  assert.equal(report.status, "VERIFIED_HISTORICAL");
  assert.equal(report.receiptsChecked, 3);
});

check("2c: recomputeHeadHashAt itself names no head for a non-integer", async () => {
  const e = (await chain(3)).getAll();
  assert.equal(recomputeHeadHashAt(e, 1.5), null);
  assert.equal(recomputeHeadHashAt(e, NaN), null);
  assert.equal(recomputeHeadHashAt(e, 0.5), null);
  assert.equal(recomputeHeadHashAt(e, 1), e[1].hash);
});

// ── 3 · verdict precedence with rejected receipts ───────────────────────────

section("3: REJECTED_RECEIPTS — after MISMATCH, before CANNOT_VERIFY_CONTINUITY");

check("3a: a Witness without retrievalIssues is read as rejecting nothing", async () => {
  const log = await chain(2);
  const report = new ContinuityVerifier(log, witnessOf([receipt(1, log.getAll()[1].hash)])).verify();
  assert.equal(report.status, "VERIFIED_HISTORICAL");
  assert.equal(report.rejectedReceipts, 0);
  assert.deepEqual(report.rejectReasons, []);
  const empty = new ContinuityVerifier(log, witnessOf([])).verify();
  assert.equal(empty.status, "CANNOT_VERIFY_CONTINUITY");
  assert.equal(empty.rejectedReceipts, 0);
});

check("3b: reproducing receipts + a rejection ⇒ REJECTED_RECEIPTS, reasons carried", async () => {
  const log = await chain(2);
  const report = new ContinuityVerifier(
    log,
    witnessOf([receipt(1, log.getAll()[1].hash)], { rejected: 1, reasons: ["receipt-x: bad"] })
  ).verify();
  assert.equal(report.status, "REJECTED_RECEIPTS");
  assert.equal(report.receiptsChecked, 1);
  assert.equal(report.rejectedReceipts, 1);
  assert.deepEqual(report.rejectReasons, ["receipt-x: bad"]);
});

check("3c: no receipts + a rejection ⇒ REJECTED_RECEIPTS, not CANNOT_VERIFY_CONTINUITY", async () => {
  const log = await chain(2);
  const report = new ContinuityVerifier(log, witnessOf([], { rejected: 2, reasons: ["a", "b"] })).verify();
  assert.equal(report.status, "REJECTED_RECEIPTS");
  assert.equal(report.receiptsChecked, 0);
  assert.equal(report.rejectedReceipts, 2);
});

check("3d: a mismatch + a rejection ⇒ MISMATCH, with the rejection still reported", async () => {
  const log = await chain(2);
  const report = new ContinuityVerifier(
    log,
    witnessOf([receipt(1, "f".repeat(64))], { rejected: 1, reasons: ["r"] })
  ).verify();
  assert.equal(report.status, "MISMATCH");
  assert.equal(report.rejectedReceipts, 1);
});

check("3e: an issues report of zero rejections changes nothing", async () => {
  const log = await chain(2);
  const report = new ContinuityVerifier(log, witnessOf([], { rejected: 0, reasons: [] })).verify();
  assert.equal(report.status, "CANNOT_VERIFY_CONTINUITY");
});

// ── 4 · an entry too deep to hash ───────────────────────────────────────────

section("4: an entry the stack cannot hash makes its receipts MISMATCH; nothing throws");

/** The entries of a 4-entry chain with entry 2's parameters nested far past any stack. */
async function withUnhashableAt2(): Promise<LogEntry[]> {
  const entries = (await chain(4)).getAll();
  let deep: unknown = 1;
  for (let i = 0; i < 200_000; i++) deep = [deep];
  return entries.map((e, i) =>
    i === 2 ? ({ ...e, parameters: { deep } } as unknown as LogEntry) : e
  );
}

check("4a: recomputeHeadHashAt / recomputeHeadHashes return null from that entry on, and never throw", async () => {
  const entries = await withUnhashableAt2();
  assert.equal(recomputeHeadHashAt(entries, 1), entries[1].hash, "the prefix before it still reproduces");
  assert.equal(recomputeHeadHashAt(entries, 2), null);
  assert.equal(recomputeHeadHashAt(entries, 3), null);
  const heads = recomputeHeadHashes(entries, [0, 1, 2, 3, 7]);
  assert.deepEqual([...heads.entries()], [
    [0, entries[0].hash],
    [1, entries[1].hash],
    [2, null],
    [3, null],
    [7, null],
  ]);
});

check("4b: receipts at or past it ⇒ MISMATCH with a reason saying the entry cannot be hashed; before it they reproduce", async () => {
  const entries = await withUnhashableAt2();
  const log = { getAll: () => entries } as unknown as LockedEvidenceLog;
  const report = new ContinuityVerifier(
    log,
    witnessOf([
      receipt(1, entries[1].hash),
      receipt(2, entries[2].hash),
      receipt(3, "f".repeat(64)),
      receipt(9, "e".repeat(64)),
    ])
  ).verify();
  assert.equal(report.status, "MISMATCH");
  assert.equal(report.receiptsChecked, 4);
  assert.deepEqual(report.mismatches.map((m) => m.seq_no), [2, 3, 9]);
  for (const m of report.mismatches.slice(0, 2)) {
    assert.equal(m.recomputed_head_hash, null);
    assert.equal(
      m.reason,
      `the head at seq ${m.seq_no} cannot be recomputed: an entry up to it cannot be hashed`
    );
  }
  assert.match(report.mismatches[2].reason, /absent \(truncated or rebuilt short\)/, "the truncation reason is kept for seq past the end");
});

// ── run ─────────────────────────────────────────────────────────────────────

(async () => {
  for (const step of pending) await step();
  console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
})();
