// ──────────────────────────────────────────────────────────────────────────────
// ILAS — the published test vectors (docs/s4-test-vectors.json) reproduce with
// ILAS core code. A change to the hash rule, the canonical form or a verifier
// that would move the published bytes fails here, in the ordinary test run,
// not only in a manual regenerate-and-diff.
//   npx ts-node src/vectors.test.ts
//
// The hash_chain inputs are the generator's (scripts/s4-test-vectors.ts):
//   entry(n) = { timestamp: 1_700_000_000_000 + n, moduleId "test",
//                eventType "unit", provenanceTag "LaneA", parameters { n },
//                outcome "ok" },  n = 0..4, appended to an unstamped log.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { createPublicKey, verify as verifySignature } from "crypto";
import { readFileSync } from "fs";
import { join } from "path";
import { LockedEvidenceLog } from "./l0";
import type { ClerkSubmissionReceipt } from "./types";
import { canonicalise } from "./l0/canonical";
import { verifyClerkReceipt } from "./l0/clerk-verify";
import { canonicalReceiptPreimage } from "./s4/file-drop-witness";

let passed = 0;
let failed = 0;
const pending: Array<() => Promise<void>> = [];

function checkAsync(name: string, fn: () => Promise<void> | void): void {
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

interface WitnessVector {
  receipt: { seq_no: number; head_hash: string; witness_ts: number; witness_sig: string };
  preimage: string;
}
interface ClerkVector {
  record_signed: Record<string, unknown>;
  payload: unknown;
  preimage?: string;
}
interface Vectors {
  witness_public_key_spki_pem: string;
  clerk_public_key_spki_pem: string;
  hash_chain: { entries: Array<{ sequenceNumber: number; hash: string; previousHash: string }> };
  receipt_valid: WitnessVector;
  receipt_altered_seq: WitnessVector;
  clerk_receipt_valid: ClerkVector;
  clerk_receipt_wrong_payload: ClerkVector;
  canonical_examples: Array<{ input: unknown; canonical: string }>;
}

const V = JSON.parse(
  readFileSync(join(__dirname, "..", "docs", "s4-test-vectors.json"), "utf8")
) as Vectors;

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

const log = new LockedEvidenceLog();
for (let i = 0; i < 5; i++) log.append(entry(i));

console.log("── docs/s4-test-vectors.json reproduces with ILAS core ──");

checkAsync("hash_chain: every hash and previousHash reproduces from the generator's entries", () => {
  assert.equal(V.hash_chain.entries.length, 5);
  V.hash_chain.entries.forEach((want, i) => {
    const got = log.getEntry(i)!;
    assert.equal(got.sequenceNumber, want.sequenceNumber, `seq ${i}`);
    assert.equal(got.previousHash, want.previousHash, `previousHash at ${i}`);
    assert.equal(got.hash, want.hash, `hash at ${i}`);
  });
});

checkAsync("canonical_examples: every input canonicalises to the published bytes", () => {
  assert.ok(V.canonical_examples.length > 0);
  for (const ex of V.canonical_examples) {
    assert.equal(canonicalise(ex.input), ex.canonical, JSON.stringify(ex.input));
  }
});

checkAsync("witness receipt_valid: preimage reproduces, the signature verifies, and it names this chain's head", () => {
  const r = V.receipt_valid.receipt;
  const preimage = canonicalReceiptPreimage(r);
  assert.equal(preimage, V.receipt_valid.preimage);
  const ok = verifySignature(
    null,
    Buffer.from(preimage, "utf8"),
    createPublicKey(V.witness_public_key_spki_pem),
    Buffer.from(r.witness_sig, "base64")
  );
  assert.equal(ok, true, "the published witness receipt does not verify");
  assert.equal(r.head_hash, log.getEntry(r.seq_no)!.hash, "the receipt is not over the chain the code computes");
});

checkAsync("witness receipt_altered_seq: the same signature over an altered seq_no does NOT verify", () => {
  const r = V.receipt_altered_seq.receipt;
  const preimage = canonicalReceiptPreimage(r);
  assert.equal(preimage, V.receipt_altered_seq.preimage);
  const ok = verifySignature(
    null,
    Buffer.from(preimage, "utf8"),
    createPublicKey(V.witness_public_key_spki_pem),
    Buffer.from(r.witness_sig, "base64")
  );
  assert.equal(ok, false);
});

checkAsync("clerk_receipt_valid verifies; its preimage reproduces", () => {
  const v = V.clerk_receipt_valid;
  const res = verifyClerkReceipt(v.record_signed, V.clerk_public_key_spki_pem, v.payload);
  assert.ok(res.ok, res.reason);
  if (v.preimage !== undefined) {
    const { receipt_hash: _h, signature: _s, ...unsigned } = v.record_signed;
    assert.equal(canonicalise(unsigned), v.preimage);
  }
});

checkAsync("clerk_receipt_wrong_payload does NOT verify (payload_commitment)", () => {
  const v = V.clerk_receipt_wrong_payload;
  const res = verifyClerkReceipt(v.record_signed, V.clerk_public_key_spki_pem, v.payload);
  assert.equal(res.ok, false);
  assert.match(res.reason, /payload_commitment/);
});

checkAsync("clerk_receipt_valid commits through an L0 route bound to vector-submitter / vector-channel", async () => {
  const v = V.clerk_receipt_valid;
  const stamped = new LockedEvidenceLog({
    clerk: {
      client: { submit: async () => v.record_signed as unknown as ClerkSubmissionReceipt },
      submitterId: "vector-submitter",
      channel: "vector-channel",
      clerkPublicKeyPem: V.clerk_public_key_spki_pem,
    },
  });
  const committed = await stamped.append(v.payload as ReturnType<typeof entry>);
  assert.equal(committed.clerkReceipt!.receipt_hash, v.record_signed.receipt_hash);
  // and the binding is real: the same receipt on a route for another submitter is refused
  const other = new LockedEvidenceLog({
    clerk: {
      client: { submit: async () => v.record_signed as unknown as ClerkSubmissionReceipt },
      submitterId: "someone-else",
      channel: "vector-channel",
      clerkPublicKeyPem: V.clerk_public_key_spki_pem,
    },
  });
  let refused = false;
  try {
    await other.append(v.payload as ReturnType<typeof entry>);
  } catch {
    refused = true;
  }
  assert.ok(refused, "a receipt booked for vector-submitter committed on another submitter's route");
});

void (async () => {
  for (const t of pending) await t();
  console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
})();
