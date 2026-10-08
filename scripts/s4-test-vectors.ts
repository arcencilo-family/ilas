// ──────────────────────────────────────────────────────────────────────────────
// Generates docs/s4-test-vectors.json from the code itself.
//   npx ts-node scripts/s4-test-vectors.ts
//
// The Ed25519 seeds below (0x42 for the witness key, 0x43 for the clerk key)
// are PUBLIC and exist only so the vectors are reproducible. A key derived from
// either must never be used for a real witness or a real clerk.
// ──────────────────────────────────────────────────────────────────────────────

import { createPrivateKey, createPublicKey, sign, verify } from "crypto";
import { writeFileSync } from "fs";
import { join } from "path";
import { LockedEvidenceLog } from "../src/l0";
import { canonicalReceiptPreimage } from "../src/s4/file-drop-witness";
import type { WitnessReceipt } from "../src/s4/types";
import { canonicalise, sha256Hex } from "../src/l0/canonical";
import { verifyClerkReceipt } from "../src/l0/clerk-verify";

const TEST_SEED = Buffer.alloc(32, 0x42); // PUBLIC TEST SEED — not a secret
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

const priv = createPrivateKey({
  key: Buffer.concat([PKCS8_ED25519_PREFIX, TEST_SEED]),
  format: "der",
  type: "pkcs8",
});
const pub = createPublicKey(priv);
const pubPem = pub.export({ type: "spki", format: "pem" }) as string;

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

// 1. Hash chain: five entries, hashes computed by the code.
const log = new LockedEvidenceLog();
for (let i = 0; i < 5; i++) log.append(entry(i));
const chain = log.getAll().map((e) => ({
  sequenceNumber: e.sequenceNumber,
  hash: e.hash,
  previousHash: e.previousHash,
}));

// 2. Witness receipt: preimage and Ed25519 signature over it.
const headAt3 = log.getEntry(3)!.hash;
const good: Omit<WitnessReceipt, "witness_sig"> = {
  seq_no: 3,
  head_hash: headAt3,
  witness_ts: 1_700_000_000_123,
};
const preimage = canonicalReceiptPreimage(good);
const sig = sign(null, Buffer.from(preimage, "utf8"), priv).toString("base64");
const validOk = verify(null, Buffer.from(preimage, "utf8"), pub, Buffer.from(sig, "base64"));

// 3. Negative: same signature, altered seq_no must NOT verify.
const tamperedPreimage = canonicalReceiptPreimage({ ...good, seq_no: 4 });
const tamperedOk = verify(null, Buffer.from(tamperedPreimage, "utf8"), pub, Buffer.from(sig, "base64"));

if (!validOk || tamperedOk) {
  throw new Error("vector self-check failed — refusing to write vectors");
}

// 4. Clerk receipt (G1): record signed over canonical(record minus
//    receipt_hash, signature); payload_commitment binds it to the payload.
const clerkPayload = entry(7);
const clerkRecord = {
  kind: "SUBMISSION",
  submitter_id: "vector-submitter",
  channel: "vector-channel",
  clerk_id: "vector-clerk",
  clerk_boot_id: "vector-boot",
  clerk_seq: 0,
  clerk_time: { wall_ms: 1_700_000_500_000, monotonic_ns: "1000" },
  prev_receipt_hash: "0".repeat(64),
  signature_alg: "ed25519" as const,
  declared_timestamp: clerkPayload.timestamp,
  payload_commitment: sha256Hex(canonicalise(clerkPayload)),
  separation: "SEPARATE_PROCESS",
  intake: "SOCKET",
};
const clerkPreimage = canonicalise(clerkRecord);
const clerkReceiptHash = sha256Hex(clerkPreimage);
// A SEPARATE test key for the clerk. A clerk and a witness never share a key.
const CLERK_TEST_SEED = Buffer.alloc(32, 0x43); // PUBLIC TEST SEED — not a secret
const clerkPriv = createPrivateKey({
  key: Buffer.concat([PKCS8_ED25519_PREFIX, CLERK_TEST_SEED]),
  format: "der",
  type: "pkcs8",
});
const clerkPubPem = createPublicKey(clerkPriv).export({ type: "spki", format: "pem" }) as string;
const clerkSig = sign(null, Buffer.from(clerkPreimage, "utf8"), clerkPriv).toString("base64");
const clerkSigned = { ...clerkRecord, receipt_hash: clerkReceiptHash, signature: clerkSig };
const clerkOk = verifyClerkReceipt(clerkSigned, clerkPubPem, clerkPayload);
const clerkWrongPayload = verifyClerkReceipt(clerkSigned, clerkPubPem, entry(8));
if (!clerkOk.ok || clerkWrongPayload.ok) {
  throw new Error("clerk vector self-check failed — refusing to write vectors");
}

// 5. Canonical-form examples (ILAS-CANON-JSON-1).
const canonicalExamples = [
  { input: { b: 1, a: 2 }, canonical: canonicalise({ b: 1, a: 2 }) },
  { input: { x: [1, { y: "z" }], n: null }, canonical: canonicalise({ x: [1, { y: "z" }], n: null }) },
  { input: { a: 1, gone: undefined }, canonical: canonicalise({ a: 1, gone: undefined }) },
];

const out = {
  generated_by: "scripts/s4-test-vectors.ts",
  test_key_warning:
    "Public test seeds: 0x42 × 32 for the witness key, 0x43 × 32 for the clerk key. Never use either for a real witness or clerk.",
  witness_public_key_spki_pem: pubPem,
  clerk_public_key_spki_pem: clerkPubPem,
  hash_chain: {
    rule: "sha256(JSON.stringify({sequenceNumber, previousHash, timestamp, moduleId, eventType, provenanceTag, parameters, outcome, clerkReceipt})); genesis previousHash = 64 zeros",
    entries: chain,
  },
  receipt_valid: {
    receipt: { ...good, witness_sig: sig },
    preimage,
    expect: "verifies",
  },
  clerk_receipt_valid: {
    clerk_public_key: "clerk_public_key_spki_pem",
    record_signed: clerkSigned,
    payload: clerkPayload,
    preimage: clerkPreimage,
    expect: "verifies",
  },
  clerk_receipt_wrong_payload: {
    clerk_public_key: "clerk_public_key_spki_pem",
    record_signed: clerkSigned,
    payload: entry(8),
    expect: "does_not_verify (payload_commitment mismatch)",
  },
  canonical_examples: canonicalExamples,
  receipt_altered_seq: {
    receipt: { ...good, seq_no: 4, witness_sig: sig },
    preimage: tamperedPreimage,
    expect: "does_not_verify",
  },
};

const target = join(__dirname, "..", "docs", "s4-test-vectors.json");
writeFileSync(target, JSON.stringify(out, null, 2) + "\n");
console.log(`wrote ${target}`);
console.log(`receipt preimage: ${JSON.stringify(preimage)}`);
console.log(`chain head at seq 4: ${chain[4].hash}`);
