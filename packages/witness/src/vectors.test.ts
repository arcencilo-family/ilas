// ──────────────────────────────────────────────────────────────────────────────
// Reference witness — the witness part of docs/s4-test-vectors.json, checked
// with this package's own preimage and verify code (nothing from ILAS core).
//   npx ts-node packages/witness/src/vectors.test.ts
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { createPrivateKey, createPublicKey } from "crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { receiptBytes, receiptPreimage, signReceipt, verifyReceipt } from "./receipt";
import { ReferenceWitness } from "./witness";

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

interface VectorReceipt {
  seq_no: number;
  head_hash: string;
  witness_ts: number;
  witness_sig: string;
}
interface Vectors {
  test_key_warning: string;
  witness_public_key_spki_pem: string;
  receipt_valid: { receipt: VectorReceipt; preimage: string; expect: string };
  receipt_altered_seq: { receipt: VectorReceipt; preimage: string; expect: string };
}

const vectors = JSON.parse(
  readFileSync(join(__dirname, "..", "..", "..", "docs", "s4-test-vectors.json"), "utf8")
) as Vectors;
const publicKey = createPublicKey(vectors.witness_public_key_spki_pem);

/**
 * The vectors' witness key is a PUBLIC TEST SEED, documented in the vector file
 * itself (32 bytes of 0x42). It is rebuilt here only to show that this
 * package's signer reproduces the published signature byte for byte.
 */
function publicTestSeedKey() {
  assert.match(vectors.test_key_warning, /0x42/, "the vector file documents the seed");
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const der = Buffer.concat([pkcs8Prefix, Buffer.alloc(32, 0x42)]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

console.log("── witness vectors ──");

check("receipt_valid: the preimage is the published string", () => {
  assert.equal(receiptPreimage(vectors.receipt_valid.receipt), vectors.receipt_valid.preimage);
});

check("receipt_valid: verifies against witness_public_key_spki_pem", () => {
  assert.equal(vectors.receipt_valid.expect, "verifies");
  assert.equal(verifyReceipt(vectors.receipt_valid.receipt, publicKey), true);
});

check("receipt_altered_seq: the preimage is the published string", () => {
  assert.equal(
    receiptPreimage(vectors.receipt_altered_seq.receipt),
    vectors.receipt_altered_seq.preimage
  );
});

check("receipt_altered_seq: does NOT verify", () => {
  assert.equal(vectors.receipt_altered_seq.expect, "does_not_verify");
  assert.equal(verifyReceipt(vectors.receipt_altered_seq.receipt, publicKey), false);
});

check("the public test seed's public key is the published one", () => {
  const derived = createPublicKey(publicTestSeedKey()).export({ type: "spki", format: "pem" });
  assert.equal(derived, vectors.witness_public_key_spki_pem);
});

check("signing the vector fields with the seed reproduces the published signature", () => {
  const { seq_no, head_hash, witness_ts } = vectors.receipt_valid.receipt;
  const signed = signReceipt({ seq_no, head_hash, witness_ts }, publicTestSeedKey());
  assert.deepEqual(signed, vectors.receipt_valid.receipt);
});

check("the witness core, given the seed and clock, emits exactly receipt_valid", () => {
  const root = mkdtempSync(join(tmpdir(), "ilas-witness-vectors-"));
  try {
    const intake = join(root, "intake");
    const outbox = join(root, "outbox");
    mkdirSync(intake);
    mkdirSync(outbox);
    const witness = ReferenceWitness.open({
      config: {
        witnessSetId: "vector-set",
        intakeDir: intake,
        storePath: join(root, "store.jsonl"),
        privateKeyPath: join(root, "unused.key"),
        submitters: [{ id: "vector-node", outboxDir: outbox }],
        pollIntervalMs: 1000,
      },
      privateKey: publicTestSeedKey(),
      clock: () => vectors.receipt_valid.receipt.witness_ts,
    });
    const r = vectors.receipt_valid.receipt;
    writeFileSync(
      join(intake, "vector-node"),
      JSON.stringify({ seq_no: r.seq_no, head_hash: r.head_hash, ts: 1, witness_set_id: "vector-set" }) +
        "\n"
    );
    const events = witness.pollOnce();
    assert.equal(events.length, 1);
    assert.equal(events[0].kind, "RETAINED");
    const written = readFileSync(join(outbox, "receipt-000000000000.json"), "utf8");
    assert.equal(written, receiptBytes(r), "the outbox file is the vector receipt");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
