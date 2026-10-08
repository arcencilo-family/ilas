// ──────────────────────────────────────────────────────────────────────────────
// Reference clerk — the clerk part of docs/s4-test-vectors.json.
//   npx ts-node packages/clerk/src/vectors.test.ts
//
// Checked twice: with this package's own verifier and book check, and with
// ILAS's verifyClerkReceipt. The vector key is a PUBLIC test seed (32 bytes of
// 0x43, see scripts/s4-test-vectors.ts); it must never sign anything real.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { createPrivateKey, createPublicKey, generateKeyPairSync } from "crypto";
import { readFileSync, writeFileSync } from "fs";
import { join, resolve } from "path";
import { verifyClerkReceipt } from "../../../src/l0/clerk-verify";
import { verifyBookFile, verifyBookRecords } from "./book";
import { main } from "./cli";
import { receiptPreimage, signReceipt, verifyReceipt } from "./receipt";
import type { UnsignedClerkReceipt, Verdict } from "./receipt";
import { check, checkAsync, runAll, section, tempDir } from "./test-support";

interface ClerkVector {
  record_signed: Record<string, unknown>;
  payload: unknown;
  preimage?: string;
  expect: string;
}

const vectors = JSON.parse(
  readFileSync(resolve(__dirname, "..", "..", "..", "docs", "s4-test-vectors.json"), "utf8")
) as {
  clerk_public_key_spki_pem: string;
  witness_public_key_spki_pem: string;
  clerk_receipt_valid: ClerkVector;
  clerk_receipt_wrong_payload: ClerkVector;
};

const PUB = vectors.clerk_public_key_spki_pem;
const valid = vectors.clerk_receipt_valid;
const wrong = vectors.clerk_receipt_wrong_payload;

section("clerk_receipt_valid");

check("the vector expects to verify", () => {
  assert.equal(valid.expect, "verifies");
});

check("the canonical preimage of the record equals the published preimage", () => {
  assert.equal(receiptPreimage(valid.record_signed), valid.preimage);
});

check("this package's verifier accepts it, bound to its payload", () => {
  const v = verifyReceipt(valid.record_signed, PUB, { value: valid.payload });
  assert.ok(v.ok, v.reason);
});

check("ILAS's verifyClerkReceipt accepts it", () => {
  const v = verifyClerkReceipt(valid.record_signed, PUB, valid.payload);
  assert.ok(v.ok, v.reason);
});

check("as a one-receipt book it verifies (genesis link, clerk_seq 0)", () => {
  const v = verifyBookRecords([valid.record_signed], PUB);
  assert.ok(v.ok, v.reason);
  assert.equal(v.head, valid.record_signed.receipt_hash);
});

checkAsync("as a book file it verifies, and `cli verify` exits 0", async () => {
  const dir = tempDir();
  const book = join(dir, "vector-book.jsonl");
  const pub = join(dir, "vector.pub.pem");
  writeFileSync(book, JSON.stringify(valid.record_signed) + "\n");
  writeFileSync(pub, PUB);
  assert.ok(verifyBookFile(book, PUB).ok);
  const out: string[] = [];
  const code = await main(["verify", "--book", book, "--pub", pub], { out: (l) => out.push(l), err: (l) => out.push(l) });
  assert.equal(code, 0, out.join("\n"));
  assert.match(out.join("\n"), /book verifies: 1 receipt/);
});

check("this package's signer, given the public test seed, reproduces the exact receipt_hash and signature", () => {
  const seed = Buffer.alloc(32, 0x43);
  const priv = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    format: "der",
    type: "pkcs8",
  });
  assert.equal(createPublicKey(priv).export({ type: "spki", format: "pem" }), PUB);
  const { receipt_hash, signature, ...unsigned } = valid.record_signed;
  const signed = signReceipt(unsigned as unknown as UnsignedClerkReceipt, priv);
  assert.equal(signed.receipt_hash, receipt_hash);
  assert.equal(signed.signature, signature);
});

section("clerk_receipt_wrong_payload");

check("the vector expects a payload_commitment mismatch", () => {
  assert.match(wrong.expect, /does_not_verify/);
});

check("this package's verifier refuses it for the payload_commitment", () => {
  const v = verifyReceipt(wrong.record_signed, PUB, { value: wrong.payload });
  assert.equal(v.ok, false);
  assert.match(v.reason, /payload_commitment does not match/);
});

check("ILAS's verifyClerkReceipt refuses it for the payload_commitment", () => {
  const v = verifyClerkReceipt(wrong.record_signed, PUB, wrong.payload);
  assert.equal(v.ok, false);
  assert.match(v.reason, /payload_commitment does not match/);
});

check("its signature is still the clerk's: the refusal is the payload binding, not the key", () => {
  assert.ok(verifyReceipt(wrong.record_signed, PUB).ok);
  assert.ok(verifyBookRecords([wrong.record_signed], PUB).ok);
});

section("Negative controls");

check("under another key (the witness test key) both verifiers refuse the valid vector", () => {
  const other = vectors.witness_public_key_spki_pem;
  assert.equal(verifyReceipt(valid.record_signed, other, { value: valid.payload }).ok, false);
  assert.equal(verifyClerkReceipt(valid.record_signed, other, valid.payload).ok, false);
});

check("what the verifier cannot even compute is a refusal, never a pass (the fail-closed path)", () => {
  let deep: unknown = 1;
  for (let i = 0; i < 70; i++) deep = { d: deep };
  const rsaPublicPem = generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey.export({
    type: "spki",
    format: "pem",
  }) as string;
  const cases: Array<[string, Verdict]> = [
    // A record with no canonical form, carrying a bogus hash and signature.
    [
      "record nested deeper than 64 levels",
      verifyReceipt(
        { ...valid.record_signed, extra: deep, receipt_hash: "a".repeat(64), signature: Buffer.alloc(64).toString("base64") },
        PUB
      ),
    ],
    ["key of the wrong type", verifyReceipt(valid.record_signed, rsaPublicPem)],
    ["payload with no canonical form", verifyReceipt(valid.record_signed, PUB, { value: NaN })],
  ];
  for (const [name, v] of cases) {
    assert.equal(v.ok, false, `${name}: verified (${v.reason})`);
    assert.match(v.reason, /^verification error:/, name);
  }
});

check("signature text that decodes to the vector's signature bytes, but is not its canonical base64, is refused", () => {
  const sig = valid.record_signed.signature as string;
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const trailingBits = sig.slice(0, 85) + alphabet[alphabet.indexOf(sig[85]) | 1] + "==";
  for (const text of [sig.replace(/=+$/, ""), `${sig}!!`, trailingBits]) {
    assert.ok(Buffer.from(text, "base64").equals(Buffer.from(sig, "base64")));
    const changed = { ...valid.record_signed, signature: text };
    assert.equal(verifyReceipt(changed, PUB, { value: valid.payload }).ok, false, `own verifier accepted ${text}`);
    assert.equal(verifyClerkReceipt(changed, PUB, valid.payload).ok, false, `ILAS accepted ${text}`);
  }
});

check("the vector key's PRIVATE half given as the public key is refused, not reduced to its public half", () => {
  const priv = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 0x43)]),
    format: "der",
    type: "pkcs8",
  });
  const privatePem = priv.export({ type: "pkcs8", format: "pem" }) as string;
  const v = verifyReceipt(valid.record_signed, privatePem, { value: valid.payload });
  assert.equal(v.ok, false);
  assert.match(v.reason, /give only the public key/);
});

check("any single signed field changed ⇒ both verifiers refuse", () => {
  for (const k of Object.keys(valid.record_signed)) {
    if (k === "receipt_hash" || k === "signature") continue;
    const v = valid.record_signed[k];
    const changed = { ...valid.record_signed, [k]: typeof v === "number" ? v + 1 : typeof v === "string" ? v + "x" : { changed: true } };
    assert.equal(verifyReceipt(changed, PUB).ok, false, `own verifier accepted a changed ${k}`);
    assert.equal(verifyClerkReceipt(changed, PUB, valid.payload).ok, false, `ILAS accepted a changed ${k}`);
  }
});

runAll();
