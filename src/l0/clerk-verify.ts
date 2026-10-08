// ──────────────────────────────────────────────────────────────────────────────
// ILAS — clerk receipt verification (docs/S4-WIRE-SPEC.md §7.3; closes gap G1)
//
// A clerk receipt is accepted only if all of the following hold:
//   1. receipt_hash == sha256( canonical(record minus receipt_hash, signature) )
//   2. signature is a valid Ed25519 signature, by the configured clerk key, over
//      those same canonical bytes
//   3. payload_commitment == sha256( canonical(payload) ), where payload is the
//      exact object L0 submitted
//
// Every field of the record except receipt_hash and signature is signed, so
// there is no "extra field" channel here. The verifier does not need to know the
// field list, and a clerk that adds fields does not break it.
//
// The signature must be canonical base64: Node's decoder skips characters it
// does not understand and tolerates missing or extra padding, so without this
// rule two different strings could decode to the same signature.
//
// The configured key must be a PUBLIC key. Node quietly derives the public half
// from a private key PEM; a private key here means the clerk's signing key is on
// the node, so it is refused rather than used.
//
// Fails closed: any exception, malformed input, or wrong key is a refusal.
// ──────────────────────────────────────────────────────────────────────────────

import { createPrivateKey, createPublicKey, verify as verifySignature } from "crypto";
import { canonicalise, sha256Hex } from "./canonical";

export interface ClerkVerifyResult {
  ok: boolean;
  reason: string;
}

/**
 * True when `pem` is private key material: PEM text naming a private key, or
 * anything Node parses as a private key. Such text must never be accepted where
 * a public key is expected.
 */
export function holdsPrivateKey(pem: string): boolean {
  if (/PRIVATE KEY/.test(pem)) return true;
  try {
    createPrivateKey(pem);
    return true;
  } catch {
    return false;
  }
}

/** True when `s` is exactly the base64 encoding Node itself would produce. */
export function isCanonicalBase64(s: string): boolean {
  return Buffer.from(s, "base64").toString("base64") === s;
}

export function verifyClerkReceipt(
  receipt: Record<string, unknown>,
  clerkPublicKeyPem: string,
  payload: unknown
): ClerkVerifyResult {
  try {
    if (receipt.signature_alg !== "ed25519") {
      return { ok: false, reason: "signature_alg is not ed25519" };
    }
    if (typeof receipt.signature !== "string" || receipt.signature.length === 0) {
      return { ok: false, reason: "signature missing" };
    }
    if (!isCanonicalBase64(receipt.signature)) {
      return { ok: false, reason: "signature is not canonical base64" };
    }
    if (typeof receipt.receipt_hash !== "string") {
      return { ok: false, reason: "receipt_hash missing" };
    }

    const { receipt_hash, signature, ...unsigned } = receipt;
    const preimage = canonicalise(unsigned);

    if (sha256Hex(preimage) !== receipt_hash) {
      return { ok: false, reason: "receipt_hash does not match the canonical record" };
    }

    if (holdsPrivateKey(clerkPublicKeyPem)) {
      return {
        ok: false,
        reason: "the configured clerk key is a private key; give only the clerk's public key",
      };
    }
    const key = createPublicKey(clerkPublicKeyPem);
    if (key.asymmetricKeyType !== "ed25519") {
      return { ok: false, reason: "configured clerk key is not ed25519" };
    }
    const signatureOk = verifySignature(
      null,
      Buffer.from(preimage, "utf8"),
      key,
      Buffer.from(signature, "base64")
    );
    if (!signatureOk) {
      return { ok: false, reason: "signature does not verify against the configured clerk key" };
    }

    if (receipt.payload_commitment !== sha256Hex(canonicalise(payload))) {
      return { ok: false, reason: "payload_commitment does not match the submitted payload" };
    }

    return { ok: true, reason: "verified" };
  } catch (err) {
    return { ok: false, reason: `verification error: ${String(err)}` };
  }
}
