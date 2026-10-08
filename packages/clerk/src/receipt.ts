// ──────────────────────────────────────────────────────────────────────────────
// Reference clerk — the submission receipt: its fields, how it is signed, and
// how a single receipt is checked.
//
// Signing rule (docs/S4-WIRE-SPEC.md §7.1–§7.3):
//   preimage     = canonicalise(record without receipt_hash and signature)
//   receipt_hash = sha256Hex(preimage)
//   signature    = base64 Ed25519 over the UTF-8 bytes of preimage
//   payload_commitment = sha256Hex(canonicalise(payload))
//
// Every field except receipt_hash and signature is signed. The checker below
// does not need a fixed field list, so a record with fewer fields than this
// clerk writes (for example the published test vector) is checked by the same
// rule.
// ──────────────────────────────────────────────────────────────────────────────

import { createPrivateKey, createPublicKey, sign as ed25519Sign, verify as ed25519Verify } from "crypto";
import type { KeyObject } from "crypto";
import { canonicalise, sha256Hex } from "../../../src/l0/canonical";
import type { ClerkSubmissionReceipt } from "../../../src/types";

/** Version tag carried (and signed) in every receipt this clerk writes. */
export const RECEIPT_FORM = "ILAS-CLERK-RECEIPT-1";

/** prev_receipt_hash of the first receipt in a book. */
export const GENESIS_RECEIPT_HASH = "0".repeat(64);

export type Separation = ClerkSubmissionReceipt["separation"];
export type Intake = ClerkSubmissionReceipt["intake"];

/**
 * A receipt as this clerk writes it: every field of ILAS's
 * ClerkSubmissionReceipt, plus the form tag and the two names the submitter
 * presented. All of them except receipt_hash and signature are signed.
 */
export interface ClerkReceipt extends ClerkSubmissionReceipt {
  readonly receipt_form: typeof RECEIPT_FORM;
  /** The id the submitter presented. A name, not an authenticated identity. */
  readonly submitter_id: string;
  readonly channel: string;
}

export type UnsignedClerkReceipt = Omit<ClerkReceipt, "receipt_hash" | "signature">;

export interface Verdict {
  ok: boolean;
  reason: string;
}

const HEX64 = /^[0-9a-f]{64}$/;
/** An Ed25519 signature is 64 bytes: exactly 88 base64 characters, padded. */
const ED25519_SIG_B64 = /^[A-Za-z0-9+/]{86}==$/;

/** SHA-256 of the canonical form of `payload`. Throws if it has none. */
export function payloadCommitment(payload: unknown): string {
  return sha256Hex(canonicalise(payload));
}

/** The exact string that is hashed and signed for `record`. */
export function receiptPreimage(record: Record<string, unknown>): string {
  const { receipt_hash: _hash, signature: _sig, ...unsigned } = record;
  return canonicalise(unsigned);
}

/** Sign an unsigned record. The result carries receipt_hash and signature. */
export function signReceipt(unsigned: UnsignedClerkReceipt, privateKey: KeyObject): ClerkReceipt {
  const preimage = canonicalise(unsigned);
  const signature = ed25519Sign(null, Buffer.from(preimage, "utf8"), privateKey).toString("base64");
  return { ...unsigned, receipt_hash: sha256Hex(preimage), signature };
}

/**
 * True when `pem` is private key material: PEM text naming a private key, or
 * anything Node parses as a private key.
 */
export function holdsPrivateKeyMaterial(pem: string): boolean {
  if (/PRIVATE KEY/.test(pem)) return true;
  try {
    createPrivateKey(pem);
    return true;
  } catch {
    return false;
  }
}

/** True when `s` is exactly the base64 text Node itself writes for its bytes. */
export function isCanonicalBase64(s: string): boolean {
  return Buffer.from(s, "base64").toString("base64") === s;
}

const GIVE_PUBLIC_KEY_ONLY =
  "a private key was given where the clerk's public key belongs; give only the public key (clerk.pub.pem)";

/**
 * Accept a PEM string or a KeyObject; refuse anything that is not an Ed25519
 * public key. A private key is refused, not reduced to its public half:
 * createPublicKey would quietly derive it, and a private key in a verifier's
 * hands means the signing key has left the clerk.
 */
export function toEd25519PublicKey(key: KeyObject | string): KeyObject {
  if (typeof key === "string" && holdsPrivateKeyMaterial(key)) {
    throw new Error(GIVE_PUBLIC_KEY_ONLY);
  }
  const k = typeof key === "string" ? createPublicKey(key) : key;
  if (k.type === "private") {
    throw new Error(GIVE_PUBLIC_KEY_ONLY);
  }
  if (k.type !== "public") {
    throw new Error("expected a public key");
  }
  if (k.asymmetricKeyType !== "ed25519") {
    throw new Error(`expected an ed25519 public key, got ${String(k.asymmetricKeyType)}`);
  }
  return k;
}

export function isPlainRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Check one receipt against a public key.
 *
 *   1. receipt_hash is the SHA-256 of the canonical record minus receipt_hash
 *      and signature;
 *   2. signature is an Ed25519 signature over those bytes by `publicKey`,
 *      written as canonical padded base64 (88 characters);
 *   3. if `payload` is given: payload_commitment is the SHA-256 of
 *      canonicalise(payload.value).
 *
 * `payload` is wrapped so that "no payload to check" and "the payload is
 * undefined" cannot be confused. Fails closed: any exception is a refusal.
 */
export function verifyReceipt(
  record: unknown,
  publicKey: KeyObject | string,
  payload?: { value: unknown }
): Verdict {
  try {
    if (!isPlainRecord(record)) return { ok: false, reason: "receipt is not a JSON object" };
    if (record.signature_alg !== "ed25519") {
      return { ok: false, reason: "signature_alg is not ed25519" };
    }
    if (typeof record.signature !== "string" || !ED25519_SIG_B64.test(record.signature)) {
      return { ok: false, reason: "signature is missing or is not 64 bytes of base64" };
    }
    // The last character before "==" carries 4 unused bits; Node's decoder
    // ignores them, so 16 different strings would decode to one signature.
    if (!isCanonicalBase64(record.signature)) {
      return { ok: false, reason: "signature is not canonical base64" };
    }
    if (typeof record.receipt_hash !== "string" || !HEX64.test(record.receipt_hash)) {
      return { ok: false, reason: "receipt_hash is missing or is not 64 lowercase hex characters" };
    }
    const preimage = receiptPreimage(record);
    if (sha256Hex(preimage) !== record.receipt_hash) {
      return { ok: false, reason: "receipt_hash does not match the canonical record" };
    }
    const key = toEd25519PublicKey(publicKey);
    const good = ed25519Verify(
      null,
      Buffer.from(preimage, "utf8"),
      key,
      Buffer.from(record.signature, "base64")
    );
    if (!good) return { ok: false, reason: "signature does not verify against the given public key" };
    if (payload !== undefined) {
      if (record.payload_commitment !== payloadCommitment(payload.value)) {
        return { ok: false, reason: "payload_commitment does not match the given payload" };
      }
    }
    return { ok: true, reason: "verified" };
  } catch (err) {
    return { ok: false, reason: `verification error: ${(err as Error).message ?? String(err)}` };
  }
}
