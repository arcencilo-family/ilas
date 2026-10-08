// ──────────────────────────────────────────────────────────────────────────────
// Reference witness — WITNESS_RECEIPT: preimage, signing, verification.
//
// Written from docs/S4-WIRE-SPEC.md §4, not imported from ILAS core, so that the
// interop tests compare two independent implementations of the same text:
//
//   preimage = [ String(seq_no), head_hash, String(witness_ts) ].join(" ")
//   witness_sig = base64( Ed25519( UTF-8 bytes of preimage ) )
//
// A receipt object has exactly the four keys seq_no, head_hash, witness_ts,
// witness_sig. The signature covers three of them; anything else on the object
// would be unsigned content, so it is not a receipt.
// ──────────────────────────────────────────────────────────────────────────────

import { sign, verify } from "crypto";
import type { KeyObject } from "crypto";

/** The three signed fields of a receipt. */
export interface ReceiptFields {
  readonly seq_no: number;
  readonly head_hash: string;
  readonly witness_ts: number;
}

/** The wire object written to an outbox. */
export interface WitnessReceipt extends ReceiptFields {
  readonly witness_sig: string;
}

export const RECEIPT_KEYS = ["seq_no", "head_hash", "witness_ts", "witness_sig"] as const;

/** Ed25519 signatures are 64 bytes; canonical base64 of 64 bytes is 88 characters. */
const SIGNATURE_BYTES = 64;

/** The exact signed string. */
export function receiptPreimage(fields: ReceiptFields): string {
  return [String(fields.seq_no), fields.head_hash, String(fields.witness_ts)].join(" ");
}

/**
 * Sign the three fields with an Ed25519 private key. Ed25519 is deterministic:
 * the same key and fields always give the same signature, which is what lets a
 * receipt be rebuilt from the store byte for byte.
 */
export function signReceipt(fields: ReceiptFields, privateKey: KeyObject): WitnessReceipt {
  const witness_sig = sign(
    null,
    Buffer.from(receiptPreimage(fields), "utf8"),
    privateKey
  ).toString("base64");
  // Key order is fixed here so that receiptBytes() is a function of the fields.
  return {
    seq_no: fields.seq_no,
    head_hash: fields.head_hash,
    witness_ts: fields.witness_ts,
    witness_sig,
  };
}

/** True when `value` is an object with exactly the four receipt keys, well typed. */
export function isReceiptShape(value: unknown): value is WitnessReceipt {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  if (keys.length !== RECEIPT_KEYS.length) return false;
  for (const key of RECEIPT_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) return false;
  }
  const r = value as Record<string, unknown>;
  return (
    typeof r.seq_no === "number" &&
    Number.isSafeInteger(r.seq_no) &&
    typeof r.head_hash === "string" &&
    typeof r.witness_ts === "number" &&
    Number.isFinite(r.witness_ts) &&
    typeof r.witness_sig === "string"
  );
}

/**
 * Decode a signature only if it is the canonical base64 of exactly 64 bytes.
 * Node's base64 decoder skips characters it does not understand; without this
 * check two different strings could decode to the same signature.
 */
export function decodeSignature(text: string): Buffer | null {
  const bytes = Buffer.from(text, "base64");
  if (bytes.length !== SIGNATURE_BYTES) return null;
  if (bytes.toString("base64") !== text) return null;
  return bytes;
}

/** Verify a receipt against an Ed25519 public key. Never throws. */
export function verifyReceipt(receipt: unknown, publicKey: KeyObject): boolean {
  if (!isReceiptShape(receipt)) return false;
  const signature = decodeSignature(receipt.witness_sig);
  if (signature === null) return false;
  try {
    return verify(null, Buffer.from(receiptPreimage(receipt), "utf8"), publicKey, signature);
  } catch {
    return false;
  }
}

/** The exact bytes of a receipt file: one JSON object and a newline. */
export function receiptBytes(receipt: WitnessReceipt): string {
  return (
    JSON.stringify({
      seq_no: receipt.seq_no,
      head_hash: receipt.head_hash,
      witness_ts: receipt.witness_ts,
      witness_sig: receipt.witness_sig,
    }) + "\n"
  );
}

/** Receipt file name for a store index. Twelve digits: names sort in store order. */
export function receiptFileName(index: number): string {
  return `receipt-${String(index).padStart(12, "0")}.json`;
}

/** Inverse of receiptFileName(); null for any other name. */
export function receiptIndexOf(name: string): number | null {
  const match = /^receipt-(\d{12})\.json$/.exec(name);
  return match === null ? null : Number(match[1]);
}
