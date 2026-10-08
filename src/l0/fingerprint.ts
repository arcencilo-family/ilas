// ──────────────────────────────────────────────────────────────────────────────
// ILAS — public key fingerprints
//
// "sha256:" + lowercase hex SHA-256 of the key's SPKI DER bytes. Short enough to
// read aloud or compare by eye, so the operator of a clerk or a witness can
// confirm out of band that the node was given THEIR public key. The same format
// is printed by the packages' keygen and fingerprint commands.
// ──────────────────────────────────────────────────────────────────────────────

import { createHash, createPublicKey } from "crypto";

/** Fingerprint of a PEM public key. Throws if `pem` is not a readable public key. */
export function publicKeyFingerprint(pem: string): string {
  const der = createPublicKey(pem).export({ type: "spki", format: "der" });
  return "sha256:" + createHash("sha256").update(der).digest("hex");
}
