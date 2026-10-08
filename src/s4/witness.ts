// ──────────────────────────────────────────────────────────────────────────────
// ILAS — S-4 Witness interface + NullWitness stub
//
// READ THIS FIRST. The S-4 anchor requires a witness that (a) retains head
// hashes in a WORM / append-only store and (b) is INDEPENDENT of this node. A
// second local file, another directory, another process on this box — none of
// those are witnesses; a witness the node can reach into is the node holding its
// own head, which is self-certification.
//
// Therefore this file ships ONLY the interface and a null implementation that
// certifies nothing. Choosing and wiring a real, independent witness is the
// deployer's decision (docs/S4-WIRE-SPEC.md §2), not a code decision, and
// deliberately not made here. Do not replace NullWitness with a local-file
// "witness" and call the anchor done (see the status note in index.ts).
// ──────────────────────────────────────────────────────────────────────────────

import type { HeadCommit, WitnessReceipt } from "./types";

export interface Witness {
  /** Stable id of the witness set this instance represents. */
  readonly id: string;

  /**
   * Submit a head commit to the witness. A REAL witness durably retains the head
   * hash independently and (eventually) returns a signed receipt. Fire-and-file;
   * submission is not proof of retention.
   */
  submit(commit: HeadCommit): void;

  /**
   * The receipts the witness has retained and signed. A REAL implementation
   * fetches these FROM the independent witness store, not from local disk. The
   * continuity predicate checks every one of these against the live chain.
   *
   * An empty result means "no continuity assertion is available", which the
   * predicate reports as CANNOT_VERIFY_CONTINUITY — never as "ok".
   */
  retrieveReceipts(): WitnessReceipt[];

  /**
   * OPTIONAL. What the most recent retrieveReceipts() call could not accept.
   * `rejected` counts receipts the implementation was able to check (it had
   * what it needs to verify them) and refused; `reasons` says why. Refusing a
   * receipt keeps it away from the predicate, but the refusal itself is a hard
   * finding: the continuity predicate reports REJECTED_RECEIPTS for it, so a
   * forged or corrupted receipt cannot pass for a clean result. Having nothing
   * to check with (no key) is NOT a rejection; it ends in
   * CANNOT_VERIFY_CONTINUITY. An implementation without this method is read as
   * rejecting nothing.
   */
  retrievalIssues?(): { rejected: number; reasons: readonly string[] };

  /**
   * OPTIONAL. The fingerprint of the public key this implementation checks
   * receipts against, in the format of src/l0/fingerprint.ts ("sha256:" + hex
   * SHA-256 of the key's SPKI DER), so that an operator can compare it out of
   * band with the one the witness's own keygen printed. null when it has no
   * usable key. It names a key; it says nothing about who holds the private
   * half or whether the witness is independent. An implementation without this
   * method is reported as having no key to show.
   */
  publicKeyFingerprint?(): string | null;
}

/**
 * NullWitness — the honest placeholder. Retains nothing, signs nothing, returns
 * no receipts. With it wired, the continuity predicate can only ever report
 * CANNOT_VERIFY_CONTINUITY. That is the correct posture until a real, independent
 * witness exists: the system must not be able to manufacture a continuity
 * positive out of a witness that isn't there.
 */
export class NullWitness implements Witness {
  readonly id: string;

  constructor(id = "null-witness") {
    this.id = id;
  }

  submit(_commit: HeadCommit): void {
    // Intentionally does nothing. There is no independent store to retain into.
  }

  retrieveReceipts(): WitnessReceipt[] {
    return [];
  }
}
