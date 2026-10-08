// ──────────────────────────────────────────────────────────────────────────────
// ILAS — S-4 anchor preparation (record types)
// Field names are the wire names in docs/S4-WIRE-SPEC.md §3 (HEAD_COMMIT) and
// §4 (WITNESS_RECEIPT). Do not rename: these shapes are the contract with the
// witness process and with any tool an operator uses to inspect the node.
// ──────────────────────────────────────────────────────────────────────────────

/**
 * HEAD_COMMIT — local, DECORATIVE bookkeeping (docs/S4-WIRE-SPEC.md §3). Marks
 * which chain head was last shipped to a witness set. It is NOT evidence of
 * anything the chain does not already carry, and nothing verifies against it.
 * It exists to record intent and to close the startup-adjacency window (see
 * head-commit.ts).
 */
export interface HeadCommit {
  seq_no: number;         // sequence number of the head at emit time (-1 if empty chain)
  head_hash: string;      // hash of that head (genesis hash if empty chain)
  ts: number;             // local emit timestamp (ms)
  witness_set_id: string; // which witness set this head was committed to
}

/**
 * WITNESS_RECEIPT — the witness's signed acknowledgement that it has retained a
 * given head hash at a given sequence (docs/S4-WIRE-SPEC.md §4). Any local copy
 * the node keeps (see ReceiptStore) is a convenience for an operator inspecting
 * the node, nothing more; the evidential fact is the witness's own retention of
 * it in a WORM/append-only store the node cannot reach into.
 */
export interface WitnessReceipt {
  seq_no: number;
  head_hash: string;
  witness_ts: number;
  witness_sig: string;
}

export type ContinuityStatus =
  // Every receipt the witness client verified and returned reproduced from the
  // live chain, and the client rejected none. Note: this upgrades NOTHING — it
  // only means no returned receipt was violated (docs/S4-WIRE-SPEC.md §6). It
  // cannot see a genuine receipt that was deleted before the client read it.
  | "VERIFIED_HISTORICAL"
  // At least one returned receipt could not be reproduced. Hard finding.
  | "MISMATCH"
  // The witness client could check receipts (it had a usable key) and found at
  // least one it could not accept: unreadable, malformed, wrong shape, bad
  // signature, or a non-canonical signature encoding. Hard finding: something
  // in the witness channel does not verify. MISMATCH takes precedence.
  | "REJECTED_RECEIPTS"
  // No witness / no receipts retained, or none that could be checked. Distinct
  // from a clean result and from a failure: we cannot speak to continuity.
  | "CANNOT_VERIFY_CONTINUITY";

export interface ContinuityMismatch {
  seq_no: number;
  expected_head_hash: string;    // what the witness retained
  recomputed_head_hash: string | null; // what the live chain yields (null = absent)
  reason: string;
}

export interface ContinuityReport {
  status: ContinuityStatus;
  receiptsChecked: number;
  mismatches: ContinuityMismatch[];
  /**
   * Receipts the witness client rejected on the fetch behind this report (see
   * Witness.retrievalIssues). 0 when the client reports none or cannot report.
   */
  rejectedReceipts: number;
  /** Why they were rejected, as the client said it (possibly capped). */
  rejectReasons: string[];
  ts: number;
}
