// ──────────────────────────────────────────────────────────────────────────────
// ILAS — S-4 continuity predicate (docs/S4-WIRE-SPEC.md §6)
//
// THE PREDICATE:
//   For EVERY retained receipt (seq N1 … Nk), independently recompute the head at
//   seq N_i from the live chain and compare it to the retained head_hash. Any
//   mismatch, at any N_i, is a hard finding.
//
// Never latest-head-only. A chain rebuilt to reproduce today's head must also
// reproduce every historical head the witness retains. Each receipt is an
// independent constraint; the set grows monotonically with cadence. Every
// receipt is checked; none is skipped or sampled. The recomputation behind them
// is ONE pass from genesis over the entries' contents (no stored hash trusted),
// not a fresh replay per receipt, so the cost is linear in chain + receipts.
//
// Verdict precedence:
//   MISMATCH                  a returned receipt does not reproduce
//   REJECTED_RECEIPTS         the witness client refused receipts it was able to
//                             check (Witness.retrievalIssues): forged, corrupted,
//                             malformed — something in the channel does not verify
//   CANNOT_VERIFY_CONTINUITY  no receipts to check (no witness, no key, nothing yet)
//   VERIFIED_HISTORICAL       every returned receipt reproduced, none rejected
//
// A matching predicate upgrades NOTHING. Receipts arm the alarm; they never
// manufacture a positive. The assembly must not move any state upward on a clean
// continuity result. A deleted receipt leaves no trace here: the predicate can
// only check what the witness client still finds.
//
// This class does not check witness signatures. It checks whatever receipts the
// Witness it is given returns; FileDropWitness returns only receipts whose
// signature verifies against the configured witness key (file-drop-witness.ts),
// and reports the ones it refused through retrievalIssues().
// ──────────────────────────────────────────────────────────────────────────────

import { recomputeHeadHashes } from "../l0";
import type { LockedEvidenceLog } from "../l0";
import type { Witness } from "./witness";
import type { ContinuityMismatch, ContinuityReport } from "./types";

/** Head hash of an empty chain — the genesis previous-hash. */
export const GENESIS_HEAD_HASH = "0".repeat(64);

export class ContinuityVerifier {
  constructor(
    private readonly log: LockedEvidenceLog,
    private readonly witness: Witness,
    private readonly clock: () => number = Date.now
  ) {}

  verify(): ContinuityReport {
    const ts = this.clock();
    const receipts = this.witness.retrieveReceipts();
    // Read straight after the fetch it describes.
    const issues = this.witness.retrievalIssues?.();
    const rejectedRaw: unknown = issues?.rejected;
    const reasonsRaw: unknown = issues?.reasons;
    const rejectedReceipts =
      typeof rejectedRaw === "number" && rejectedRaw > 0 ? rejectedRaw : 0;
    const rejectReasons = Array.isArray(reasonsRaw) ? reasonsRaw.map(String) : [];

    // Without retained receipts there is nothing to speak to continuity with —
    // unless the client refused some it could check, which is a finding.
    if (receipts.length === 0) {
      return {
        status: rejectedReceipts > 0 ? "REJECTED_RECEIPTS" : "CANNOT_VERIFY_CONTINUITY",
        receiptsChecked: 0,
        mismatches: [],
        rejectedReceipts,
        rejectReasons,
        ts,
      };
    }

    const entries = this.log.getAll();
    const mismatches: ContinuityMismatch[] = [];
    // One pass from genesis for all witnessed sequences (not one per receipt).
    const heads = recomputeHeadHashes(entries, receipts.map((r) => r.seq_no));

    // Check EVERY receipt, independently, against the live chain.
    for (const r of receipts) {
      // seq_no -1 is the head of the EMPTY prefix (a HEAD_COMMIT emitted before
      // the first append, spec §3). Every chain has that prefix, and its head is
      // the genesis hash, so such a receipt reproduces exactly when it carries the
      // genesis hash. Anything below -1 names no prefix at all.
      if (!Number.isSafeInteger(r.seq_no)) {
        mismatches.push({
          seq_no: r.seq_no,
          expected_head_hash: r.head_hash,
          recomputed_head_hash: null,
          reason: `seq ${String(r.seq_no)} is not an integer sequence number`,
        });
        continue;
      }
      if (r.seq_no < 0) {
        const ok = r.seq_no === -1 && r.head_hash === GENESIS_HEAD_HASH;
        if (!ok) {
          mismatches.push({
            seq_no: r.seq_no,
            expected_head_hash: r.head_hash,
            recomputed_head_hash: r.seq_no === -1 ? GENESIS_HEAD_HASH : null,
            reason:
              r.seq_no === -1
                ? "witnessed empty-chain head is not the genesis hash"
                : `seq ${r.seq_no} names no prefix of any chain`,
          });
        }
        continue;
      }

      const recomputed = heads.get(r.seq_no) ?? null;

      if (recomputed === null && r.seq_no < entries.length) {
        // The entry exists, but an entry up to it is nested too deeply for the
        // stack to hash, so the witnessed head cannot be reproduced. That is a
        // hard finding, never a throw out of the predicate.
        mismatches.push({
          seq_no: r.seq_no,
          expected_head_hash: r.head_hash,
          recomputed_head_hash: null,
          reason: `the head at seq ${r.seq_no} cannot be recomputed: an entry up to it cannot be hashed`,
        });
        continue;
      }

      if (recomputed === null) {
        // The live chain has no entry at the witnessed sequence — it is shorter
        // than the witness's evidence. This is the truncation case: the
        // chain can verify() internally as a valid prefix, yet fail here.
        mismatches.push({
          seq_no: r.seq_no,
          expected_head_hash: r.head_hash,
          recomputed_head_hash: null,
          reason:
            `live chain has ${entries.length} entries; ` +
            `witnessed seq ${r.seq_no} is absent (truncated or rebuilt short)`,
        });
        continue;
      }

      if (recomputed !== r.head_hash) {
        mismatches.push({
          seq_no: r.seq_no,
          expected_head_hash: r.head_hash,
          recomputed_head_hash: recomputed,
          reason: "recomputed head does not match witnessed head",
        });
      }
    }

    if (mismatches.length > 0) {
      return {
        status: "MISMATCH",
        receiptsChecked: receipts.length,
        mismatches,
        rejectedReceipts,
        rejectReasons,
        ts,
      };
    }

    // Every returned receipt reproduced, but the client refused others it could
    // check: the prefix that reproduces is not the whole story.
    if (rejectedReceipts > 0) {
      return {
        status: "REJECTED_RECEIPTS",
        receiptsChecked: receipts.length,
        mismatches: [],
        rejectedReceipts,
        rejectReasons,
        ts,
      };
    }

    // Every receipt reproduced. This does NOT upgrade anything — it only
    // means no witnessed head was violated. Quiet is not health.
    return {
      status: "VERIFIED_HISTORICAL",
      receiptsChecked: receipts.length,
      mismatches: [],
      rejectedReceipts: 0,
      rejectReasons,
      ts,
    };
  }
}
