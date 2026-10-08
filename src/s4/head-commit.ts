// ──────────────────────────────────────────────────────────────────────────────
// ILAS — S-4 HEAD_COMMIT emitter (docs/S4-WIRE-SPEC.md §3)
//
// Emits a HEAD_COMMIT at process init (startup-commit) and on a cadence. The
// startup-commit exists to close the startup-adjacency window: without it,
// a chain rebuilt on reload would match the last-good receipt until the first
// cadence tick. The inter-commitment window still exists and is never zero —
// that is accepted and named, not a bug to solve.
//
// HEAD_COMMIT is DECORATIVE, not evidential. It is therefore stored in its
// OWN local list, deliberately NOT appended into the L0 evidence chain — putting
// it in the chain would dress local bookkeeping up as evidence. Nothing verifies
// against these records.
// ──────────────────────────────────────────────────────────────────────────────

import { GENESIS_HEAD_HASH } from "./continuity";
import type { LockedEvidenceLog } from "../l0";
import type { Witness } from "./witness";
import type { HeadCommit } from "./types";

export class HeadCommitEmitter {
  private readonly commits: HeadCommit[] = [];

  constructor(
    private readonly log: LockedEvidenceLog,
    private readonly witness: Witness,
    private readonly clock: () => number = Date.now
  ) {}

  /**
   * Emit a commit capturing the current chain head, record it in the local list,
   * and submit it to the witness. Submission is not retention: nothing here can
   * tell whether the witness ever retained it.
   */
  emit(): HeadCommit {
    const len = this.log.length;
    const head =
      len === 0
        ? { seq_no: -1, head_hash: GENESIS_HEAD_HASH }
        : { seq_no: len - 1, head_hash: this.log.getEntry(len - 1)!.hash };

    const commit: HeadCommit = {
      seq_no: head.seq_no,
      head_hash: head.head_hash,
      ts: this.clock(),
      witness_set_id: this.witness.id,
    };

    this.commits.push(commit);
    this.witness.submit(commit);
    return commit;
  }

  /** The startup-commit. Semantically identical to emit(); named for intent. */
  emitStartupCommit(): HeadCommit {
    return this.emit();
  }

  getCommits(): readonly HeadCommit[] {
    return this.commits;
  }

  getLastCommit(): HeadCommit | null {
    return this.commits.length === 0
      ? null
      : this.commits[this.commits.length - 1];
  }
}
