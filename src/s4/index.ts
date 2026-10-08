// ──────────────────────────────────────────────────────────────────────────────
// ILAS — S-4 anchor preparation (barrel)
//
// STATUS: S-4-READY, not S-4-complete. This subsystem emits head commits,
// stores and verifies receipts, and runs the all-receipts continuity predicate —
// but the anchor itself is missing until an INDEPENDENT, WORM witness is wired.
//
// A transport client for a separate witness process exists (FileDropWitness).
// Wired to a separate witness process's intake and outbox, and
// given that witness's public key, continuity can report VERIFIED_HISTORICAL or
// MISMATCH on signature-verified receipts, and REJECTED_RECEIPTS when the client
// refused receipts it was able to check. That is the wire, not the anchor: the
// client retains nothing, and whether the witness process is INDEPENDENT of this
// node is a deployment fact — bought by OS users and directory permissions — that
// no code here can verify and none of it asserts. With the shipped NullWitness, or
// with no key, or with an unreadable outbox, continuity can still only report
// CANNOT_VERIFY_CONTINUITY, which remains the honest default. Do not describe this
// as more than "a wire exists; the anchor still awaits an attested witness".
// A reference witness process that speaks this wire lives in packages/witness;
// where and under whose account it runs is the deployer's choice.
// See witness.ts, file-drop-witness.ts, and docs/S4-WIRE-SPEC.md §2 and §7.4.
// ──────────────────────────────────────────────────────────────────────────────

export type {
  HeadCommit,
  WitnessReceipt,
  ContinuityStatus,
  ContinuityMismatch,
  ContinuityReport,
} from "./types";

export type { Witness } from "./witness";
export { NullWitness } from "./witness";
export { HeadCommitEmitter } from "./head-commit";
export { ContinuityVerifier, GENESIS_HEAD_HASH } from "./continuity";
export { ReceiptStore } from "./receipt-store";

export type {
  FileDropWitnessConfig,
  FileDropFetchDiagnostics,
  FileDropSubmitDiagnostics,
} from "./file-drop-witness";
export {
  FileDropWitness,
  canonicalReceiptPreimage,
  submitterIdProblem,
  MAX_SUBMITTER_ID_BYTES,
  MAX_RECEIPT_BYTES,
  FILE_DROP_WITNESS_IS_A_CLIENT_NOT_A_WITNESS,
  SUBMISSION_IS_NOT_RETENTION,
  UNVERIFIED_RECEIPTS_ARE_DROPPED,
  INDEPENDENCE_IS_A_DEPLOYMENT_FACT,
} from "./file-drop-witness";
