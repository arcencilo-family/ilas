export enum IntegrityState {
  VERIFIED = "VERIFIED",
  DEGRADED = "DEGRADED",
  QUARANTINED = "QUARANTINED",
  UNVERIFIED = "UNVERIFIED",
}

export type ProvenanceTag = "LaneA" | "LaneB" | "LaneC";

export type CanaryDepth = "shallow" | "medium" | "deep";

export type SignalSeverity = "clean" | "soft_alarm" | "hard_alarm";

/**
 * The fields of a clerk submission receipt that L0 reads (docs/S4-WIRE-SPEC.md
 * §7.1). A clerk may write more fields than these; every field it writes except
 * receipt_hash and signature is signed, and L0 verifies (§7.3), and keeps on the
 * entry, the whole record it is handed, not just the fields typed here. ILAS
 * depends only on this shape and never imports a clerk implementation. The
 * reference clerk in packages/clerk writes a superset of it.
 */
export interface ClerkSubmissionReceipt {
  readonly kind: "SUBMISSION";
  /** The submitter the clerk booked this for. L0 requires its route's submitterId. */
  readonly submitter_id: string;
  /** The channel the clerk booked this on. L0 requires its route's channel. */
  readonly channel: string;
  readonly clerk_id: string;
  readonly clerk_boot_id: string;
  readonly separation: "SEPARATE_PROCESS" | "IN_PROCESS_NO_SEPARATION";
  readonly separation_warning: string | null;
  readonly clerk_principal: string;
  readonly intake: "SOCKET" | "LOCAL_CALL" | "CLERK_INTERNAL";
  readonly clerk_seq: number;
  readonly clerk_time: {
    readonly wall_ms: number;
    readonly monotonic_ns: string;
  };
  readonly prev_receipt_hash: string;
  readonly receipt_hash: string;
  readonly signature: string;
  readonly signature_alg: "ed25519";
  readonly declared_timestamp: number | null;
  readonly payload_commitment: string;
  readonly payload_retained: boolean;
  readonly payload_canonical: string | null;
}

export interface LogEntry {
  sequenceNumber: number;
  hash: string;
  previousHash: string;
  timestamp: number;
  moduleId: string;
  eventType: string;
  provenanceTag: ProvenanceTag;
  parameters: Record<string, unknown>;
  outcome: string;
  /**
   * Absent only on legacy/explicitly unstamped logs. With a clerk route, L0
   * checks it (docs/S4-WIRE-SPEC.md §7.3) before an entry commits, and again for
   * every entry loaded from disk; a log that holds a missing or failing receipt
   * loads as CANNOT_VERIFY.
   */
  clerkReceipt?: ClerkSubmissionReceipt;
}

export interface CanaryToken {
  id: string;
  value: string;
  depth: CanaryDepth;
  plantedAt: number;
  rotatedAt: number | null;
}

export interface DriftSnapshot {
  parameterId: string;
  previousValue: number;
  currentValue: number;
  absoluteChange: number;
  timestamp: number;
}

export interface ModuleSignal {
  moduleId: string;
  severity: SignalSeverity;
  message: string;
  timestamp: number;
}

// ── M7 types ──────────────────────────────────────────────────────────────────

export type ActionType =
  | "memory_read"
  | "memory_write"
  | "external_call"
  | "canary_plant"
  | "canary_check"
  | "integrity_scan"
  | "config_change"
  | "file_op"
  | "parameter_register";

export interface PermissionResult {
  permitted: boolean;
  actionType: ActionType;
  provenanceTag: ProvenanceTag;
  expectedLanes: ProvenanceTag[];
}

// ── M6 types ──────────────────────────────────────────────────────────────────

export type EscalationLevel = "tool" | "system";

export interface EscalationRecord {
  id: string;
  level: EscalationLevel;
  reason: string;
  grantedAt: number;
  expiresAt: number;
  revokedAt: number | null;
  coolOffUntil: number;
}

export type EscalateStatus = "granted" | "granted_soft_alarm" | "denied_cooling";

export interface EscalateResult {
  status: EscalateStatus;
  escalation?: EscalationRecord;
  reason?: string;
}

// ── M1 types ──────────────────────────────────────────────────────────────────

export interface ScanCommitment {
  seed: string;
  committedAt: number;
}

export interface ScanStatus {
  shouldScan: boolean;
  nextScanAt: number;
  nextScanIn: number;
  scheduledCount: number;
}

// ── M2 types ──────────────────────────────────────────────────────────────────

export interface RotationResult {
  selectedFamilies: string[];
  rotationIndex: number;
  seed: string;
  commitment: string;
}

export interface PassCondition {
  met: boolean;
  rotationsTested: number;
  nonAdjacentPasses: number;
}

// ── M4 types ──────────────────────────────────────────────────────────────────

export type ExpectedBehavior = "confirm" | "refuse" | "answer_only" | "delegate";
export type ProbeCategory    = "permission_boundary" | "data_leak" | "instruction_fidelity" | "escalation_attempt";
export type DivergenceLevel  = "none" | "minor" | "major";

export interface Probe {
  id: string;
  input: string;
  expectedBehavior: ExpectedBehavior;
  category: ProbeCategory;
  indistinguishable: boolean;
}

export interface ProbeResult {
  probeId: string;
  match: boolean;
  divergence: DivergenceLevel;
  details: string;
  timestamp: number;
}
