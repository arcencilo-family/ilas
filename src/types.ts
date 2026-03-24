export enum IntegrityState {
  VERIFIED = "VERIFIED",
  DEGRADED = "DEGRADED",
  QUARANTINED = "QUARANTINED",
  UNVERIFIED = "UNVERIFIED",
}

export type ProvenanceTag = "LaneA" | "LaneB" | "LaneC";

export type CanaryDepth = "shallow" | "medium" | "deep";

export type SignalSeverity = "clean" | "soft_alarm" | "hard_alarm";

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
