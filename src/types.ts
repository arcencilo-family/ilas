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
