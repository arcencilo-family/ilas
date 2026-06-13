export { IntegrityState } from "./types";
export type {
  LogEntry,
  CanaryToken,
  DriftSnapshot,
  ModuleSignal,
  ProvenanceTag,
  CanaryDepth,
  SignalSeverity,
  ActionType,
  PermissionResult,
  EscalationLevel,
  EscalationRecord,
  EscalateStatus,
  EscalateResult,
  ScanCommitment,
  ScanStatus,
  RotationResult,
  PassCondition,
  ExpectedBehavior,
  ProbeCategory,
  DivergenceLevel,
  Probe,
  ProbeResult,
} from "./types";

export { LockedEvidenceLog } from "./l0";
export type { VerifyResult } from "./l0";

export { CanaryManager } from "./m3";
export type { CheckOutboundResult, CheckSeverity } from "./m3";

export { DriftMonitor } from "./m5";
export type { ChangeResult, ChangeStatus } from "./m5";

export { VerdictEngine } from "./v0";
export type { HistoryEntry } from "./v0";

export { ProvenanceTracker } from "./m7";
export { PrivilegeManager } from "./m6";
export { ScanScheduler } from "./m1";
export { DetectionRotator } from "./m2";
export { ProbeManager, STARTER_PROBES } from "./m4";
export { ConservationAuditor } from "./m8";
export type {
  IngestStatus as M8IngestStatus,
  CloseStatus as M8CloseStatus,
  IngestResult as M8IngestResult,
  CloseResult as M8CloseResult,
  PendingEntry as M8PendingEntry,
  LivenessReport as M8LivenessReport,
} from "./m8";

// ── ILASKillStack ─────────────────────────────────────────────────────────────

import { IntegrityState } from "./types";
import { LockedEvidenceLog } from "./l0";
import { CanaryManager } from "./m3";
import { DriftMonitor } from "./m5";
import { VerdictEngine } from "./v0";
import { ProvenanceTracker } from "./m7";
import { PrivilegeManager } from "./m6";
import { ScanScheduler } from "./m1";
import { DetectionRotator } from "./m2";
import { ProbeManager } from "./m4";
import { ConservationAuditor } from "./m8";

export interface KillStackStatus {
  state: IntegrityState;
  logSize: number;
  activeCanaries: number;
  cumulativeDrift: number;
  provenanceMismatches: number;
  activeEscalations: number;
  nextScanIn: number;
  rotationCycles: number;
  probeLibrarySize: number;
  openSessions: number;
  pendingPairs: number;
}

export class ILASKillStack {
  readonly log:        LockedEvidenceLog;
  readonly canary:     CanaryManager;
  readonly drift:      DriftMonitor;
  readonly verdict:    VerdictEngine;
  readonly provenance: ProvenanceTracker;
  readonly privilege:  PrivilegeManager;
  readonly scanner:    ScanScheduler;
  readonly rotation:   DetectionRotator;
  readonly probes:     ProbeManager;
  readonly auditor:    ConservationAuditor;

  constructor() {
    this.log        = new LockedEvidenceLog();
    this.canary     = new CanaryManager(this.log);
    this.drift      = new DriftMonitor(this.log);
    this.verdict    = new VerdictEngine(this.log);
    this.provenance = new ProvenanceTracker(this.log);
    this.privilege  = new PrivilegeManager(this.log);
    this.scanner    = new ScanScheduler(this.log);
    this.rotation   = new DetectionRotator(this.log);
    this.probes     = new ProbeManager(this.log);
    this.auditor    = new ConservationAuditor(this.log);
  }

  status(): KillStackStatus {
    return {
      state:               this.verdict.getState(),
      logSize:             this.log.length,
      activeCanaries:      this.canary.getActiveCanaries().length,
      cumulativeDrift:     this.drift.getCumulativeDrift(),
      provenanceMismatches:this.provenance.getMismatchCount(),
      activeEscalations:   this.privilege.getActiveEscalations().length,
      nextScanIn:          this.scanner.getNextScanIn(),
      rotationCycles:      this.rotation.getRotationCount(),
      probeLibrarySize:    this.probes.getProbeCount(),
      openSessions:        this.auditor.getOpenSessions(),
      pendingPairs:        this.auditor.getPendingCount(),
    };
  }
}
