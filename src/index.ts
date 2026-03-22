export { IntegrityState } from "./types";
export type {
  LogEntry,
  CanaryToken,
  DriftSnapshot,
  ModuleSignal,
  ProvenanceTag,
  CanaryDepth,
  SignalSeverity,
} from "./types";

export { LockedEvidenceLog } from "./l0";
export type { VerifyResult } from "./l0";

export { CanaryManager } from "./m3";
export type { CheckOutboundResult, CheckSeverity } from "./m3";

export { DriftMonitor } from "./m5";
export type { ChangeResult, ChangeStatus } from "./m5";

export { VerdictEngine } from "./v0";
export type { HistoryEntry } from "./v0";

// ── ILASKillStack ─────────────────────────────────────────────────────────────

import { IntegrityState } from "./types";
import { LockedEvidenceLog } from "./l0";
import { CanaryManager } from "./m3";
import { DriftMonitor } from "./m5";
import { VerdictEngine } from "./v0";

export interface KillStackStatus {
  state: IntegrityState;
  logSize: number;
  activeCanaries: number;
  cumulativeDrift: number;
}

export class ILASKillStack {
  readonly log: LockedEvidenceLog;
  readonly canary: CanaryManager;
  readonly drift: DriftMonitor;
  readonly verdict: VerdictEngine;

  constructor() {
    this.log = new LockedEvidenceLog();
    this.canary = new CanaryManager(this.log);
    this.drift = new DriftMonitor(this.log);
    this.verdict = new VerdictEngine(this.log);
  }

  status(): KillStackStatus {
    return {
      state: this.verdict.getState(),
      logSize: this.log.length,
      activeCanaries: this.canary.getActiveCanaries().length,
      cumulativeDrift: this.drift.getCumulativeDrift(),
    };
  }
}
