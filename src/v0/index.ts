import { IntegrityState, type ModuleSignal } from "../types";
import { LockedEvidenceLog } from "../l0";

export interface HistoryEntry {
  state: IntegrityState;
  timestamp: number;
  reason: string;
}

const UPGRADE_PATH: Partial<Record<IntegrityState, IntegrityState>> = {
  [IntegrityState.UNVERIFIED]: IntegrityState.DEGRADED,
  [IntegrityState.DEGRADED]: IntegrityState.VERIFIED,
};

const DEGRADE_PATH: Partial<Record<IntegrityState, IntegrityState>> = {
  [IntegrityState.VERIFIED]: IntegrityState.DEGRADED,
  [IntegrityState.DEGRADED]: IntegrityState.UNVERIFIED,
};

export class VerdictEngine {
  private state: IntegrityState = IntegrityState.UNVERIFIED;
  private readonly history: HistoryEntry[] = [];
  private stalenessMs: number | null = null;
  private stalenessTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(private readonly log: LockedEvidenceLog) {
    this.pushHistory(IntegrityState.UNVERIFIED, "initialized");
  }

  // ── state mutation ─────────────────────────────────────────────────────────

  private pushHistory(state: IntegrityState, reason: string): void {
    this.history.push({ state, timestamp: Date.now(), reason });
  }

  private transition(next: IntegrityState, reason: string): void {
    this.state = next;
    this.pushHistory(next, reason);
    this.log.append({
      timestamp: Date.now(),
      moduleId: "v0",
      eventType: "state_transition",
      provenanceTag: "LaneA",
      parameters: { next, reason },
      outcome: next,
    });
  }

  // ── public API ─────────────────────────────────────────────────────────────

  processSignal(signal: ModuleSignal): IntegrityState {
    this.log.append({
      timestamp: signal.timestamp,
      moduleId: signal.moduleId,
      eventType: "signal_received",
      provenanceTag: "LaneA",
      parameters: { severity: signal.severity, message: signal.message },
      outcome: signal.severity,
    });

    if (signal.severity === "hard_alarm") {
      this.transition(
        IntegrityState.QUARANTINED,
        `hard_alarm from ${signal.moduleId}: ${signal.message}`
      );
    } else if (signal.severity === "soft_alarm") {
      if (this.state !== IntegrityState.QUARANTINED) {
        this.transition(
          IntegrityState.DEGRADED,
          `soft_alarm from ${signal.moduleId}: ${signal.message}`
        );
      }
      // QUARANTINED: soft_alarm cannot upgrade or downgrade — no-op
    }
    // clean: no automatic upgrade

    return this.state;
  }

  runVerificationCycle(
    signals: ModuleSignal[],
    independentReviewComplete = false
  ): IntegrityState {
    this.resetStalenessTimer();

    this.log.append({
      timestamp: Date.now(),
      moduleId: "v0",
      eventType: "verification_cycle",
      provenanceTag: "LaneA",
      parameters: { signalCount: signals.length, independentReviewComplete },
      outcome: "running",
    });

    const allClean = signals.every((s) => s.severity === "clean");

    if (!allClean) {
      for (const s of signals) {
        if (s.severity !== "clean") this.processSignal(s);
      }
      return this.state;
    }

    // All signals clean —
    if (this.state === IntegrityState.QUARANTINED) {
      if (independentReviewComplete) {
        this.transition(
          IntegrityState.DEGRADED,
          "verification cycle: all clean + independent review complete"
        );
      }
      // else stays QUARANTINED — clean signals alone are not enough
    } else {
      const next = UPGRADE_PATH[this.state];
      if (next !== undefined) {
        this.transition(next, "verification cycle: all clean");
      }
      // VERIFIED → already at ceiling, no-op
    }

    return this.state;
  }

  setStalenessTimeout(ms: number): void {
    this.stalenessMs = ms;
    this.resetStalenessTimer();
  }

  getState(): IntegrityState {
    return this.state;
  }

  getHistory(): HistoryEntry[] {
    return [...this.history];
  }

  // ── staleness ──────────────────────────────────────────────────────────────

  private resetStalenessTimer(): void {
    if (this.stalenessTimer !== null) {
      clearTimeout(this.stalenessTimer);
      this.stalenessTimer = null;
    }
    if (this.stalenessMs === null) return;

    this.stalenessTimer = setTimeout(() => {
      this.stalenessTimer = null;
      const next = DEGRADE_PATH[this.state];
      if (next !== undefined) {
        this.transition(next, "staleness timeout: no verification cycle");
      }
      // Re-arm so continued inactivity keeps degrading
      this.resetStalenessTimer();
    }, this.stalenessMs);
  }
}
