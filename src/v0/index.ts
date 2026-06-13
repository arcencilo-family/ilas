// ──────────────────────────────────────────────────────────────────────────────
// ILAS — V0 Verdict Engine
// Patch: confidence decay (freshness as N = N0 * e^(-lambda*t))
// Added: 2026-06-13 (CEST) — Uncle Frank + AI colleagues
//
// What changed and why:
//   The existing setStalenessTimeout() degrades state on a fixed push-timer.
//   This patch ADDS a pull-based, queryable freshness signal: confidence in the
//   current VERIFIED/DEGRADED state decays exponentially since the last genuine
//   verification event, and crossing a floor triggers ONE degrade step.
//
// Invariants preserved (do not break):
//   - Decay only DEGRADES. Upgrades still require explicit clean cycles.
//   - Decay NEVER acts on QUARANTINED (one-way trap stays terminal).
//   - Confidence is piecewise-monotonic: strictly decreasing between resets;
//     resets to 1.0 occur ONLY on a genuine freshness event (clean verification
//     cycle) or immediately after a decay-degrade re-arm. It never rises on its own.
//   - The legacy setStalenessTimeout() is untouched and still works.
//
// Not wired here (by design — V0 only consumes ModuleSignals, it does not own M5):
//   lambda-suppression detection. Register lambda with the DriftMonitor at the
//   deployment site; if an attacker suppresses lambda -> 0 to freeze confidence,
//   M5 emits a hard_alarm into V0 and the engine QUARANTINES. See v0.decay.test.ts.
// ──────────────────────────────────────────────────────────────────────────────

import { IntegrityState, type ModuleSignal } from "../types";
import { LockedEvidenceLog } from "../l0";

export interface HistoryEntry {
  state: IntegrityState;
  timestamp: number;
  reason: string;
}

export interface FreshnessSnapshot {
  decayEnabled: boolean;
  confidence: number;        // 1.0 = just verified, -> 0 as evidence ages
  lambdaPerMs: number | null;
  floor: number;
  lastFreshAt: number;
  ageMs: number;
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

  // ── decay (freshness) state ────────────────────────────────────────────────
  private decayLambda: number | null = null;   // per-ms decay rate; null = disabled
  private decayFloor = 0.5;                     // confidence below this => degrade one step
  private lastFreshAt = 0;                      // timestamp of last genuine freshness event

  constructor(
    private readonly log: LockedEvidenceLog,
    private readonly clock: () => number = Date.now
  ) {
    this.lastFreshAt = this.clock();
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

    // All signals clean — this is a genuine freshness event: reset decay clock.
    // (Reset even when QUARANTINED-without-review or already VERIFIED: clean
    //  evidence was just gathered. State movement rules below are unchanged.)
    this.markFresh("clean verification cycle");

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

  // ── decay / freshness API ────────────────────────────────────────────────--

  /**
   * Enable exponential confidence decay.
   * @param lambdaPerMs  decay rate per millisecond (> 0). Larger = decays faster.
   *                     Half-life = ln(2) / lambdaPerMs.
   * @param floor        confidence in [0,1) at which one degrade step fires.
   */
  setDecayRate(lambdaPerMs: number, floor = 0.5): void {
    if (!(lambdaPerMs > 0)) throw new Error("decay lambda must be > 0");
    if (!(floor >= 0 && floor < 1)) throw new Error("decay floor must be in [0,1)");
    this.decayLambda = lambdaPerMs;
    this.decayFloor = floor;
    this.markFresh("decay enabled");
    this.log.append({
      timestamp: this.clock(),
      moduleId: "v0",
      eventType: "decay_configured",
      provenanceTag: "LaneA",
      parameters: { lambdaPerMs, floor },
      outcome: "enabled",
    });
  }

  /** Current confidence in [0,1]. 1.0 just after a freshness event; 0 if QUARANTINED. */
  confidence(): number {
    if (this.state === IntegrityState.QUARANTINED) return 0;
    if (this.decayLambda === null) return 1;
    const age = Math.max(0, this.clock() - this.lastFreshAt);
    return Math.exp(-this.decayLambda * age);
  }

  getFreshness(): FreshnessSnapshot {
    return {
      decayEnabled: this.decayLambda !== null,
      confidence: this.confidence(),
      lambdaPerMs: this.decayLambda,
      floor: this.decayFloor,
      lastFreshAt: this.lastFreshAt,
      ageMs: Math.max(0, this.clock() - this.lastFreshAt),
    };
  }

  /**
   * Evaluate freshness NOW. Pull-based companion to the push-based staleness
   * timer: call once per agent turn (or on a tick). If confidence has fallen
   * below the floor, degrade exactly ONE step and re-arm (reset the clock so a
   * second crossing degrades again — mirrors the legacy timer's re-arm).
   * No-op when decay is disabled or state is QUARANTINED. Never upgrades.
   */
  evaluateFreshness(): IntegrityState {
    if (this.decayLambda === null) return this.state;
    if (this.state === IntegrityState.QUARANTINED) return this.state;

    if (this.confidence() < this.decayFloor) {
      const next = DEGRADE_PATH[this.state];
      if (next !== undefined) {
        this.transition(next, "freshness decay: confidence below floor");
      }
      // re-arm regardless: at UNVERIFIED (no next) this just resets the clock
      this.markFresh("decay re-arm");
    }
    return this.state;
  }

  private markFresh(_reason: string): void {
    this.lastFreshAt = this.clock();
  }

  // ── staleness (legacy push-timer; unchanged) ────────────────────────────────

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
