import type { DriftSnapshot } from "../types";
import type { LockedEvidenceLog } from "../l0";

const ROLLING_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
const SINGLE_PARAM_THRESHOLD = 0.05; // 5% of baseline
const CUMULATIVE_THRESHOLD = 0.10;   // 10% of sum of all baselines
const NEAR_ZERO = 0.001;

export type ChangeStatus = "ok" | "flagged" | "material";

export interface ChangeResult {
  snapshot: DriftSnapshot;
  status: ChangeStatus;
}

interface ParameterRecord {
  baseline: number;
  current: number;
  structural: boolean;
}

interface ChangeRecord {
  parameterId: string;
  absoluteChange: number;
  timestamp: number;
}

function rollingChanges(log: ChangeRecord[], windowStart: number): ChangeRecord[] {
  return log.filter((r) => r.timestamp >= windowStart);
}

function worstOf(a: ChangeStatus, b: ChangeStatus): ChangeStatus {
  if (a === "material" || b === "material") return "material";
  if (a === "flagged"  || b === "flagged")  return "flagged";
  return "ok";
}

export class DriftMonitor {
  private readonly params = new Map<string, ParameterRecord>();
  private readonly changeLog: ChangeRecord[] = [];

  constructor(private readonly log?: LockedEvidenceLog) {}

  registerParameter(id: string, value: number, structural = false): void {
    this.params.set(id, { baseline: value, current: value, structural });
    this.log?.enqueue({
      timestamp: Date.now(),
      moduleId: "m5",
      eventType: "parameter_registered",
      provenanceTag: "LaneC",
      parameters: { id, value, structural },
      outcome: "ok",
    });
  }

  recordChange(id: string, newValue: number): ChangeResult {
    const record = this.params.get(id);
    if (!record) {
      throw new Error(`Unknown parameter: "${id}"`);
    }

    const now = Date.now();
    const previousValue = record.current;
    const absoluteChange = Math.abs(newValue - previousValue);

    const snapshot: DriftSnapshot = {
      parameterId: id,
      previousValue,
      currentValue: newValue,
      absoluteChange,
      timestamp: now,
    };

    record.current = newValue;
    this.changeLog.push({ parameterId: id, absoluteChange, timestamp: now });

    const windowStart = now - ROLLING_WINDOW_MS;
    const recent = rollingChanges(this.changeLog, windowStart);

    let status: ChangeStatus = "ok";

    // Near-zero: any param suppressed to <= 0.001 is material
    if (newValue <= NEAR_ZERO) {
      status = worstOf(status, "material");
    }

    // Structural: any change requires review
    if (record.structural && absoluteChange > 0) {
      status = worstOf(status, "flagged");
    }

    // Single-param rolling drift > 5% of baseline
    const paramBaseline = record.baseline;
    if (paramBaseline !== 0) {
      const paramRollingDelta = recent
        .filter((r) => r.parameterId === id)
        .reduce((sum, r) => sum + r.absoluteChange, 0);
      if (paramRollingDelta / Math.abs(paramBaseline) > SINGLE_PARAM_THRESHOLD) {
        status = worstOf(status, "flagged");
      }
    }

    // Cumulative drift across all params > 10% of sum of all baselines
    const totalBaseline = Array.from(this.params.values()).reduce(
      (sum, p) => sum + Math.abs(p.baseline),
      0
    );
    if (totalBaseline !== 0) {
      const totalRollingDelta = recent.reduce((sum, r) => sum + r.absoluteChange, 0);
      if (totalRollingDelta / totalBaseline > CUMULATIVE_THRESHOLD) {
        status = worstOf(status, "material");
      }
    }

    this.log?.enqueue({
      timestamp: now,
      moduleId: "m5",
      eventType: "parameter_changed",
      provenanceTag: "LaneC",
      parameters: {
        id,
        previousValue,
        newValue,
        absoluteChange,
        status,
      },
      outcome: status,
    });

    return { snapshot, status };
  }

  getCumulativeDrift(): number {
    const windowStart = Date.now() - ROLLING_WINDOW_MS;
    return this.changeLog
      .filter((r) => r.timestamp >= windowStart)
      .reduce((sum, r) => sum + r.absoluteChange, 0);
  }

  getParameter(id: string): ParameterRecord | undefined {
    return this.params.get(id);
  }
}
