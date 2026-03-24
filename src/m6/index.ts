import { randomBytes } from "crypto";
import type { LockedEvidenceLog } from "../l0";

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

// "granted_soft_alarm" means granted but rolling cap threshold crossed
export type EscalateStatus = "granted" | "granted_soft_alarm" | "denied_cooling";

export interface EscalateResult {
  status: EscalateStatus;
  escalation?: EscalationRecord;
  reason?: string;
}

const MAX_DURATION_MS: Record<EscalationLevel, number> = {
  tool:   15 * 60 * 1000,  // 15 min
  system: 60 * 60 * 1000,  // 60 min
};

const ROLLING_WINDOW_MS  = 24 * 60 * 60 * 1000;  // 24 hours
const ROLLING_CAP_MS     = ROLLING_WINDOW_MS * 0.25; // 25% = 6 hours
const MIN_COOL_OFF_MS    = 5 * 60 * 1000;            // 5 min

export class PrivilegeManager {
  private readonly escalations = new Map<string, EscalationRecord>();

  constructor(private readonly log?: LockedEvidenceLog) {}

  escalate(level: EscalationLevel, durationMs: number, reason: string): EscalateResult {
    const now = Date.now();
    const clampedDuration = Math.min(durationMs, MAX_DURATION_MS[level]);

    // Cooling-off check: any same-level escalation still cooling off?
    for (const esc of this.escalations.values()) {
      if (esc.level === level && esc.coolOffUntil > now) {
        this.log?.append({
          timestamp: now,
          moduleId: "m6",
          eventType: "escalation_denied",
          provenanceTag: "LaneC",
          parameters: { level, reason, coolOffUntil: esc.coolOffUntil },
          outcome: "denied_cooling",
        });
        return {
          status: "denied_cooling",
          reason: `cooling off until ${new Date(esc.coolOffUntil).toISOString()}`,
        };
      }
    }

    // Rolling 24h usage (sum of effective durations for escalations granted in the window)
    const windowStart = now - ROLLING_WINDOW_MS;
    const rollingUsageMs = Array.from(this.escalations.values())
      .filter((e) => e.grantedAt >= windowStart)
      .reduce((sum, e) => {
        const end = e.revokedAt ?? e.expiresAt;
        return sum + (end - e.grantedAt);
      }, 0);

    // Cool-off = escalation duration, floor at MIN_COOL_OFF_MS
    const coolOffMs = Math.max(clampedDuration, MIN_COOL_OFF_MS);

    const id = randomBytes(8).toString("hex");
    const escalation: EscalationRecord = {
      id,
      level,
      reason,
      grantedAt: now,
      expiresAt: now + clampedDuration,
      revokedAt: null,
      coolOffUntil: now + clampedDuration + coolOffMs,
    };

    this.escalations.set(id, escalation);

    // Soft alarm if rolling usage (including this grant) reaches 25% cap
    const newRollingUsage = rollingUsageMs + clampedDuration;
    const alarm = newRollingUsage >= ROLLING_CAP_MS;
    const status: EscalateStatus = alarm ? "granted_soft_alarm" : "granted";

    this.log?.append({
      timestamp: now,
      moduleId: "m6",
      eventType: "escalation_granted",
      provenanceTag: "LaneC",
      parameters: {
        id,
        level,
        reason,
        durationMs: clampedDuration,
        rollingUsageMs: newRollingUsage,
        capMs: ROLLING_CAP_MS,
      },
      outcome: status,
    });

    return { status, escalation };
  }

  checkEscalation(id: string): boolean {
    const esc = this.escalations.get(id);
    if (!esc) return false;
    const now = Date.now();
    return esc.revokedAt === null && now < esc.expiresAt;
  }

  revokeEscalation(id: string): boolean {
    const esc = this.escalations.get(id);
    if (!esc || esc.revokedAt !== null) return false;
    const now = Date.now();
    esc.revokedAt = now;
    this.log?.append({
      timestamp: now,
      moduleId: "m6",
      eventType: "escalation_revoked",
      provenanceTag: "LaneC",
      parameters: { id, level: esc.level, reason: esc.reason },
      outcome: "revoked",
    });
    return true;
  }

  getActiveEscalations(): EscalationRecord[] {
    const now = Date.now();
    return Array.from(this.escalations.values()).filter(
      (e) => e.revokedAt === null && now < e.expiresAt
    );
  }
}
