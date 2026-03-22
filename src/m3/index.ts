import { randomBytes } from "crypto";
import type { CanaryToken, CanaryDepth } from "../types";
import type { LockedEvidenceLog } from "../l0";

const ROLLING_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
const QUARANTINE_THRESHOLD = 3;

export type CheckSeverity = "none" | "alarm" | "quarantine";

export interface CheckOutboundResult {
  hit: boolean;
  tokens?: CanaryToken[];
  severity: CheckSeverity;
}

interface HitRecord {
  tokenId: string;
  timestamp: number;
}

function freshValue(): string {
  return randomBytes(32).toString("hex");
}

export class CanaryManager {
  private readonly canaries = new Map<string, CanaryToken>();
  private readonly hitLog: HitRecord[] = [];

  constructor(private readonly log?: LockedEvidenceLog) {}

  plantCanary(depth: CanaryDepth): CanaryToken {
    const id = randomBytes(8).toString("hex");
    const token: CanaryToken = {
      id,
      value: freshValue(),
      depth,
      plantedAt: Date.now(),
      rotatedAt: null,
    };
    this.canaries.set(id, token);
    this.log?.append({
      timestamp: token.plantedAt,
      moduleId: "m3",
      eventType: "canary_planted",
      provenanceTag: "LaneB",
      parameters: { id: token.id, depth },
      outcome: "ok",
    });
    return token;
  }

  checkOutbound(content: string): CheckOutboundResult {
    const now = Date.now();
    const hitTokens: CanaryToken[] = [];

    for (const token of this.canaries.values()) {
      if (content.includes(token.value)) {
        hitTokens.push(token);
        this.hitLog.push({ tokenId: token.id, timestamp: now });
      }
    }

    if (hitTokens.length === 0) {
      return { hit: false, severity: "none" };
    }

    const windowStart = now - ROLLING_WINDOW_MS;
    const recentHits = this.hitLog.filter((h) => h.timestamp >= windowStart);

    const severity: CheckSeverity =
      recentHits.length >= QUARANTINE_THRESHOLD ? "quarantine" : "alarm";

    this.log?.append({
      timestamp: now,
      moduleId: "m3",
      eventType: "canary_hit",
      provenanceTag: "LaneB",
      parameters: {
        hitCount: hitTokens.length,
        rollingHits: recentHits.length,
        tokenIds: hitTokens.map((t) => t.id),
      },
      outcome: severity,
    });

    return { hit: true, tokens: hitTokens, severity };
  }

  rotateCanaries(): void {
    const now = Date.now();
    for (const [id, token] of this.canaries) {
      this.canaries.set(id, {
        ...token,
        value: freshValue(),
        rotatedAt: now,
      });
    }
  }

  getActiveCanaries(): CanaryToken[] {
    return Array.from(this.canaries.values());
  }
}
