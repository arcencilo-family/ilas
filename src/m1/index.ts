import { createHash, randomBytes } from "crypto";
import type { LockedEvidenceLog } from "../l0";

export interface ScanCommitment {
  seed: string;      // SHA-256 hex of raw random seed
  committedAt: number;
}

export interface ScanStatus {
  shouldScan: boolean;
  nextScanAt: number;
  nextScanIn: number;
  scheduledCount: number;
}

// Jitter parameters — interval in [MIN_INTERVAL_MS, MAX_INTERVAL_MS]
// Guarantees at least 3 scans per 24h (24h / 7h = 3.43)
const MIN_INTERVAL_MS = 4 * 60 * 60 * 1000;  // 4 hours
const MAX_INTERVAL_MS = 7 * 60 * 60 * 1000;  // 7 hours

export class ScanScheduler {
  private readonly rawSeed: Buffer;
  private readonly commitment: ScanCommitment;
  private nextScanAt: number = 0;
  private scheduledCount: number = 0;

  constructor(private readonly log?: LockedEvidenceLog) {
    this.rawSeed = randomBytes(32);
    this.commitment = {
      seed: createHash("sha256").update(this.rawSeed).digest("hex"),
      committedAt: Date.now(),
    };
    // Schedule the first scan without logging (internal init)
    this.nextScanAt = Date.now() + this._deriveInterval();
    this.scheduledCount = 1;
  }

  private _deriveInterval(): number {
    // Hash(seed || scheduledCount) → deterministic float in [0,1)
    const countBuf = Buffer.alloc(4);
    countBuf.writeUInt32BE(this.scheduledCount);
    const digest = createHash("sha256")
      .update(this.rawSeed)
      .update(countBuf)
      .digest();
    const fraction = digest.readUInt32BE(0) / 0xffffffff;
    return Math.round(MIN_INTERVAL_MS + fraction * (MAX_INTERVAL_MS - MIN_INTERVAL_MS));
  }

  generateSchedule(): number {
    const now = Date.now();
    const intervalMs = this._deriveInterval();
    this.nextScanAt = now + intervalMs;
    this.scheduledCount++;

    this.log?.append({
      timestamp: now,
      moduleId: "m1",
      eventType: "schedule_generated",
      provenanceTag: "LaneB",
      parameters: {
        nextScanAt: this.nextScanAt,
        scheduledCount: this.scheduledCount,
        intervalMs,
      },
      outcome: "ok",
    });

    return this.nextScanAt;
  }

  verifySeed(): boolean {
    const recomputed = createHash("sha256").update(this.rawSeed).digest("hex");
    return recomputed === this.commitment.seed;
  }

  shouldScanNow(): boolean {
    return Date.now() >= this.nextScanAt;
  }

  getNextScanIn(): number {
    return Math.max(0, this.nextScanAt - Date.now());
  }

  getCommitment(): ScanCommitment {
    return { ...this.commitment };
  }

  getStatus(): ScanStatus {
    const now = Date.now();
    return {
      shouldScan: now >= this.nextScanAt,
      nextScanAt: this.nextScanAt,
      nextScanIn: Math.max(0, this.nextScanAt - now),
      scheduledCount: this.scheduledCount,
    };
  }
}
