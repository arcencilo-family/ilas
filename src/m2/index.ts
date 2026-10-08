import { createHash, randomBytes } from "crypto";
import type { ModuleSignal } from "../types";
import type { LockedEvidenceLog } from "../l0";

const MIN_FAMILIES          = 4;
const MAX_STATIC_WINDOW_MS  = 72 * 60 * 60 * 1000;  // 72 hours
const MIN_ROTATIONS_PER_CYCLE = 3;

export interface RotationResult {
  selectedFamilies: string[];
  rotationIndex: number;
  seed: string;        // hex — the "reveal" half of the commit-reveal
  commitment: string;  // SHA-256(seed) — logged to L0 at rotation time
}

export interface PassCondition {
  met: boolean;
  rotationsTested: number;
  nonAdjacentPasses: number;
}

interface FamilyRecord {
  id: string;
  name: string;
  checkFn: () => ModuleSignal;
}

interface RotationRecord {
  index: number;
  selectedFamilies: string[];
  seed: string;
  commitment: string;
  timestamp: number;
}

interface TrackedResult {
  rotationIndex: number;
  signals: ModuleSignal[];
  allClean: boolean;
  timestamp: number;
}

export class DetectionRotator {
  private readonly families     = new Map<string, FamilyRecord>();
  private activeFamilyIds: string[] = [];
  private readonly rotations: RotationRecord[] = [];
  private readonly tracked      = new Map<number, TrackedResult>();
  private lastRotationAt        = 0;

  constructor(private readonly log?: LockedEvidenceLog) {}

  registerFamily(id: string, name: string, checkFn: () => ModuleSignal): void {
    this.families.set(id, { id, name, checkFn });
    this.log?.enqueue({
      timestamp: Date.now(),
      moduleId: "m2",
      eventType: "family_registered",
      provenanceTag: "LaneB",
      parameters: { id, name, totalFamilies: this.families.size },
      outcome: "ok",
    });
  }

  rotate(): RotationResult {
    if (this.families.size < MIN_FAMILIES) {
      throw new Error(
        `Cannot rotate: need at least ${MIN_FAMILIES} families, have ${this.families.size}`
      );
    }

    const now        = Date.now();
    const familyIds  = Array.from(this.families.keys());
    const seedBytes  = randomBytes(32);
    const seed       = seedBytes.toString("hex");
    const commitment = createHash("sha256").update(seedBytes).digest("hex");

    // Select 2 or 3 families — byte 0 determines count, remainder drives shuffle
    const count = Math.min(
      (seedBytes[0] & 1) === 0 ? 2 : 3,
      familyIds.length
    );

    // Fisher-Yates shuffle seeded from seedBytes (bytes 1–31, cyclic)
    const pool = [...familyIds];
    for (let i = pool.length - 1; i > 0; i--) {
      const j = seedBytes[(i * 7 + 1) % 32] % (i + 1);
      [pool[i], pool[j]] = [pool[j], pool[i]];
    }
    const selectedFamilies = pool.slice(0, count);

    // The active set, the rotation record, the evidence entry and the result
    // each get their own copy: what a caller does with the result cannot change
    // which families run or what was recorded.
    this.activeFamilyIds = [...selectedFamilies];
    this.lastRotationAt  = now;

    const rotationIndex = this.rotations.length;
    this.rotations.push({
      index: rotationIndex,
      selectedFamilies: [...selectedFamilies],
      seed,
      commitment,
      timestamp: now,
    });

    this.log?.enqueue({
      timestamp: now,
      moduleId: "m2",
      eventType: "rotation",
      provenanceTag: "LaneB",
      parameters: { rotationIndex, selectedFamilies: [...selectedFamilies], commitment, count },
      outcome: "ok",
    });

    return { selectedFamilies: [...selectedFamilies], rotationIndex, seed, commitment };
  }

  getActiveFamilies(): string[] {
    return [...this.activeFamilyIds];
  }

  runActiveFamilies(): ModuleSignal[] {
    const signals: ModuleSignal[] = [];
    for (const id of this.activeFamilyIds) {
      const family = this.families.get(id);
      if (!family) continue;
      try {
        signals.push(family.checkFn());
      } catch (err) {
        signals.push({
          moduleId: "m2",
          severity: "soft_alarm",
          message: `family "${id}" threw during check: ${(err as Error).message}`,
          timestamp: Date.now(),
        });
      }
    }
    return signals;
  }

  trackRotationResults(rotationIndex: number, signals: ModuleSignal[]): void {
    const allClean = signals.every((s) => s.severity === "clean");
    this.tracked.set(rotationIndex, {
      rotationIndex,
      signals,
      allClean,
      timestamp: Date.now(),
    });
    this.log?.enqueue({
      timestamp: Date.now(),
      moduleId: "m2",
      eventType: "rotation_results_tracked",
      provenanceTag: "LaneB",
      parameters: { rotationIndex, signalCount: signals.length, allClean },
      outcome: allClean ? "clean" : "alarm",
    });
  }

  getPassCondition(): PassCondition {
    const rotationsTested = this.tracked.size;

    const passingIndices = Array.from(this.tracked.entries())
      .filter(([, r]) => r.allClean)
      .map(([idx]) => idx)
      .sort((a, b) => a - b);

    // Count pairs of passing rotations whose index gap is > 1 (non-adjacent)
    let nonAdjacentPasses = 0;
    for (let i = 0; i < passingIndices.length; i++) {
      for (let j = i + 1; j < passingIndices.length; j++) {
        if (passingIndices[j] - passingIndices[i] > 1) nonAdjacentPasses++;
      }
    }

    const met = rotationsTested >= MIN_ROTATIONS_PER_CYCLE && nonAdjacentPasses >= 1;
    return { met, rotationsTested, nonAdjacentPasses };
  }

  // Standalone verifier — any caller can check a disclosed seed against its commitment
  verifySeed(seed: string, commitment: string): boolean {
    const recomputed = createHash("sha256")
      .update(Buffer.from(seed, "hex"))
      .digest("hex");
    return recomputed === commitment;
  }

  isStaticWindowExceeded(): boolean {
    if (this.lastRotationAt === 0) return false;
    return Date.now() - this.lastRotationAt > MAX_STATIC_WINDOW_MS;
  }

  getRotationCount(): number {
    return this.rotations.length;
  }
}
