import { createHash } from "crypto";
import type { LogEntry } from "../types";

const GENESIS_PREV_HASH = "0".repeat(64);

type LogEntryInput = Omit<LogEntry, "sequenceNumber" | "hash" | "previousHash">;

export interface VerifyResult {
  valid: boolean;
  brokenAt?: number;
}

function hashEntry(
  sequenceNumber: number,
  previousHash: string,
  input: LogEntryInput
): string {
  const payload = JSON.stringify({
    sequenceNumber,
    previousHash,
    timestamp: input.timestamp,
    moduleId: input.moduleId,
    eventType: input.eventType,
    provenanceTag: input.provenanceTag,
    parameters: input.parameters,
    outcome: input.outcome,
  });
  return createHash("sha256").update(payload).digest("hex");
}

export class LockedEvidenceLog {
  private readonly chain: LogEntry[] = [];

  append(input: LogEntryInput): LogEntry {
    const sequenceNumber = this.chain.length;
    const previousHash =
      sequenceNumber === 0
        ? GENESIS_PREV_HASH
        : this.chain[sequenceNumber - 1].hash;

    const hash = hashEntry(sequenceNumber, previousHash, input);

    const entry: LogEntry = {
      sequenceNumber,
      hash,
      previousHash,
      timestamp: input.timestamp,
      moduleId: input.moduleId,
      eventType: input.eventType,
      provenanceTag: input.provenanceTag,
      parameters: input.parameters,
      outcome: input.outcome,
    };

    this.chain.push(entry);
    return entry;
  }

  verify(): VerifyResult {
    for (let i = 0; i < this.chain.length; i++) {
      const entry = this.chain[i];

      const expectedPrevHash =
        i === 0 ? GENESIS_PREV_HASH : this.chain[i - 1].hash;

      if (entry.previousHash !== expectedPrevHash) {
        return { valid: false, brokenAt: i };
      }

      const expectedHash = hashEntry(i, entry.previousHash, entry);
      if (entry.hash !== expectedHash) {
        return { valid: false, brokenAt: i };
      }
    }

    return { valid: true };
  }

  get length(): number {
    return this.chain.length;
  }

  getEntry(sequenceNumber: number): LogEntry | undefined {
    return this.chain[sequenceNumber];
  }

  getAll(): readonly LogEntry[] {
    return this.chain;
  }
}
