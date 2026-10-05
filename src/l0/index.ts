import { createHash } from "crypto";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
} from "fs";
import { dirname } from "path";
import type { LogEntry } from "../types";

const GENESIS_PREV_HASH = "0".repeat(64);

type LogEntryInput = Omit<LogEntry, "sequenceNumber" | "hash" | "previousHash">;

export interface VerifyResult {
  valid: boolean;
  brokenAt?: number;
}

// ── Durability ────────────────────────────────────────────────────────────────
// Persistence is OPT-IN. `new LockedEvidenceLog()` with no options is the
// in-memory behaviour (no load, no write). Durability engages only when a
// `path` is supplied.
//
// A missing, unreadable, or failing-verify file MUST NOT produce a clean start.
// The log comes up in an explicit non-clean state that is visible through
// getDurabilityInfo().

export type L0LoadState =
  | "IN_MEMORY"             // no path — durability disabled (default)
  | "LOADED_VERIFIED"       // file present, parsed, verify() valid
  | "FIRST_BOOT_OR_ERASED"  // file absent — first run and erased history look the same
  | "CANNOT_VERIFY";        // file present but unreadable / unparseable / broken

export interface DurabilityInfo {
  durable: boolean;
  path: string | null;
  loadState: L0LoadState;
  /** true only for LOADED_VERIFIED — anything else is a non-clean start. */
  clean: boolean;
  entriesLoaded: number;
  brokenAt: number | null;
  /** false once a persistence write has failed this run. */
  writeHealthy: boolean;
  lastError: string | null;
  /** true while appends are written to disk; false when durability is fail-closed. */
  persisting: boolean;
}

export interface LockedEvidenceLogOptions {
  /** Enable durability by pointing at a JSONL file. Omit for in-memory. */
  path?: string;
}

/** Thrown when a durable append cannot be persisted. Propagated, never swallowed. */
export class L0WriteError extends Error {
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = "L0WriteError";
  }
}

function hashEntry(
  sequenceNumber: number,
  previousHash: string,
  input: LogEntryInput
): string {
  const payload = JSON.stringify({
    sequenceNumber,
    previousHash,
    outcome: input.outcome,
  });
  return createHash("sha256").update(payload).digest("hex");
}

export class LockedEvidenceLog {
  private readonly chain: LogEntry[] = [];

  // ── durability state ─────────────────────────────────────────────────────
  private readonly path: string | null;
  private loadState: L0LoadState = "IN_MEMORY";
  private brokenAt: number | null = null;
  private persisting = false;
  private writeHealthy = true;
  private lastError: string | null = null;

  // ── replay guard ─────────────────────────────────────────────────────────
  // When a chain is loaded from disk, module constructors that seed bootstrap
  // entries (ProbeManager's probe_registered appends) would otherwise re-append
  // and grow the chain on every restart. The assembly wraps construction in
  // begin/endReplayGuard() so those appends are skipped. The guard lives here,
  // so no mechanism module needs to know about it.
  private replayGuard = false;

  constructor(options?: LockedEvidenceLogOptions) {
    this.path = options?.path ?? null;
    if (this.path === null) {
      this.loadState = "IN_MEMORY";
      return;
    }
    this.loadFromDisk();
  }

  // ── load ───────────────────────────────────────────────────────────────────

  private loadFromDisk(): void {
    const path = this.path as string;

    if (!existsSync(path)) {
      // Absent file: first run or erased history — the code cannot tell which.
      // Surface as non-clean; seed and persist so the node is operational.
      this.loadState = "FIRST_BOOT_OR_ERASED";
      try {
        mkdirSync(dirname(path), { recursive: true });
        this.persisting = true;
      } catch (err) {
        this.persisting = false;
        this.writeHealthy = false;
        this.lastError = `cannot create log directory: ${String(err)}`;
      }
      return;
    }

    let raw: string;
    try {
      raw = readFileSync(path, "utf8");
    } catch (err) {
      // Present but unreadable. Fail closed: do not persist, do not fabricate a
      // clean chain, do not overwrite the file we cannot read.
      this.loadState = "CANNOT_VERIFY";
      this.persisting = false;
      this.lastError = `cannot read log file: ${String(err)}`;
      return;
    }

    const lines = raw.split("\n").filter((l) => l.trim().length > 0);
    const loaded: LogEntry[] = [];
    for (let i = 0; i < lines.length; i++) {
      try {
        loaded.push(JSON.parse(lines[i]) as LogEntry);
      } catch (err) {
        this.loadState = "CANNOT_VERIFY";
        this.persisting = false;
        this.brokenAt = i;
        this.lastError = `malformed JSON at line ${i}: ${String(err)}`;
        return;
      }
    }

    // Reconstruct and verify the loaded chain BEFORE accepting it.
    for (const e of loaded) this.chain.push(e);
    const v = this.verify();
    if (!v.valid) {
      // Tamper-evident break. Keep the loaded entries in memory for inspection
      // through getAll(), but do not persist new appends onto a chain that did
      // not verify, and report non-clean.
      this.loadState = "CANNOT_VERIFY";
      this.persisting = false;
      this.brokenAt = v.brokenAt ?? null;
      this.lastError = `chain verification failed at index ${v.brokenAt}`;
      return;
    }

    if (loaded.length === 0) {
      // Empty-but-present file: non-clean, but we can persist onward.
      this.loadState = "FIRST_BOOT_OR_ERASED";
      this.persisting = true;
      return;
    }

    this.loadState = "LOADED_VERIFIED";
    this.persisting = true;
  }

  // ── replay guard control ─────────────────────────────────────────────────

  /** True when construction loaded a non-empty, verified chain from disk. */
  loadedExisting(): boolean {
    return this.loadState === "LOADED_VERIFIED";
  }

  beginReplayGuard(): void {
    this.replayGuard = true;
  }

  endReplayGuard(): void {
    this.replayGuard = false;
  }

  // ── append ───────────────────────────────────────────────────────────────

  append(input: LogEntryInput): LogEntry {
    // Suppress bootstrap re-seeding on reload. Return a sentinel that is never
    // chained or persisted; every construction-time caller discards it.
    if (this.replayGuard) {
      return {
        sequenceNumber: -1,
        hash: "",
        previousHash: "",
        timestamp: input.timestamp,
        moduleId: input.moduleId,
        eventType: input.eventType,
        provenanceTag: input.provenanceTag,
        parameters: input.parameters,
        outcome: "suppressed_bootstrap_replay",
      };
    }

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

    // Persist BEFORE committing to the in-memory chain, so a write failure does
    // not silently diverge disk from memory. Callers discard append()'s return
    // value, so the throw is the only channel that cannot be ignored.
    if (this.persisting) {
      try {
        appendFileSync(this.path as string, JSON.stringify(entry) + "\n");
      } catch (err) {
        this.writeHealthy = false;
        this.lastError = `append write failed at seq ${sequenceNumber}: ${String(err)}`;
        throw new L0WriteError(this.lastError, err);
      }
    }

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

  // ── durability surface (for status endpoints) ─────────────────────────────

  getLoadState(): L0LoadState {
    return this.loadState;
  }

  /** True only for a clean, verified durable load. */
  isClean(): boolean {
    return this.loadState === "LOADED_VERIFIED";
  }

  getDurabilityInfo(): DurabilityInfo {
    return {
      durable: this.path !== null,
      path: this.path,
      loadState: this.loadState,
      clean: this.loadState === "LOADED_VERIFIED",
      entriesLoaded:
        this.loadState === "LOADED_VERIFIED" ||
        this.loadState === "CANNOT_VERIFY"
          ? this.chain.length
          : 0,
      brokenAt: this.brokenAt,
      writeHealthy: this.writeHealthy,
      lastError: this.lastError,
      persisting: this.persisting,
    };
  }
}
