// ──────────────────────────────────────────────────────────────────────────────
// Reference witness — the retention store.
//
// An append-only JSONL file owned by the witness. One record per retained
// commit, one line per record, in this key order:
//
//   index         0, 1, 2, … — the line's position in the file
//   prev_hash     the previous record's hash; 64 zeros for index 0
//   submitter_id  the submitter the commit was attributed to: the declared name
//                 of the intake file it was read from (not authenticated)
//   commit        the HeadCommit exactly as accepted
//   witness_ts    the witness's clock when it retained the commit, ms
//   witness_sig   the receipt signature over "<seq_no> <head_hash> <witness_ts>"
//   conflicts     notes on earlier records this one disagrees with (see below)
//   hash          SHA-256 (hex) of ILAS-CANON-JSON-1 of the record minus `hash`
//                 and `record_sig`
//   record_sig    base64 Ed25519 signature, by the witness key, over
//                 "ILAS-WITNESS-STORE-RECORD-1\n<hash>"
//
// The hash covers every other field, and prev_hash chains it to the record
// before, so record_sig authenticates the record whole and the store up to it:
// attribution, index, order, the commit's ts and the conflict notes. Without
// the key, a record cannot be changed, re-attributed, removed from the middle,
// reordered or replayed with recomputed hashes; only a cut back to a clean
// prefix still verifies (the outbox check at start-up is what notices that).
// The receipt preimage starts with a number and this one with a letter, so a
// record signature can never pass for a receipt signature or the reverse.
//
// Conflict notes are computed from the records before this one, by the same
// function on write and on verify, so a store that verifies carries exactly the
// notes its own history implies:
//
//   SAME_SEQ_DIFFERENT_HEAD  this submitter was retained earlier at the same
//                            seq_no with a different head_hash (a rewrite)
//   SEQ_LOWER_THAN_RETAINED  this submitter was retained earlier at a higher
//                            seq_no (a rollback)
//
// Reading the store is strict. A store verifies only if every line is the exact
// serialisation of a well-formed record, every link and hash recomputes, no
// record repeats a head already retained for its submitter, every conflict note
// is the one its history implies, and (when a public key is given) every
// receipt signature and every record signature verifies. A record without a
// record_sig is refused. The file must end with a newline: a missing one means
// an append was cut short.
// ──────────────────────────────────────────────────────────────────────────────

import { sign, verify } from "crypto";
import type { KeyObject } from "crypto";
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  openSync,
  writeSync,
} from "fs";
import { dirname } from "path";
import { canonicalise, sha256Hex } from "../../../src/l0/canonical";
import { GENESIS_HASH, bareNameProblem, checkHeadCommit } from "./commit";
import { readErrorText, readRegularFile } from "./regular-file";
import type { HeadCommit } from "./commit";
import { decodeSignature, verifyReceipt } from "./receipt";
import type { WitnessReceipt } from "./receipt";

export type ConflictNote =
  | {
      readonly kind: "SAME_SEQ_DIFFERENT_HEAD";
      readonly prior_index: number;
      readonly prior_head_hash: string;
    }
  | {
      readonly kind: "SEQ_LOWER_THAN_RETAINED";
      readonly prior_index: number;
      readonly prior_seq_no: number;
    };

export interface StoreRecord {
  readonly index: number;
  readonly prev_hash: string;
  readonly submitter_id: string;
  readonly commit: HeadCommit;
  readonly witness_ts: number;
  readonly witness_sig: string;
  readonly conflicts: readonly ConflictNote[];
  readonly hash: string;
  readonly record_sig: string;
}

/** A record before it is signed. */
export type UnsignedRecord = Omit<StoreRecord, "record_sig">;
/** A record before it is hashed and signed. */
export type UnhashedRecord = Omit<StoreRecord, "hash" | "record_sig">;

const RECORD_KEYS = [
  "index",
  "prev_hash",
  "submitter_id",
  "commit",
  "witness_ts",
  "witness_sig",
  "conflicts",
  "hash",
  "record_sig",
] as const;

/** Domain tag at the start of every record signature's preimage. */
export const RECORD_SIG_DOMAIN = "ILAS-WITNESS-STORE-RECORD-1";

/** The exact string a record signature is made over. */
export function recordSigPreimage(hash: string): string {
  return `${RECORD_SIG_DOMAIN}\n${hash}`;
}

/** Sign a hashed record with the witness's Ed25519 private key. */
export function signRecord(record: UnsignedRecord, privateKey: KeyObject): StoreRecord {
  const record_sig = sign(
    null,
    Buffer.from(recordSigPreimage(record.hash), "utf8"),
    privateKey
  ).toString("base64");
  return { ...record, record_sig };
}

/**
 * True when record_sig is the canonical base64 of an Ed25519 signature by this
 * key over the record's hash. Never throws. It does not recompute the hash; the
 * caller checks that the hash is the record's own.
 */
export function verifyRecordSig(record: StoreRecord, publicKey: KeyObject): boolean {
  const signature = decodeSignature(record.record_sig);
  if (signature === null) return false;
  try {
    return verify(null, Buffer.from(recordSigPreimage(record.hash), "utf8"), publicKey, signature);
  } catch {
    return false;
  }
}

/** The record's hash: SHA-256 of the canonical form of everything but `hash` and `record_sig`. */
export function recordHash(record: UnhashedRecord): string {
  return sha256Hex(
    canonicalise({
      index: record.index,
      prev_hash: record.prev_hash,
      submitter_id: record.submitter_id,
      commit: record.commit,
      witness_ts: record.witness_ts,
      witness_sig: record.witness_sig,
      conflicts: record.conflicts,
    })
  );
}

/** The exact line a record is stored as, without the newline. */
export function recordLine(record: StoreRecord): string {
  return JSON.stringify({
    index: record.index,
    prev_hash: record.prev_hash,
    submitter_id: record.submitter_id,
    commit: {
      seq_no: record.commit.seq_no,
      head_hash: record.commit.head_hash,
      ts: record.commit.ts,
      witness_set_id: record.commit.witness_set_id,
    },
    witness_ts: record.witness_ts,
    witness_sig: record.witness_sig,
    conflicts: record.conflicts.map((c) =>
      c.kind === "SAME_SEQ_DIFFERENT_HEAD"
        ? { kind: c.kind, prior_index: c.prior_index, prior_head_hash: c.prior_head_hash }
        : { kind: c.kind, prior_index: c.prior_index, prior_seq_no: c.prior_seq_no }
    ),
    hash: record.hash,
    record_sig: record.record_sig,
  });
}

/** The receipt a record stands for. */
export function receiptOf(record: StoreRecord): WitnessReceipt {
  return {
    seq_no: record.commit.seq_no,
    head_hash: record.commit.head_hash,
    witness_ts: record.witness_ts,
    witness_sig: record.witness_sig,
  };
}

// ── per-submitter history: duplicates and conflict notes ──────────────────────

/**
 * What has been retained for each submitter: every (seq_no, head_hash) pair with
 * the index that first retained it, and the highest seq_no seen. Writer and
 * verifier both use this, so the notes cannot drift between them.
 */
export class SubmitterHistory {
  private readonly heads = new Map<string, Map<number, Map<string, number>>>();
  private readonly highest = new Map<string, { seq_no: number; index: number }>();

  /** Index of an earlier record with the same submitter, seq_no and head_hash. */
  retainedAt(submitterId: string, commit: HeadCommit): number | null {
    return this.heads.get(submitterId)?.get(commit.seq_no)?.get(commit.head_hash) ?? null;
  }

  /** The notes a new record for this commit must carry, in prior_index order. */
  conflictsFor(submitterId: string, commit: HeadCommit): ConflictNote[] {
    const notes: ConflictNote[] = [];
    const atSeq = this.heads.get(submitterId)?.get(commit.seq_no);
    if (atSeq !== undefined) {
      for (const [hash, index] of atSeq) {
        if (hash !== commit.head_hash) {
          notes.push({ kind: "SAME_SEQ_DIFFERENT_HEAD", prior_index: index, prior_head_hash: hash });
        }
      }
    }
    const top = this.highest.get(submitterId);
    if (top !== undefined && top.seq_no > commit.seq_no) {
      notes.push({
        kind: "SEQ_LOWER_THAN_RETAINED",
        prior_index: top.index,
        prior_seq_no: top.seq_no,
      });
    }
    return notes.sort((a, b) => a.prior_index - b.prior_index);
  }

  add(submitterId: string, commit: HeadCommit, index: number): void {
    let bySeq = this.heads.get(submitterId);
    if (bySeq === undefined) {
      bySeq = new Map();
      this.heads.set(submitterId, bySeq);
    }
    let byHash = bySeq.get(commit.seq_no);
    if (byHash === undefined) {
      byHash = new Map();
      bySeq.set(commit.seq_no, byHash);
    }
    if (!byHash.has(commit.head_hash)) byHash.set(commit.head_hash, index);
    const top = this.highest.get(submitterId);
    if (top === undefined || commit.seq_no > top.seq_no) {
      this.highest.set(submitterId, { seq_no: commit.seq_no, index });
    }
  }
}

// ── reading and verifying ─────────────────────────────────────────────────────

export class StoreBroken extends Error {
  /** 1-based line number, or null when the problem is not one line's. */
  constructor(message: string, readonly line: number | null) {
    super(line === null ? message : `line ${line}: ${message}`);
    this.name = "StoreBroken";
  }
}

export interface ReadStoreOptions {
  /**
   * Check every witness_sig and every record_sig against this key. Without it,
   * only the file's own consistency is checked, which anyone can recompute.
   */
  readonly publicKey?: KeyObject;
  /** Require every commit to carry this witness_set_id. */
  readonly witnessSetId?: string;
}

export interface StoreContents {
  readonly exists: boolean;
  readonly records: StoreRecord[];
  /** Byte length of the file as read. */
  readonly size: number;
}

function sameJson(a: unknown, b: unknown): boolean {
  return canonicalise(a) === canonicalise(b);
}

function parseConflicts(value: unknown, index: number, line: number): ConflictNote[] {
  if (!Array.isArray(value)) throw new StoreBroken("conflicts must be an array", line);
  return value.map((c: unknown) => {
    if (typeof c !== "object" || c === null || Array.isArray(c)) {
      throw new StoreBroken("a conflict note must be an object", line);
    }
    const n = c as Record<string, unknown>;
    const keys = Object.keys(n).sort().join(",");
    if (
      typeof n.prior_index !== "number" ||
      !Number.isSafeInteger(n.prior_index) ||
      n.prior_index < 0 ||
      n.prior_index >= index
    ) {
      throw new StoreBroken("a conflict note must point at an earlier record", line);
    }
    if (n.kind === "SAME_SEQ_DIFFERENT_HEAD" && keys === "kind,prior_head_hash,prior_index") {
      if (typeof n.prior_head_hash !== "string") {
        throw new StoreBroken("prior_head_hash must be a string", line);
      }
      return {
        kind: "SAME_SEQ_DIFFERENT_HEAD",
        prior_index: n.prior_index,
        prior_head_hash: n.prior_head_hash,
      };
    }
    if (n.kind === "SEQ_LOWER_THAN_RETAINED" && keys === "kind,prior_index,prior_seq_no") {
      if (typeof n.prior_seq_no !== "number" || !Number.isSafeInteger(n.prior_seq_no)) {
        throw new StoreBroken("prior_seq_no must be an integer", line);
      }
      return {
        kind: "SEQ_LOWER_THAN_RETAINED",
        prior_index: n.prior_index,
        prior_seq_no: n.prior_seq_no,
      };
    }
    throw new StoreBroken(`unknown or misshapen conflict note ${JSON.stringify(c)}`, line);
  });
}

/** Parse and verify one line. Throws StoreBroken. */
function parseRecord(
  text: string,
  index: number,
  prevHash: string,
  history: SubmitterHistory,
  options: ReadStoreOptions
): StoreRecord {
  const line = index + 1;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new StoreBroken("not valid JSON", line);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new StoreBroken("not a JSON object", line);
  }
  const keys = Object.keys(parsed);
  if (!keys.includes("record_sig")) {
    throw new StoreBroken(
      "record has no record_sig: every record must be signed with the witness key, " +
        "and an unsigned record is refused",
      line
    );
  }
  if (keys.length !== RECORD_KEYS.length || keys.some((k, i) => k !== RECORD_KEYS[i])) {
    throw new StoreBroken(`keys must be exactly ${RECORD_KEYS.join(", ")} in that order`, line);
  }
  const r = parsed as Record<string, unknown>;
  if (r.index !== index) {
    throw new StoreBroken(`index is ${JSON.stringify(r.index)}, expected ${index}`, line);
  }
  if (r.prev_hash !== prevHash) {
    throw new StoreBroken("prev_hash does not link to the previous record", line);
  }
  const nameProblem = bareNameProblem(r.submitter_id);
  if (nameProblem !== null) throw new StoreBroken(`submitter_id ${nameProblem}`, line);
  const submitterId = r.submitter_id as string;
  const check = checkHeadCommit(r.commit, options.witnessSetId);
  if (!check.ok) throw new StoreBroken(`commit: ${check.reason}`, line);
  if (typeof r.witness_ts !== "number" || !Number.isSafeInteger(r.witness_ts) || r.witness_ts < 0) {
    throw new StoreBroken("witness_ts must be a non-negative safe integer", line);
  }
  if (typeof r.witness_sig !== "string") throw new StoreBroken("witness_sig must be a string", line);
  const conflicts = parseConflicts(r.conflicts, index, line);
  if (typeof r.hash !== "string") throw new StoreBroken("hash must be a string", line);
  if (typeof r.record_sig !== "string") throw new StoreBroken("record_sig must be a string", line);

  const record: StoreRecord = {
    index,
    prev_hash: prevHash,
    submitter_id: submitterId,
    commit: check.commit,
    witness_ts: r.witness_ts,
    witness_sig: r.witness_sig,
    conflicts,
    hash: r.hash,
    record_sig: r.record_sig,
  };
  if (recordLine(record) !== text) {
    throw new StoreBroken("line is not the exact serialisation of its record", line);
  }
  if (recordHash(record) !== record.hash) {
    throw new StoreBroken("hash does not match the record", line);
  }
  if (options.publicKey !== undefined) {
    if (!verifyReceipt(receiptOf(record), options.publicKey)) {
      throw new StoreBroken("witness_sig does not verify against the public key", line);
    }
    if (!verifyRecordSig(record, options.publicKey)) {
      throw new StoreBroken(
        "record_sig does not verify against the public key: this record, as it " +
          "stands, was not signed by the witness key (a field, the attribution, " +
          "the index or the order was changed and the hashes recomputed, or the " +
          "record was written without the key)",
        line
      );
    }
  }
  const earlier = history.retainedAt(submitterId, record.commit);
  if (earlier !== null) {
    throw new StoreBroken(
      `repeats the head already retained for this submitter at index ${earlier}`,
      line
    );
  }
  if (!sameJson(conflicts, history.conflictsFor(submitterId, record.commit))) {
    throw new StoreBroken("conflict notes differ from what the earlier records imply", line);
  }
  return record;
}

/**
 * Read and verify a store file. An absent file is reported as such, not as an
 * error; any other problem throws StoreBroken, a path that is not a regular
 * file included (a FIFO there is refused at once, never waited on).
 */
export function readStore(path: string, options: ReadStoreOptions = {}): StoreContents {
  let bytes: Buffer;
  try {
    bytes = readRegularFile(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { exists: false, records: [], size: 0 };
    }
    throw new StoreBroken(`cannot read store ${path}: ${readErrorText(error)}`, null);
  }
  if (bytes.length === 0) return { exists: true, records: [], size: 0 };
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) {
    throw new StoreBroken("store is not valid UTF-8", null);
  }
  if (!text.endsWith("\n")) {
    throw new StoreBroken(
      "store does not end with a newline: the last append was cut short",
      text.split("\n").length
    );
  }
  const lines = text.slice(0, -1).split("\n");
  const history = new SubmitterHistory();
  const records: StoreRecord[] = [];
  let prevHash = GENESIS_HASH;
  for (let i = 0; i < lines.length; i++) {
    const record = parseRecord(lines[i], i, prevHash, history, options);
    history.add(record.submitter_id, record.commit, record.index);
    records.push(record);
    prevHash = record.hash;
  }
  return { exists: true, records, size: bytes.length };
}

// ── appending ─────────────────────────────────────────────────────────────────

export class StoreWriteError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StoreWriteError";
  }
}

/** Opened only to be fsync'd: never blocks (a FIFO put in its place), refuses a non-directory. */
const OPEN_DIRECTORY_FLAGS =
  constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | (constants.O_NONBLOCK ?? 0);

/** fsync a directory so a new or renamed entry in it survives a crash. Best effort. */
export function fsyncDirectory(dir: string): void {
  let fd: number | null = null;
  try {
    fd = openSync(dir, OPEN_DIRECTORY_FLAGS);
    fsyncSync(fd);
  } catch {
    // Not every platform lets a directory be opened or synced.
  } finally {
    if (fd !== null) {
      try {
        closeSync(fd);
      } catch {
        // nothing more to do
      }
    }
  }
}

/**
 * Appends records to a store this process has read and verified. Each append is
 * written with O_APPEND, fsync'd, and checked: the file must have been exactly
 * the size this writer last left it (otherwise something else wrote to it), and
 * must have grown by exactly the line's length.
 */
export class StoreAppender {
  private expectedSize: number;

  constructor(readonly path: string, currentSize: number) {
    this.expectedSize = currentSize;
  }

  /** Create an empty store file. Refuses if one already exists. */
  static create(path: string): StoreAppender {
    const fd = openSync(path, "wx", 0o644);
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    fsyncDirectory(dirname(path));
    return new StoreAppender(path, 0);
  }

  append(record: StoreRecord): void {
    const bytes = Buffer.from(recordLine(record) + "\n", "utf8");
    let fd: number;
    try {
      fd = openSync(this.path, "a");
    } catch (error) {
      throw new StoreWriteError(`cannot open store ${this.path} for append: ${String(error)}`);
    }
    try {
      const before = fstatSync(fd).size;
      if (before !== this.expectedSize) {
        throw new StoreWriteError(
          `store ${this.path} is ${before} bytes; this witness last left it at ` +
            `${this.expectedSize}. Something else has written to it. Nothing was appended.`
        );
      }
      let offset = 0;
      while (offset < bytes.length) {
        offset += writeSync(fd, bytes, offset, bytes.length - offset);
      }
      fsyncSync(fd);
      const after = fstatSync(fd).size;
      if (after !== before + bytes.length) {
        throw new StoreWriteError(
          `store ${this.path} grew from ${before} to ${after} bytes; ` +
            `expected ${before + bytes.length}`
        );
      }
      this.expectedSize = after;
    } catch (error) {
      if (error instanceof StoreWriteError) throw error;
      throw new StoreWriteError(`append to ${this.path} failed: ${String(error)}`);
    } finally {
      try {
        closeSync(fd);
      } catch {
        // the append's own outcome is what matters
      }
    }
  }
}
