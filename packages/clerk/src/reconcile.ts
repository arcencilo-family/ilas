// ──────────────────────────────────────────────────────────────────────────────
// Reference clerk — reconcile the clerk's book with a node's L0 log.
//
// The clerk books a receipt before the node checks it, so the book can hold
// receipts the node never committed: the node refused the receipt, the answer
// was lost, the client timed out after sending, an append failed after the
// clerk booked it, or the entry was kept in memory only (docs/S4-WIRE-SPEC.md
// §7.4). And a log can carry receipts the book no longer holds: a book cut
// back to an earlier receipt, removed, or replaced still verifies on its own.
//
// This compares the two, for one submitter and channel:
//   (a) receipts in the book for that submitter and channel that no log entry
//       carries (an entry whose receipt fails (c) does not count as carrying
//       it);
//   (b) log entries whose receipt passes ILAS's receipt rules but is not in
//       the book;
//   (c) log entries whose receipt fails ILAS's own receipt rules, the ones L0
//       applies when it loads a log with this route: verifyClerkReceipt (from
//       ILAS core) against this clerk's key and the entry's six payload
//       fields, a submitter_id and channel that name this route, and each
//       receipt on at most one entry of a log. L0 refuses such a log.
//
// The book is verified first; a book that does not verify is an error, not a
// comparison. The log is read as data: no writer lock is taken, nothing is
// written, and its hash chain is not checked (L0 does that when it loads it).
// ──────────────────────────────────────────────────────────────────────────────

import { closeSync } from "fs";
import type { KeyObject } from "crypto";
import { verifyClerkReceipt } from "../../../src/l0/clerk-verify";
import { openRegularFileForReading, readLines, verifyBookFile } from "./book";
import { isPlainRecord, toEd25519PublicKey } from "./receipt";

/** The book or a log could not be read, or the book does not verify. */
export class ReconcileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReconcileError";
  }
}

export interface ReconcileOptions {
  bookPath: string;
  /** One or more L0 log files of the node (JSONL, as L0 writes them). */
  logPaths: readonly string[];
  /** The clerk's public key. */
  publicKey: KeyObject | string;
  /** The node's route: the submitter_id and channel it submits under. */
  submitterId: string;
  channel: string;
}

/** A receipt in the book, for this submitter and channel, that no log entry carries. */
export interface BookOnlyReceipt {
  clerkSeq: number;
  receiptHash: string;
}

/** A log entry listed under (b) or (c), with the reason. */
export interface LogOnlyEntry {
  logPath: string;
  /** Position of the entry in its log, counting from 0 and skipping blank lines, as L0 does. */
  index: number;
  sequenceNumber: number | null;
  clerkSeq: number | null;
  receiptHash: string | null;
  reason: string;
}

export interface LogTally {
  path: string;
  entries: number;
  withReceipt: number;
  /** Entries with no clerkReceipt at all. They are counted, not compared. */
  withoutReceipt: number;
}

export interface ReconcileReport {
  /** Receipts in the book (all verified). */
  bookCount: number;
  /** receipt_hash of the book's last receipt. */
  bookHead: string;
  /** Receipts in the book for this submitter and channel. */
  bookForRoute: number;
  logs: LogTally[];
  /** (a), in clerk_seq order. */
  bookOnly: BookOnlyReceipt[];
  /** (b), in log order: receipts that pass ILAS's rules and are not in the book. */
  logOnly: LogOnlyEntry[];
  /** (c), in log order: receipts that fail ILAS's receipt rules for their entry on this route. */
  refused: LogOnlyEntry[];
}

/** No line limit beyond what the process can hold: L0 itself reads its log whole. */
const NO_LINE_LIMIT = Number.MAX_SAFE_INTEGER;

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function safeInteger(v: unknown): number | null {
  return typeof v === "number" && Number.isSafeInteger(v) ? v : null;
}

/** The six payload fields of a log entry: what L0 submitted, and what its receipt binds. */
function entryPayload(e: Record<string, unknown>): Record<string, unknown> {
  return {
    timestamp: e.timestamp,
    moduleId: e.moduleId,
    eventType: e.eventType,
    provenanceTag: e.provenanceTag,
    parameters: e.parameters,
    outcome: e.outcome,
  };
}

/**
 * Why ILAS's receipt rules refuse `r` on `entry` for this route, or null: the
 * route binding, at most one entry per receipt in a log (`earlier` holds the
 * receipts already accepted on this log, by receipt_hash), and ILAS's own
 * verifyClerkReceipt over the entry's payload. The order is L0's.
 */
function receiptRefusal(
  r: Record<string, unknown>,
  entry: Record<string, unknown>,
  route: { submitterId: string; channel: string; keyPem: string },
  earlier: ReadonlyMap<string, number>
): string | null {
  if (r.submitter_id !== route.submitterId) {
    return `submitter_id ${JSON.stringify(r.submitter_id)} does not name the reconciled submitter`;
  }
  if (r.channel !== route.channel) {
    return `channel ${JSON.stringify(r.channel)} does not name the reconciled channel`;
  }
  const at = typeof r.receipt_hash === "string" ? earlier.get(r.receipt_hash) : undefined;
  if (at !== undefined) {
    return `the same receipt as entry ${at} of this log; a receipt binds one entry`;
  }
  const v = verifyClerkReceipt(r, route.keyPem, entryPayload(entry));
  return v.ok ? null : `fails ILAS's receipt check: ${v.reason}`;
}

/** Compare the book with the logs. Throws ReconcileError for anything that stops the comparison. */
export function reconcileBookAndLogs(options: ReconcileOptions): ReconcileReport {
  const { bookPath, logPaths, submitterId, channel } = options;
  if (logPaths.length === 0) throw new ReconcileError("no log file given");
  let key: KeyObject;
  let keyPem: string;
  try {
    key = toEd25519PublicKey(options.publicKey);
    keyPem = key.export({ type: "spki", format: "pem" }) as string;
  } catch (err) {
    throw new ReconcileError(`clerk public key: ${messageOf(err)}`);
  }
  const route = { submitterId, channel, keyPem };

  // The book's receipts for this route, by receipt_hash, in clerk_seq order.
  const forRoute = new Map<string, { clerkSeq: number; onLog: boolean }>();
  const book = verifyBookFile(bookPath, key, (r) => {
    if (r.submitter_id === submitterId && r.channel === channel) {
      forRoute.set(r.receipt_hash as string, { clerkSeq: r.clerk_seq as number, onLog: false });
    }
  });
  if (!book.ok) {
    throw new ReconcileError(
      `book does NOT verify: ${book.reason} (${book.count} receipt(s) verified before the break); ` +
        `nothing was compared`
    );
  }

  const logs: LogTally[] = [];
  const logOnly: LogOnlyEntry[] = [];
  const refused: LogOnlyEntry[] = [];
  for (const logPath of logPaths) {
    const tally: LogTally = { path: logPath, entries: 0, withReceipt: 0, withoutReceipt: 0 };
    /** Receipts accepted on this log so far: receipt_hash → entry index. */
    const accepted = new Map<string, number>();
    let fd: number;
    try {
      fd = openRegularFileForReading(logPath);
    } catch (err) {
      throw new ReconcileError(`cannot read log ${logPath}: ${messageOf(err)}`);
    }
    try {
      let index = 0;
      for (const line of readLines(fd, NO_LINE_LIMIT)) {
        // L0's reading: the file is UTF-8 text, and blank lines are skipped.
        const text = line.bytes.toString("utf8");
        if (text.trim().length === 0) continue;
        let entry: unknown;
        try {
          entry = JSON.parse(text);
        } catch (err) {
          throw new ReconcileError(
            line.terminated
              ? `log ${logPath}: line at index ${index} is not valid JSON (${messageOf(err)})`
              : `log ${logPath}: torn final line at index ${index}: the file ends inside it, without a newline`
          );
        }
        if (!isPlainRecord(entry)) {
          throw new ReconcileError(`log ${logPath}: line at index ${index} is not a JSON object`);
        }
        tally.entries++;
        const at = { logPath, index, sequenceNumber: safeInteger(entry.sequenceNumber) };
        index++;
        const r = entry.clerkReceipt;
        if (r === undefined || r === null) {
          tally.withoutReceipt++;
          continue;
        }
        tally.withReceipt++;
        if (!isPlainRecord(r)) {
          refused.push({ ...at, clerkSeq: null, receiptHash: null, reason: "clerkReceipt is not a JSON object" });
          continue;
        }
        const hash = typeof r.receipt_hash === "string" ? r.receipt_hash : null;
        const found = { ...at, clerkSeq: safeInteger(r.clerk_seq), receiptHash: hash };
        const refusal = receiptRefusal(r, entry, route, accepted);
        if (refusal !== null) {
          // Not counted as carrying a booked receipt: that booking stays under (a).
          refused.push({ ...found, reason: refusal });
          continue;
        }
        // Signed by this key with this receipt_hash: equal hashes mean the same receipt.
        accepted.set(hash as string, at.index);
        const booked = forRoute.get(hash as string);
        if (booked !== undefined) {
          booked.onLog = true;
          continue;
        }
        logOnly.push({ ...found, reason: "not in the book" });
      }
    } finally {
      closeSync(fd);
    }
    logs.push(tally);
  }

  const bookOnly: BookOnlyReceipt[] = [];
  for (const [receiptHash, b] of forRoute) {
    if (!b.onLog) bookOnly.push({ clerkSeq: b.clerkSeq, receiptHash });
  }
  return {
    bookCount: book.count,
    bookHead: book.head,
    bookForRoute: forRoute.size,
    logs,
    bookOnly,
    logOnly,
    refused,
  };
}

/** True when the report lists no gap of any kind. */
export function reconcileFoundNoGaps(r: ReconcileReport): boolean {
  return r.bookOnly.length === 0 && r.logOnly.length === 0 && r.refused.length === 0;
}
