import { createHash, createPublicKey, randomBytes } from "crypto";
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  unlinkSync,
  writeSync,
} from "fs";
import type { BigIntStats } from "fs";
import { basename, dirname, isAbsolute, join, resolve, sep } from "path";
import type { ClerkSubmissionReceipt, LogEntry } from "../types";
import { canonicalise } from "./canonical";
import { holdsPrivateKey, verifyClerkReceipt } from "./clerk-verify";
import { publicKeyFingerprint } from "./fingerprint";

const GENESIS_PREV_HASH = "0".repeat(64);

type LogEntryInput = Omit<
  LogEntry,
  "sequenceNumber" | "hash" | "previousHash" | "clerkReceipt"
>;
type StampedLogEntryInput = LogEntryInput & {
  clerkReceipt?: ClerkSubmissionReceipt;
};

/** The only fields a stored log line may carry (clerkReceipt is optional). */
const ENTRY_KEYS: ReadonlySet<string> = new Set([
  "sequenceNumber",
  "hash",
  "previousHash",
  "timestamp",
  "moduleId",
  "eventType",
  "provenanceTag",
  "parameters",
  "outcome",
  "clerkReceipt",
]);

export interface ClerkSubmitRequest {
  submitter_id: string;
  channel: string;
  declared_timestamp?: number | null;
  payload: unknown;
}

/**
 * The one method L0 needs from a clerk client. Any object of this shape will do;
 * L0 never imports a clerk implementation (docs/S4-WIRE-SPEC.md §1). The
 * reference clerk in packages/clerk ships clients that implement it.
 */
export interface ClerkSubmitClient {
  submit(req: ClerkSubmitRequest): Promise<ClerkSubmissionReceipt>;
  /**
   * Optional. The largest payload this client can deliver, in UTF-8 bytes of
   * its canonical form (docs/S4-WIRE-SPEC.md §7.2). L0 reads it once, when the
   * log is built; it must then be a positive safe integer. A larger entry is
   * refused with L0PayloadError before anything is submitted, and the log goes
   * on. Absent: L0 sets no size limit.
   */
  readonly maxPayloadBytes?: number;
}

export interface ClerkRoute {
  client: ClerkSubmitClient;
  /** Non-empty. Every receipt must name exactly this submitter_id. */
  submitterId: string;
  /** Non-empty. Every receipt must name exactly this channel. */
  channel: string;
  /**
   * PEM Ed25519 public key of the clerk. Required. There is no default: a key
   * nobody chose cannot authenticate anything. Receipts are accepted only if
   * their signature verifies against this key. A private key is refused.
   */
  clerkPublicKeyPem: string;
}

export interface ClerkClockStamp {
  sequenceNumber: number;
  clerk_seq: number;
  clerk_time: { wall_ms: number; monotonic_ns: string };
  separation: "SEPARATE_PROCESS" | "IN_PROCESS_NO_SEPARATION";
  intake: "SOCKET" | "LOCAL_CALL" | "CLERK_INTERNAL";
  clerk_id: string;
  clerk_boot_id: string;
}

export interface VerifyResult {
  valid: boolean;
  brokenAt?: number;
}

// ── Durability ────────────────────────────────────────────────────────────────
// Persistence is OPT-IN. `new LockedEvidenceLog()` with no options is byte-for-
// byte the original in-memory behaviour (no load, no write) — every existing
// module, test, and caller is unaffected. Durability engages only when a `path`
// is supplied.
//
// Load-state is the whole point: a missing, unreadable, or failing-verify file
// MUST NOT produce a clean start. We come up in an explicit, non-clean
// state that is visible on the status endpoint.

export type L0LoadState =
  | "IN_MEMORY"             // no path — durability disabled (default; tests)
  | "LOADED_VERIFIED"       // file present, parsed, verify() valid (and, with a clerk route, every receipt checked)
  | "FIRST_BOOT_OR_ERASED"  // file absent or empty — undecidable first-run vs wipe
  | "CANNOT_VERIFY";        // file present but unreadable / unparseable / broken / a line not exactly as L0 writes it

export interface DurabilityInfo {
  durable: boolean;
  path: string | null;
  loadState: L0LoadState;
  /**
   * true only for LOADED_VERIFIED — anything else is a non-clean start. It
   * describes the hash chain (and, with a clerk route, the receipts the route
   * checked); see receiptsUnchecked for receipts nothing checked.
   */
  clean: boolean;
  /** How many entries were read from disk at load. Fixed at load. */
  entriesLoaded: number;
  brokenAt: number | null;
  /** false once a persistence write has failed this run (see commit()). */
  writeHealthy: boolean;
  lastError: string | null;
  /** true while writes are persisted; false when durability is fail-closed. */
  persisting: boolean;
  /**
   * Loaded entries that carry a clerk receipt although the log was loaded
   * WITHOUT a clerk route, so their receipts were not checked. 0 with a route.
   * Fixed at load.
   */
  receiptsUnchecked: number;
  /**
   * true when this log took over a stale writer lock ("<path>.lock") at
   * construction: its process was gone, or it named this process's pid with
   * another process start, or none (an earlier process with the same pid).
   */
  lockTakenOver: boolean;
}

export interface LockedEvidenceLogOptions {
  /** Enable durability by pointing at a JSONL file. Omit for in-memory. */
  path?: string;
  /**
   * Route appends through a clerk (docs/S4-WIRE-SPEC.md §7). Omit only for
   * explicitly unstamped/legacy use. With a path as well, every entry loaded
   * from the file must carry a receipt that passes §7.3 for this route, so a
   * log written without a clerk cannot be continued with one: start a new file.
   */
  clerk?: ClerkRoute;
  /**
   * With a path: fsync the file after every entry, before the entry counts as
   * committed. Default true. Set false only in tests and benchmarks that ask
   * for it: an entry is then on disk only once the operating system flushes it,
   * and a power loss can take entries a witness or a clerk already holds.
   */
  fsync?: boolean;
}

/** Thrown when a durable append cannot be persisted. Propagated, never swallowed. */
export class L0WriteError extends Error {
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = "L0WriteError";
  }
}

/** Thrown when the clerk did not return a confirmable submission receipt. */
export class L0ClerkError extends Error {
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = "L0ClerkError";
  }
}

/**
 * Thrown (no clerk) or rejected (clerk) when an entry has no JSON form (a
 * BigInt, a cycle) or, with a clerk, no canonical form (nesting deeper than the
 * canonical limit), a timestamp that is not a number, or a canonical form larger
 * than the client's maxPayloadBytes. Refused before anything is submitted or
 * committed. It refuses that one entry only; it does not stop the log.
 */
export class L0PayloadError extends Error {
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = "L0PayloadError";
  }
}

/**
 * A message for any thrown or rejected value, without ever throwing. A clerk
 * client or a payload's toJSON can throw anything: String() itself throws for
 * an object with no usable toString/valueOf, for one whose toString throws,
 * and for a revoked Proxy (where Object.prototype.toString throws too).
 */
function describe(value: unknown): string {
  try {
    return String(value);
  } catch {
    // fall through
  }
  try {
    return Object.prototype.toString.call(value);
  } catch {
    return "[unprintable value]";
  }
}

/** `value instanceof ctor`, false instead of a throw (a revoked Proxy throws). */
function isA<T>(value: unknown, ctor: abstract new (...args: never[]) => T): value is T {
  try {
    return value instanceof ctor;
  } catch {
    return false;
  }
}

/** The `code` of a Node system error, or undefined. */
function errorCode(err: unknown): unknown {
  try {
    return (err as { code?: unknown } | null)?.code;
  } catch {
    return undefined;
  }
}

// ── The log file on disk ──────────────────────────────────────────────────────
// The file is opened ONCE, by name, and everything after that is done on the
// descriptor: the read at load and every append. The open never follows a
// symbolic link at the log path and never blocks on a FIFO; fstat on the
// descriptor then refuses anything that is not a regular file. Every caller up
// to ILASKillStack.status() is synchronous, so a blocked open would stop the node.

const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const O_NONBLOCK = constants.O_NONBLOCK ?? 0;
/** The log file, for reading at load and appending after. */
const LOG_OPEN_FLAGS = constants.O_RDWR | constants.O_APPEND | O_NOFOLLOW | O_NONBLOCK;
/** The log file, read only: one this process may read but not write. */
const LOG_READ_FLAGS = constants.O_RDONLY | O_NOFOLLOW | O_NONBLOCK;
/** A new log file: created by this open, or not at all. */
const LOG_CREATE_FLAGS = LOG_OPEN_FLAGS | constants.O_CREAT | constants.O_EXCL;
/** A new writer lock: created by this open, or not at all. */
const LOCK_CREATE_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | O_NOFOLLOW;
const LOCK_READ_FLAGS = constants.O_RDONLY | O_NOFOLLOW | O_NONBLOCK;
/** A writer lock is about 150 bytes; a larger file at the lock path is not one. */
const MAX_LOCK_BYTES = 4096;
/** The log file is read in pieces of this size at load, never as one string. */
const LOAD_CHUNK_BYTES = 1 << 20;

/**
 * A relative log path anchored at the working directory, read once (at
 * construction), so a later process.chdir() cannot move the log, its lock or
 * the checks before each append. The working directory is prefixed, not
 * normalised: "..", a symbolic link and a trailing slash are left for the file
 * system to resolve, exactly as it would resolve the path as given. An absolute
 * or empty path is returned as it is. Throws when the working directory cannot
 * be read (it was removed).
 */
function anchorLogPath(path: string): string {
  if (path.length === 0 || isAbsolute(path)) return path;
  // Not process.cwd(): Node caches it, so after the working directory is removed
  // or renamed it still names the old place (and L0 would recreate a removed
  // directory, or open a new one at the old name). getcwd() via the native
  // realpath reports where the process really is, or throws if it is gone.
  const cwd = realpathSync.native(".");
  return cwd.endsWith(sep) ? `${cwd}${path}` : `${cwd}${sep}${path}`;
}

/** What kind of file `st` describes, for a message. */
function fileKind(st: { isDirectory(): boolean; isFIFO(): boolean; isSocket(): boolean; isSymbolicLink(): boolean; isCharacterDevice(): boolean; isBlockDevice(): boolean }): string {
  if (st.isDirectory()) return "a directory";
  if (st.isFIFO()) return "a FIFO";
  if (st.isSocket()) return "a socket";
  if (st.isSymbolicLink()) return "a symbolic link";
  if (st.isCharacterDevice() || st.isBlockDevice()) return "a device";
  return "a special file";
}

/** An open error, saying so when the cause is a symbolic link that was not followed. */
function describeOpenError(err: unknown): string {
  const text = describe(err);
  return errorCode(err) === "ELOOP"
    ? `${text} (a symbolic link at the log path is not followed)`
    : text;
}

/** Write every byte of `bytes` at the descriptor's position (the end, for O_APPEND). */
function writeAll(fd: number, bytes: Buffer): void {
  let offset = 0;
  while (offset < bytes.length) {
    const n = writeSync(fd, bytes, offset, bytes.length - offset);
    if (n <= 0) throw new Error(`write returned ${n} with ${bytes.length - offset} bytes left`);
    offset += n;
  }
}

/** Best effort: make a new directory entry durable. Not every platform allows it. */
function syncDirectory(dir: string): void {
  let fd: number | null = null;
  try {
    fd = openSync(dir, constants.O_RDONLY);
    fsyncSync(fd);
  } catch {
    // not supported here; the file's own fsync still runs on every entry
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

/** The text of a small regular file: no symbolic link followed, no FIFO opened blocking. */
function readSmallRegularFile(path: string, max: number): string {
  const fd = openSync(path, LOCK_READ_FLAGS);
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error(`${path} is not a regular file (${fileKind(st)})`);
    const buffer = Buffer.alloc(max + 1);
    let length = 0;
    for (;;) {
      const n = readSync(fd, buffer, length, buffer.length - length, null);
      if (n === 0) break;
      length += n;
      if (length > max) throw new Error(`${path} is larger than ${max} bytes`);
    }
    return buffer.toString("utf8", 0, length);
  } finally {
    closeSync(fd);
  }
}

// ── The writer lock: one writer per log file ──────────────────────────────────
// Two writers appending to one file fork its chain, and the next start cannot
// load it. "<path>.lock" holds { pid, instance, processStart, started }. It
// appears whole or not at all: the text is written and synced to a staged file
// beside it (".ilas-lock-<instance>"), which is then hard-linked to the lock
// path (the link fails if a lock is already there) and removed. A crash can
// leave a stray staged file, which is harmless and may be deleted; it cannot
// leave an empty or partial lock. Only on a file system without hard links is
// the lock created in place and then written.
//
// processStart is when the locking process started: on Linux "proc:" and field
// 22 of /proc/self/stat (clock ticks after boot), elsewhere "uptime:" and
// Date.now() - process.uptime() in whole seconds, equal within 2 s.
//
// Another live process holding the lock is a deployment error: the constructor
// throws L0WriteError naming that pid. So is another thread of this process (a
// worker thread): the lock names this pid and this processStart, with an
// instance this thread did not create. A lock whose process is gone is stale
// and is taken over; so is one naming this pid with ANOTHER processStart (an
// earlier process that had the same pid: a container restarted as pid 1), or
// with none (a lock written before processStart was recorded). Pids are
// compared within one pid namespace only. Between two processes that find the
// same stale lock at the same moment there is a small window; the next start
// still verifies the whole chain, so a fork that slips through it is reported,
// not hidden. A worker that ends without close() leaves its lock, which the rest
// of the process then refuses until it is removed by hand.
//
// A file at the lock path that cannot be parsed as a lock (empty, damaged, not
// written by L0) is refused, never taken over: the message tells the operator
// to check that nothing has the log open and then remove the lock by hand.
//
// Within one thread the NEWEST log on a path owns it: opening the path again
// (a restart inside one process, as tests do) supersedes the older log, which
// then refuses every append. close() releases the lock, and so does process
// exit. A log without a path takes no lock.

const LOCK_INSTANCE = /^[0-9a-f]{32}$/;
const PROCESS_START = /^(proc|uptime):(\d+)$/;
/** "uptime:" starts are wall-clock estimates: equal within this many seconds. */
const UPTIME_TOLERANCE_S = 2;

interface LockHolder {
  pid: number;
  instance: string;
  /** null for a lock written before processStart was recorded. */
  processStart: string | null;
}

function parseWriterLock(text: string): LockHolder | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const { pid, instance, processStart } = parsed as {
    pid?: unknown;
    instance?: unknown;
    processStart?: unknown;
  };
  if (typeof pid !== "number" || !Number.isSafeInteger(pid) || pid <= 0) return null;
  if (typeof instance !== "string" || !LOCK_INSTANCE.test(instance)) return null;
  if (processStart === undefined) return { pid, instance, processStart: null };
  if (typeof processStart !== "string" || !PROCESS_START.test(processStart)) return null;
  return { pid, instance, processStart };
}

let ownProcessStart: string | null = null;

/**
 * When this process started, as a writer lock records it. A "proc:" value is
 * read once per thread and kept; the "uptime:" estimate is NOT kept, so a
 * transient /proc read error (descriptor pressure) is retried next time.
 * The estimate is boot-relative (monotonic clock minus process uptime), so it
 * is the same in every thread of a process and a wall-clock step cannot move it.
 */
function processStartOf(): string {
  if (ownProcessStart !== null) return ownProcessStart;
  if (process.platform === "linux") {
    try {
      const stat = readFileSync("/proc/self/stat", "utf8");
      // Field 2 (the command) is in parentheses and may hold spaces: count from after it.
      const field22 = stat.slice(stat.lastIndexOf(")") + 2).split(" ")[19];
      if (field22 !== undefined && /^\d+$/.test(field22)) {
        ownProcessStart = `proc:${field22}`;
        return ownProcessStart;
      }
    } catch {
      // no /proc here, or not right now: fall back to the estimate below
    }
  }
  return `uptime:${Math.round(Number(process.hrtime.bigint() / 1_000_000n) / 1000 - process.uptime())}`;
}

/**
 * Whether two recorded process starts name DIFFERENT process starts. True only
 * when both parse, are the same kind, and differ (exactly for "proc:", by more
 * than the tolerance for "uptime:"). Anything else — mixed kinds, a value that
 * does not parse — is not proof of another process, so the caller fails closed.
 */
function anotherProcessStart(a: string, b: string): boolean {
  const x = PROCESS_START.exec(a);
  const y = PROCESS_START.exec(b);
  if (x === null || y === null || x[1] !== y[1]) return false;
  if (x[1] === "proc") return x[2] !== y[2];
  return Math.abs(Number(x[2]) - Number(y[2])) > UPTIME_TOLERANCE_S;
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return errorCode(err) === "EPERM";
  }
}

/** The log on a path that owns it in this process, as the lock registry keeps it. */
interface PathClaim {
  owner: LockedEvidenceLog;
  lockPath: string;
  instance: string;
}

interface WriterLocks {
  /** Lock path (directory resolved) → the newest log on it in this process. */
  claims: Map<string, PathClaim>;
  /** Instance ids of the locks this process created and still holds. */
  instances: Set<string>;
  exitHook: boolean;
}

/** Shared by every copy of this module loaded in one process. */
const WRITER_LOCKS: WriterLocks = (() => {
  const slots = globalThis as unknown as Record<symbol, WriterLocks | undefined>;
  const key = Symbol.for("ilas.l0.writerLocks");
  return (slots[key] ??= { claims: new Map(), instances: new Set(), exitHook: false });
})();

/** One key per lock file, however its path is spelled. */
function lockKey(lockPath: string): string {
  const absolute = resolve(lockPath);
  try {
    return join(realpathSync(dirname(absolute)), basename(absolute));
  } catch {
    return absolute;
  }
}

/** Remove the lock file if it still names this process and `instance`. Never throws. */
function releaseLockFile(lockPath: string, instance: string): void {
  try {
    const holder = parseWriterLock(readSmallRegularFile(lockPath, MAX_LOCK_BYTES));
    if (holder !== null && holder.pid === process.pid && holder.instance === instance) {
      unlinkSync(lockPath);
    }
  } catch {
    // already gone, or not ours: nothing to release
  }
}

function ensureLockExitHook(): void {
  if (WRITER_LOCKS.exitHook) return;
  WRITER_LOCKS.exitHook = true;
  process.on("exit", () => {
    for (const claim of WRITER_LOCKS.claims.values()) {
      releaseLockFile(claim.lockPath, claim.instance);
    }
    WRITER_LOCKS.claims.clear();
  });
}

type LockOutcome =
  | { ok: true; instance: string; takenOver: boolean }
  | { ok: false; problem: string };

type LockFileOutcome =
  | { kind: "created" }
  | { kind: "exists" }
  | { kind: "failed"; stage: "create" | "write"; err: unknown };

/** What link() reports on a file system that has no hard links. */
const NO_HARD_LINKS: ReadonlySet<unknown> = new Set(["EPERM", "ENOTSUP", "EOPNOTSUPP", "ENOSYS", "EXDEV"]);

/** Write the whole lock text, sync it if asked, and close the descriptor. */
function writeLockText(fd: number, text: Buffer, sync: boolean): void {
  try {
    writeAll(fd, text);
    if (sync) fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function removeQuietly(path: string): void {
  try {
    unlinkSync(path);
  } catch {
    // already gone; a staged file left behind is harmless
  }
}

/**
 * Create the lock file at `lockPath` holding `text`, whole or not at all: the
 * text goes to a staged file first, which link() then puts at the lock path.
 * "exists" when something is at the lock path already.
 */
function createLockFile(lockPath: string, text: Buffer, instance: string, sync: boolean): LockFileOutcome {
  // A short name that does not grow with the log's name.
  const staged = join(dirname(lockPath), `.ilas-lock-${instance}`);
  let fd: number;
  try {
    fd = openSync(staged, LOCK_CREATE_FLAGS, 0o644);
  } catch (err) {
    return { kind: "failed", stage: "create", err };
  }
  try {
    writeLockText(fd, text, sync);
  } catch (err) {
    removeQuietly(staged);
    return { kind: "failed", stage: "write", err };
  }
  try {
    linkSync(staged, lockPath);
    return { kind: "created" };
  } catch (err) {
    const code = errorCode(err);
    if (code === "EEXIST") return { kind: "exists" };
    if (!NO_HARD_LINKS.has(code)) return { kind: "failed", stage: "create", err };
  } finally {
    removeQuietly(staged);
  }
  // No hard links on this file system: create the lock in place, then write it.
  let direct: number;
  try {
    direct = openSync(lockPath, LOCK_CREATE_FLAGS, 0o644);
  } catch (err) {
    return errorCode(err) === "EEXIST" ? { kind: "exists" } : { kind: "failed", stage: "create", err };
  }
  try {
    writeLockText(direct, text, sync);
  } catch (err) {
    removeQuietly(lockPath);
    return { kind: "failed", stage: "write", err };
  }
  return { kind: "created" };
}

/**
 * Take the writer lock for `logPath`. Throws L0WriteError when another live
 * process, or another thread of this process, holds it, or when a file stands
 * at the lock path that cannot be parsed as a lock (remove it by hand).
 * Returns a problem, without throwing, when the lock cannot be created at all
 * (a directory that cannot be created, written or searched): the load decides
 * what that means.
 */
function takeWriterLock(lockPath: string, logPath: string, sync: boolean): LockOutcome {
  let takenOver = false;
  for (let attempt = 0; attempt < 3; attempt++) {
    const instance = randomBytes(16).toString("hex");
    const text = Buffer.from(
      JSON.stringify({
        pid: process.pid,
        instance,
        processStart: processStartOf(),
        started: new Date().toISOString(),
      }) + "\n",
      "utf8"
    );
    const created = createLockFile(lockPath, text, instance, sync);
    if (created.kind === "created") {
      WRITER_LOCKS.instances.add(instance);
      return { ok: true, instance, takenOver };
    }
    if (created.kind === "failed") {
      if (created.stage === "create" && errorCode(created.err) === "ENOENT" && attempt === 0) {
        try {
          mkdirSync(dirname(lockPath), { recursive: true });
        } catch (mkdirErr) {
          return { ok: false, problem: `cannot create log directory: ${String(mkdirErr)}` };
        }
        continue;
      }
      return {
        ok: false,
        problem: `cannot ${created.stage} the writer lock ${lockPath}: ${describe(created.err)}`,
      };
    }
    let found: string;
    try {
      found = readSmallRegularFile(lockPath, MAX_LOCK_BYTES);
    } catch (readErr) {
      if (errorCode(readErr) === "ENOENT") continue; // released meanwhile
      throw new L0WriteError(
        `the writer lock ${lockPath} cannot be read (${describe(readErr)}). If no node is running on ${logPath}, remove it by hand.`,
        readErr
      );
    }
    const holder = parseWriterLock(found);
    if (holder === null) {
      throw new L0WriteError(
        `the writer lock ${lockPath} names no process: it cannot be parsed as a writer lock ` +
          `(empty, damaged, or not written by L0), so it is not taken over. Check that no ` +
          `process has ${logPath} open (for example: lsof ${logPath}, or fuser ${logPath}), ` +
          `then remove ${lockPath} by hand.`
      );
    }
    if (holder.pid === process.pid) {
      // Held by this thread: the newest log on the path takes it over.
      if (WRITER_LOCKS.instances.has(holder.instance)) {
        return { ok: true, instance: holder.instance, takenOver: false };
      }
      // This pid and this process start, but not this thread's: another live
      // thread of this process (a worker thread) writes the log.
      if (holder.processStart !== null && !anotherProcessStart(holder.processStart, processStartOf())) {
        throw new L0WriteError(
          `the log ${logPath} is in use by another thread of this process (pid ${holder.pid}, ` +
            `writer lock ${lockPath}). Two writers on one log file fork its chain. If no thread ` +
            `of this process writes this log (a worker that ended without close()), remove the ` +
            `lock file by hand.`
        );
      }
      // Otherwise an earlier process with this pid left it: stale.
    } else if (processAlive(holder.pid)) {
      throw new L0WriteError(
        `the log ${logPath} is in use by process ${holder.pid} (writer lock ${lockPath}). ` +
          `Two writers on one log file fork its chain. If no node is running on this log ` +
          `(the pid may now belong to another program), remove the lock file by hand.`
      );
    }
    try {
      unlinkSync(lockPath);
    } catch (unlinkErr) {
      if (errorCode(unlinkErr) !== "ENOENT") {
        return {
          ok: false,
          problem: `cannot remove the stale writer lock ${lockPath}: ${describe(unlinkErr)}`,
        };
      }
    }
    takenOver = true;
  }
  return { ok: false, problem: `could not take the writer lock ${lockPath}` };
}

function hashEntry(
  sequenceNumber: number,
  previousHash: string,
  input: StampedLogEntryInput
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
    clerkReceipt: input.clerkReceipt,
  });
  return createHash("sha256").update(payload).digest("hex");
}

/** Freeze a JSON-shaped value and everything inside it. */
function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as object)) deepFreeze(child);
  }
  return value;
}

/** The six payload fields of an entry: what L0 submits and what a receipt binds. */
function payloadOf(e: LogEntryInput): LogEntryInput {
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
 * The entry L0 will submit and commit: exactly the six payload fields of
 * `input`, read once, normalised by a JSON round trip (so NaN and Infinity
 * become null and undefined properties drop, exactly as on disk), and frozen.
 * Nothing is read from the caller's object after this. With a clerk the result
 * must also have a canonical form (docs/S4-WIRE-SPEC.md §7.2), because a payload
 * without one can never verify; its timestamp must be a number or null, the
 * only declared_timestamp a clerk books (§7.1); and its canonical form must
 * fit the client's maxPayloadBytes, when the client sets one.
 */
function snapshotPayload(
  input: LogEntryInput,
  forClerk: boolean,
  maxPayloadBytes: number | null
): LogEntryInput {
  let snapshot: LogEntryInput;
  try {
    snapshot = JSON.parse(JSON.stringify(payloadOf(input))) as LogEntryInput;
  } catch (err) {
    throw new L0PayloadError(
      `entry has no JSON form; nothing was submitted or committed: ${describe(err)}`,
      err
    );
  }
  if (forClerk) {
    // NaN and the infinities are null by now. A missing or non-numeric
    // timestamp would be refused by the clerk (which stops the log) or booked
    // as null and then fail the declared_timestamp check here (an orphan
    // receipt, and the log stops). Refuse it before either can happen.
    const ts = (snapshot as { timestamp?: unknown }).timestamp;
    if (ts !== null && typeof ts !== "number") {
      throw new L0PayloadError(
        `entry timestamp is ${ts === undefined ? "missing" : `a ${typeof ts}`}; with a clerk it must be a number; nothing was submitted or committed`
      );
    }
    let canonical: string;
    try {
      canonical = canonicalise(snapshot);
    } catch (err) {
      throw new L0PayloadError(
        `entry has no canonical form; nothing was submitted or committed: ${describe(err)}`,
        err
      );
    }
    if (maxPayloadBytes !== null) {
      const bytes = Buffer.byteLength(canonical, "utf8");
      if (bytes > maxPayloadBytes) {
        throw new L0PayloadError(
          `entry is ${bytes} bytes in canonical form; the clerk client takes at most ${maxPayloadBytes}; nothing was submitted or committed`
        );
      }
    }
  }
  try {
    return deepFreeze(snapshot);
  } catch (err) {
    // JSON copes with nesting the recursive freeze cannot finish.
    throw new L0PayloadError(
      `entry is nested too deeply to be kept; nothing was submitted or committed: ${describe(err)}`,
      err
    );
  }
}

/** Identity of an entry for the replay guard: everything but the timestamp. Never throws. */
function replayKey(e: LogEntryInput): string {
  const fields = {
    moduleId: e.moduleId,
    eventType: e.eventType,
    provenanceTag: e.provenanceTag,
    parameters: e.parameters,
    outcome: e.outcome,
  };
  try {
    return canonicalise(fields);
  } catch {
    // no canonical form (nesting past the canonical limit): fall through
  }
  try {
    return JSON.stringify(fields);
  } catch {
    // Nested too deeply even for JSON: a key that matches nothing, so the
    // entry is never taken for a replay.
    return `\u0000unkeyable:${randomBytes(16).toString("hex")}`;
  }
}

/** What is wrong with a parsed log line's shape, or null. */
function entryShapeProblem(parsed: unknown): string | null {
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return "not a JSON object";
  }
  for (const k of Object.keys(parsed)) {
    if (!ENTRY_KEYS.has(k)) return `unknown field ${JSON.stringify(k)}`;
  }
  return null;
}

/**
 * The receipt rules that need no key (docs/S4-WIRE-SPEC.md §7.3, shape checks
 * and the route binding), for a receipt offered for `payload` on `route`.
 * Returns what is wrong, or null.
 */
function receiptShapeProblem(
  receipt: ClerkSubmissionReceipt,
  payload: LogEntryInput,
  route: ClerkRoute
): string | null {
  if (receipt === null || typeof receipt !== "object" || Array.isArray(receipt)) {
    return "the receipt is not an object";
  }
  if (receipt.kind !== "SUBMISSION") return "kind is not SUBMISSION";
  if (!Number.isInteger(receipt.clerk_seq)) return "clerk_seq is not an integer";
  if (receipt.clerk_seq < 0) return "clerk_seq is negative";
  if (!Number.isFinite(receipt.clerk_time?.wall_ms)) return "clerk_time.wall_ms is not a finite number";
  if (typeof receipt.clerk_time?.monotonic_ns !== "string") return "clerk_time.monotonic_ns is not a string";
  if (receipt.clerk_time.monotonic_ns.length === 0) return "clerk_time.monotonic_ns is empty";
  if (receipt.declared_timestamp !== payload.timestamp) {
    return "declared_timestamp does not match the entry's timestamp";
  }
  if (typeof receipt.receipt_hash !== "string" || receipt.receipt_hash.length === 0) {
    return "receipt_hash is missing";
  }
  if (receipt.signature_alg !== "ed25519") return "signature_alg is not ed25519";
  if (
    receipt.separation !== "SEPARATE_PROCESS" &&
    receipt.separation !== "IN_PROCESS_NO_SEPARATION"
  ) {
    return "separation is not a known value";
  }
  if (
    receipt.intake !== "SOCKET" &&
    receipt.intake !== "LOCAL_CALL" &&
    receipt.intake !== "CLERK_INTERNAL"
  ) {
    return "intake is not a known value";
  }
  // The one self-contradictory combination: a clerk that claims a separate
  // process cannot have been reached through an observed local call.
  if (receipt.separation === "SEPARATE_PROCESS" && receipt.intake === "LOCAL_CALL") {
    return "SEPARATE_PROCESS claimed over a LOCAL_CALL intake";
  }
  // The route binding: a receipt booked for another submitter or channel is not
  // a receipt for this log.
  if (receipt.submitter_id !== route.submitterId) {
    return "submitter_id does not name this route's submitter";
  }
  if (receipt.channel !== route.channel) {
    return "channel does not name this route's channel";
  }
  return null;
}

type ReceiptRefusal =
  | { kind: "shape"; detail: string }
  | { kind: "reused"; detail: string }
  | { kind: "verify"; detail: string };

/**
 * Every rule a receipt must pass to stand on this log for `payload`: the shape
 * checks, the route binding, at most once per log, and the cryptographic check
 * (signature by the route's key, payload_commitment over `payload`). Shared by
 * append and load, so both apply one rule.
 */
function receiptRefusal(
  receipt: ClerkSubmissionReceipt,
  payload: LogEntryInput,
  route: ClerkRoute,
  alreadyOnLog: ReadonlySet<string>
): ReceiptRefusal | null {
  const shape = receiptShapeProblem(receipt, payload, route);
  if (shape !== null) return { kind: "shape", detail: shape };
  if (alreadyOnLog.has(receipt.receipt_hash)) {
    return { kind: "reused", detail: `receipt_hash ${receipt.receipt_hash}` };
  }
  const verdict = verifyClerkReceipt(
    receipt as unknown as Record<string, unknown>,
    route.clerkPublicKeyPem,
    payload
  );
  return verdict.ok ? null : { kind: "verify", detail: verdict.reason };
}

function describeRefusal(r: ReceiptRefusal): string {
  switch (r.kind) {
    case "shape":
      return `a malformed or mismatched receipt (${r.detail})`;
    case "reused":
      return `a receipt already committed on this log (${r.detail}); a receipt binds one entry`;
    case "verify":
      return `a receipt that failed verification (${r.detail})`;
  }
}

/**
 * Independently recompute the head hash at sequence `n` from the raw contents of
 * `entries`, using the same hashing definition as append() and verify()
 * (docs/S4-WIRE-SPEC.md §5). Returns null if `n` is out of range (e.g. the chain
 * is shorter than a witnessed sequence — a truncation the continuity predicate
 * must catch), or if an entry up to `n` cannot be hashed (nested too deeply for
 * the stack). Never throws. This trusts NONE of the
 * stored `hash` fields: it re-links from genesis over each entry's payload, so a
 * tampered payload yields a divergent head.
 */
export function recomputeHeadHashAt(
  entries: readonly LogEntry[],
  n: number
): string | null {
  if (!Number.isSafeInteger(n) || n < 0 || n >= entries.length) return null;
  let prev = GENESIS_PREV_HASH;
  try {
    for (let i = 0; i <= n; i++) {
      prev = hashEntry(i, prev, entries[i]);
    }
  } catch {
    return null; // an entry up to n cannot be hashed
  }
  return prev;
}

/**
 * The same recomputation for many sequence numbers in ONE pass from genesis:
 * O(entries + requests) instead of O(entries × requests). Each requested `n`
 * maps to its recomputed head, or null when `n` is not a valid index of
 * `entries` (not a safe integer, negative, or past the end) or an entry up to
 * `n` cannot be hashed (nested too deeply for the stack). Never throws.
 */
export function recomputeHeadHashes(
  entries: readonly LogEntry[],
  seqNos: Iterable<number>
): Map<number, string | null> {
  const out = new Map<number, string | null>();
  let max = -1;
  for (const n of seqNos) {
    const valid = Number.isSafeInteger(n) && n >= 0 && n < entries.length;
    out.set(n, null);
    if (valid && n > max) max = n;
  }
  let prev = GENESIS_PREV_HASH;
  for (let i = 0; i <= max; i++) {
    try {
      prev = hashEntry(i, prev, entries[i]);
    } catch {
      break; // entry i cannot be hashed: every head from i on stays null
    }
    if (out.has(i)) out.set(i, prev);
  }
  return out;
}

/** A route as the log keeps it: checked, frozen, with the client's size limit. */
interface CheckedClerkRoute extends ClerkRoute {
  /** The client's maxPayloadBytes, read once at construction; null when it sets none. */
  readonly maxPayloadBytes: number | null;
}

/**
 * Validate a clerk route and return a frozen copy. Throws L0ClerkError when the
 * client cannot submit, when the client's maxPayloadBytes is present but not a
 * positive safe integer, when submitterId or channel is not a non-empty string,
 * or when clerkPublicKeyPem is missing, a private key, unparseable, or not an
 * Ed25519 public key (docs/S4-WIRE-SPEC.md §7.3). Each field is read exactly
 * once: what is checked is what is kept, whatever accessors the route has.
 */
function checkedClerkRoute(route: ClerkRoute): CheckedClerkRoute {
  let client: unknown;
  let submitterId: unknown;
  let channel: unknown;
  let pem: unknown;
  let submit: unknown;
  let maxPayloadBytes: unknown;
  try {
    ({ client, submitterId, channel, clerkPublicKeyPem: pem } = route);
    submit = (client as { submit?: unknown } | null | undefined)?.submit;
    if (typeof submit === "function") {
      maxPayloadBytes = (client as { maxPayloadBytes?: unknown }).maxPayloadBytes;
    }
  } catch (err) {
    throw new L0ClerkError(`clerk route could not be read: ${describe(err)}`, err);
  }
  if (typeof submit !== "function") {
    throw new L0ClerkError("clerk route has no client with a submit() method");
  }
  if (
    maxPayloadBytes !== undefined &&
    !(typeof maxPayloadBytes === "number" && Number.isSafeInteger(maxPayloadBytes) && maxPayloadBytes > 0)
  ) {
    throw new L0ClerkError(
      `the clerk client's maxPayloadBytes must be a positive safe integer when present (got ${describe(maxPayloadBytes)})`
    );
  }
  for (const [field, v] of [
    ["submitterId", submitterId],
    ["channel", channel],
  ] as const) {
    if (typeof v !== "string" || v.length === 0) {
      throw new L0ClerkError(
        `clerk route needs ${field}: a non-empty string. Every receipt must name it.`
      );
    }
  }
  if (typeof pem !== "string" || pem.trim().length === 0) {
    throw new L0ClerkError(
      "clerk route needs clerkPublicKeyPem: the clerk's Ed25519 public key (PEM). There is no default."
    );
  }
  if (holdsPrivateKey(pem)) {
    throw new L0ClerkError(
      "clerkPublicKeyPem holds a private key. Give the node only the clerk's public key (clerk.pub.pem); the private key stays with the clerk."
    );
  }
  let kind: string | undefined;
  try {
    kind = createPublicKey(pem).asymmetricKeyType;
  } catch (err) {
    throw new L0ClerkError(`clerkPublicKeyPem is not a readable public key: ${String(err)}`, err);
  }
  if (kind !== "ed25519") {
    throw new L0ClerkError(`clerkPublicKeyPem is a ${String(kind)} key; an Ed25519 key is required`);
  }
  return Object.freeze({
    client: client as ClerkSubmitClient,
    submitterId: submitterId as string,
    channel: channel as string,
    clerkPublicKeyPem: pem,
    maxPayloadBytes: maxPayloadBytes === undefined ? null : (maxPayloadBytes as number),
  });
}

export class LockedEvidenceLog {
  private readonly chain: LogEntry[] = [];

  // ── durability state ─────────────────────────────────────────────────────
  /** The path as given; reported in DurabilityInfo.path. */
  private readonly path: string | null;
  /**
   * The path every file operation uses (the log, its lock, the checks before
   * each append): the given path, anchored at construction when it is
   * relative, so a later process.chdir() changes nothing. null without a path,
   * or when a relative path could not be anchored.
   */
  private readonly filePath: string | null;
  private readonly clerk: CheckedClerkRoute | null;
  private loadState: L0LoadState = "IN_MEMORY";
  private brokenAt: number | null = null;
  private entriesLoaded = 0;
  private persisting = false;        // whether appends are written to disk
  private writeHealthy = true;
  private lastError: string | null = null;
  /**
   * Set when this durable log must not commit anything, even in memory: its
   * file or directory cannot be written, a failed write could not be taken
   * back, the file changed under it, a newer log on the path superseded it, or
   * it was closed. Every append then throws L0WriteError; with a clerk route it
   * is refused before anything is submitted.
   */
  private writeRefusal: string | null = null;
  private readonly fsyncEnabled: boolean;
  /** The log file, opened once at load; open only while this log writes to it. */
  private fd: number | null = null;
  /** The bytes this log last left the file at. */
  private fileBytes = 0;
  /** Device and inode of the file this log opened, to see it removed or replaced. */
  private fileIdentity: { dev: bigint; ino: bigint } | null = null;
  /** The file ends without a newline: the next entry is written after one. */
  private needsNewline = false;
  /** Why the file is read only to this process, when it is. */
  private unwritable: string | null = null;
  /** Why the writer lock could not be taken, when it could not. */
  private lockProblem: string | null = null;
  private lockClaimKey: string | null = null;
  private lockTakenOver = false;
  private receiptsUnchecked = 0;
  private closed = false;
  /** publicKeyFingerprint of the clerk route's key, or null without a route. */
  private readonly clerkKeyFingerprint: string | null;

  // ── replay guard ─────────────────────────────────────────────────────────
  // When a chain is loaded from disk, module constructors that seed bootstrap
  // entries (ProbeManager's 10 probe_registered appends — the ONLY appends that
  // happen at construction) would otherwise re-append and grow the chain by 10
  // per restart. The assembly wraps construction in begin/endReplayGuard().
  // While the guard is on, an append is skipped only when an equal entry (same
  // moduleId, eventType, provenanceTag, parameters, outcome; the timestamp is
  // ignored) is already on the loaded chain, each loaded entry matching at most
  // one append. Anything else is appended normally, so a bootstrap that was
  // interrupted part-way is completed on the next start. The guard lives here,
  // not in the mechanism modules, so no mechanism module is touched.
  private replayPending: Map<string, number> | null = null;
  /** Commits stay in invocation order even when clerk receipts return out of order. */
  private appendBarrier: Promise<void> = Promise.resolve();
  /** The first failure reached in commit order. Stops the log. */
  private appendFailure: Error | null = null;
  /**
   * The first submission seen to fail (thrown, or its promise rejected), set the
   * moment it is seen. Stops further SUBMISSIONS at once; appends submitted
   * earlier keep their place in the barrier and still commit if they verify.
   */
  private submitFailure: Error | null = null;
  /** receipt_hash of every receipt on the chain: a receipt commits at most once. */
  private readonly committedReceipts = new Set<string>();
  private readonly queued = new Set<Promise<LogEntry>>();
  private queuedFailure: Error | null = null;

  constructor(options?: LockedEvidenceLogOptions) {
    this.path = options?.path ?? null;
    // A clerk route is checked at wiring time, so a missing or wrong-kind key
    // fails at startup instead of at the first append. The route is copied: a
    // caller changing its object later cannot swap the key under a running log.
    this.clerk = options?.clerk ? checkedClerkRoute(options.clerk) : null;
    this.fsyncEnabled = options?.fsync !== false;
    this.clerkKeyFingerprint =
      this.clerk === null ? null : publicKeyFingerprint(this.clerk.clerkPublicKeyPem);
    if (this.path === null) {
      this.filePath = null;
      this.loadState = "IN_MEMORY";
      return;
    }
    let anchored: string | null = null;
    try {
      anchored = anchorLogPath(this.path);
    } catch (err) {
      this.filePath = null;
      this.cannotVerify(
        `cannot resolve the relative log path ${this.path}: the working directory cannot be read (${describe(err)})`
      );
      return;
    }
    this.filePath = anchored;
    this.takeLock(); // throws L0WriteError when another live process or thread holds the log
    this.loadFromDisk();
  }

  // ── the writer lock ────────────────────────────────────────────────────────

  /**
   * Take "<path>.lock" before reading the file, so nothing else appends while
   * this log loads it. Throws L0WriteError only for another live holder (a
   * process, or another thread of this one) or a lock file that names no
   * process; a lock that cannot be created is noted, and the load refuses to
   * persist without it.
   */
  private takeLock(): void {
    const path = this.filePath as string;
    if (path.length === 0) {
      this.lockProblem = "the log path is empty";
      return;
    }
    const lockPath = `${path}.lock`;
    let outcome: LockOutcome;
    try {
      outcome = takeWriterLock(lockPath, path, this.fsyncEnabled);
    } catch (err) {
      if (isA(err, L0WriteError)) throw err;
      outcome = { ok: false, problem: `cannot take the writer lock ${lockPath}: ${describe(err)}` };
    }
    if (!outcome.ok) {
      this.lockProblem = outcome.problem;
      return;
    }
    ensureLockExitHook();
    const key = lockKey(lockPath);
    const previous = WRITER_LOCKS.claims.get(key);
    if (previous !== undefined && previous.owner !== this) previous.owner.supersede();
    WRITER_LOCKS.claims.set(key, { owner: this, lockPath, instance: outcome.instance });
    this.lockClaimKey = key;
    this.lockTakenOver = outcome.takenOver;
  }

  /**
   * A newer log on the same path in this process owns the file now: this one
   * refuses every further append. Called by that newer log.
   */
  private supersede(): void {
    this.lockClaimKey = null;
    this.persisting = false;
    if (this.writeRefusal === null) {
      this.writeRefusal = `superseded: a newer LockedEvidenceLog on ${this.filePath} in this process owns the file`;
    }
    this.closeFile();
  }

  /**
   * Stop writing, close the file and release the writer lock. Every later
   * append throws L0WriteError (with a clerk route, before anything is
   * submitted). Await settle() first: an append still waiting for its receipt
   * is refused when it reaches the file. A log without a path holds nothing,
   * and close() leaves it as it is.
   */
  close(): void {
    if (this.path === null || this.closed) return;
    this.closed = true;
    this.persisting = false;
    if (this.writeRefusal === null) this.writeRefusal = "closed: this log was closed";
    this.closeFile();
    if (this.lockClaimKey !== null) {
      const claim = WRITER_LOCKS.claims.get(this.lockClaimKey);
      if (claim !== undefined && claim.owner === this) {
        WRITER_LOCKS.claims.delete(this.lockClaimKey);
        WRITER_LOCKS.instances.delete(claim.instance);
        releaseLockFile(claim.lockPath, claim.instance);
      }
      this.lockClaimKey = null;
    }
  }

  private closeFile(): void {
    if (this.fd === null) return;
    try {
      closeSync(this.fd);
    } catch {
      // nothing more to do: the descriptor is gone either way
    }
    this.fd = null;
  }

  // ── load ───────────────────────────────────────────────────────────────────

  /**
   * Load the file. Whatever goes wrong while loading, the result is a state,
   * never a throw out of the constructor: anything not handled below (a stack
   * overflow, a fault nobody foresaw) is CANNOT_VERIFY, not persisting.
   */
  private loadFromDisk(): void {
    try {
      this.loadFromDiskUnguarded();
    } catch (err) {
      this.loadState = "CANNOT_VERIFY";
      this.persisting = false;
      this.lastError = `log file could not be loaded: ${describe(err)}`;
    }
    // The descriptor stays open only while this log writes through it.
    if (!this.persisting) this.closeFile();
  }

  private cannotVerify(lastError: string, brokenAt: number | null = null): void {
    this.loadState = "CANNOT_VERIFY";
    this.persisting = false;
    this.brokenAt = brokenAt;
    this.lastError = lastError;
  }

  /**
   * Fail closed: a durable log that cannot write must not commit in memory
   * only. Every append throws L0WriteError (see commit()); with a clerk,
   * append() refuses before anything is submitted.
   */
  private refuseWrites(reason: string): void {
    this.persisting = false;
    this.writeHealthy = false;
    this.lastError = reason;
    this.writeRefusal = reason;
  }

  /** The load accepted the file: write onto it, if this log may. */
  private startPersisting(): void {
    if (this.unwritable !== null) return this.refuseWrites(this.unwritable);
    if (this.lockProblem !== null) return this.refuseWrites(this.lockProblem);
    this.persisting = true;
  }

  private loadFromDiskUnguarded(): void {
    const path = this.filePath as string;

    // One open, kept for every append. Only ENOENT means "absent". Any other
    // failure (an unreadable file, EACCES on its directory, ENOTDIR, a symbolic
    // link, EIO, ...) means history may be there and cannot be reached: not a
    // first boot. Fail closed: do NOT persist, do NOT fabricate a clean chain,
    // do NOT write where we can't read.
    let fd: number | null = null;
    try {
      fd = openSync(path, LOG_OPEN_FLAGS);
    } catch (err) {
      const code = errorCode(err);
      if (code === "EACCES" || code === "EPERM" || code === "EROFS") {
        // Perhaps readable but not writable: read it, never write it.
        try {
          fd = openSync(path, LOG_READ_FLAGS);
        } catch (readErr) {
          return this.cannotVerify(`cannot read log file: ${describeOpenError(readErr)}`);
        }
        this.unwritable = `log file is not writable: ${describe(err)}`;
      } else if (code !== "ENOENT") {
        return this.cannotVerify(`cannot read log file: ${describeOpenError(err)}`);
      }
    }

    if (fd === null) {
      // Absent file: genuine first run OR erased history — undecidable in code.
      // Surface as non-clean; DO seed + persist so the node is operational
      // and a durable chain starts from here. A human resolves the ambiguity.
      this.loadState = "FIRST_BOOT_OR_ERASED";
      try {
        mkdirSync(dirname(path), { recursive: true });
      } catch (err) {
        return this.refuseWrites(`cannot create log directory: ${String(err)}`);
      }
      if (this.lockProblem !== null) return this.refuseWrites(this.lockProblem);
      try {
        this.fd = openSync(path, LOG_CREATE_FLAGS, 0o666);
      } catch (err) {
        return this.refuseWrites(`cannot create log file: ${describeOpenError(err)}`);
      }
      const st = fstatSync(this.fd, { bigint: true });
      this.fileIdentity = { dev: st.dev, ino: st.ino };
      this.fileBytes = 0;
      if (this.fsyncEnabled) syncDirectory(dirname(path));
      this.persisting = true;
      return;
    }

    this.fd = fd;
    const st = fstatSync(fd, { bigint: true });
    if (!st.isFile()) {
      return this.cannotVerify(`cannot read log file: ${path} is not a regular file (${fileKind(st)})`);
    }
    this.fileIdentity = { dev: st.dev, ino: st.ino };

    // Every line is checked as it is read, and the first line that fails stops
    // the load (nothing after it is read). Line i holds entry i.
    const loaded: LogEntry[] = [];
    const accept = (bytes: Buffer, final: boolean): boolean => {
      const i = loaded.length;
      let parsed: unknown;
      try {
        parsed = JSON.parse(bytes.toString("utf8"));
      } catch (err) {
        // A last line without its newline that is not whole is a torn write:
        // refused, and never cut off automatically.
        this.cannotVerify(
          final
            ? `torn final line at index ${i}: the file ends inside this line, without a newline; nothing was removed`
            : `malformed JSON at line ${i}: ${String(err)}`,
          i
        );
        return false;
      }
      // A stored line carries the entry fields and nothing else...
      const problem = entryShapeProblem(parsed);
      if (problem !== null) {
        this.cannotVerify(`line ${i} is not a log entry: ${problem}`, i);
        return false;
      }
      // ...and is exactly the text L0 writes for that entry, JSON.stringify of
      // it, byte for byte. JSON.parse keeps only the last value of a repeated
      // key, so text the hash never covered could otherwise stand in the file.
      let stored: string | null = null;
      try {
        stored = JSON.stringify(parsed);
      } catch {
        // nested too deeply for the stack: the freeze below or verify() refuses it
      }
      if (stored !== null && !bytes.equals(Buffer.from(stored, "utf8"))) {
        this.cannotVerify(
          `line ${i} is not stored as L0 writes it: it is not exactly JSON.stringify of its own entry ` +
            `(a repeated key, extra whitespace, another escape, or bytes that are not UTF-8)`,
          i
        );
        return false;
      }
      // JSON.parse copes with nesting the recursive freeze cannot finish.
      try {
        loaded.push(deepFreeze(parsed as LogEntry));
      } catch (err) {
        this.cannotVerify(`line ${i} cannot be loaded: ${describe(err)}`, i);
        return false;
      }
      return true;
    };

    // Read through the descriptor in chunks and split the lines here. The file
    // is never one string, so a log longer than the longest string the runtime
    // can make still loads; only each line must fit in one.
    const chunk = Buffer.allocUnsafe(LOAD_CHUNK_BYTES);
    let partial: Buffer[] = [];
    let position = 0;
    let lastByte = -1;
    for (;;) {
      const n = readSync(fd, chunk, 0, chunk.length, position);
      if (n === 0) break;
      position += n;
      lastByte = chunk[n - 1];
      const view = chunk.subarray(0, n);
      let start = 0;
      for (let nl = view.indexOf(0x0a, start); nl !== -1; nl = view.indexOf(0x0a, start)) {
        const piece = view.subarray(start, nl);
        const line = partial.length === 0 ? piece : Buffer.concat([...partial, piece]);
        partial = [];
        if (!accept(line, false)) return;
        start = nl + 1;
      }
      if (start < n) partial.push(Buffer.from(view.subarray(start)));
    }
    // A file that does not end with a newline: a crash kept a line but not its
    // last byte, or a tool stripped it. A last line that is a whole entry is
    // loaded, and the next entry is written after a newline, so it never joins
    // onto that line.
    if (partial.length > 0 && !accept(Buffer.concat(partial), true)) return;
    this.fileBytes = position;
    this.needsNewline = position > 0 && lastByte !== 0x0a;

    // Reconstruct and verify the loaded chain BEFORE accepting it.
    for (const e of loaded) {
      this.chain.push(e);
      const h = e.clerkReceipt?.receipt_hash;
      if (typeof h === "string") this.committedReceipts.add(h);
    }
    this.entriesLoaded = loaded.length;
    // Without a route, loading checks the hash chain only (docs/S4-WIRE-SPEC.md
    // §7.3): any receipts on the loaded entries are whatever the file held.
    if (this.clerk === null) {
      this.receiptsUnchecked = loaded.filter(
        (e) => e.clerkReceipt !== undefined && e.clerkReceipt !== null
      ).length;
    }
    const v = this.verify();
    if (!v.valid) {
      // Present but tamper-evident break. Fail closed: keep the loaded entries
      // in memory for forensic inspection via getAll(), but do NOT persist new
      // appends onto a chain we could not verify, and report non-clean.
      this.loadState = "CANNOT_VERIFY";
      this.persisting = false;
      this.brokenAt = v.brokenAt ?? null;
      this.lastError = `chain verification failed at index ${v.brokenAt}`;
      return;
    }

    if (loaded.length === 0) {
      // Empty-but-present file: treat like an absent history — non-clean, but
      // we can persist onward.
      this.loadState = "FIRST_BOOT_OR_ERASED";
      this.startPersisting();
      return;
    }

    // With a clerk route, the hash chain alone is not enough: anyone who can
    // write the file can recompute hashes. Every loaded entry must carry a
    // receipt that passes the same rule an append does, against this route's
    // key and the entry's own stored payload, and no receipt may stand twice.
    if (this.clerk !== null) {
      const seen = new Set<string>();
      for (let i = 0; i < loaded.length; i++) {
        const e = loaded[i];
        const refusal =
          e.clerkReceipt === undefined
            ? "no clerk receipt"
            : (() => {
                const r = receiptRefusal(e.clerkReceipt, payloadOf(e), this.clerk!, seen);
                return r === null ? null : describeRefusal(r);
              })();
        if (refusal !== null) {
          this.loadState = "CANNOT_VERIFY";
          this.persisting = false;
          this.brokenAt = i;
          this.lastError = `clerk receipt check failed at index ${i}: ${refusal}`;
          return;
        }
        seen.add(e.clerkReceipt!.receipt_hash);
      }
    }

    this.loadState = "LOADED_VERIFIED";
    this.startPersisting();
  }

  // ── replay guard control ─────────────────────────────────────────────────

  /** True when construction loaded a non-empty, verified chain from disk. */
  loadedExisting(): boolean {
    return this.loadState === "LOADED_VERIFIED";
  }

  /** Begin suppressing appends that repeat an entry already on the chain. */
  beginReplayGuard(): void {
    const pending = new Map<string, number>();
    for (const e of this.chain) {
      const k = replayKey(e);
      pending.set(k, (pending.get(k) ?? 0) + 1);
    }
    this.replayPending = pending;
  }

  endReplayGuard(): void {
    this.replayPending = null;
  }

  /** True (and one match consumed) when the guard covers this entry. */
  private consumeReplay(payload: LogEntryInput): boolean {
    if (this.replayPending === null) return false;
    const k = replayKey(payload);
    const n = this.replayPending.get(k) ?? 0;
    if (n === 0) return false;
    if (n === 1) this.replayPending.delete(k);
    else this.replayPending.set(k, n - 1);
    return true;
  }

  // ── append ───────────────────────────────────────────────────────────────

  append(input: LogEntryInput): Promise<LogEntry> {
    const route = this.clerk;

    // A known clerk failure stops the log for the life of the process (fail
    // closed; recovery is a restart). Refuse BEFORE submitting, so the clerk
    // never books a frame this log has already decided it will not commit.
    if (route !== null) {
      // A durable log that has refused writes (its directory or file cannot be
      // written, a failed write could not be taken back, the file changed under
      // it, it was superseded or closed) can never commit. That stops the log
      // at the next append, before that append is submitted.
      if (this.writeRefusal !== null && this.appendFailure === null) {
        this.writeHealthy = false;
        this.lastError = `append write failed at seq ${this.chain.length}: ${this.writeRefusal}`;
        this.appendFailure = new L0WriteError(this.lastError);
      }
      const stopped = this.appendFailure ?? this.submitFailure;
      if (stopped !== null) return Promise.reject(stopped);
    }

    // One snapshot, taken now: it is what is submitted, verified, hashed and
    // stored. Without a clerk a refusal throws, like every other failure on
    // that path; with a clerk it rejects.
    let payload: LogEntryInput;
    try {
      payload = snapshotPayload(input, route !== null, route?.maxPayloadBytes ?? null);
    } catch (err) {
      if (route === null) throw err;
      return Promise.reject(err);
    }

    // Suppress a bootstrap re-seed of an entry already on the loaded chain.
    // Return a sentinel that is never chained or persisted; every
    // construction-time caller discards it.
    if (this.consumeReplay(payload)) {
      return Promise.resolve(
        deepFreeze({
          sequenceNumber: -1,
          hash: "",
          previousHash: "",
          ...payload,
          outcome: "suppressed_bootstrap_replay",
        })
      );
    }

    // Legacy/explicitly unstamped mode preserves the old synchronous commit
    // timing, but the public return is a Promise so every production caller can
    // honestly await the clerk-configured path.
    if (route === null) {
      return Promise.resolve(this.commit(payload));
    }

    let submitted: Promise<ClerkSubmissionReceipt>;
    try {
      submitted = Promise.resolve(
        route.client.submit({
          submitter_id: route.submitterId,
          channel: route.channel,
          declared_timestamp: payload.timestamp,
          payload,
        })
      );
    } catch (err) {
      this.noteSubmitFailure(err);
      submitted = Promise.reject(err);
    }
    // Observe the submission's outcome at once. This (a) stops further
    // submissions the moment a rejection is seen, and (b) means the promise is
    // never left unhandled: the barrier step below may run only after earlier
    // I/O, or may throw an earlier failure without ever awaiting it. The step
    // still awaits the original promise, so the caller sees the real error.
    void submitted.then(undefined, (err: unknown) => this.noteSubmitFailure(err));

    const operation = this.appendBarrier.then(async () => {
      if (this.appendFailure !== null) throw this.appendFailure;
      let received: unknown;
      try {
        received = await submitted;
      } catch (err) {
        throw new L0ClerkError(
          `clerk submission failed; L0 append did not land: ${describe(err)}`,
          err
        );
      }
      let receipt: ClerkSubmissionReceipt;
      try {
        receipt = this.confirmReceipt(received, payload, route);
      } catch (err) {
        if (isA(err, L0ClerkError)) throw err;
        throw new L0ClerkError(
          `clerk receipt could not be checked; L0 append did not land: ${describe(err)}`,
          err
        );
      }
      return this.commit({ ...payload, clerkReceipt: receipt });
    });

    // Swallow only on the internal sequencing barrier; the operation returned
    // to the caller still rejects. Poisoning prevents a later append from
    // stepping over an earlier unconfirmed record.
    this.appendBarrier = operation.then(
      () => undefined,
      (err: unknown) => {
        this.appendFailure = isA(err, Error) ? err : new L0ClerkError(describe(err), err);
      }
    );
    return operation;
  }

  /** Never throws, whatever `err` is: it runs where a throw would go unhandled. */
  private noteSubmitFailure(err: unknown): void {
    if (this.submitFailure === null) {
      this.submitFailure = new L0ClerkError(
        `clerk submission failed; L0 append did not land: ${describe(err)}`,
        err
      );
    }
  }

  /**
   * Synchronous-module seam. The module records the intent here; deployment
   * glue awaits settle() once before disposition. Clerk-mode entries still do
   * not commit until a receipt is confirmed, and any rejection is retained.
   */
  enqueue(input: LogEntryInput): void {
    const operation = this.append(input);
    this.queued.add(operation);
    void operation.then(
      () => this.queued.delete(operation),
      (err: unknown) => {
        this.queued.delete(operation);
        this.keepQueuedFailure(isA(err, Error) ? err : new L0ClerkError(describe(err), err));
      }
    );
  }

  /**
   * Keep a failure that an append met where no caller can catch it (an append
   * made from a timer): settle() throws it, exactly as it throws a failure an
   * enqueued append met. Never throws, whatever `err` is.
   */
  keepFailure(err: unknown): void {
    this.keepQueuedFailure(isA(err, Error) ? err : new L0WriteError(describe(err), err));
  }

  private keepQueuedFailure(failure: Error): void {
    // A failure that stops the log is kept for good; a refused payload is
    // reported once and never hides or replaces a stop.
    if (this.queuedFailure === null || isA(this.queuedFailure, L0PayloadError)) {
      this.queuedFailure = failure;
    }
  }

  /**
   * The one async chokepoint synchronous module callers must await. Throws the
   * failure an enqueued append met. A failure that stopped the log is thrown on
   * every later call; a refused payload (L0PayloadError) is thrown once.
   */
  async settle(): Promise<void> {
    while (this.queued.size > 0) {
      await Promise.allSettled([...this.queued]);
    }
    const failure = this.queuedFailure;
    if (failure !== null) {
      if (isA(failure, L0PayloadError)) this.queuedFailure = null;
      throw failure;
    }
  }

  /**
   * Check a receipt the clerk returned for `payload` and return the copy that
   * will be committed. The receipt is copied through JSON first, so what is
   * checked is exactly what is stored.
   */
  private confirmReceipt(
    received: unknown,
    payload: LogEntryInput,
    route: ClerkRoute
  ): ClerkSubmissionReceipt {
    if (received === null || typeof received !== "object" || Array.isArray(received)) {
      throw new L0ClerkError(
        `clerk returned no receipt object (got ${received === null ? "null" : typeof received}); L0 append did not land`
      );
    }
    const receipt = JSON.parse(JSON.stringify(received)) as ClerkSubmissionReceipt;
    const refusal = receiptRefusal(receipt, payload, route, this.committedReceipts);
    if (refusal === null) return deepFreeze(receipt);
    switch (refusal.kind) {
      case "shape":
        throw new L0ClerkError(
          `clerk returned a malformed or mismatched receipt (${refusal.detail}); L0 append did not land`
        );
      case "reused":
        throw new L0ClerkError(
          `clerk receipt is already committed on this log (${refusal.detail}); a receipt binds one entry; L0 append did not land`
        );
      case "verify":
        // Cryptographic check (docs/S4-WIRE-SPEC.md §7.3, closes gap G1): the
        // receipt must be signed by the configured clerk key and must bind to
        // this exact payload.
        throw new L0ClerkError(
          `clerk receipt failed verification (${refusal.detail}); L0 append did not land`
        );
    }
  }

  private commit(input: StampedLogEntryInput): LogEntry {

    const sequenceNumber = this.chain.length;
    const previousHash =
      sequenceNumber === 0
        ? GENESIS_PREV_HASH
        : this.chain[sequenceNumber - 1].hash;

    // A durable log that has refused writes cannot persist anything. Refuse,
    // so memory never runs ahead of disk.
    if (this.writeRefusal !== null) {
      this.writeHealthy = false;
      this.lastError = `append write failed at seq ${sequenceNumber}: ${this.writeRefusal}`;
      throw new L0WriteError(this.lastError);
    }

    // Committed entries are immutable: nothing a caller does afterwards can
    // change what was hashed. An entry nested too deeply for the stack to hash
    // or serialise is refused here, before anything is written.
    let entry: LogEntry;
    let line: string | null = null;
    try {
      const hash = hashEntry(sequenceNumber, previousHash, input);
      entry = deepFreeze({
        sequenceNumber,
        hash,
        previousHash,
        timestamp: input.timestamp,
        moduleId: input.moduleId,
        eventType: input.eventType,
        provenanceTag: input.provenanceTag,
        parameters: input.parameters,
        outcome: input.outcome,
        clerkReceipt: input.clerkReceipt,
      });
      if (this.persisting) line = JSON.stringify(entry);
    } catch (err) {
      throw new L0PayloadError(
        `entry cannot be hashed or serialised (nested too deeply); nothing was committed: ${describe(err)}`,
        err
      );
    }

    // Persist BEFORE committing to the in-memory chain, so a write failure does
    // not silently diverge disk from memory. On failure we surface it: mark
    // durability unhealthy AND throw. Without a clerk the throw leaves append()
    // synchronously; with a clerk it rejects the append's promise and, like any
    // failure on the clerk path, stops the log.
    if (line !== null) this.persist(sequenceNumber, line);

    this.chain.push(entry);
    if (entry.clerkReceipt !== undefined) {
      this.committedReceipts.add(entry.clerkReceipt.receipt_hash);
    }
    return entry;
  }

  /**
   * Stop writing for the life of this log: every later append throws
   * L0WriteError (with a clerk, before anything is submitted).
   */
  private stopWriting(reason: string): void {
    this.persisting = false;
    this.writeHealthy = false;
    this.writeRefusal = reason;
    this.closeFile();
  }

  /**
   * Write one entry's line and fsync it. Returns only when the line is on disk.
   *
   * The file must still be the one this log opened (same device and inode at
   * the path) at the size this log left it; otherwise something removed,
   * replaced or wrote to it, nothing is written, and this log stops writing.
   * A write or fsync that fails can still have landed part of the line, so the
   * file is cut back to its size before this entry (and synced). If that works,
   * this entry is refused and a later append may try again. If it does not,
   * the file may hold a torn line, and this log stops writing.
   */
  private persist(sequenceNumber: number, line: string): void {
    const path = this.filePath as string;
    const failed = (detail: string): string =>
      `append write failed at seq ${sequenceNumber}: ${detail}`;

    const fd = this.fd;
    if (fd === null) {
      this.lastError = failed("the log file is not open; nothing was written");
      this.stopWriting(`the log file is not open (seq ${sequenceNumber})`);
      throw new L0WriteError(this.lastError);
    }

    let sizeBefore: number;
    let change: string | null = null;
    try {
      const st = fstatSync(fd, { bigint: true });
      let atPath: BigIntStats | null = null;
      try {
        atPath = lstatSync(path, { bigint: true });
      } catch (err) {
        if (errorCode(err) !== "ENOENT") throw err;
      }
      const id = this.fileIdentity;
      if (atPath === null) {
        change = `the log file ${path} was removed while this log ran`;
      } else if (id === null || atPath.dev !== id.dev || atPath.ino !== id.ino || st.dev !== id.dev || st.ino !== id.ino) {
        change = `the log file at ${path} is no longer the file this log opened (replaced while it ran)`;
      } else if (st.size !== BigInt(this.fileBytes)) {
        change = `the log file is ${st.size} bytes; this log left it at ${this.fileBytes}, so something else wrote to it`;
      }
      sizeBefore = Number(st.size);
    } catch (err) {
      // Nothing was written; a later append may try again.
      this.writeHealthy = false;
      this.lastError = failed(`the log file could not be checked: ${describe(err)}; nothing was written`);
      throw new L0WriteError(this.lastError, err);
    }
    if (change !== null) {
      this.lastError = failed(`${change}. Nothing was appended, and this log writes nothing more`);
      this.stopWriting(change);
      throw new L0WriteError(this.lastError);
    }

    const bytes = Buffer.from((this.needsNewline ? "\n" : "") + line + "\n", "utf8");
    try {
      writeAll(fd, bytes);
      if (this.fsyncEnabled) fsyncSync(fd);
    } catch (err) {
      let cutBack = true;
      let cutError: unknown = null;
      try {
        ftruncateSync(fd, sizeBefore);
        if (this.fsyncEnabled) fsyncSync(fd);
      } catch (e) {
        cutBack = false;
        cutError = e;
      }
      if (cutBack) {
        this.writeHealthy = false;
        this.lastError = failed(
          `${describe(err)}; the file was cut back to the ${sizeBefore} bytes it held before this entry, and the entry was not committed`
        );
        throw new L0WriteError(this.lastError, err);
      }
      this.lastError = failed(
        `${describe(err)}; cutting the file back to the ${sizeBefore} bytes it held before this entry also failed (${describe(cutError)}), so the file may hold a torn line. This log writes nothing more`
      );
      this.stopWriting(
        `an earlier write (seq ${sequenceNumber}) failed and could not be taken back; the file may hold a torn line`
      );
      throw new L0WriteError(this.lastError, err);
    }
    this.fileBytes = sizeBefore + bytes.length;
    this.needsNewline = false;
  }

  // ── verify: internal consistency only (docs/S4-WIRE-SPEC.md §5) ──────────

  verify(): VerifyResult {
    for (let i = 0; i < this.chain.length; i++) {
      const entry = this.chain[i];

      // The stored index is part of what is hashed; it must be the position.
      if (entry.sequenceNumber !== i) {
        return { valid: false, brokenAt: i };
      }

      const expectedPrevHash =
        i === 0 ? GENESIS_PREV_HASH : this.chain[i - 1].hash;

      if (entry.previousHash !== expectedPrevHash) {
        return { valid: false, brokenAt: i };
      }

      // An entry whose hash cannot be recomputed (nesting too deep for the
      // stack) cannot be verified: a break there, never a throw.
      let expectedHash: string;
      try {
        expectedHash = hashEntry(i, entry.previousHash, entry);
      } catch {
        return { valid: false, brokenAt: i };
      }
      if (entry.hash !== expectedHash) {
        return { valid: false, brokenAt: i };
      }
    }

    return { valid: true };
  }

  get length(): number {
    return this.chain.length;
  }

  /** The committed entry at `sequenceNumber`. Frozen. */
  getEntry(sequenceNumber: number): LogEntry | undefined {
    return this.chain[sequenceNumber];
  }

  /**
   * Every entry, in order, as a frozen copy: the array and each entry are
   * frozen, and the array is not the chain, so nothing done to the result
   * (sort, reverse, splice, an assignment) can change the chain.
   */
  getAll(): readonly LogEntry[] {
    return Object.freeze(this.chain.slice());
  }

  /**
   * The clerk's sequence and time stamps, one per entry that carries a clerk
   * receipt, in chain order. Read from the receipts already on the chain (it
   * calls no clerk) and returned as copies, so changing a stamp cannot change
   * the chain. Entries without a receipt are skipped. A loaded stamp was
   * checked only when this log has a clerk route and loaded LOADED_VERIFIED.
   * Without a route, loading checks the hash chain only, so loaded stamps are
   * whatever the file held (getDurabilityInfo().receiptsUnchecked counts
   * them), as they are on a CANNOT_VERIFY load.
   */
  getClerkClockSource(): readonly ClerkClockStamp[] {
    return this.chain.flatMap((entry) => {
      const r = entry.clerkReceipt;
      return r === undefined || r === null || typeof r !== "object"
        ? []
        : [
            {
              sequenceNumber: entry.sequenceNumber,
              clerk_seq: r.clerk_seq,
              clerk_time: { ...r.clerk_time },
              separation: r.separation,
              intake: r.intake,
              clerk_id: r.clerk_id,
              clerk_boot_id: r.clerk_boot_id,
            },
          ];
    });
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
      clean: this.isClean(),
      entriesLoaded: this.entriesLoaded,
      brokenAt: this.brokenAt,
      writeHealthy: this.writeHealthy,
      lastError: this.lastError,
      persisting: this.persisting,
      receiptsUnchecked: this.receiptsUnchecked,
      lockTakenOver: this.lockTakenOver,
    };
  }

  /**
   * publicKeyFingerprint() of the clerk route's public key ("sha256:" + hex of
   * its SPKI DER), or null when this log has no clerk route. For the clerk's
   * operator to compare, out of band, with the key they hold.
   */
  getClerkKeyFingerprint(): string | null {
    return this.clerkKeyFingerprint;
  }
}
