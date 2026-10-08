// ──────────────────────────────────────────────────────────────────────────────
// Reference clerk — the book: an append-only JSONL file of signed receipts.
//
// One receipt per line, in clerk_seq order. Each receipt names the hash of the
// one before it (prev_receipt_hash; 64 zeros for the first), so removing,
// reordering or editing a line breaks the chain or a signature.
//
// What the book check proves, and what it does not:
//   · it proves every line was signed by the given key and that the lines form
//     one unbroken chain from genesis;
//   · it does NOT prove the book is complete at the tail: a book cut back to an
//     earlier line still verifies. Only someone who kept a later receipt (the
//     node keeps one per log entry) can show that.
//
// Writer side: the clerk appends with O_APPEND and fsyncs after every line. A
// receipt is handed out only after its line is on disk. Nothing here makes the
// file append-only for other users of the same account; edits are detected on
// the next start, not prevented.
// ──────────────────────────────────────────────────────────────────────────────

import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  unlinkSync,
  writeSync,
} from "fs";
import { randomBytes } from "crypto";
import type { KeyObject } from "crypto";
import { dirname } from "path";
import { sha256Hex } from "../../../src/l0/canonical";
import {
  GENESIS_RECEIPT_HASH,
  RECEIPT_FORM,
  isPlainRecord,
  toEd25519PublicKey,
  verifyReceipt,
} from "./receipt";
import type { ClerkReceipt, Verdict } from "./receipt";

/** A book line longer than this is treated as damage, not read into memory. */
export const MAX_BOOK_LINE_BYTES = 16 * 1024 * 1024;

const HEX64 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;

export class BookError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BookError";
  }
}

/** The book exists but does not verify. The clerk refuses to run on it. */
export class BookVerificationError extends BookError {
  constructor(message: string, readonly brokenAt: number) {
    super(message);
    this.name = "BookVerificationError";
  }
}

/** Another live process holds the book, or the lock cannot be taken. */
export class BookLockError extends BookError {
  constructor(message: string) {
    super(message);
    this.name = "BookLockError";
  }
}

/** A write or fsync failed. The book refuses every later append. */
export class BookWriteError extends BookError {
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = "BookWriteError";
  }
}

export interface BookVerdict {
  ok: boolean;
  /** Receipts that verified (all of them when ok). */
  count: number;
  /** receipt_hash of the last verified receipt; genesis if none. */
  head: string;
  /** Index of the first line that failed, or null. */
  brokenAt: number | null;
  reason: string;
  lastBootId: string | null;
}

// ── the chain check, one record at a time ────────────────────────────────────

/**
 * Checks records in book order. `check()` advances only when the record at the
 * current position verifies; the first failure is final for that position.
 */
export class BookChecker {
  private readonly key: KeyObject;
  private n = 0;
  private headHash = GENESIS_RECEIPT_HASH;
  private bootId: string | null = null;
  private lastMonotonic: bigint | null = null;
  private readonly finishedBoots = new Set<string>();

  constructor(publicKey: KeyObject | string) {
    this.key = toEd25519PublicKey(publicKey);
  }

  get count(): number {
    return this.n;
  }

  get head(): string {
    return this.headHash;
  }

  get lastBootId(): string | null {
    return this.bootId;
  }

  /** Would `record` verify at the current position? Does not advance. */
  peek(record: unknown): Verdict {
    return this.inspect(record);
  }

  check(record: unknown): Verdict {
    const v = this.inspect(record);
    if (!v.ok) return v;
    const r = record as Record<string, unknown>;
    const boot = r.clerk_boot_id as string;
    const mono = BigInt((r.clerk_time as Record<string, unknown>).monotonic_ns as string);
    if (this.bootId !== null && boot !== this.bootId) this.finishedBoots.add(this.bootId);
    this.bootId = boot;
    this.lastMonotonic = mono;
    this.headHash = r.receipt_hash as string;
    this.n++;
    return v;
  }

  private inspect(record: unknown): Verdict {
    if (!isPlainRecord(record)) return { ok: false, reason: "line is not a JSON object" };
    const sig = verifyReceipt(record, this.key);
    if (!sig.ok) return sig;
    if (record.kind !== "SUBMISSION") return { ok: false, reason: "kind is not SUBMISSION" };
    if (record.receipt_form !== undefined && record.receipt_form !== RECEIPT_FORM) {
      return { ok: false, reason: `unknown receipt_form ${JSON.stringify(record.receipt_form)}` };
    }
    if (record.clerk_seq !== this.n) {
      return {
        ok: false,
        reason: `clerk_seq is ${JSON.stringify(record.clerk_seq)}, expected ${this.n}`,
      };
    }
    if (record.prev_receipt_hash !== this.headHash) {
      return { ok: false, reason: "prev_receipt_hash does not name the previous receipt" };
    }
    if (typeof record.payload_commitment !== "string" || !HEX64.test(record.payload_commitment)) {
      return { ok: false, reason: "payload_commitment is not 64 lowercase hex characters" };
    }
    if (record.payload_retained === true) {
      if (
        typeof record.payload_canonical !== "string" ||
        sha256Hex(record.payload_canonical) !== record.payload_commitment
      ) {
        return { ok: false, reason: "retained payload does not match payload_commitment" };
      }
    } else if (record.payload_retained === false) {
      if (record.payload_canonical !== null) {
        return { ok: false, reason: "payload_canonical is set although payload_retained is false" };
      }
    } else if (record.payload_retained !== undefined) {
      return { ok: false, reason: "payload_retained is not a boolean" };
    }
    if (typeof record.clerk_boot_id !== "string" || record.clerk_boot_id.length === 0) {
      return { ok: false, reason: "clerk_boot_id is missing" };
    }
    const t = record.clerk_time;
    if (
      !isPlainRecord(t) ||
      typeof t.wall_ms !== "number" ||
      !Number.isFinite(t.wall_ms) ||
      typeof t.monotonic_ns !== "string" ||
      !DECIMAL.test(t.monotonic_ns)
    ) {
      return { ok: false, reason: "clerk_time is malformed" };
    }
    const boot = record.clerk_boot_id;
    if (boot === this.bootId) {
      if (this.lastMonotonic !== null && BigInt(t.monotonic_ns) < this.lastMonotonic) {
        return { ok: false, reason: "monotonic_ns went backwards within one boot" };
      }
    } else if (this.finishedBoots.has(boot)) {
      return { ok: false, reason: "clerk_boot_id reappears after a later boot" };
    }
    return { ok: true, reason: "verified" };
  }
}

// ── reading ──────────────────────────────────────────────────────────────────

export interface RawLine {
  bytes: Buffer;
  /** false for a last line with no trailing newline (a torn write). */
  terminated: boolean;
}

/**
 * Open `path` for reading only if it is a regular file. The open does not
 * block on a FIFO (O_NONBLOCK), and fstat on the descriptor refuses a FIFO, a
 * socket, a directory or a device, so a reader never hangs on one.
 */
export function openRegularFileForReading(path: string): number {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  try {
    if (!fstatSync(fd).isFile()) throw new Error(`${path} is not a regular file`);
  } catch (err) {
    closeSync(fd);
    throw err;
  }
  return fd;
}

/**
 * Lines of the file behind `fd`, read from offset 0 in bounded chunks. A line
 * longer than `maxLineBytes` ends the reading with an empty, unterminated line.
 */
export function* readLines(fd: number, maxLineBytes: number = MAX_BOOK_LINE_BYTES): Generator<RawLine> {
  const chunk = Buffer.allocUnsafe(1 << 20);
  let pending: Buffer[] = [];
  let pendingLen = 0;
  let position = 0;
  for (;;) {
    const n = readSync(fd, chunk, 0, chunk.length, position);
    if (n === 0) break;
    position += n;
    const data = chunk.subarray(0, n);
    let start = 0;
    for (;;) {
      const nl = data.indexOf(0x0a, start);
      if (nl === -1) break;
      const piece = data.subarray(start, nl);
      const bytes =
        pendingLen > 0 ? Buffer.concat([...pending, piece]) : Buffer.from(piece);
      pending = [];
      pendingLen = 0;
      yield { bytes, terminated: true };
      start = nl + 1;
    }
    if (start < n) {
      pending.push(Buffer.from(data.subarray(start)));
      pendingLen += n - start;
      if (pendingLen > maxLineBytes) {
        yield { bytes: Buffer.alloc(0), terminated: false };
        return;
      }
    }
  }
  if (pendingLen > 0) yield { bytes: Buffer.concat(pending), terminated: false };
}

/**
 * Check every line of the book behind `fd`. `onRecord` sees each record that
 * verified, in book order, as soon as it has.
 */
function scan(
  fd: number,
  checker: BookChecker,
  onRecord?: (record: Record<string, unknown>) => void
): BookVerdict {
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  const fail = (reason: string): BookVerdict => ({
    ok: false,
    count: checker.count,
    head: checker.head,
    brokenAt: checker.count,
    reason: `receipt ${checker.count}: ${reason}`,
    lastBootId: checker.lastBootId,
  });
  for (const line of readLines(fd)) {
    if (!line.terminated) {
      return fail(
        line.bytes.length === 0
          ? `line longer than ${MAX_BOOK_LINE_BYTES} bytes`
          : "last line has no newline (a write may have been cut off)"
      );
    }
    if (line.bytes.length === 0) return fail("empty line");
    let text: string;
    try {
      text = decoder.decode(line.bytes);
    } catch {
      return fail("line is not valid UTF-8");
    }
    let record: unknown;
    try {
      record = JSON.parse(text);
    } catch (err) {
      return fail(`line is not valid JSON (${(err as Error).message})`);
    }
    const v = checker.check(record);
    if (!v.ok) return fail(v.reason);
    if (onRecord !== undefined) onRecord(record as Record<string, unknown>);
  }
  return {
    ok: true,
    count: checker.count,
    head: checker.head,
    brokenAt: null,
    reason: "verified",
    lastBootId: checker.lastBootId,
  };
}

/**
 * Verify a whole book file against a public key. Never throws for content.
 * `onRecord` sees each receipt that verified, in book order; a verdict that is
 * not ok means the records it saw end before the break. Anything at `path`
 * that is not a regular file (a FIFO, a directory) is refused, not read.
 */
export function verifyBookFile(
  path: string,
  publicKey: KeyObject | string,
  onRecord?: (record: Record<string, unknown>) => void
): BookVerdict {
  const checker = new BookChecker(publicKey);
  let fd: number;
  try {
    fd = openRegularFileForReading(path);
  } catch (err) {
    return {
      ok: false,
      count: 0,
      head: GENESIS_RECEIPT_HASH,
      brokenAt: 0,
      reason: `cannot open book: ${(err as Error).message}`,
      lastBootId: null,
    };
  }
  try {
    return scan(fd, checker, onRecord);
  } finally {
    closeSync(fd);
  }
}

/** Verify records already in memory (for example a receipt list from elsewhere). */
export function verifyBookRecords(records: readonly unknown[], publicKey: KeyObject | string): BookVerdict {
  const checker = new BookChecker(publicKey);
  for (const r of records) {
    const v = checker.check(r);
    if (!v.ok) {
      return {
        ok: false,
        count: checker.count,
        head: checker.head,
        brokenAt: checker.count,
        reason: `receipt ${checker.count}: ${v.reason}`,
        lastBootId: checker.lastBootId,
      };
    }
  }
  return {
    ok: true,
    count: checker.count,
    head: checker.head,
    brokenAt: null,
    reason: "verified",
    lastBootId: checker.lastBootId,
  };
}

// ── the lock: one writer per book ────────────────────────────────────────────
//
// Two clerks appending to one book would fork its chain. The lock file holds
// two lines: the pid of the process that owns the book, and a random token
// that process drew when it took the lock. A lock whose process is gone is
// taken over. Between two starting clerks that both find the same stale lock
// there is a small window; the loser's next append still cannot break the
// chain silently, because the next start verifies the whole book.
//
// A lock naming THIS process's pid is live only if this process holds its
// token. Otherwise an earlier process with the same pid left it: a clerk in a
// container that crashed and came back as pid 1 again. Pids are compared
// within one pid namespace only; the lock does not keep apart clerks in
// different containers (or on different hosts) that share one book file.

const LOCK_TOKEN = /^[0-9a-f]{32}$/;

/** Tokens of the book locks this process holds, shared by every copy of this module loaded in it. */
const HELD_LOCK_TOKENS: Set<string> = (() => {
  const slots = globalThis as unknown as Record<symbol, Set<string> | undefined>;
  const key = Symbol.for("ilas.clerk.heldBookLockTokens");
  return (slots[key] ??= new Set<string>());
})();

interface LockHolder {
  pid: number;
  /** null for a lock in the older one-line form (pid only). */
  token: string | null;
}

/** `<pid>\n<token>\n`, or the older `<pid>\n`. Anything else names no process. */
function parseLock(text: string): LockHolder | null {
  const lines = text.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
  if (lines.length < 1 || lines.length > 2 || !DECIMAL.test(lines[0])) return null;
  if (lines.length === 2 && !LOCK_TOKEN.test(lines[1])) return null;
  return { pid: Number(lines[0]), token: lines.length === 2 ? lines[1] : null };
}

function holderAlive(holder: LockHolder): boolean {
  if (holder.pid === process.pid) {
    return holder.token !== null && HELD_LOCK_TOKENS.has(holder.token);
  }
  try {
    process.kill(holder.pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** Take the lock; returns the token written into it. */
function acquireLock(lockPath: string): string {
  for (let attempt = 0; attempt < 2; attempt++) {
    let fd: number;
    try {
      fd = openSync(lockPath, "wx", 0o600);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== "EEXIST") {
        throw new BookLockError(`cannot create lock file ${lockPath}: ${(err as Error).message}`);
      }
      let text = "";
      try {
        text = readFileSync(lockPath, "utf8").trim();
      } catch (readErr) {
        if ((readErr as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw new BookLockError(`cannot read lock file ${lockPath}: ${(readErr as Error).message}`);
      }
      const holder = parseLock(text);
      if (holder === null) {
        throw new BookLockError(
          `lock file ${lockPath} exists but names no process. If no clerk is running ` +
            `on this book, remove the lock file by hand.`
        );
      }
      if (holderAlive(holder)) {
        throw new BookLockError(
          holder.pid === process.pid
            ? `book is in use by process ${holder.pid}, this process (lock file ${lockPath})`
            : `book is in use by process ${holder.pid} (lock file ${lockPath}). If you are ` +
                `sure no clerk is running on this book (the pid may now belong to another ` +
                `process), remove the lock file by hand.`
        );
      }
      try {
        unlinkSync(lockPath);
      } catch (unlinkErr) {
        if ((unlinkErr as NodeJS.ErrnoException).code !== "ENOENT") {
          throw new BookLockError(
            `cannot remove stale lock ${lockPath}: ${(unlinkErr as Error).message}`
          );
        }
      }
      continue;
    }
    const token = randomBytes(16).toString("hex");
    try {
      writeSync(fd, `${process.pid}\n${token}\n`);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    HELD_LOCK_TOKENS.add(token);
    return token;
  }
  throw new BookLockError(`could not take the lock ${lockPath}`);
}

function releaseLock(lockPath: string, token: string): void {
  HELD_LOCK_TOKENS.delete(token);
  try {
    const holder = parseLock(readFileSync(lockPath, "utf8"));
    if (holder !== null && holder.pid === process.pid && holder.token === token) unlinkSync(lockPath);
  } catch {
    /* already gone, or not ours: nothing to release */
  }
}

/** Best effort: make a new directory entry durable. Not every platform allows it. */
function fsyncDirectory(dir: string): void {
  let fd: number | null = null;
  try {
    fd = openSync(dir, "r");
    fsyncSync(fd);
  } catch {
    /* not supported here; the file's own fsync still ran */
  } finally {
    if (fd !== null) closeSync(fd);
  }
}

// ── the writer ───────────────────────────────────────────────────────────────

export type BookOpenState =
  /** No book, or an empty one: starts at clerk_seq 0. First run, or erased — code cannot tell. */
  | "NEW"
  /** A non-empty book was read and every line verified. */
  | "LOADED_VERIFIED";

export class Book {
  private broken: string | null = null;
  private closed = false;

  private constructor(
    readonly path: string,
    readonly lockPath: string,
    private readonly lockToken: string,
    readonly state: BookOpenState,
    private fd: number,
    private readonly checker: BookChecker
  ) {}

  /**
   * Take the lock, read and verify the whole book, and open it for appending.
   * A book that does not verify is refused (BookVerificationError): the clerk
   * will not extend a chain it cannot vouch for.
   */
  static open(path: string, publicKey: KeyObject | string): Book {
    const lockPath = `${path}.lock`;
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const lockToken = acquireLock(lockPath);
    let fd: number | null = null;
    try {
      let existed = true;
      try {
        lstatSync(path);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
        existed = false;
      }
      fd = openSync(path, "a+", 0o600);
      if (!existed) fsyncDirectory(dirname(path));
      const checker = new BookChecker(publicKey);
      const verdict = scan(fd, checker);
      if (!verdict.ok) {
        throw new BookVerificationError(
          `book ${path} does not verify (${verdict.reason}); refusing to run on it`,
          verdict.brokenAt ?? 0
        );
      }
      const state: BookOpenState = checker.count === 0 ? "NEW" : "LOADED_VERIFIED";
      const book = new Book(path, lockPath, lockToken, state, fd, checker);
      fd = null;
      return book;
    } catch (err) {
      if (fd !== null) closeSync(fd);
      releaseLock(lockPath, lockToken);
      throw err;
    }
  }

  /** Receipts in the book. Also the clerk_seq the next receipt must carry. */
  get count(): number {
    return this.checker.count;
  }

  /** receipt_hash of the last receipt; genesis for an empty book. */
  get head(): string {
    return this.checker.head;
  }

  get lastBootId(): string | null {
    return this.checker.lastBootId;
  }

  /** Why the book stopped accepting appends, or null. */
  get failure(): string | null {
    return this.broken;
  }

  /**
   * Append one receipt and fsync. Returns only when the line is on disk. The
   * receipt is first checked exactly as a later start would check it, so the
   * book never takes a line that would make the clerk refuse to start.
   */
  append(receipt: ClerkReceipt): void {
    if (this.closed) throw new BookError("book is closed");
    if (this.broken !== null) {
      throw new BookWriteError(`book stopped after an earlier failure: ${this.broken}`);
    }
    const text = JSON.stringify(receipt);
    // Check the record as a later start will read it: parsed back from the line.
    const reread: unknown = JSON.parse(text);
    const preCheck = this.checker.peek(reread);
    if (!preCheck.ok) {
      throw new BookError(`refusing to append a receipt that would not verify: ${preCheck.reason}`);
    }
    const line = Buffer.from(text + "\n", "utf8");
    try {
      let off = 0;
      while (off < line.length) off += writeSync(this.fd, line, off, line.length - off);
      fsyncSync(this.fd);
    } catch (err) {
      this.broken = `write failed at clerk_seq ${receipt.clerk_seq}: ${(err as Error).message}`;
      throw new BookWriteError(this.broken, err);
    }
    const v = this.checker.check(reread);
    if (!v.ok) {
      // peek() accepted this same object a moment ago; reaching here is a bug.
      this.broken = `appended receipt failed its own check: ${v.reason}`;
      throw new BookWriteError(this.broken);
    }
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      closeSync(this.fd);
    } finally {
      releaseLock(this.lockPath, this.lockToken);
    }
  }
}
