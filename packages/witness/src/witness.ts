// ──────────────────────────────────────────────────────────────────────────────
// Reference witness — the core.
//
// One poll does, for every intake directory (the shared one, and each
// submitter's own) and every file in it whose name is a submitter declared for
// that directory:
//
//   read the bytes (regular files only, never through a symlink, small files only)
//   → validate them as a HEAD_COMMIT addressed to this witness set
//   → if this submitter's head (seq_no, head_hash) is already retained: no new
//     record, no new receipt
//   → otherwise sign the receipt fields, hash and sign the record, append it to
//     the store and fsync it
//   → only then write the receipt into that submitter's own outbox
//     (staging file, fsync, rename)
//   → remove the intake file, but only if its bytes are still the ones read.
//
// Names starting with "." are skipped without a word: they are the client's
// temporary files, renamed onto the submitter's name once complete.
//
// Intakes and outboxes are shared ground: a node writes its intake, and an
// outbox is the one place a writer other than the witness is defended against.
// So no entry in them is checked by name and then opened by name. Each is
// opened once, O_RDONLY|O_NOFOLLOW|O_NONBLOCK (a symlink is refused, a FIFO
// cannot block), and only that descriptor is judged and read. A file the
// witness writes there is created new (O_CREAT|O_EXCL|O_NOFOLLOW, random name)
// inside a staging directory that lstat shows to be a real directory.
//
// What this code can say about itself: it retained what it says it retained, in
// a chain it re-verifies on every start, and it signed each of those records
// whole (record_sig) as well as its receipt fields (witness_sig).
// What it cannot say: that the commit came from the node it is attributed to.
// The attribution is the intake path the commit was read from; who can write
// that path is decided by the deployment's file permissions. Nor can it say
// that it is independent of the node it witnesses. That is decided by who runs
// it, on which host and account, and who holds its key.
// ──────────────────────────────────────────────────────────────────────────────

import { createHash, createPublicKey, randomBytes } from "crypto";
import type { KeyObject } from "crypto";
import type { Stats } from "fs";
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "fs";
import { dirname, join } from "path";
import { checkHeadCommit, GENESIS_HASH } from "./commit";
import type { WitnessConfig } from "./config";
import { publicKeyFingerprint } from "./keys";
import {
  receiptBytes,
  receiptFileName,
  receiptIndexOf,
  signReceipt,
} from "./receipt";
import {
  StoreAppender,
  StoreBroken,
  SubmitterHistory,
  fsyncDirectory,
  readStore,
  receiptOf,
  recordHash,
  signRecord,
} from "./store";
import type { ConflictNote, StoreContents, StoreRecord, UnhashedRecord } from "./store";

/** A HEAD_COMMIT is about 150 bytes; anything far larger is not one. */
export const MAX_INTAKE_BYTES = 4096;

/** Inside each outbox: where receipts are written before they are renamed into place. */
export const STAGING_DIR = ".staging";

export type RefusalCode =
  | "KEY_NOT_ED25519"
  | "DIRECTORY_MISSING"
  | "STORE_BROKEN"
  | "STORE_UNWRITABLE"
  | "OUTBOX_UNREADABLE"
  | "OUTBOX_AHEAD_OF_STORE"
  | "OUTBOX_MISMATCH"
  | "OUTBOX_UNWRITABLE";

/** The witness will not start. The message says why and what to look at. */
export class WitnessRefusal extends Error {
  constructor(readonly code: RefusalCode, message: string) {
    super(message);
    this.name = "WitnessRefusal";
  }
}

/** The witness stopped mid-run because it could not retain safely. */
export class WitnessHalted extends Error {
  /** What the halted poll had already done before it stopped (already retained, so worth logging). */
  readonly events: readonly PollEvent[];

  constructor(message: string, events: readonly PollEvent[] = []) {
    super(message);
    this.name = "WitnessHalted";
    this.events = events;
  }
}

export type PollEvent =
  /** A commit was retained (and its receipt written, unless receiptFile is null). */
  | {
      readonly kind: "RETAINED";
      readonly submitterId: string;
      readonly index: number;
      readonly seq_no: number;
      readonly head_hash: string;
      readonly witness_ts: number;
      readonly conflicts: readonly ConflictNote[];
      readonly receiptFile: string | null;
    }
  /** This submitter's head (seq_no, head_hash) was already retained; nothing new written. */
  | {
      readonly kind: "DUPLICATE";
      readonly submitterId: string;
      readonly seq_no: number;
      readonly head_hash: string;
      readonly priorIndex: number;
    }
  /** Not parseable yet. May be a write in progress; it is read again next poll. */
  | { readonly kind: "DEFERRED"; readonly submitterId: string; readonly sha256: string }
  /** Still not parseable, and byte-identical to the previous poll. Left in place. */
  | {
      readonly kind: "MALFORMED";
      readonly submitterId: string;
      readonly reason: string;
      readonly sha256: string;
      readonly byteLength: number;
    }
  /** Parsed, but not an acceptable HEAD_COMMIT for this witness. Not signed. Left in place. */
  | {
      readonly kind: "REFUSED";
      readonly submitterId: string;
      readonly reason: string;
      /** SHA-256 of the bytes read; null when the file was too large to read. */
      readonly sha256: string | null;
    }
  /**
   * A name in an intake that is not a submitter declared for that directory
   * (including the name of a submitter that has its own intake, found anywhere
   * else). Left alone.
   */
  | { readonly kind: "UNDECLARED"; readonly name: string; readonly intakeDir: string }
  /** A declared name that is not a regular file (directory, symlink, …). Left alone. */
  | { readonly kind: "NOT_A_FILE"; readonly submitterId: string; readonly detail: string }
  /** A declared file that could not be read. Left alone. */
  | { readonly kind: "UNREADABLE"; readonly submitterId: string; readonly detail: string }
  /** An intake directory itself could not be listed. */
  | { readonly kind: "INTAKE_UNREADABLE"; readonly intakeDir: string; readonly detail: string }
  /** A consumed intake file was not removed (changed since it was read, or unlink failed). */
  | { readonly kind: "INTAKE_LEFT"; readonly submitterId: string; readonly reason: string }
  /** A receipt whose earlier write failed has now been written. */
  | {
      readonly kind: "RECEIPT_WRITTEN";
      readonly submitterId: string;
      readonly index: number;
      readonly receiptFile: string;
    }
  /** A retained record's receipt could not be written; retried every poll. */
  | {
      readonly kind: "RECEIPT_PENDING";
      readonly submitterId: string;
      readonly index: number;
      readonly detail: string;
    };

export interface StartupReport {
  /** True when no store existed and an empty one was created. */
  readonly storeCreated: boolean;
  readonly records: number;
  /** publicKeyFingerprint() of the witness's public key: "sha256:" + hex, as keygen prints it. */
  readonly publicKeyFingerprint: string;
  /** Receipts that were missing from an outbox and were rebuilt from the store. */
  readonly receiptsRestored: readonly { index: number; submitterId: string; file: string }[];
  /** Files in an outbox that are not this witness's receipts. Reported, not touched. */
  readonly foreignOutboxFiles: readonly string[];
  /** Store records whose submitter is not in the current config (no outbox to write to). */
  readonly recordsForUndeclaredSubmitters: number;
}

export interface WitnessOptions {
  /**
   * The configuration. Take it from loadConfigFile() or parseConfig(): they
   * check that the intakes, outboxes, store and key are kept apart, and this
   * class does not repeat those checks.
   */
  readonly config: WitnessConfig;
  /** Ed25519 private key. Load it with loadPrivateKeyFile(). */
  readonly privateKey: KeyObject;
  /** Witness clock in ms. Defaults to Date.now. Must return a non-negative integer. */
  readonly clock?: () => number;
}

type EntryRead =
  | { readonly kind: "bytes"; readonly bytes: Buffer }
  | { readonly kind: "absent" }
  | { readonly kind: "not-a-file"; readonly detail: string }
  | { readonly kind: "too-large"; readonly size: number }
  | { readonly kind: "error"; readonly detail: string };

const OPEN_ENTRY_FLAGS =
  constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);

/** "wx" plus O_NOFOLLOW: a staging file is always a new file of this witness's own. */
const CREATE_STAGING_FLAGS =
  constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0);

/**
 * Read one entry of a directory another party can write (an intake, an
 * outbox). One open by name, without following a symlink and without blocking
 * on a FIFO; everything after that is decided on the descriptor, so whatever is
 * renamed onto the name meanwhile changes nothing. Only a regular file of at
 * most MAX_INTAKE_BYTES is read, and never more than one byte past that,
 * whatever the file claims its size is.
 */
function readEntry(path: string): EntryRead {
  let fd: number;
  try {
    fd = openSync(path, OPEN_ENTRY_FLAGS);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return { kind: "absent" };
    if (code === "ELOOP") return { kind: "not-a-file", detail: "symbolic link" };
    return { kind: "error", detail: String(error) };
  }
  try {
    const stats = fstatSync(fd);
    if (!stats.isFile()) {
      return { kind: "not-a-file", detail: stats.isDirectory() ? "directory" : "special file" };
    }
    if (stats.size > MAX_INTAKE_BYTES) return { kind: "too-large", size: stats.size };
    const buffer = Buffer.alloc(MAX_INTAKE_BYTES + 1);
    let length = 0;
    for (;;) {
      const n = readSync(fd, buffer, length, buffer.length - length, null);
      if (n === 0) break;
      length += n;
      if (length > MAX_INTAKE_BYTES) {
        return { kind: "too-large", size: Math.max(length, fstatSync(fd).size) };
      }
    }
    return { kind: "bytes", bytes: Buffer.from(buffer.subarray(0, length)) };
  } catch (error) {
    return { kind: "error", detail: String(error) };
  } finally {
    closeSync(fd);
  }
}

/** Why an outbox entry that has a receipt's name cannot be read as one. */
function entryProblem(read: Exclude<EntryRead, { kind: "bytes" } | { kind: "absent" }>): string {
  switch (read.kind) {
    case "not-a-file":
      return `it is a ${read.detail}, not a regular file`;
    case "too-large":
      return `it is ${read.size} bytes, larger than any receipt`;
    case "error":
      return read.detail;
  }
}

/** What lstat found where a real directory was expected. */
function describeKind(stats: Stats): string {
  if (stats.isSymbolicLink()) return "a symbolic link";
  if (stats.isFile()) return "a regular file";
  if (stats.isFIFO()) return "a FIFO";
  return "a special file";
}

/** File names of this witness's staging files: "<receipt name>.<hex>.tmp". */
const STAGING_FILE = /^receipt-\d{12}\.json\.[0-9a-f]+\.tmp$/;

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function requireDirectory(path: string, label: string): void {
  let isDir = false;
  let detail = "";
  try {
    isDir = statSync(path).isDirectory();
    if (!isDir) detail = "it exists but is not a directory";
  } catch (error) {
    detail = String(error);
  }
  if (!isDir) {
    throw new WitnessRefusal(
      "DIRECTORY_MISSING",
      `${label} ${path} is not usable (${detail}). The witness creates no directories ` +
        `of its own: who may read and write them is a deployment decision. Create it, ` +
        `with the permissions you intend, and start again.`
    );
  }
}

function writeAll(fd: number, bytes: Buffer): void {
  let offset = 0;
  while (offset < bytes.length) offset += writeSync(fd, bytes, offset, bytes.length - offset);
}

/** One intake directory, and the submitters whose commits are read from it. */
interface Intake {
  readonly dir: string;
  readonly label: string;
  readonly ids: ReadonlySet<string>;
}

/** Key of a reported condition: directory, entry name, and which kind of report. */
function slotKey(dir: string, name: string, slot: string): string {
  return `${dir}\0${name}\0${slot}`;
}

export class ReferenceWitness {
  readonly publicKey: KeyObject;
  readonly startup: StartupReport;

  private readonly config: WitnessConfig;
  private readonly privateKey: KeyObject;
  private readonly clock: () => number;
  private readonly outboxes: ReadonlyMap<string, string>;
  private readonly intakes: readonly Intake[];
  private readonly store: StoreRecord[];
  private readonly appender: StoreAppender;
  private readonly history = new SubmitterHistory();

  /** Unparseable bytes seen on the previous poll, by intake directory and name. */
  private readonly firstSighting = new Map<string, { dir: string; name: string; digest: string }>();
  /** What has been reported per intake entry and slot, so a standing condition is reported once. */
  private readonly reported = new Map<string, { dir: string; name: string; fingerprint: string }>();
  /** Store indices whose receipt is not yet in its outbox, with the last failure reported. */
  private readonly pendingReceipts = new Map<number, string>();
  private halted: string | null = null;

  private constructor(options: WitnessOptions) {
    this.config = options.config;
    this.privateKey = options.privateKey;
    this.clock = options.clock ?? Date.now;
    this.outboxes = new Map(options.config.submitters.map((s) => [s.id, s.outboxDir]));

    if (options.privateKey.asymmetricKeyType !== "ed25519") {
      throw new WitnessRefusal(
        "KEY_NOT_ED25519",
        `the signing key is ${String(options.privateKey.asymmetricKeyType)}; ed25519 is required`
      );
    }
    this.publicKey = createPublicKey(options.privateKey);

    // Which directory each submitter's commit is read from: its own intake if
    // it has one, otherwise the shared one. The shared intake is polled even
    // when every submitter has its own, so that anything dropped there under a
    // submitter's name is reported (UNDECLARED) rather than taken for it.
    const intakes: Intake[] = [];
    const shared = this.config.submitters.filter((s) => s.intakeDir === undefined).map((s) => s.id);
    if (this.config.intakeDir !== undefined) {
      intakes.push({ dir: this.config.intakeDir, label: "intakeDir", ids: new Set(shared) });
    } else if (shared.length > 0) {
      throw new WitnessRefusal(
        "DIRECTORY_MISSING",
        `submitter(s) ${shared.map((id) => JSON.stringify(id)).join(", ")} have no intake ` +
          `directory: set intakeDir, or give each its own`
      );
    }
    for (const s of this.config.submitters) {
      if (s.intakeDir !== undefined) {
        intakes.push({
          dir: s.intakeDir,
          label: `intakeDir of submitter ${JSON.stringify(s.id)}`,
          ids: new Set([s.id]),
        });
      }
    }
    this.intakes = intakes;

    for (const intake of this.intakes) requireDirectory(intake.dir, intake.label);
    for (const s of this.config.submitters) {
      requireDirectory(s.outboxDir, `outboxDir of submitter ${JSON.stringify(s.id)}`);
    }
    requireDirectory(dirname(this.config.storePath), "the directory of storePath");

    // ── load and verify the store; refuse to run on anything that does not verify
    let contents: StoreContents;
    try {
      contents = readStore(this.config.storePath, {
        publicKey: this.publicKey,
        witnessSetId: this.config.witnessSetId,
      });
    } catch (error) {
      const detail = error instanceof StoreBroken ? error.message : String(error);
      throw new WitnessRefusal(
        "STORE_BROKEN",
        `the witness store ${this.config.storePath} does not verify: ${detail}. ` +
          `Refusing to run: a witness that cannot vouch for its own history must not ` +
          `extend it. Inspect it with "verify"; do not edit or delete it to get past this.`
      );
    }
    this.store = contents.records;
    for (const r of this.store) this.history.add(r.submitter_id, r.commit, r.index);

    // Outboxes before store creation: a refusal here must not leave a fresh,
    // empty store behind where a lost one used to be.
    const reconciled = this.reconcileOutboxes();

    let storeCreated = false;
    if (contents.exists) {
      this.appender = new StoreAppender(this.config.storePath, contents.size);
    } else {
      try {
        this.appender = StoreAppender.create(this.config.storePath);
      } catch (error) {
        throw new WitnessRefusal(
          "STORE_UNWRITABLE",
          `cannot create the witness store ${this.config.storePath}: ${String(error)}`
        );
      }
      storeCreated = true;
    }

    this.startup = {
      storeCreated,
      records: this.store.length,
      publicKeyFingerprint: publicKeyFingerprint(this.publicKey),
      ...reconciled,
    };
  }

  /**
   * Open a witness: check the directories, load and verify the store (creating
   * an empty one on first run), and bring every outbox in line with the store.
   * Throws WitnessRefusal instead of starting in a state it cannot vouch for.
   */
  static open(options: WitnessOptions): ReferenceWitness {
    return new ReferenceWitness(options);
  }

  /** The retained records, oldest first. */
  records(): readonly StoreRecord[] {
    return [...this.store];
  }

  isHalted(): boolean {
    return this.halted !== null;
  }

  // ── outbox ⇄ store ──────────────────────────────────────────────────────────

  /**
   * Every receipt file in an outbox must be the receipt of a store record for
   * that outbox's submitter, byte for byte. A receipt beyond the end of the
   * store means the store lost records (truncated, replaced, or removed); a
   * receipt that differs means the store or the outbox was altered. Either way
   * the witness refuses to start rather than write new history over it.
   * Receipts missing from an outbox are rebuilt from the store (Ed25519 is
   * deterministic, so they are the same bytes that were written before).
   */
  private reconcileOutboxes(): Pick<
    StartupReport,
    "receiptsRestored" | "foreignOutboxFiles" | "recordsForUndeclaredSubmitters"
  > {
    const receiptsRestored: { index: number; submitterId: string; file: string }[] = [];
    const foreignOutboxFiles: string[] = [];

    for (const { id, outboxDir } of this.config.submitters) {
      let names: string[];
      try {
        names = readdirSync(outboxDir).sort();
      } catch (error) {
        throw new WitnessRefusal(
          "OUTBOX_UNREADABLE",
          `cannot list the outbox of ${JSON.stringify(id)} (${outboxDir}): ${String(error)}`
        );
      }
      const present = new Set<number>();
      for (const name of names) {
        const path = join(outboxDir, name);
        if (name === STAGING_DIR) {
          // Not a real directory (a symlink planted in its place, a file):
          // reported, not followed, not touched. Receipts stay pending until
          // it is gone (see stagingDir()).
          if (!this.clearStaging(path)) foreignOutboxFiles.push(path);
          continue;
        }
        const index = receiptIndexOf(name);
        if (index === null) {
          foreignOutboxFiles.push(path);
          continue;
        }
        if (index >= this.store.length) {
          throw new WitnessRefusal(
            "OUTBOX_AHEAD_OF_STORE",
            `${path} is the receipt for store record ${index}, but the store at ` +
              `${this.config.storePath} holds only ${this.store.length} record(s). The ` +
              `store has lost records (truncated, replaced or removed) or this outbox ` +
              `belongs to another witness. Refusing to start: restore the store, or move ` +
              `the old receipts aside deliberately.`
          );
        }
        const record = this.store[index];
        const expected = receiptBytes(receiptOf(record));
        // Never by name: a FIFO planted here would block the start for good,
        // and a symlink would let the outbox's writer choose what is compared.
        const read = readEntry(path);
        if (read.kind === "absent") continue; // removed since the listing: rebuilt below
        if (read.kind !== "bytes") {
          throw new WitnessRefusal(
            "OUTBOX_UNREADABLE",
            `cannot read ${path}: ${entryProblem(read)}. It has a receipt's name, so it ` +
              `is neither taken for a receipt nor replaced. Refusing to start.`
          );
        }
        if (record.submitter_id !== id || !read.bytes.equals(Buffer.from(expected, "utf8"))) {
          throw new WitnessRefusal(
            "OUTBOX_MISMATCH",
            `${path} is not the receipt the store holds for record ${index}` +
              (record.submitter_id !== id
                ? ` (that record belongs to submitter ${JSON.stringify(record.submitter_id)})`
                : "") +
              `. The store or the outbox was altered. Refusing to start.`
          );
        }
        present.add(index);
      }
      for (const record of this.store) {
        if (record.submitter_id !== id || present.has(record.index)) continue;
        try {
          const file = this.writeReceipt(record);
          receiptsRestored.push({ index: record.index, submitterId: id, file });
        } catch (error) {
          throw new WitnessRefusal(
            "OUTBOX_UNWRITABLE",
            `cannot restore receipt ${record.index} into ${outboxDir}: ${String(error)}`
          );
        }
      }
    }

    const declared = new Set(this.outboxes.keys());
    const recordsForUndeclaredSubmitters = this.store.filter(
      (r) => !declared.has(r.submitter_id)
    ).length;
    return { receiptsRestored, foreignOutboxFiles, recordsForUndeclaredSubmitters };
  }

  /**
   * Remove staging files left by an interrupted receipt write. Only from a real
   * directory (lstat, never through a symlink), and only names this witness
   * gives its staging files. Returns false when `dir` is not a real directory.
   */
  private clearStaging(dir: string): boolean {
    try {
      if (!lstatSync(dir).isDirectory()) return false;
    } catch {
      return true; // gone since the listing
    }
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch {
      return true;
    }
    for (const name of names) {
      if (!STAGING_FILE.test(name)) continue;
      try {
        unlinkSync(join(dir, name));
      } catch {
        // a leftover staging file is untidy, not dangerous: it is never renamed
      }
    }
    return true;
  }

  /**
   * The outbox's staging directory, created (mode 0700) if absent. Accepted
   * only if lstat shows a real directory: a symlink in its place is not
   * followed, and the receipt stays pending until it is removed.
   */
  private stagingDir(outbox: string): string {
    const staging = join(outbox, STAGING_DIR);
    try {
      mkdirSync(staging, { mode: 0o700 });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    const stats = lstatSync(staging);
    if (!stats.isDirectory()) {
      throw new Error(
        `${staging} is ${describeKind(stats)}, not a directory; receipts are not ` +
          `staged through it. Remove it and the witness creates its own.`
      );
    }
    return staging;
  }

  /**
   * Write a record's receipt into its submitter's outbox: write and fsync a
   * new staging file inside the outbox's own staging directory, then rename it
   * into place. The node's client skips directories, so it never sees a partial
   * receipt. An existing regular file with the same bytes counts as written;
   * anything else at the receipt's name (other bytes, a symlink, a FIFO, a
   * directory) is never overwritten, and the receipt stays pending.
   */
  private writeReceipt(record: StoreRecord): string {
    const outbox = this.outboxes.get(record.submitter_id);
    if (outbox === undefined) {
      throw new Error(`submitter ${JSON.stringify(record.submitter_id)} has no outbox`);
    }
    const name = receiptFileName(record.index);
    const finalPath = join(outbox, name);
    const bytes = Buffer.from(receiptBytes(receiptOf(record)), "utf8");

    const existing = readEntry(finalPath);
    if (existing.kind === "bytes") {
      if (existing.bytes.equals(bytes)) return finalPath;
      throw new Error(`${finalPath} already exists with different content; it was not overwritten`);
    }
    if (existing.kind !== "absent") {
      throw new Error(
        `${finalPath} already exists and cannot be read as a receipt ` +
          `(${entryProblem(existing)}); it was not overwritten`
      );
    }

    // A new file under a name nobody can predict: nothing planted in the
    // staging directory can be opened, truncated or written through.
    const tmp = join(this.stagingDir(outbox), `${name}.${randomBytes(6).toString("hex")}.tmp`);
    const fd = openSync(tmp, CREATE_STAGING_FLAGS, 0o644);
    try {
      if (!fstatSync(fd).isFile()) throw new Error(`${tmp} is not a regular file`);
      writeAll(fd, bytes);
      fsyncSync(fd);
    } catch (error) {
      closeSync(fd);
      try {
        unlinkSync(tmp);
      } catch {
        // cleared on the next start
      }
      throw error;
    }
    closeSync(fd);
    try {
      renameSync(tmp, finalPath);
    } catch (error) {
      try {
        unlinkSync(tmp);
      } catch {
        // cleared on the next start
      }
      throw error;
    }
    fsyncDirectory(outbox);
    return finalPath;
  }

  // ── polling ─────────────────────────────────────────────────────────────────

  /**
   * Process the intake once. Returns what happened; a standing condition (an
   * undeclared file, a refused commit left in place, …) is reported on the poll
   * where it is first seen, and again only if it changes.
   *
   * Throws WitnessHalted if a record could not be appended to the store; the
   * error carries the events of this poll that happened before the failure.
   * After that, every call throws: the store may now end in a partial line, and
   * the next start will verify it and refuse if so.
   */
  pollOnce(): PollEvent[] {
    if (this.halted !== null) throw new WitnessHalted(this.halted);
    const events: PollEvent[] = [];
    try {
      return this.poll(events);
    } catch (error) {
      if (error instanceof WitnessHalted) throw new WitnessHalted(error.message, [...events]);
      throw error;
    }
  }

  private poll(events: PollEvent[]): PollEvent[] {
    this.retryPendingReceipts(events);
    for (const intake of this.intakes) this.pollIntake(intake, events);
    return events;
  }

  private pollIntake(intake: Intake, events: PollEvent[]): void {
    const dir = intake.dir;
    let names: string[];
    try {
      names = readdirSync(dir).sort();
    } catch (error) {
      this.once(dir, "", "intake", String(error), {
        kind: "INTAKE_UNREADABLE",
        intakeDir: dir,
        detail: String(error),
      }, events);
      return;
    }
    this.reported.delete(slotKey(dir, "", "intake"));
    const present = new Set(names);
    for (const [key, entry] of this.reported) {
      if (entry.dir === dir && entry.name !== "" && !present.has(entry.name)) this.reported.delete(key);
    }
    for (const [key, entry] of this.firstSighting) {
      if (entry.dir === dir && !present.has(entry.name)) this.firstSighting.delete(key);
    }

    for (const name of names) {
      // The client's temporary files: written under a dot name, then renamed
      // onto the submitter's name. Never read, never reported.
      if (name.startsWith(".")) continue;
      const path = join(dir, name);
      if (!intake.ids.has(name)) {
        let fingerprint = "gone";
        try {
          const st = lstatSync(path);
          fingerprint = `${st.size}:${st.mtimeMs}`;
        } catch {
          // listed a moment ago; report it anyway
        }
        this.once(dir, name, "status", `undeclared:${fingerprint}`, {
          kind: "UNDECLARED",
          name,
          intakeDir: dir,
        }, events);
        continue;
      }
      const read = readEntry(path);
      switch (read.kind) {
        case "absent":
          continue;
        case "not-a-file":
          this.once(dir, name, "status", `not-a-file:${read.detail}`, {
            kind: "NOT_A_FILE",
            submitterId: name,
            detail: read.detail,
          }, events);
          continue;
        case "error":
          this.once(dir, name, "status", `unreadable:${read.detail}`, {
            kind: "UNREADABLE",
            submitterId: name,
            detail: read.detail,
          }, events);
          continue;
        case "too-large":
          this.once(dir, name, "status", `too-large:${read.size}`, {
            kind: "REFUSED",
            submitterId: name,
            reason: `file is ${read.size} bytes; a HEAD_COMMIT is at most ${MAX_INTAKE_BYTES}`,
            sha256: null,
          }, events);
          continue;
        case "bytes":
          this.handleBytes(dir, name, path, read.bytes, events);
          continue;
      }
    }
  }

  private once(
    dir: string,
    name: string,
    slot: string,
    fingerprint: string,
    event: PollEvent,
    events: PollEvent[]
  ): void {
    const key = slotKey(dir, name, slot);
    if (this.reported.get(key)?.fingerprint === fingerprint) return;
    this.reported.set(key, { dir, name, fingerprint });
    events.push(event);
  }

  private retryPendingReceipts(events: PollEvent[]): void {
    for (const [index, lastDetail] of [...this.pendingReceipts]) {
      const record = this.store[index];
      try {
        const file = this.writeReceipt(record);
        this.pendingReceipts.delete(index);
        events.push({ kind: "RECEIPT_WRITTEN", submitterId: record.submitter_id, index, receiptFile: file });
      } catch (error) {
        const detail = String(error);
        if (detail !== lastDetail) {
          this.pendingReceipts.set(index, detail);
          events.push({ kind: "RECEIPT_PENDING", submitterId: record.submitter_id, index, detail });
        }
      }
    }
  }

  private handleBytes(
    dir: string,
    name: string,
    path: string,
    bytes: Buffer,
    events: PollEvent[]
  ): void {
    const digest = sha256(bytes);
    const sightingKey = `${dir}\0${name}`;

    let parsed: unknown;
    try {
      parsed = JSON.parse(bytes.toString("utf8"));
    } catch {
      // A writer that writes in place (the ILAS client renames into place, but
      // another writer may not) can be caught half-way. Report it malformed only
      // when the same bytes are still there next poll.
      if (this.firstSighting.get(sightingKey)?.digest === digest) {
        this.once(dir, name, "status", `malformed:${digest}`, {
          kind: "MALFORMED",
          submitterId: name,
          reason: "not valid JSON, unchanged since the previous poll",
          sha256: digest,
          byteLength: bytes.length,
        }, events);
      } else {
        this.firstSighting.set(sightingKey, { dir, name, digest });
        this.reported.delete(slotKey(dir, name, "status"));
        events.push({ kind: "DEFERRED", submitterId: name, sha256: digest });
      }
      return;
    }
    this.firstSighting.delete(sightingKey);

    const check = checkHeadCommit(parsed, this.config.witnessSetId);
    if (!check.ok) {
      this.once(dir, name, "status", `refused:${digest}`, {
        kind: "REFUSED",
        submitterId: name,
        reason: check.reason,
        sha256: digest,
      }, events);
      return;
    }
    const commit = check.commit;

    // A head already retained for this submitter is a duplicate, whatever came
    // in between: a return to an earlier, already-retained head (a rollback to
    // it) writes no second record. The rollback still shows, because the node
    // holds the receipt for the higher head its chain no longer reproduces.
    const prior = this.history.retainedAt(name, commit);
    if (prior !== null) {
      this.once(dir, name, "status", `duplicate:${digest}`, {
        kind: "DUPLICATE",
        submitterId: name,
        seq_no: commit.seq_no,
        head_hash: commit.head_hash,
        priorIndex: prior,
      }, events);
      this.consume(dir, name, path, bytes, events);
      return;
    }

    const witness_ts = this.clock();
    if (!Number.isSafeInteger(witness_ts) || witness_ts < 0) {
      this.halted = `the witness clock returned ${String(witness_ts)}, not a non-negative integer of ms`;
      throw new WitnessHalted(this.halted);
    }
    const receipt = signReceipt(
      { seq_no: commit.seq_no, head_hash: commit.head_hash, witness_ts },
      this.privateKey
    );
    const unhashed: UnhashedRecord = {
      index: this.store.length,
      prev_hash: this.store.length === 0 ? GENESIS_HASH : this.store[this.store.length - 1].hash,
      submitter_id: name,
      commit,
      witness_ts,
      witness_sig: receipt.witness_sig,
      conflicts: this.history.conflictsFor(name, commit),
    };
    const record: StoreRecord = signRecord({ ...unhashed, hash: recordHash(unhashed) }, this.privateKey);

    // Retain first. If this fails nothing is emitted, the intake file stays,
    // and the witness stops.
    try {
      this.appender.append(record);
    } catch (error) {
      this.halted =
        `could not append to the witness store: ${String(error)}. The witness has ` +
        `stopped. On the next start the store is verified and, if the append left a ` +
        `partial line, the witness refuses to run until an operator has looked at it.`;
      throw new WitnessHalted(this.halted);
    }
    this.store.push(record);
    this.history.add(name, commit, record.index);
    this.reported.delete(slotKey(dir, name, "status"));

    // Then emit. A failed receipt write is retried every poll; the record is
    // already retained, so the intake file is consumed either way.
    let receiptFile: string | null = null;
    try {
      receiptFile = this.writeReceipt(record);
    } catch (error) {
      this.pendingReceipts.set(record.index, String(error));
      events.push({
        kind: "RECEIPT_PENDING",
        submitterId: name,
        index: record.index,
        detail: String(error),
      });
    }
    events.push({
      kind: "RETAINED",
      submitterId: name,
      index: record.index,
      seq_no: commit.seq_no,
      head_hash: commit.head_hash,
      witness_ts,
      conflicts: record.conflicts,
      receiptFile,
    });
    this.consume(dir, name, path, bytes, events);
  }

  /**
   * Remove a processed intake file, but only if it still holds the bytes that
   * were processed: a newer commit written over it in the meantime is left for
   * the next poll. The remaining race is the instant between this re-read and
   * the unlink; a commit written exactly then is removed unprocessed.
   */
  private consume(dir: string, name: string, path: string, bytes: Buffer, events: PollEvent[]): void {
    const now = readEntry(path);
    if (now.kind === "absent") return;
    if (now.kind !== "bytes" || !now.bytes.equals(bytes)) {
      this.once(dir, name, "left", sha256(bytes), {
        kind: "INTAKE_LEFT",
        submitterId: name,
        reason: "the file changed after it was read; the newer content is read next poll",
      }, events);
      return;
    }
    try {
      unlinkSync(path);
    } catch (error) {
      this.once(dir, name, "left", `unlink:${String(error)}`, {
        kind: "INTAKE_LEFT",
        submitterId: name,
        reason: `could not remove it: ${String(error)}`,
      }, events);
    }
  }
}
