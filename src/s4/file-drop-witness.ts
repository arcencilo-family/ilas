// ──────────────────────────────────────────────────────────────────────────────
// ILAS — S-4 FileDropWitness: a TRANSPORT CLIENT for a separate witness process
//
// THE RULE IN witness.ts STANDS AND THIS FILE DOES NOT BREACH IT: a witness the
// node can reach into is not a witness. Read the distinction before reading the
// code:
//
//   THE DIRECTORIES ARE THE WIRE, NOT THE STORE. The retainer is a SEPARATE
//   WITNESS PROCESS with its own hash-chained append-only store, its own signing
//   key, and its own clock. This class hands commits to that process's intake and
//   reads back what that process signed. It is a transport client. It is not a
//   witness and must never name itself one. It retains nothing: delete the outbox
//   and this class has no evidence left, because it never held any.
//
//   WHETHER THAT PROCESS IS INDEPENDENT OF THIS NODE IS A DEPLOYMENT FACT THIS
//   CODE CANNOT VERIFY AND DOES NOT ASSERT. Same user, same box ⇒ the deployment
//   is self-witnessed (docs/S4-WIRE-SPEC.md §2) and adds little assurance, and
//   this class says so rather than hiding it. A separate OS user, an intake the
//   node may write but not read, and an outbox the node may read but not write
//   is where independence starts — bought by the kernel, not by this file.
//   Wiring this class does not finish the S-4 anchor.
//
// WHY THE SIGNATURE CHECK LIVES HERE. continuity.ts trusts every receipt it is
// handed; there is no witness-signature check anywhere else in S-4. That is
// harmless with NullWitness (always empty) and becomes the entire attack surface
// the moment receipts come off a directory: an adversary who can write the
// outbox puts forgeries there whose head_hash matches the REWRITTEN chain, and
// to a reader that does not check signatures MISMATCH becomes
// VERIFIED_HISTORICAL. Retained-receipt evidence is exactly the thing the S-4
// anchor exists to make unforgeable, and an unverified reader hands that
// property straight back. So: every receipt is checked against the witness's
// public key before it is returned, and one that fails is never returned — it
// does not reach the predicate to pass it. While the key is usable, every outbox
// entry that fails (unreadable; not a regular file when opened — a symbolic
// link, a FIFO, any other special file; larger than MAX_RECEIPT_BYTES;
// malformed JSON; wrong shape; bad signature; non-canonical signature
// encoding) is also counted and reported through
// retrievalIssues(), and the predicate then reports REJECTED_RECEIPTS, a hard
// finding: a forged receipt beside genuine ones does not leave the verdict at
// VERIFIED_HISTORICAL. No key, or no readable outbox, means no receipts at all,
// and the predicate then reports CANNOT_VERIFY_CONTINUITY. Saying nothing about
// continuity is correct; saying the wrong thing is not.
//
// WHAT THE CHECK DOES NOT COVER. It stops a forgery from counting. It does not
// stop a writer of the outbox from DELETING genuine receipts. If the receipts
// for the rewritten part of the chain are simply gone, the ones that remain
// still reproduce and the verdict can read VERIFIED_HISTORICAL; this client
// cannot see a receipt that is not there. The witness's own start-up check of
// its outbox against its store — which restores a missing receipt and refuses
// to start on one that differs — is what brings such a deletion back into view.
//
// DIRECTION IS THE WHOLE POINT. This class writes into intakeDir and never reads
// it back — not even a stat, so that a write-only intake is enough for it. It
// reads outboxDir and never writes into it. The permission boundary is what buys
// the independence this code cannot assert, and the code must not need both ways.
//
// THE INTAKE IS SHARED GROUND. Other accounts can write it (the witness, which
// deletes what it consumes; other nodes of the same witness set), so whatever
// sits at <intakeDir>/<submitterId> between two submits may have been planted.
// A commit is therefore never written through that name: it goes into a fresh
// dot-named temporary file created exclusively, is synced, and is then renamed
// onto <submitterId>. A rename replaces a symlink or a FIFO standing at that name
// instead of following or opening it.
//
// THE OUTBOX IS SHARED GROUND TOO: its writer is the adversary the signature
// check defends against, and it can rename anything onto a receipt's name at
// any moment. So no outbox entry is ever checked by name and then opened by
// name. Each one is opened once, O_RDONLY|O_NOFOLLOW|O_NONBLOCK — a symbolic
// link is refused rather than followed, and a FIFO cannot block the open — and
// only that descriptor is judged (fstat: a regular file of at most
// MAX_RECEIPT_BYTES) and read. Every caller up to ILASKillStack.status() is
// synchronous; a read that blocked would stop the node. Only an entry the
// directory listing itself reports as a directory is skipped unopened (the
// witness keeps its staging directory, mode 0700, inside the outbox); that
// decides only what is NOT read, never what is.
//
// THE KEY FILE IS READ THE SAME WAY, on every fetch: opened once,
// O_RDONLY|O_NONBLOCK, and judged on the descriptor (a regular file of at most
// 64 KiB), so a FIFO or a device at publicKeyPath is an unreadable key — no
// receipts, CANNOT_VERIFY_CONTINUITY — and never a stopped status(). A symbolic
// link there IS followed: the operator chose the path, and a link is a fair way
// to rotate the key. publicKeyFingerprint() reports the key that would be used,
// so the operator can compare it with what the witness's keygen printed.
// ──────────────────────────────────────────────────────────────────────────────

import { createPrivateKey, createPublicKey, randomBytes, verify as verifySignature } from "crypto";
import type { KeyObject } from "crypto";
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readSync,
  readdirSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { join } from "path";
import { publicKeyFingerprint as fingerprintOfPem } from "../l0/fingerprint";
import type { HeadCommit, WitnessReceipt } from "./types";
import type { Witness } from "./witness";

// ── Self-description (exported: an operator inspecting the node is owed these) ─

export const FILE_DROP_WITNESS_IS_A_CLIENT_NOT_A_WITNESS =
  "The directories are the WIRE, not the STORE. The retainer is a separate witness " +
  "process with its own hash-chained append-only store, its own signing key, and its " +
  "own clock. This class is a transport client: it hands commits to that process's " +
  "intake and reads back what that process signed. It is not a witness, retains " +
  "nothing, and must never name itself one. Whether that process is INDEPENDENT of " +
  "this node is a deployment fact this code cannot verify and does not assert. Same " +
  "user, same box means a self-witnessed deployment with little assurance. A separate " +
  "OS user, an intake the node may write but not read, and an outbox the node may " +
  "read but not write is where independence starts — bought by the kernel, not by " +
  "this file.";

export const SUBMISSION_IS_NOT_RETENTION =
  "This client can prove it wrote a commit to a directory. It cannot prove any witness " +
  "read it, retained it, or still holds it. The evidential object is the witness's own " +
  "store, which this code cannot see.";

export const UNVERIFIED_RECEIPTS_ARE_DROPPED =
  "Only signature-verified receipts reach the continuity predicate. With no key, or an " +
  "unreadable outbox, this client returns nothing, and continuity reports that it cannot " +
  "be verified. It never returns a receipt it could not check. A receipt it was able to " +
  "check and had to refuse is not hidden: it is reported, and continuity then reports " +
  "rejected receipts as a finding. An outbox entry that is a symbolic link, a special " +
  "file, or larger than any receipt is refused unread and reported the same way. It " +
  "cannot report a receipt that was deleted.";

export const INDEPENDENCE_IS_A_DEPLOYMENT_FACT =
  "Whether the witness process is INDEPENDENT of this node is a deployment fact this " +
  "code cannot verify and does not assert. Same user, same box means the deployment is " +
  "self-witnessed, with little assurance, and this class says so. A separate OS user, " +
  "with an intake the node may write but not read and an outbox the node may read " +
  "but not write, is where independence starts — bought by the kernel, not by this " +
  "file. Wiring this client does not finish the S-4 anchor and nothing here should be " +
  "read as saying it does.";

// ── Wire format ──────────────────────────────────────────────────────────────

/**
 * The receipt signature preimage. Field order is NOT a guess: it is the preimage
 * fixed by docs/S4-WIRE-SPEC.md §4, which the reference witness in
 * packages/witness signs:
 *   [String(seq_no), head_hash, String(witness_ts)].join(" ")
 * with Ed25519, base64-encoding the signature. A test pins the exact string, and
 * docs/s4-test-vectors.json carries a signed example.
 * If the witness ever changes this order, every receipt stops verifying and this
 * client returns nothing — wrong-way-safe, never silently permissive.
 */
export function canonicalReceiptPreimage(
  receipt: Omit<WitnessReceipt, "witness_sig">
): string {
  return [
    String(receipt.seq_no),
    receipt.head_hash,
    String(receipt.witness_ts),
  ].join(" ");
}

const RECEIPT_KEYS = ["seq_no", "head_hash", "witness_ts", "witness_sig"] as const;

/**
 * The signature's bytes, or null unless `text` is the canonical (padded,
 * standard-alphabet) base64 of exactly 64 bytes — the only spelling the
 * reference witness writes and the only one its own verifier accepts. Node's
 * decoder is lenient (it skips junk, missing padding and URL-safe letters), so
 * without this many strings would decode to one signature and the two §4
 * verifiers would disagree about which receipts are valid.
 */
function decodeSignature(text: string): Buffer | null {
  const bytes = Buffer.from(text, "base64");
  if (bytes.length !== 64 || bytes.toString("base64") !== text) return null;
  return bytes;
}

/**
 * True when `bytes` hold PRIVATE key material. createPublicKey() would quietly
 * derive the public half from it, so a misplaced signing key would be accepted
 * as if it were the public key; the caller refuses instead and says why.
 */
function holdsPrivateKey(bytes: Buffer): boolean {
  if (bytes.toString("latin1").includes("PRIVATE KEY")) return true;
  try {
    createPrivateKey(bytes);
    return true;
  } catch {
    return false;
  }
}

/**
 * Exact-shape check. Extra fields are rejected rather than ignored: the signature
 * covers three fields only, so anything else on the object is unsigned attacker
 * copy and must not ride along into the predicate.
 */
function asReceipt(value: unknown): WitnessReceipt | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const own = Object.keys(value as Record<string, unknown>);
  if (own.length !== RECEIPT_KEYS.length) return null;
  for (const key of RECEIPT_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) return null;
  }
  const candidate = value as Record<string, unknown>;
  if (
    typeof candidate.seq_no !== "number" ||
    !Number.isSafeInteger(candidate.seq_no) ||
    typeof candidate.head_hash !== "string" ||
    typeof candidate.witness_ts !== "number" ||
    !Number.isFinite(candidate.witness_ts) ||
    typeof candidate.witness_sig !== "string"
  ) {
    return null;
  }
  return value as unknown as WitnessReceipt;
}

// ── Submitter ids ────────────────────────────────────────────────────────────

/**
 * The longest submitter id, in UTF-8 bytes, that this client can write. The id
 * is a file name twice over: the drop file <submitterId>, and the temporary
 * file ".<submitterId>.<12 hex>.tmp" it is first written to. A file name holds
 * at most 255 bytes on the common Linux and macOS file systems (NAME_MAX), and
 * the temporary name adds "." + "." + 12 hex + ".tmp" = 1 + 1 + 12 + 4 = 18
 * bytes, so 255 − 18 = 237.
 */
export const MAX_SUBMITTER_ID_BYTES = 255 - ".".length - ".".length - 12 - ".tmp".length;

// Unicode category Cc: U+0000–U+001F, U+007F (DEL) and U+0080–U+009F.
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f-\u009f]/;

/**
 * Why `id` cannot be this client's submitter id, or null when it can. The id
 * must be writable as a file name exactly as spelled, and must not be a name
 * the witness ignores:
 *   - a non-empty string, not "." or "..", with no "/" or "\" in it;
 *   - no control character (U+0000–U+001F, U+007F–U+009F; NUL is one);
 *   - well-formed UTF-16 (a lone surrogate is written to disk as U+FFFD, which
 *     is a different name from the one the witness was configured with);
 *   - not starting with "." (dot names in an intake are temporary files);
 *   - at most MAX_SUBMITTER_ID_BYTES (237) bytes in UTF-8.
 */
export function submitterIdProblem(id: unknown): string | null {
  if (typeof id !== "string" || id.length === 0) {
    return "must be a bare filename (a non-empty string)";
  }
  if (id === "." || id === ".." || id.includes("/") || id.includes("\\")) {
    return 'must be a bare filename (not "." or "..", no "/" or "\\")';
  }
  if (CONTROL_CHARACTER.test(id)) {
    return "must be a bare filename (no control character: U+0000–U+001F, U+007F–U+009F)";
  }
  if (Buffer.from(id, "utf8").toString("utf8") !== id) {
    return (
      "must be well-formed Unicode (a lone surrogate would be written to disk as " +
      "U+FFFD, a different name)"
    );
  }
  if (id.startsWith(".")) {
    return 'must not start with "." (the witness ignores dot names in the intake)';
  }
  const bytes = Buffer.byteLength(id, "utf8");
  if (bytes > MAX_SUBMITTER_ID_BYTES) {
    return (
      `must be at most ${MAX_SUBMITTER_ID_BYTES} bytes in UTF-8, is ${bytes} (the ` +
      `temporary file ".<submitterId>.<12 hex>.tmp" must fit a 255-byte file name)`
    );
  }
  return null;
}

// ── Reading one outbox entry ─────────────────────────────────────────────────

/** A receipt is about 200 bytes; an outbox file larger than this is refused unread. */
export const MAX_RECEIPT_BYTES = 4096;

const OPEN_OUTBOX_ENTRY_FLAGS =
  constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);

/** "wx" plus O_NOFOLLOW: the intake's temporary file is always a new file of this client's. */
const CREATE_TEMP_FLAGS =
  constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0);

/**
 * The text of one outbox entry, or why it was not read. One open, by name,
 * without following a symbolic link and without blocking on a FIFO; everything
 * after that is decided on the descriptor, so a writer of the outbox who
 * renames something else onto the name meanwhile changes nothing. Reads at most
 * one byte past MAX_RECEIPT_BYTES, whatever the file claims its size is.
 */
function readOutboxEntry(path: string): { text: string } | { problem: string } {
  let fd: number;
  try {
    fd = openSync(path, OPEN_OUTBOX_ENTRY_FLAGS);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ELOOP") {
      return { problem: "a symbolic link; not followed, not read" };
    }
    return { problem: `unreadable: ${String(error)}` };
  }
  try {
    const stats = fstatSync(fd);
    if (!stats.isFile()) {
      const kind = stats.isDirectory() ? "a directory" : stats.isFIFO() ? "a FIFO" : "a special file";
      return { problem: `not a regular file when opened (${kind}); not read` };
    }
    if (stats.size > MAX_RECEIPT_BYTES) {
      return {
        problem: `file is ${stats.size} bytes; a receipt is at most ${MAX_RECEIPT_BYTES}; not read`,
      };
    }
    const buffer = Buffer.alloc(MAX_RECEIPT_BYTES + 1);
    let length = 0;
    for (;;) {
      const n = readSync(fd, buffer, length, buffer.length - length, null);
      if (n === 0) break;
      length += n;
      if (length > MAX_RECEIPT_BYTES) {
        return { problem: `file grew past ${MAX_RECEIPT_BYTES} bytes while it was read` };
      }
    }
    return { text: buffer.toString("utf8", 0, length) };
  } catch (error) {
    return { problem: `unreadable: ${String(error)}` };
  } finally {
    closeSync(fd);
  }
}

// ── Reading the witness's public key ─────────────────────────────────────────

/** A PEM public key is a few hundred bytes; a key file larger than this is not read. */
const MAX_KEY_FILE_BYTES = 64 * 1024;

/**
 * Open without blocking: a FIFO at publicKeyPath must not stop status().
 * A symbolic link IS followed: the operator chooses this path, and pointing a
 * link at a new key file is a legitimate way to rotate the key.
 */
const OPEN_KEY_FILE_FLAGS = constants.O_RDONLY | (constants.O_NONBLOCK ?? 0);

/**
 * The bytes of the key file, judged on its descriptor: anything but a regular
 * file of at most MAX_KEY_FILE_BYTES (a FIFO, a device such as /dev/zero, a
 * directory) throws unread. Reads at most one byte past the cap, whatever the
 * file claims its size is.
 */
function readKeyFile(path: string): Buffer {
  const fd = openSync(path, OPEN_KEY_FILE_FLAGS);
  try {
    const stats = fstatSync(fd);
    if (!stats.isFile()) throw new Error(`${path} is not a regular file; not read`);
    if (stats.size > MAX_KEY_FILE_BYTES) {
      throw new Error(`${path} is ${stats.size} bytes, more than ${MAX_KEY_FILE_BYTES}; not read`);
    }
    const buffer = Buffer.alloc(MAX_KEY_FILE_BYTES + 1);
    let length = 0;
    for (;;) {
      const n = readSync(fd, buffer, length, buffer.length - length, null);
      if (n === 0) break;
      length += n;
      if (length > MAX_KEY_FILE_BYTES) {
        throw new Error(`${path} grew past ${MAX_KEY_FILE_BYTES} bytes while it was read`);
      }
    }
    return buffer.subarray(0, length);
  } finally {
    closeSync(fd);
  }
}

// ── Config and diagnostics ───────────────────────────────────────────────────

export interface FileDropWitnessConfig {
  /** The witness set id this instance speaks to. Stamped into every HEAD_COMMIT. */
  readonly id: string;
  /** Directory the commits are dropped into. Written, never read back. */
  readonly intakeDir: string;
  /** Directory the witness's signed receipts land in. Read, never written. */
  readonly outboxDir: string;
  /**
   * The submitter id this node presents to the witness, which is ALSO the drop
   * filename — see the trade-off note on submit(). Must be a bare filename and
   * must not start with "." (dot names in the intake are temporary files, which
   * the witness ignores); the whole rule is submitterIdProblem().
   */
  readonly submitterId: string;
  /**
   * Path of the witness's Ed25519 PUBLIC key, as a PEM file. Absent ⇒ nothing
   * can be verified ⇒ retrieveReceipts() returns empty ⇒ CANNOT_VERIFY_CONTINUITY.
   * A file holding a PRIVATE key is refused the same way, with a reason saying
   * so: the node is to be given the public key only. There is no default and
   * there must never be one: a default key is a key nobody chose.
   */
  readonly publicKeyPath?: string;
}

/** What the last retrieveReceipts() actually did. A drop is a finding for the operator. */
export interface FileDropFetchDiagnostics {
  readonly found: number;
  readonly verified: number;
  readonly dropped: number;
  /**
   * Drops that happened while a usable key was available — files this client
   * could have checked and refused. Reported through retrievalIssues(); the
   * continuity predicate treats any as REJECTED_RECEIPTS. 0 without a key.
   */
  readonly rejected: number;
  readonly dropReasons: readonly string[];
  readonly keyAvailable: boolean;
}

/** What submit() has managed so far. A failed write is a hole in the evidence. */
export interface FileDropSubmitDiagnostics {
  readonly attempted: number;
  readonly written: number;
  readonly failed: number;
  readonly failureReasons: readonly string[];
}

/** Reason lists are capped so a long-running node cannot grow them without bound. */
const MAX_REASONS = 32;

function capped(reasons: string[]): void {
  while (reasons.length > MAX_REASONS) reasons.shift();
}

export class FileDropWitness implements Witness {
  readonly id: string;

  private readonly config: FileDropWitnessConfig;

  private lastFetch: FileDropFetchDiagnostics = {
    found: 0,
    verified: 0,
    dropped: 0,
    rejected: 0,
    dropReasons: [],
    keyAvailable: false,
  };

  private submitAttempted = 0;
  private submitWritten = 0;
  private submitFailed = 0;
  private readonly submitFailureReasons: string[] = [];

  constructor(config: FileDropWitnessConfig) {
    // A submitter id that is a path would let a config typo write outside the
    // intake; one that no file name can hold (a NUL, a lone surrogate, too
    // long for the temporary name) would fail every submit; a dot name is one
    // the witness ignores. Refuse all of them at construction: this is a wiring
    // error, not a transport one, and the emitter's path must never be where it
    // surfaces.
    const problem = submitterIdProblem(config.submitterId);
    if (problem !== null) {
      throw new Error(`submitterId ${problem}, got ${JSON.stringify(config.submitterId)}`);
    }
    this.config = config;
    this.id = config.id;
  }

  /**
   * Drop one commit into the intake. Fire-and-file: SUBMISSION IS NOT RETENTION.
   * A written file proves this process wrote a file, and nothing else — not that
   * any witness read it, retained it, or still holds it.
   *
   * DESIGN TRADE-OFF: the drop filename is the submitter id, not a name sortable
   * by seq_no. A seq_no-sortable name would let a witness that polls its intake in
   * lexical order consume the drops in order. But a witness may also use THE
   * WHOLE FILENAME AS THE PRESENTED SUBMITTER ID and match it exactly against the
   * submitters it was configured with — the reference witness in packages/witness
   * does exactly that. A filename that varies with seq_no can then never be a
   * declared submitter: no drop would be accepted, no receipt would ever be
   * signed, and the alarm this client exists to arm would never arm. The two
   * properties are not both obtainable, so the filename is the injected
   * submitterId exactly. The cost is named and real: a commit dropped before the
   * poller consumed the previous one overwrites it, and this client cannot see
   * that happen, because seeing it would mean reading the intake back. The newer commit is the one kept, because a
   * receipt at a later seq constrains a longer prefix of the chain. Losing an
   * intermediate commit degrades the evidence; the emitter's cadence supplies more.
   *
   * HOW THE FILE IS WRITTEN. Never through <submitterId> itself: whatever stands
   * at that name may have been planted by another account that can write the
   * intake. The commit goes into ".<submitterId>.<12 random hex>.tmp", created
   * with exclusive create and O_NOFOLLOW (an existing file or symlink at that
   * name fails the write), checked on its descriptor to be a regular file,
   * written and synced through that descriptor, and renamed onto <submitterId>
   * (the id is bounded so that the temporary name fits a file name: see
   * MAX_SUBMITTER_ID_BYTES). The rename replaces a
   * symlink or a FIFO at the target rather than following or opening it, so a
   * planted link cannot redirect the write and a planted FIFO cannot block the
   * node; the witness also never sees a half-written commit.
   *
   * A write failure is recorded and swallowed. Taking down the node's emitter over
   * a transport hiccup buys nothing and costs the whole chain.
   */
  submit(commit: HeadCommit): void {
    this.submitAttempted++;
    const target = join(this.config.intakeDir, this.config.submitterId);
    const temp = join(
      this.config.intakeDir,
      `.${this.config.submitterId}.${randomBytes(6).toString("hex")}.tmp`
    );
    let tempCreated = false;
    try {
      mkdirSync(this.config.intakeDir, { recursive: true });
      const fd = openSync(temp, CREATE_TEMP_FLAGS); // mode 0o666 less umask, as "wx" was
      tempCreated = true;
      try {
        if (!fstatSync(fd).isFile()) {
          throw new Error(`${temp} is not a regular file when opened`);
        }
        // Exactly the four HEAD_COMMIT fields (docs/S4-WIRE-SPEC.md §3), no
        // envelope: a witness that checks the shape exactly, as the reference
        // witness in packages/witness does, refuses an object with extra keys.
        writeFileSync(fd, JSON.stringify(commit) + "\n", "utf8");
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      renameSync(temp, target);
      tempCreated = false;
      this.submitWritten++;
    } catch (error) {
      if (tempCreated) {
        try {
          unlinkSync(temp);
        } catch {
          // Best effort: a stray dot file is ignored by the witness.
        }
      }
      this.submitFailed++;
      this.submitFailureReasons.push(`seq ${commit.seq_no}: ${String(error)}`);
      capped(this.submitFailureReasons);
    }
  }

  /**
   * Read the outbox and return ONLY receipts whose signature verifies against the
   * witness's public key. Everything else is dropped with a reason. Nothing here
   * throws: an unreadable outbox, a malformed file, a missing key and a forgery all
   * end with fewer receipts, or none. They do not end alike, though: with no key
   * (or no readable outbox) nothing could be checked, which is
   * CANNOT_VERIFY_CONTINUITY; a file refused while the key was usable is a
   * REJECTION, reported through retrievalIssues() as a finding.
   */
  retrieveReceipts(): WitnessReceipt[] {
    const dropReasons: string[] = [];
    const key = this.loadPublicKey();
    if (key.key === null && key.detail !== null) dropReasons.push(key.detail);

    let entries: { readonly name: string; readonly isDirectory: boolean }[];
    try {
      entries = readdirSync(this.config.outboxDir, { withFileTypes: true })
        .map((d) => ({ name: d.name, isDirectory: d.isDirectory() }))
        .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    } catch (error) {
      dropReasons.push(`outbox unreadable: ${String(error)}`);
      capped(dropReasons);
      this.lastFetch = {
        found: 0,
        verified: 0,
        dropped: 0,
        rejected: 0,
        dropReasons,
        keyAvailable: key.key !== null,
      };
      return [];
    }

    const verified: WitnessReceipt[] = [];
    let found = 0;
    let dropped = 0;

    for (const { name, isDirectory } of entries) {
      // Skipped unopened: never a receipt, and the witness's 0700 staging
      // directory cannot be opened from another account at all. This listing
      // only ever decides what is NOT read; what IS read is decided on the
      // descriptor in readOutboxEntry().
      if (isDirectory) continue;
      found++;

      const read = readOutboxEntry(join(this.config.outboxDir, name));
      if ("problem" in read) {
        dropped++;
        dropReasons.push(`${name}: ${read.problem}`);
        continue;
      }
      const raw = read.text;

      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        dropped++;
        dropReasons.push(`${name}: malformed JSON`);
        continue;
      }

      const receipt = asReceipt(parsed);
      if (receipt === null) {
        dropped++;
        dropReasons.push(`${name}: not a WITNESS_RECEIPT shape`);
        continue;
      }

      if (key.key === null) {
        dropped++;
        dropReasons.push(
          `${name} (seq ${receipt.seq_no}): no witness public key available; ` +
            `this receipt cannot be checked and is not returned`
        );
        continue;
      }

      const signature = decodeSignature(receipt.witness_sig);
      if (signature === null) {
        dropped++;
        dropReasons.push(
          `${name} (seq ${receipt.seq_no}): witness_sig is not the canonical base64 ` +
            `of a 64-byte Ed25519 signature`
        );
        continue;
      }

      let ok = false;
      let detail = "signature does not verify against the witness public key";
      try {
        ok = verifySignature(
          null,
          Buffer.from(canonicalReceiptPreimage(receipt), "utf8"),
          key.key,
          signature
        );
      } catch (error) {
        detail = `signature could not be checked: ${String(error)}`;
      }
      if (!ok) {
        dropped++;
        dropReasons.push(`${name} (seq ${receipt.seq_no}): ${detail}`);
        continue;
      }

      verified.push(receipt);
    }

    capped(dropReasons);
    this.lastFetch = {
      found,
      verified: verified.length,
      dropped,
      // With a usable key every drop above is a file that could be checked and
      // was refused. Without one, nothing was checkable, so nothing was rejected.
      rejected: key.key !== null ? dropped : 0,
      dropReasons,
      keyAvailable: key.key !== null,
    };
    return verified;
  }

  /**
   * What the last fetch found, verified and dropped. A dropped receipt is a
   * finding an operator inspecting the node must be able to see, and silence
   * about it would be the same failure this class exists to prevent. The part
   * the continuity predicate acts on is retrievalIssues().
   */
  getLastFetchDiagnostics(): FileDropFetchDiagnostics {
    return this.lastFetch;
  }

  /**
   * Witness.retrievalIssues: the receipts the last retrieveReceipts() refused
   * while it had a usable key, and why. Any such refusal makes the continuity
   * predicate report REJECTED_RECEIPTS (unless a MISMATCH outranks it).
   */
  retrievalIssues(): { rejected: number; reasons: readonly string[] } {
    const { rejected, dropReasons } = this.lastFetch;
    return { rejected, reasons: rejected > 0 ? [...dropReasons] : [] };
  }

  /** What submit() has managed. A failed write is a commit the witness never saw. */
  getSubmitDiagnostics(): FileDropSubmitDiagnostics {
    return {
      attempted: this.submitAttempted,
      written: this.submitWritten,
      failed: this.submitFailed,
      failureReasons: [...this.submitFailureReasons],
    };
  }

  /**
   * Witness.publicKeyFingerprint: the fingerprint of the key a fetch would use
   * now ("sha256:" + hex SHA-256 of its SPKI DER, the format of
   * src/l0/fingerprint.ts), read from publicKeyPath with the same checks as a
   * fetch. null when there is no usable key: no path, an unreadable or
   * non-regular file, a private key, or a key that is not Ed25519. It names the
   * key this client trusts; it cannot say who holds the private half.
   */
  publicKeyFingerprint(): string | null {
    const { key } = this.loadPublicKey();
    if (key === null) return null;
    return fingerprintOfPem(key.export({ type: "spki", format: "pem" }) as string);
  }

  /**
   * Re-read on every fetch rather than caching at construction: a key rotated or
   * placed after startup is then seen, and a key removed stops being trusted.
   * Read through readKeyFile(), which never blocks: a FIFO or a device at the
   * path is an unreadable key, not a stopped node.
   */
  private loadPublicKey(): { key: KeyObject | null; detail: string | null } {
    const path = this.config.publicKeyPath;
    if (path === undefined) {
      return {
        key: null,
        detail:
          "no publicKeyPath was injected; no receipt can be checked, so none is returned",
      };
    }
    let bytes: Buffer;
    try {
      bytes = readKeyFile(path);
    } catch (error) {
      return { key: null, detail: `cannot read witness public key: ${String(error)}` };
    }
    if (holdsPrivateKey(bytes)) {
      return {
        key: null,
        detail:
          `witness publicKeyPath ${path} holds a PRIVATE key; it is not used. Give this ` +
          `node only the witness's PUBLIC key file — the private key belongs to the ` +
          `witness alone`,
      };
    }
    try {
      const key = createPublicKey(bytes);
      if (key.asymmetricKeyType !== "ed25519") {
        return {
          key: null,
          detail: `witness public key is ${String(key.asymmetricKeyType)}, not ed25519`,
        };
      }
      return { key, detail: null };
    } catch (error) {
      return { key: null, detail: `cannot read witness public key: ${String(error)}` };
    }
  }
}
