// ──────────────────────────────────────────────────────────────────────────────
// Reference clerk — the core: takes a request, numbers it, timestamps it,
// signs a receipt, appends the receipt to the book, and only then returns it.
//
// One core owns one book (a lock file enforces it) and one signing key. The
// core is synchronous end to end: sequence allocation, signing, write and
// fsync happen in one call, so two requests can never interleave.
//
// separation / intake are fixed when the core is opened:
//   SEPARATE_PROCESS          + SOCKET      — the clerkd daemon
//   IN_PROCESS_NO_SEPARATION  + LOCAL_CALL  — the in-process client
// They state how this clerk was set up and how requests reach it. The daemon
// cannot see which process is on the other end of its socket, so
// SEPARATE_PROCESS is the daemon's configuration, not a check of the peer.
// ──────────────────────────────────────────────────────────────────────────────

import { randomBytes } from "crypto";
import type { KeyObject } from "crypto";
import { userInfo } from "os";
import { canonicalise, sha256Hex } from "../../../src/l0/canonical";
import { Book } from "./book";
import type { BookOpenState } from "./book";
import { publicKeyPemOf } from "./keys";
import { RECEIPT_FORM, signReceipt } from "./receipt";
import type { ClerkReceipt, Intake, Separation, UnsignedClerkReceipt } from "./receipt";
import { ClerkRequestError, validateRequest } from "./wire";

export const IN_PROCESS_WARNING =
  "in-process clerk: it runs inside the submitter's own process and holds its " +
  "signing key in the same memory. This buys no separation: the submitter can " +
  "sign anything this clerk can.";

export interface ClerkCoreOptions {
  /** Name this clerk signs into every receipt. */
  clerkId: string;
  privateKey: KeyObject;
  /** The append-only JSONL book. Created (mode 0600) if absent. */
  bookPath: string;
  separation: Separation;
  /**
   * If set, only these submitter_id values are accepted. This compares names;
   * it does not authenticate the submitter.
   */
  allowedSubmitters?: readonly string[] | null;
  /** Keep the canonical payload in the receipt (and so in the book). Default false. */
  retainPayload?: boolean;
}

/** The core refuses all work after a book write failed. */
export class ClerkStoppedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ClerkStoppedError";
  }
}

function osPrincipal(): string {
  try {
    return userInfo().username;
  } catch {
    // No passwd entry (some containers). Report the numeric id instead.
    return typeof process.getuid === "function" ? `uid:${process.getuid()}` : "unknown";
  }
}

export class ClerkCore {
  readonly clerkId: string;
  /** Random per open. Lets a reader tell restarts apart in the book. */
  readonly bootId: string;
  /** OS user name of the process holding this core. */
  readonly principal: string;
  readonly separation: Separation;
  readonly intake: Intake;
  readonly separationWarning: string | null;
  readonly publicKeyPem: string;
  readonly bookPath: string;
  /** NEW when the book was absent or empty (first run, or erased: code cannot tell). */
  readonly bookState: BookOpenState;

  private readonly key: KeyObject;
  private readonly book: Book;
  private readonly allowed: ReadonlySet<string> | null;
  private readonly retainPayload: boolean;
  private stopped: string | null = null;
  private closed = false;

  private constructor(options: ClerkCoreOptions, book: Book) {
    this.clerkId = options.clerkId;
    this.key = options.privateKey;
    this.book = book;
    this.bookPath = options.bookPath;
    this.bookState = book.state;
    this.bootId = randomBytes(16).toString("hex");
    this.principal = osPrincipal();
    this.separation = options.separation;
    this.intake = options.separation === "SEPARATE_PROCESS" ? "SOCKET" : "LOCAL_CALL";
    this.separationWarning =
      options.separation === "SEPARATE_PROCESS" ? null : IN_PROCESS_WARNING;
    this.publicKeyPem = publicKeyPemOf(options.privateKey);
    this.allowed =
      options.allowedSubmitters == null ? null : new Set(options.allowedSubmitters);
    this.retainPayload = options.retainPayload === true;
  }

  /**
   * Open the book (verify every line against this key; refuse if anything
   * breaks) and return a core ready to sign.
   */
  static open(options: ClerkCoreOptions): ClerkCore {
    if (typeof options.clerkId !== "string" || options.clerkId.length === 0) {
      throw new Error("clerkId must be a non-empty string");
    }
    if (
      options.separation !== "SEPARATE_PROCESS" &&
      options.separation !== "IN_PROCESS_NO_SEPARATION"
    ) {
      throw new Error(`unknown separation ${JSON.stringify(options.separation)}`);
    }
    if (options.privateKey.asymmetricKeyType !== "ed25519" || options.privateKey.type !== "private") {
      throw new Error("privateKey must be an ed25519 private key");
    }
    const book = Book.open(options.bookPath, publicKeyPemOf(options.privateKey));
    return new ClerkCore(options, book);
  }

  /** clerk_seq the next receipt will carry. */
  get nextSeq(): number {
    return this.book.count;
  }

  /** receipt_hash of the last receipt in the book. */
  get head(): string {
    return this.book.head;
  }

  /** Why the core stopped, or null while it is accepting work. */
  get failure(): string | null {
    return this.stopped;
  }

  /**
   * Book one submission. Returns the signed receipt after it is on disk.
   * Throws ClerkRequestError for a refused request (nothing booked) and
   * ClerkStoppedError once a write has failed.
   */
  submit(request: unknown): ClerkReceipt {
    if (this.closed) throw new ClerkStoppedError("clerk is closed");
    if (this.stopped !== null) throw new ClerkStoppedError(`clerk stopped: ${this.stopped}`);

    const req = validateRequest(request);
    if (this.allowed !== null && !this.allowed.has(req.submitter_id)) {
      throw new ClerkRequestError(
        `submitter_id ${JSON.stringify(req.submitter_id)} is not on this clerk's list`
      );
    }
    let canonicalPayload: string;
    try {
      canonicalPayload = canonicalise(req.payload);
    } catch (err) {
      throw new ClerkRequestError(`payload has no canonical form: ${(err as Error).message}`);
    }

    const unsigned: UnsignedClerkReceipt = {
      receipt_form: RECEIPT_FORM,
      kind: "SUBMISSION",
      clerk_id: this.clerkId,
      clerk_boot_id: this.bootId,
      clerk_principal: this.principal,
      separation: this.separation,
      separation_warning: this.separationWarning,
      intake: this.intake,
      clerk_seq: this.book.count,
      clerk_time: {
        wall_ms: Date.now(),
        monotonic_ns: process.hrtime.bigint().toString(),
      },
      prev_receipt_hash: this.book.head,
      submitter_id: req.submitter_id,
      channel: req.channel,
      declared_timestamp: req.declared_timestamp,
      payload_commitment: sha256Hex(canonicalPayload),
      payload_retained: this.retainPayload,
      payload_canonical: this.retainPayload ? canonicalPayload : null,
      signature_alg: "ed25519",
    };
    const receipt = signReceipt(unsigned, this.key);
    try {
      this.book.append(receipt);
    } catch (err) {
      // Whatever reached the disk is checked on the next start. Until then,
      // sign nothing more: the book's state is not known.
      this.stopped = (err as Error).message;
      throw new ClerkStoppedError(`clerk stopped: ${this.stopped}`);
    }
    return receipt;
  }

  /** Close the book and release its lock. Idempotent. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.book.close();
  }
}
