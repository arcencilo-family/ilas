// ──────────────────────────────────────────────────────────────────────────────
// Reference clerk — clients that satisfy ILAS's ClerkSubmitClient.
//
//   SocketClerkClient     one connection per submission to a clerkd socket.
//                         Refuses, before sending, any payload that would not
//                         reach the clerk unchanged (see wire.ts).
//   InProcessClerkClient  calls a ClerkCore in the caller's own process. Its
//                         receipts say IN_PROCESS_NO_SEPARATION / LOCAL_CALL
//                         and carry a separation_warning, because the caller
//                         shares memory with the signing key.
//   pingClerkd            is a clerkd answering on a socket? One probe that
//                         clerkd refuses, so nothing is booked.
//
// Neither client verifies the receipt's signature: ILAS does that with the
// public key configured on its ClerkRoute, and that is the check that counts.
// ──────────────────────────────────────────────────────────────────────────────

import { createConnection } from "net";
import type { ClerkSubmitClient, ClerkSubmitRequest } from "../../../src/l0/index";
import { ClerkCore } from "./core";
import type { ClerkCoreOptions } from "./core";
import type { ClerkReceipt } from "./receipt";
import { isPlainRecord } from "./receipt";
import { encodeRequest, MAX_PAYLOAD_BYTES, MAX_RESPONSE_BYTES } from "./wire";

export const DEFAULT_TIMEOUT_MS = 10_000;

/** The longest delay setTimeout keeps (2^31 − 1 ms); it turns a longer one into 1 ms. */
export const MAX_TIMER_MS = 2_147_483_647;

/** The clerk could not be reached, did not answer in time, or answered garbage. */
export class ClerkTransportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ClerkTransportError";
  }
}

/** The clerk answered and refused the submission. Nothing was booked. */
export class ClerkRefusedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ClerkRefusedError";
  }
}

export interface SocketClerkClientOptions {
  socketPath: string;
  /**
   * How long to wait for connect + answer. Default 10 s. More than 0 and at
   * most 2147483647 (the longest delay setTimeout keeps); anything else is
   * refused by the constructor.
   */
  timeoutMs?: number;
}

export class SocketClerkClient implements ClerkSubmitClient {
  readonly socketPath: string;
  readonly timeoutMs: number;
  /**
   * The largest payload, in UTF-8 bytes of its canonical form, whose request
   * line always fits the clerk's line limit: MAX_PAYLOAD_BYTES (the
   * arithmetic is in wire.ts). ILAS reads it once, when the log is built,
   * and refuses a larger entry with L0PayloadError before submitting it.
   */
  readonly maxPayloadBytes: number = MAX_PAYLOAD_BYTES;
  /** Settles when the previous request has finished; requests go out one at a time. */
  private tail: Promise<void> = Promise.resolve();

  constructor(options: SocketClerkClientOptions) {
    if (typeof options.socketPath !== "string" || options.socketPath.length === 0) {
      throw new Error("socketPath is required");
    }
    const t = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isFinite(t) || t <= 0) throw new Error("timeoutMs must be a positive number");
    if (t > MAX_TIMER_MS) {
      // setTimeout would replace it with 1 ms, and every submission would time out at once.
      throw new Error(`timeoutMs is ${t}; a timer runs for at most ${MAX_TIMER_MS} ms (about 24.8 days)`);
    }
    this.socketPath = options.socketPath;
    this.timeoutMs = t;
  }

  /**
   * Send one request and resolve with the clerk's receipt. Rejects with
   * ClerkPayloadError / ClerkRequestError before connecting if the request
   * cannot be sent faithfully, ClerkRefusedError if the clerk said no, and
   * ClerkTransportError for everything else (no clerk, timeout, bad answer).
   *
   * Requests from one client reach the clerk in the order submit() was
   * called: each waits for the previous one to finish. ILAS submits in append
   * order, so clerk_seq then rises along the ILAS chain.
   *
   * The payload is checked and serialised when submit() is called, not when
   * the request is sent. The timeout runs from when the request is sent. A
   * timeout after sending does not mean nothing was booked: the clerk may have
   * appended the receipt and lost the connection.
   */
  submit(req: ClerkSubmitRequest): Promise<ClerkReceipt> {
    let line: string;
    try {
      line = encodeRequest(req);
    } catch (err) {
      return Promise.reject(err);
    }
    const result = this.tail.then(() => this.send(line));
    this.tail = result.then(
      () => undefined,
      () => undefined
    );
    return result;
  }

  private async send(line: string): Promise<ClerkReceipt> {
    const answer = await exchangeLine(this.socketPath, line, this.timeoutMs);
    if (answer.ok) return answer.receipt;
    throw new ClerkRefusedError(`clerk refused the submission: ${answer.error}`);
  }
}

type WellFormedAnswer =
  | { ok: true; receipt: ClerkReceipt }
  | { ok: false; error: string };

/**
 * Connect to `path`, send `line` and its newline, and resolve with the first
 * answer line once it is a well-formed clerkd response: {"ok":true,
 * "receipt":{…}} or {"ok":false,"error":"…"}. Rejects with ClerkTransportError
 * when nothing listens there, nothing answers within `timeoutMs` of the
 * connect attempt, the connection closes first, or the answer is not such a
 * line. The connection is closed either way.
 */
function exchangeLine(path: string, line: string, timeoutMs: number): Promise<WellFormedAnswer> {
  return new Promise<WellFormedAnswer>((resolve, reject) => {
    const sock = createConnection(path);
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;
    const finish = (err: Error | null, answer?: WellFormedAnswer): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.destroy();
      if (err !== null) reject(err);
      else resolve(answer as WellFormedAnswer);
    };
    const timer = setTimeout(
      () => finish(new ClerkTransportError(`no answer from the clerk at ${path} within ${timeoutMs} ms`)),
      timeoutMs
    );
    sock.once("connect", () => {
      sock.write(line + "\n");
    });
    sock.on("data", (chunk: Buffer) => {
      const nl = chunk.indexOf(0x0a);
      if (nl === -1) {
        chunks.push(chunk);
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) {
          finish(new ClerkTransportError(`clerk answer exceeds ${MAX_RESPONSE_BYTES} bytes`));
        }
        return;
      }
      chunks.push(chunk.subarray(0, nl));
      let parsed: unknown;
      try {
        parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch (err) {
        finish(new ClerkTransportError(`clerk answer is not JSON: ${(err as Error).message}`));
        return;
      }
      if (isPlainRecord(parsed) && parsed.ok === true && isPlainRecord(parsed.receipt)) {
        finish(null, { ok: true, receipt: parsed.receipt as unknown as ClerkReceipt });
      } else if (isPlainRecord(parsed) && parsed.ok === false && typeof parsed.error === "string") {
        finish(null, { ok: false, error: parsed.error });
      } else {
        finish(new ClerkTransportError("clerk answer has an unknown shape"));
      }
    });
    sock.on("error", (err: Error) => {
      finish(new ClerkTransportError(`cannot reach the clerk at ${path}: ${err.message}`));
    });
    sock.on("close", () => {
      finish(new ClerkTransportError(`the clerk at ${path} closed the connection without answering`));
    });
  });
}

/** Default wait for `pingClerkd` (and `clerk ping`), connect to answer. */
export const DEFAULT_PING_TIMEOUT_MS = 5_000;

/**
 * The probe `pingClerkd` sends: an empty JSON object. clerkd refuses it (it
 * names no submitter), so a ping never books a receipt, and the refusal is a
 * well-formed answer line.
 */
export const PING_PROBE = "{}";

/**
 * Is a clerkd answering on `socketPath`? Sends PING_PROBE on one connection
 * and resolves once a well-formed clerkd answer line arrives (a refusal
 * counts: it is the expected answer), with how long it took. Rejects with
 * ClerkTransportError otherwise: no listener (a socket file left behind by a
 * clerkd that was killed refuses the connection), no answer within
 * `timeoutMs`, or an answer that is not a clerkd response line.
 */
export async function pingClerkd(
  socketPath: string,
  timeoutMs: number = DEFAULT_PING_TIMEOUT_MS
): Promise<{ ms: number; ok: boolean; error: string | null }> {
  if (typeof socketPath !== "string" || socketPath.length === 0) {
    throw new Error("socketPath is required");
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMER_MS) {
    throw new Error(`timeoutMs must be more than 0 and at most ${MAX_TIMER_MS}`);
  }
  const t0 = process.hrtime.bigint();
  const answer = await exchangeLine(socketPath, PING_PROBE, timeoutMs);
  const ms = Number((process.hrtime.bigint() - t0) / 1_000_000n);
  // The error text says why the probe was refused; a clerk that has stopped
  // after a failure answers too, and says so here.
  return { ms, ok: answer.ok, error: answer.ok ? null : answer.error };
}

/**
 * A clerk in the caller's own process. Useful for development and for a
 * single-process deployment that wants a book; it is not a separation. It
 * declares no maxPayloadBytes: nothing crosses a wire, so there is no line
 * limit to stay under.
 */
export class InProcessClerkClient implements ClerkSubmitClient {
  readonly core: ClerkCore;

  constructor(core: ClerkCore) {
    if (core.separation !== "IN_PROCESS_NO_SEPARATION") {
      throw new Error(
        "InProcessClerkClient needs a core opened with separation IN_PROCESS_NO_SEPARATION"
      );
    }
    this.core = core;
  }

  /** Open a core in in-process mode and wrap it. */
  static open(options: Omit<ClerkCoreOptions, "separation">): InProcessClerkClient {
    return new InProcessClerkClient(
      ClerkCore.open({ ...options, separation: "IN_PROCESS_NO_SEPARATION" })
    );
  }

  submit(req: ClerkSubmitRequest): Promise<ClerkReceipt> {
    try {
      return Promise.resolve(this.core.submit(req));
    } catch (err) {
      return Promise.reject(err);
    }
  }

  /** Close the core's book and release its lock. */
  close(): void {
    this.core.close();
  }
}
