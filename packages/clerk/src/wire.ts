// ──────────────────────────────────────────────────────────────────────────────
// Reference clerk — the wire: request shape, line limits, and the round-trip
// guard the socket client runs before it sends anything.
//
// Transport: newline-delimited JSON over a Unix domain socket. One request
// line in, one response line out, in order.
//
//   request  = { submitter_id, channel, declared_timestamp, payload }
//   response = { ok: true, receipt } | { ok: false, error }
//
// THE ROUND-TRIP PROBLEM. ILAS checks payload_commitment against the payload
// object it holds in memory. The clerk computes the commitment from the payload
// it parsed off the socket. Those are the same bytes only if
//
//     canonicalise(payload) === canonicalise(JSON.parse(JSON.stringify(payload)))
//
// For plain JSON data that holds: -0 is written as 0 by both, every finite
// double survives JSON text exactly, strings (lone surrogates included) are
// escaped identically, and a key named "__proto__" is either an own property
// on both sides or on neither. It fails for values JSON rewrites or drops: an
// undefined or missing array element, NaN and the infinities, functions,
// boxed primitives (new Number(1) is "{}" canonically but "1" in JSON), a
// toJSON whose result depends on its key argument, and so on. ILAS refuses
// most of these itself. The client refuses all of them BEFORE sending, so the
// clerk never books a receipt that ILAS is certain to reject.
// ──────────────────────────────────────────────────────────────────────────────

import { canonicalise } from "../../../src/l0/canonical";
import type { ClerkReceipt } from "./receipt";
import { isPlainRecord } from "./receipt";

/** Longest request line the clerk reads, in bytes, not counting the newline. */
export const MAX_LINE_BYTES = 1024 * 1024;

/**
 * Longest response line the client reads. A receipt that retains its payload
 * carries the payload again as an escaped string, so this is larger.
 */
export const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

/** Longest submitter_id or channel, in UTF-16 code units. */
export const MAX_NAME_LENGTH = 256;

/** The request line's own text around its four values: {"submitter_id":,"channel":,"declared_timestamp":,"payload":} */
const REQUEST_FIXED_BYTES = 16 + 11 + 22 + 11 + 1; // 61
/** A submitter_id or channel as JSON writes it, at most: 2 quotes + 6 bytes per code unit. */
const MAX_NAME_JSON_BYTES = 2 + 6 * MAX_NAME_LENGTH; // 1538
/** A declared_timestamp as JSON writes it, at most (see MAX_PAYLOAD_BYTES). */
const MAX_TIMESTAMP_JSON_BYTES = 25;

/** The most a request line can hold besides its payload. */
export const MAX_REQUEST_OVERHEAD_BYTES =
  REQUEST_FIXED_BYTES + 2 * MAX_NAME_JSON_BYTES + MAX_TIMESTAMP_JSON_BYTES; // 3162

/**
 * The largest payload, in UTF-8 bytes of its canonical form, whose request
 * line fits within MAX_LINE_BYTES whatever submitter_id, channel and
 * declared_timestamp it is sent with. SocketClerkClient declares it as its
 * maxPayloadBytes, so ILAS refuses a larger entry before submitting it.
 *
 * A request line is JSON.stringify of {submitter_id, channel,
 * declared_timestamp, payload}:
 *
 *   {"submitter_id":S,"channel":C,"declared_timestamp":T,"payload":P}
 *
 *   fixed text: {"submitter_id": 16, ,"channel": 11,
 *     ,"declared_timestamp": 22, ,"payload": 11, } 1 ............... 61
 *   S and C: at most MAX_NAME_LENGTH = 256 UTF-16 code units each. JSON
 *     writes one code unit as at most 6 bytes: a control character or a
 *     lone surrogate becomes \uXXXX (6), any other BMP character is at
 *     most 3 UTF-8 bytes, a surrogate pair is 4 bytes for 2 units.
 *     With quotes, 2 × (2 + 6 × 256) ..................................... 3076
 *   T: null (4), or a finite number as JSON writes it. The longest is a
 *     sign, "0.", five zeros and 17 significant digits:
 *     -0.0000012345678901234567. Exponent forms such as
 *     -1.7976931348623157e+308 are 24; whole numbers below 1e21 are 22 ... 25
 *                                                                        ────
 *   the most besides P (MAX_REQUEST_OVERHEAD_BYTES) ...................... 3162
 *
 *   P: the payload as JSON.stringify writes it. encodeRequest sends a
 *     payload only if canonicalise(JSON.parse(P)) equals
 *     canonicalise(payload). The canonical form writes every string and
 *     number exactly as JSON.stringify does, without whitespace, and only
 *     orders keys differently; so P has exactly as many bytes as the
 *     payload's canonical form.
 *
 *   MAX_PAYLOAD_BYTES = MAX_LINE_BYTES − 3162 = 1048576 − 3162 = 1045414
 */
export const MAX_PAYLOAD_BYTES = MAX_LINE_BYTES - MAX_REQUEST_OVERHEAD_BYTES;

export type ClerkResponse =
  | { ok: true; receipt: ClerkReceipt }
  | { ok: false; error: string };

/** The request is malformed or not allowed. Nothing was booked. */
export class ClerkRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ClerkRequestError";
  }
}

/** The payload cannot cross the wire unchanged. Nothing was sent. */
export class ClerkPayloadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ClerkPayloadError";
  }
}

/** A request after validation. */
export interface SubmitRequest {
  submitter_id: string;
  channel: string;
  declared_timestamp: number | null;
  payload: unknown;
}

const REQUEST_KEYS = new Set(["submitter_id", "channel", "declared_timestamp", "payload"]);

function checkName(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new ClerkRequestError(`${field} must be a non-empty string`);
  }
  if (value.length > MAX_NAME_LENGTH) {
    throw new ClerkRequestError(`${field} is longer than ${MAX_NAME_LENGTH} characters`);
  }
  return value;
}

/**
 * Check a request's shape. Used for in-process calls and for parsed socket
 * lines alike. Unknown keys are refused: a field the clerk does not understand
 * would otherwise be silently ignored.
 */
export function validateRequest(req: unknown): SubmitRequest {
  if (!isPlainRecord(req)) throw new ClerkRequestError("request must be a JSON object");
  for (const k of Object.keys(req)) {
    if (!REQUEST_KEYS.has(k)) throw new ClerkRequestError(`unknown request field ${JSON.stringify(k)}`);
  }
  const submitter_id = checkName(req.submitter_id, "submitter_id");
  const channel = checkName(req.channel, "channel");
  const ts = req.declared_timestamp;
  let declared_timestamp: number | null;
  if (ts === undefined || ts === null) declared_timestamp = null;
  else if (typeof ts === "number" && Number.isFinite(ts)) declared_timestamp = ts;
  else throw new ClerkRequestError("declared_timestamp must be a finite number or null");
  if (!Object.prototype.hasOwnProperty.call(req, "payload") || req.payload === undefined) {
    throw new ClerkRequestError("payload is missing");
  }
  return { submitter_id, channel, declared_timestamp, payload: req.payload };
}

/**
 * Client side: validate `req`, serialise it as one request line, and prove the
 * payload survives the trip. Throws ClerkPayloadError when the clerk would
 * commit to different canonical bytes than ILAS will check against.
 */
export function encodeRequest(req: unknown): string {
  const r = validateRequest(req);
  let expected: string;
  try {
    expected = canonicalise(r.payload);
  } catch (err) {
    throw new ClerkPayloadError(
      `payload has no canonical form (${(err as Error).message}); ILAS could not ` +
        `verify any receipt for it, so it was not sent`
    );
  }
  let line: string;
  try {
    line = JSON.stringify({
      submitter_id: r.submitter_id,
      channel: r.channel,
      declared_timestamp: r.declared_timestamp,
      payload: r.payload,
    });
  } catch (err) {
    throw new ClerkPayloadError(`payload cannot be written as JSON: ${(err as Error).message}`);
  }
  // Exactly what the clerk will do with these bytes: parse, then canonicalise.
  let arrived: string;
  try {
    arrived = canonicalise((JSON.parse(line) as { payload?: unknown }).payload);
  } catch (err) {
    throw new ClerkPayloadError(
      `payload does not survive JSON transport (${(err as Error).message}); not sent`
    );
  }
  if (arrived !== expected) {
    throw new ClerkPayloadError(
      "payload changes when written as JSON: the clerk would commit to different " +
        "bytes than ILAS checks against, and ILAS would reject the receipt. Not sent. " +
        "(Typical causes: boxed primitives, a toJSON that depends on its key, " +
        "getters that change between reads.)"
    );
  }
  const bytes = Buffer.byteLength(line, "utf8");
  if (bytes > MAX_LINE_BYTES) {
    throw new ClerkRequestError(
      `request is ${bytes} bytes; the clerk reads at most ${MAX_LINE_BYTES} bytes per line`
    );
  }
  return line;
}

/** Server side: one request line (without its newline) to a validated request. */
export function decodeRequestLine(bytes: Buffer): SubmitRequest {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new ClerkRequestError("request line is not valid UTF-8");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new ClerkRequestError(`request line is not valid JSON: ${(err as Error).message}`);
  }
  return validateRequest(parsed);
}
