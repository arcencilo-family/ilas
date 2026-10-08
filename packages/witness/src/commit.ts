// ──────────────────────────────────────────────────────────────────────────────
// Reference witness — HEAD_COMMIT validation (docs/S4-WIRE-SPEC.md §3).
//
// A commit is accepted only if it is exactly:
//   { seq_no, head_hash, ts, witness_set_id }      (four keys, no others)
//   seq_no          safe integer >= -1
//   head_hash       64 lowercase hex characters
//   ts              finite number
//   witness_set_id  string; when the caller names an expected set, equal to it
// plus one consistency rule from §3: seq_no -1 (empty chain) goes with the
// genesis hash (64 zeros), and the genesis hash goes with seq_no -1.
// ──────────────────────────────────────────────────────────────────────────────

export interface HeadCommit {
  readonly seq_no: number;
  readonly head_hash: string;
  readonly ts: number;
  readonly witness_set_id: string;
}

export const HEAD_COMMIT_KEYS = ["seq_no", "head_hash", "ts", "witness_set_id"] as const;

/** Head hash of an empty chain, and the store's own genesis link. */
export const GENESIS_HASH = "0".repeat(64);

const HEX64 = /^[0-9a-f]{64}$/;

export type CommitCheck =
  | { readonly ok: true; readonly commit: HeadCommit }
  | { readonly ok: false; readonly reason: string };

/**
 * Check `value` against the HEAD_COMMIT rules. On success the commit is returned
 * as a fresh object with its keys in the order above.
 */
export function checkHeadCommit(value: unknown, expectedSetId?: string): CommitCheck {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return { ok: false, reason: "not a JSON object" };
  }
  const keys = Object.keys(value).sort();
  const want = [...HEAD_COMMIT_KEYS].sort();
  if (keys.length !== want.length || keys.some((k, i) => k !== want[i])) {
    return {
      ok: false,
      reason: `keys must be exactly ${HEAD_COMMIT_KEYS.join(", ")}; got ${JSON.stringify(
        Object.keys(value)
      )}`,
    };
  }
  const v = value as Record<string, unknown>;
  if (typeof v.seq_no !== "number" || !Number.isSafeInteger(v.seq_no) || v.seq_no < -1) {
    return { ok: false, reason: "seq_no must be a safe integer >= -1" };
  }
  if (typeof v.head_hash !== "string" || !HEX64.test(v.head_hash)) {
    return { ok: false, reason: "head_hash must be 64 lowercase hex characters" };
  }
  if (typeof v.ts !== "number" || !Number.isFinite(v.ts)) {
    return { ok: false, reason: "ts must be a finite number" };
  }
  if (typeof v.witness_set_id !== "string") {
    return { ok: false, reason: "witness_set_id must be a string" };
  }
  if (v.seq_no === -1 && v.head_hash !== GENESIS_HASH) {
    return { ok: false, reason: "seq_no -1 (empty chain) must carry the genesis hash" };
  }
  if (v.seq_no !== -1 && v.head_hash === GENESIS_HASH) {
    return { ok: false, reason: "the genesis hash is valid only at seq_no -1" };
  }
  if (expectedSetId !== undefined && v.witness_set_id !== expectedSetId) {
    return {
      ok: false,
      reason:
        `addressed to witness set ${JSON.stringify(v.witness_set_id)}; ` +
        `this witness serves ${JSON.stringify(expectedSetId)}`,
    };
  }
  return {
    ok: true,
    commit: {
      seq_no: v.seq_no,
      head_hash: v.head_hash,
      ts: v.ts,
      witness_set_id: v.witness_set_id,
    },
  };
}

/**
 * A submitter id is a bare file name: the client uses it as the intake file
 * name. It may not start with ".": dot names in an intake are the client's
 * temporary files, which the witness never reads.
 *
 * This is the rule a store record's submitter_id is held to. A submitter
 * DECLARED in the config is held to submitterIdProblem(), which adds the limits
 * of the node's client; records written before those limits keep verifying.
 */
export function bareNameProblem(id: unknown): string | null {
  if (typeof id !== "string" || id.length === 0) return "must be a non-empty string";
  if (id === "." || id === "..") return "must not be . or ..";
  if (id.includes("/") || id.includes("\\")) return "must not contain a path separator";
  if (id.includes("\0")) return "must not contain a NUL character";
  if (id.startsWith(".")) {
    return 'must not start with "." (dot names in an intake are temporary files, which the witness ignores)';
  }
  return null;
}

/**
 * The longest submitter id, in UTF-8 bytes, the node's client can write. The id
 * is a file name twice over: the drop file <id>, and the temporary file
 * ".<id>.<12 hex>.tmp" the client writes first. A file name holds at most 255
 * bytes on the common Linux and macOS file systems (NAME_MAX), and the temporary
 * name adds "." + "." + 12 hex + ".tmp" = 1 + 1 + 12 + 4 = 18 bytes: 255 − 18 = 237.
 */
export const MAX_SUBMITTER_ID_BYTES = 255 - ".".length - ".".length - 12 - ".tmp".length;

// Unicode category Cc: U+0000–U+001F, U+007F (DEL) and U+0080–U+009F.
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f-\u009f]/;

/**
 * Why `id` cannot be declared as a submitter, or null when it can. The same ids
 * are refused as by the ILAS client's own check, so a config cannot declare a
 * submitter no client can write as:
 *   - bareNameProblem(): non-empty, not "." or "..", no "/" or "\", no NUL,
 *     not starting with ".";
 *   - no control character (U+0000–U+001F, U+007F–U+009F);
 *   - well-formed UTF-16 (a lone surrogate is written to disk as U+FFFD, which
 *     is a different name);
 *   - at most MAX_SUBMITTER_ID_BYTES (237) bytes in UTF-8.
 */
export function submitterIdProblem(id: unknown): string | null {
  const bare = bareNameProblem(id);
  if (bare !== null) return bare;
  const s = id as string;
  if (CONTROL_CHARACTER.test(s)) {
    return "must not contain a control character (U+0000–U+001F, U+007F–U+009F)";
  }
  if (Buffer.from(s, "utf8").toString("utf8") !== s) {
    return (
      "must be well-formed Unicode (a lone surrogate would be written to disk as " +
      "U+FFFD, a different name)"
    );
  }
  const bytes = Buffer.byteLength(s, "utf8");
  if (bytes > MAX_SUBMITTER_ID_BYTES) {
    return (
      `must be at most ${MAX_SUBMITTER_ID_BYTES} bytes in UTF-8, is ${bytes} (the node's ` +
      `client first writes ".<id>.<12 hex>.tmp", which must fit a 255-byte file name)`
    );
  }
  return null;
}
