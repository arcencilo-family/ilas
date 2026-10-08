// ──────────────────────────────────────────────────────────────────────────────
// Reference clerk — the clerkd config file (JSON).
//
//   {
//     "clerk_id":           "clerk-a",                     required
//     "private_key_path":   "keys/clerk.key",              required, mode 0600
//     "book_path":          "book/receipts.jsonl",         required
//     "socket_path":        "run/clerk.sock",              required
//     "socket_mode":        "0600",                        optional: "0600" | "0660"
//     "allowed_submitters": ["ilas-node"],                 optional: name check only
//     "retain_payload":     false                          optional
//   }
//
// Relative paths are resolved against the directory of the config file.
// Unknown keys are refused, so a misspelt option cannot be silently ignored.
// ──────────────────────────────────────────────────────────────────────────────

import { closeSync, readFileSync } from "fs";
import { dirname, isAbsolute, resolve } from "path";
import { openRegularFileForReading } from "./book";
import { MAX_NAME_LENGTH } from "./wire";

export interface ClerkConfig {
  clerkId: string;
  privateKeyPath: string;
  bookPath: string;
  socketPath: string;
  /** 0o600 (default): only the clerk's account connects. 0o660: its group too. */
  socketMode: 0o600 | 0o660;
  /** null: any submitter_id is accepted. A list compares names; it does not authenticate. */
  allowedSubmitters: string[] | null;
  retainPayload: boolean;
}

export class ClerkConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ClerkConfigError";
  }
}

const KNOWN_KEYS = new Set([
  "clerk_id",
  "private_key_path",
  "book_path",
  "socket_path",
  "socket_mode",
  "allowed_submitters",
  "retain_payload",
]);

function requireString(obj: Record<string, unknown>, key: string): string {
  const v = obj[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new ClerkConfigError(`"${key}" is required and must be a non-empty string`);
  }
  return v;
}

/** Validate a parsed config object. Relative paths resolve against `baseDir`. */
export function parseConfig(raw: unknown, baseDir: string): ClerkConfig {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new ClerkConfigError("config must be a JSON object");
  }
  const obj = raw as Record<string, unknown>;
  for (const k of Object.keys(obj)) {
    if (!KNOWN_KEYS.has(k)) throw new ClerkConfigError(`unknown config key "${k}"`);
  }
  const path = (key: string): string => {
    const p = requireString(obj, key);
    return isAbsolute(p) ? p : resolve(baseDir, p);
  };

  const clerkId = requireString(obj, "clerk_id");
  if (clerkId.length > MAX_NAME_LENGTH) {
    throw new ClerkConfigError(`"clerk_id" is longer than ${MAX_NAME_LENGTH} characters`);
  }

  let socketMode: 0o600 | 0o660 = 0o600;
  if (obj.socket_mode !== undefined) {
    if (obj.socket_mode === "0600") socketMode = 0o600;
    else if (obj.socket_mode === "0660") socketMode = 0o660;
    else throw new ClerkConfigError(`"socket_mode" must be "0600" or "0660"`);
  }

  let allowedSubmitters: string[] | null = null;
  if (obj.allowed_submitters !== undefined && obj.allowed_submitters !== null) {
    const list = obj.allowed_submitters;
    if (
      !Array.isArray(list) ||
      list.length === 0 ||
      !list.every((s) => typeof s === "string" && s.length > 0 && s.length <= MAX_NAME_LENGTH)
    ) {
      throw new ClerkConfigError(
        `"allowed_submitters" must be a non-empty array of non-empty strings, or omitted`
      );
    }
    allowedSubmitters = [...(list as string[])];
  }

  let retainPayload = false;
  if (obj.retain_payload !== undefined) {
    if (typeof obj.retain_payload !== "boolean") {
      throw new ClerkConfigError(`"retain_payload" must be true or false`);
    }
    retainPayload = obj.retain_payload;
  }

  return {
    clerkId,
    privateKeyPath: path("private_key_path"),
    bookPath: path("book_path"),
    socketPath: path("socket_path"),
    socketMode,
    allowedSubmitters,
    retainPayload,
  };
}

/**
 * Read and parse a config file. Anything at `file` that is not a regular file
 * (a FIFO, a socket, a directory) is refused at once; a FIFO is never waited on.
 */
export function loadConfigFile(file: string): ClerkConfig {
  let text: string;
  try {
    const fd = openRegularFileForReading(file);
    try {
      text = readFileSync(fd, "utf8");
    } finally {
      closeSync(fd);
    }
  } catch (err) {
    const message =
      (err as NodeJS.ErrnoException).code === "ENXIO" ? `${file} is not a regular file` : (err as Error).message;
    throw new ClerkConfigError(`cannot read config ${file}: ${message}`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new ClerkConfigError(`config ${file} is not valid JSON: ${(err as Error).message}`);
  }
  return parseConfig(raw, dirname(resolve(file)));
}
