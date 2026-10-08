// ──────────────────────────────────────────────────────────────────────────────
// ILAS — canonical JSON ("ILAS-CANON-JSON-1")
//
// Deterministic bytes for a JSON-shaped value. Clerk receipts are signed over
// these bytes, so the rules here are part of the wire contract (see
// docs/S4-WIRE-SPEC.md §7.2).
//
// Rules:
//   · object keys sorted by code unit; key insertion order cannot change output
//   · every property is read exactly once
//   · properties whose value is undefined are omitted (JSON semantics)
//   · undefined array elements are REFUSED, not coerced to null
//   · non-finite numbers, bigint, symbol, function are REFUSED
//   · cycles are REFUSED; depth is bounded
//   · a toJSON method gets exactly one call; its result is what is encoded
//   · strings use JSON string escaping; numbers use JSON.stringify
// ──────────────────────────────────────────────────────────────────────────────

import { createHash } from "crypto";

export const CANONICAL_FORM = "ILAS-CANON-JSON-1";

export const DEFAULT_MAX_DEPTH = 64;

export class CanonicalisationError extends Error {
  constructor(message: string, readonly path: string) {
    super(`${message} (at ${path || "<root>"})`);
    this.name = "CanonicalisationError";
  }
}

function walk(
  value: unknown,
  path: string,
  depth: number,
  maxDepth: number,
  seen: Set<object>
): string {
  if (depth > maxDepth) {
    throw new CanonicalisationError(`structure deeper than ${maxDepth} levels`, path);
  }
  if (value === null) return "null";

  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value as number)) {
      throw new CanonicalisationError(`non-finite number (${String(value)})`, path);
    }
    return JSON.stringify(value);
  }
  if (t === "string") return JSON.stringify(value);
  if (t === "undefined") throw new CanonicalisationError("undefined", path);
  if (t === "bigint") throw new CanonicalisationError("bigint has no canonical form", path);
  if (t === "symbol") throw new CanonicalisationError("symbol", path);
  if (t === "function") throw new CanonicalisationError("function", path);

  const obj = value as object;
  if (seen.has(obj)) throw new CanonicalisationError("cyclic reference", path);

  const maybe = obj as { toJSON?: unknown };
  if (typeof maybe.toJSON === "function") {
    const replaced = (maybe.toJSON as () => unknown).call(obj);
    if (replaced === obj) {
      throw new CanonicalisationError("toJSON returned the object itself", path);
    }
    seen.add(obj);
    try {
      return walk(replaced, path, depth, maxDepth, seen);
    } finally {
      seen.delete(obj);
    }
  }

  seen.add(obj);
  try {
    if (Array.isArray(obj)) {
      const parts: string[] = [];
      for (let i = 0; i < obj.length; i++) {
        const item = obj[i];
        if (item === undefined) {
          throw new CanonicalisationError(
            "undefined array element would be coerced to null",
            `${path}[${i}]`
          );
        }
        parts.push(walk(item, `${path}[${i}]`, depth + 1, maxDepth, seen));
      }
      return `[${parts.join(",")}]`;
    }

    const record = obj as Record<string, unknown>;
    const parts: string[] = [];
    for (const k of Object.keys(record).sort()) {
      const child = record[k];
      if (child === undefined) continue;
      parts.push(
        `${JSON.stringify(k)}:${walk(child, `${path}.${k}`, depth + 1, maxDepth, seen)}`
      );
    }
    return `{${parts.join(",")}}`;
  } finally {
    seen.delete(obj);
  }
}

/** Canonical string for `value`. The result is a copy; later mutation cannot change it. */
export function canonicalise(value: unknown, maxDepth: number = DEFAULT_MAX_DEPTH): string {
  return walk(value, "", 0, maxDepth, new Set<object>());
}

/** Lowercase hex SHA-256 of the UTF-8 bytes of `s`. */
export function sha256Hex(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}
