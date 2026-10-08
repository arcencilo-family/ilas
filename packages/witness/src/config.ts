// ──────────────────────────────────────────────────────────────────────────────
// Reference witness — configuration.
//
// {
//   "witnessSetId":   "witness-set-a",
//   "intakeDir":      "/srv/witness/intake",
//   "storePath":      "/srv/witness/store/witness-store.jsonl",
//   "privateKeyPath": "/srv/witness/keys/witness.key",
//   "submitters": [
//     { "id": "node-a", "outboxDir": "/srv/witness/outbox/node-a" },
//     { "id": "node-b", "outboxDir": "/srv/witness/outbox/node-b",
//       "intakeDir": "/srv/witness/intake-b" }
//   ],
//   "pollIntervalMs": 1000
// }
//
// Relative paths are resolved against the directory of the config file.
//
// One outbox per submitter is the point of the shape: the receipt preimage names
// neither the submitter nor the witness set (spec gap G2), so a node reading an
// outbox that also held another node's receipts could not tell them apart.
//
// A submitter's identity at the witness is the intake path its commit is read
// from: <intakeDir>/<id>. Nothing authenticates it. In the shared intake every
// node that can write the directory can write under every declared name. A
// submitter with its own intakeDir is read only from there, so a deployment
// that lets only that node's account write that directory keeps the others
// from submitting as it. The top-level intakeDir is then needed only for
// submitters without their own.
// ──────────────────────────────────────────────────────────────────────────────

import { realpathSync } from "fs";
import { basename, dirname, isAbsolute, join, resolve, sep } from "path";
import { submitterIdProblem } from "./commit";
import { readErrorText, readRegularFile } from "./regular-file";

export interface SubmitterConfig {
  /** The submitter id. The node's client writes its commits to <intakeDir>/<id>. */
  readonly id: string;
  /** Where this submitter's receipts are written. Its own directory, never shared. */
  readonly outboxDir: string;
  /**
   * This submitter's own intake directory. When set, its commit is read only
   * from <intakeDir>/<id> here and never from the shared intake. No other
   * submitter may use it, and nothing else may lie inside it or contain it.
   */
  readonly intakeDir?: string;
}

export interface WitnessConfig {
  readonly witnessSetId: string;
  /**
   * The shared intake, for every submitter without an intakeDir of its own.
   * Required unless every submitter has its own.
   */
  readonly intakeDir?: string;
  readonly storePath: string;
  readonly privateKeyPath: string;
  readonly submitters: readonly SubmitterConfig[];
  readonly pollIntervalMs: number;
}

export const DEFAULT_POLL_INTERVAL_MS = 1000;
export const MIN_POLL_INTERVAL_MS = 10;
export const MAX_POLL_INTERVAL_MS = 3_600_000;

const CONFIG_KEYS = [
  "witnessSetId",
  "intakeDir",
  "storePath",
  "privateKeyPath",
  "submitters",
  "pollIntervalMs",
] as const;
const REQUIRED_KEYS = ["witnessSetId", "storePath", "privateKeyPath", "submitters"];
const SUBMITTER_KEYS = ["id", "outboxDir", "intakeDir"];
const SUBMITTER_REQUIRED_KEYS = ["id", "outboxDir"];

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

/**
 * Absolute path with symlinks resolved as far as the path exists. The part that
 * does not exist yet is appended unchanged, so two spellings of one directory
 * compare equal whether or not it has been created.
 */
export function comparablePath(path: string): string {
  const absolute = resolve(path);
  const missing: string[] = [];
  let existing = absolute;
  for (;;) {
    try {
      const real = realpathSync(existing);
      return missing.length === 0 ? real : join(real, ...missing);
    } catch {
      const parent = dirname(existing);
      if (parent === existing) return absolute;
      missing.unshift(basename(existing));
      existing = parent;
    }
  }
}

/** True when `inner` is `outer` or lies beneath it. */
function within(inner: string, outer: string): boolean {
  if (inner === outer) return true;
  const prefix = outer.endsWith(sep) ? outer : outer + sep;
  return inner.startsWith(prefix);
}

function nonEmptyString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new ConfigError(`${field} must be a non-empty string`);
  }
  return value;
}

function pathField(value: unknown, field: string, baseDir: string): string {
  const raw = nonEmptyString(value, field);
  return isAbsolute(raw) ? resolve(raw) : resolve(baseDir, raw);
}

/**
 * Validate a parsed config object. `baseDir` anchors relative paths. Every rule
 * that fails throws ConfigError naming the field; nothing is defaulted except
 * pollIntervalMs.
 */
export function parseConfig(raw: unknown, baseDir: string): WitnessConfig {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new ConfigError("config must be a JSON object");
  }
  const obj = raw as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    if (!(CONFIG_KEYS as readonly string[]).includes(key)) {
      throw new ConfigError(
        `unknown config key ${JSON.stringify(key)}; allowed: ${CONFIG_KEYS.join(", ")}`
      );
    }
  }
  for (const key of REQUIRED_KEYS) {
    if (!(key in obj)) throw new ConfigError(`missing required config key ${key}`);
  }

  const witnessSetId = nonEmptyString(obj.witnessSetId, "witnessSetId");
  const intakeDir = "intakeDir" in obj ? pathField(obj.intakeDir, "intakeDir", baseDir) : undefined;
  const storePath = pathField(obj.storePath, "storePath", baseDir);
  const privateKeyPath = pathField(obj.privateKeyPath, "privateKeyPath", baseDir);

  if (!Array.isArray(obj.submitters) || obj.submitters.length === 0) {
    throw new ConfigError("submitters must be a non-empty array");
  }
  const submitters: SubmitterConfig[] = [];
  const ids = new Set<string>();
  obj.submitters.forEach((entry: unknown, i: number) => {
    const where = `submitters[${i}]`;
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      throw new ConfigError(`${where} must be an object with id and outboxDir`);
    }
    const e = entry as Record<string, unknown>;
    const keys = Object.keys(e);
    if (
      keys.some((k) => !SUBMITTER_KEYS.includes(k)) ||
      !SUBMITTER_REQUIRED_KEYS.every((k) => k in e)
    ) {
      throw new ConfigError(
        `${where} must have exactly the keys id and outboxDir, and optionally intakeDir`
      );
    }
    const problem = submitterIdProblem(e.id);
    if (problem !== null) throw new ConfigError(`${where}.id ${problem}`);
    const id = e.id as string;
    if (ids.has(id)) {
      throw new ConfigError(`submitter id ${JSON.stringify(id)} is declared twice`);
    }
    ids.add(id);
    const outboxDir = pathField(e.outboxDir, `${where}.outboxDir`, baseDir);
    submitters.push(
      "intakeDir" in e
        ? { id, outboxDir, intakeDir: pathField(e.intakeDir, `${where}.intakeDir`, baseDir) }
        : { id, outboxDir }
    );
  });

  const withoutOwnIntake = submitters.filter((s) => s.intakeDir === undefined).map((s) => s.id);
  if (intakeDir === undefined && withoutOwnIntake.length > 0) {
    throw new ConfigError(
      `missing required config key intakeDir: submitter(s) ` +
        `${withoutOwnIntake.map((id) => JSON.stringify(id)).join(", ")} have no intakeDir ` +
        `of their own, so they need the shared one`
    );
  }

  let pollIntervalMs = DEFAULT_POLL_INTERVAL_MS;
  if (obj.pollIntervalMs !== undefined) {
    const p = obj.pollIntervalMs;
    if (
      typeof p !== "number" ||
      !Number.isSafeInteger(p) ||
      p < MIN_POLL_INTERVAL_MS ||
      p > MAX_POLL_INTERVAL_MS
    ) {
      throw new ConfigError(
        `pollIntervalMs must be an integer from ${MIN_POLL_INTERVAL_MS} to ${MAX_POLL_INTERVAL_MS}`
      );
    }
    pollIntervalMs = p;
  }

  // ── directory separation ──────────────────────────────────────────────────
  // Every intake (the shared one and each submitter's own) and every outbox
  // must be distinct and must not contain one another. The store and the
  // private key must live in none of them: an outbox is read by the node, and
  // an intake is written by it.
  const dirs: { label: string; kind: "intake" | "outbox"; path: string }[] = [];
  if (intakeDir !== undefined) {
    dirs.push({ label: "intakeDir", kind: "intake", path: comparablePath(intakeDir) });
  }
  for (const s of submitters) {
    if (s.intakeDir !== undefined) {
      dirs.push({
        label: `intakeDir of submitter ${JSON.stringify(s.id)}`,
        kind: "intake",
        path: comparablePath(s.intakeDir),
      });
    }
    dirs.push({
      label: `outboxDir of submitter ${JSON.stringify(s.id)}`,
      kind: "outbox",
      path: comparablePath(s.outboxDir),
    });
  }
  for (let a = 0; a < dirs.length; a++) {
    for (let b = a + 1; b < dirs.length; b++) {
      const x = dirs[a];
      const y = dirs[b];
      if (x.path === y.path) {
        throw new ConfigError(
          `${y.label} is the same directory as ${x.label} (${x.path}). ` +
            (x.kind === "intake" && y.kind === "intake"
              ? `A submitter's own intake must be its alone: the witness takes the ` +
                `intake path a commit is read from as the submitter's identity, so a ` +
                `shared one would let another node submit under this name.`
              : `Each submitter needs its own outbox, and no outbox may be an intake: ` +
                `receipts do not name their submitter, so a shared directory mixes evidence.`)
        );
      }
      if (within(x.path, y.path) || within(y.path, x.path)) {
        throw new ConfigError(
          `${x.label} (${x.path}) and ${y.label} (${y.path}) are nested; ` +
            `the intakes and the outboxes must be separate directories`
        );
      }
    }
  }
  const store = comparablePath(storePath);
  const key = comparablePath(privateKeyPath);
  if (store === key) {
    throw new ConfigError("storePath and privateKeyPath must be different files");
  }
  for (const d of dirs) {
    if (within(store, d.path)) {
      throw new ConfigError(`storePath must not lie inside the ${d.label} (${d.path})`);
    }
    if (within(key, d.path)) {
      throw new ConfigError(
        `privateKeyPath must not lie inside the ${d.label} (${d.path}): ` +
          `the node can reach those directories`
      );
    }
  }

  return intakeDir === undefined
    ? { witnessSetId, storePath, privateKeyPath, submitters, pollIntervalMs }
    : { witnessSetId, intakeDir, storePath, privateKeyPath, submitters, pollIntervalMs };
}

/**
 * Read and validate a config file. Relative paths resolve against its directory.
 * Anything but a regular file is refused, a FIFO at once (regular-file.ts).
 */
export function loadConfigFile(path: string): WitnessConfig {
  let text: string;
  try {
    text = readRegularFile(path).toString("utf8");
  } catch (error) {
    throw new ConfigError(`cannot read config file ${path}: ${readErrorText(error)}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new ConfigError(`config file ${path} is not valid JSON: ${String(error)}`);
  }
  return parseConfig(parsed, dirname(resolve(path)));
}
