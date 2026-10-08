// ──────────────────────────────────────────────────────────────────────────────
// ILAS — a durable L0 log with a clerk route: what a reload checks.
//   npx ts-node src/l0/l0.clerk-reload.test.ts
//
// With a clerk route AND a path, the hash chain alone is not enough to accept
// a file: anyone who can write it can recompute hashes. Every loaded entry must
// carry a receipt that passes the append rule (docs/S4-WIRE-SPEC.md §7.3)
// against the route's key and the entry's own stored payload, bound to the
// route's submitter and channel, and no receipt may stand on two entries.
// Otherwise the load is CANNOT_VERIFY, fail closed.
//
// Receipts are signed by a test double with a PUBLIC test key (seed 0x42 × 32,
// the one l0.clerk.test.ts uses). Nothing here imports a clerk implementation.
// Every file lives in a temporary directory this script creates and removes.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { createHash, createPrivateKey, createPublicKey, sign as signEd25519 } from "crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { canonicalise, sha256Hex } from "./canonical";
import { LockedEvidenceLog, L0ClerkError, L0WriteError } from "./index";
import type { ClerkRoute, ClerkSubmitClient, ClerkSubmitRequest } from "./index";
import { ILASKillStack } from "../index";
import type { ClerkSubmissionReceipt } from "../types";

let passed = 0;
let failed = 0;
const pending: Array<() => Promise<void>> = [];

function section(title: string): void {
  pending.push(async () => {
    console.log(`\n── ${title} ──`);
  });
}

function checkAsync(name: string, fn: () => Promise<void> | void): void {
  pending.push(async () => {
    try {
      await fn();
      console.log(`  ✓ ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✗ ${name}`);
      console.error(`    ${(err as Error).message}`);
      failed++;
    }
  });
}

const unhandled: unknown[] = [];
process.on("unhandledRejection", (reason) => {
  unhandled.push(reason);
});

const root = mkdtempSync(join(tmpdir(), "ilas-l0-reload-"));
let counter = 0;
const freshPath = (): string => join(root, `log-${counter++}.jsonl`);

// ── the signing double ───────────────────────────────────────────────────────

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const privFromSeed = (byte: number) =>
  createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.alloc(32, byte)]),
    format: "der",
    type: "pkcs8",
  });
const CLERK_PRIV = privFromSeed(0x42);
const OTHER_PRIV = privFromSeed(0x43);
const pemOf = (k: ReturnType<typeof privFromSeed>) =>
  createPublicKey(k).export({ type: "spki", format: "pem" }) as string;
const CLERK_PUB = pemOf(CLERK_PRIV);
const OTHER_PUB = pemOf(OTHER_PRIV);

const SUBMITTER = "node-a";
const CHANNEL = "l0";

let bootCounter = 0;

function signReceipt(
  req: ClerkSubmitRequest,
  seq: number,
  over: Record<string, unknown> = {},
  signer = CLERK_PRIV
): ClerkSubmissionReceipt {
  const unsigned = {
    kind: "SUBMISSION",
    submitter_id: req.submitter_id,
    channel: req.channel,
    clerk_id: "reload-double",
    clerk_boot_id: `boot-${bootCounter}`,
    separation: "IN_PROCESS_NO_SEPARATION",
    separation_warning: "test double",
    clerk_principal: "<test double>",
    intake: "LOCAL_CALL",
    clerk_seq: seq,
    clerk_time: { wall_ms: 1_700_000_500_000 + seq, monotonic_ns: `${seq + 1}000` },
    prev_receipt_hash: "0".repeat(64),
    signature_alg: "ed25519",
    declared_timestamp: req.declared_timestamp ?? null,
    payload_commitment: sha256Hex(canonicalise(req.payload)),
    payload_retained: false,
    payload_canonical: null,
    ...over,
  };
  const preimage = canonicalise(unsigned);
  return {
    ...unsigned,
    receipt_hash: sha256Hex(preimage),
    signature: signEd25519(null, Buffer.from(preimage, "utf8"), signer).toString("base64"),
  } as unknown as ClerkSubmissionReceipt;
}

/** Signs every request (one clerk_seq per call), unless `fail(i)` says to refuse it. */
class SigningClerk implements ClerkSubmitClient {
  readonly seen: ClerkSubmitRequest[] = [];
  private seq = 0;
  constructor(private readonly fail: (i: number) => boolean = () => false) {
    bootCounter++;
  }
  submit(req: ClerkSubmitRequest): Promise<ClerkSubmissionReceipt> {
    const i = this.seen.length;
    this.seen.push(req);
    if (this.fail(i)) return Promise.reject(new Error(`clerk refused request ${i}`));
    return Promise.resolve(signReceipt(req, this.seq++));
  }
}

function route(client: ClerkSubmitClient, over: Partial<ClerkRoute> = {}): ClerkRoute {
  return { client, submitterId: SUBMITTER, channel: CHANNEL, clerkPublicKeyPem: CLERK_PUB, ...over };
}

function entry(n: number) {
  return {
    timestamp: 1_700_000_000_000 + n,
    moduleId: "test",
    eventType: "unit",
    provenanceTag: "LaneA" as const,
    parameters: { n },
    outcome: "ok",
  };
}

// ── file helpers ─────────────────────────────────────────────────────────────

type Line = Record<string, unknown>;

function readLines(p: string): Line[] {
  return readFileSync(p, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l));
}

/** Rewrite the file with every hash and link recomputed from genesis (no key needed). */
function writeRehashed(p: string, lines: Line[]): void {
  let prev = "0".repeat(64);
  lines.forEach((e, i) => {
    e.sequenceNumber = i;
    e.previousHash = prev;
    e.hash = createHash("sha256")
      .update(
        JSON.stringify({
          sequenceNumber: e.sequenceNumber,
          previousHash: e.previousHash,
          timestamp: e.timestamp,
          moduleId: e.moduleId,
          eventType: e.eventType,
          provenanceTag: e.provenanceTag,
          parameters: e.parameters,
          outcome: e.outcome,
          clerkReceipt: e.clerkReceipt,
        })
      )
      .digest("hex");
    prev = e.hash as string;
  });
  writeFileSync(p, lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
}

/** A durable, clerk-stamped log of `n` entries. Returns its path. */
async function stampedLog(n: number): Promise<string> {
  const p = freshPath();
  const log = new LockedEvidenceLog({ path: p, clerk: route(new SigningClerk()) });
  for (let i = 0; i < n; i++) await log.append(entry(i));
  return p;
}

function assertRefusedAt(log: LockedEvidenceLog, at: number, reason: RegExp): void {
  const d = log.getDurabilityInfo();
  assert.equal(d.loadState, "CANNOT_VERIFY", `loaded as ${d.loadState}`);
  assert.equal(d.clean, false);
  assert.equal(log.isClean(), false);
  assert.equal(d.brokenAt, at, `brokenAt ${d.brokenAt}: ${d.lastError}`);
  assert.equal(d.persisting, false, "fail closed: no appends onto an unverified chain");
  assert.match(d.lastError ?? "", reason);
  assert.equal(log.loadedExisting(), false);
}

// ── tests ────────────────────────────────────────────────────────────────────

section("An honest stamped log reloads clean under its route");

checkAsync("clean stamped chain ⇒ LOADED_VERIFIED, and appends continue", async () => {
  const p = await stampedLog(3);
  const b = new LockedEvidenceLog({ path: p, clerk: route(new SigningClerk()) });
  assert.equal(b.getLoadState(), "LOADED_VERIFIED", b.getDurabilityInfo().lastError ?? "");
  assert.equal(b.getDurabilityInfo().clean, true);
  await b.append(entry(3));
  assert.equal(b.length, 4);
  const c = new LockedEvidenceLog({ path: p, clerk: route(new SigningClerk()) });
  assert.equal(c.getLoadState(), "LOADED_VERIFIED", c.getDurabilityInfo().lastError ?? "");
});

checkAsync("the same file reloaded WITHOUT a route still loads as before (hash chain only)", async () => {
  const p = await stampedLog(3);
  const lines = readLines(p);
  for (const l of lines) delete l.clerkReceipt;
  writeRehashed(p, lines);
  const b = new LockedEvidenceLog({ path: p });
  assert.equal(b.getLoadState(), "LOADED_VERIFIED");
});

section("Forged, stripped, moved or foreign receipts make the load CANNOT_VERIFY");

checkAsync("an appended entry with a garbage signature (hashes recomputed) ⇒ CANNOT_VERIFY at it", async () => {
  const p = await stampedLog(3);
  const lines = readLines(p);
  const forged = JSON.parse(JSON.stringify(lines[2]));
  forged.timestamp = 1_700_000_000_077;
  forged.parameters = { n: 77 };
  forged.clerkReceipt.declared_timestamp = forged.timestamp;
  forged.clerkReceipt.clerk_seq = 77;
  forged.clerkReceipt.signature = Buffer.alloc(64, 1).toString("base64");
  lines.push(forged);
  writeRehashed(p, lines);
  const b = new LockedEvidenceLog({ path: p, clerk: route(new SigningClerk()) });
  assertRefusedAt(b, 3, /index 3/);
  assert.deepEqual(new LockedEvidenceLog({ path: p }).getLoadState(), "LOADED_VERIFIED", "precondition: the hashes are consistent");
});

checkAsync("a receipt that is genuine but for ANOTHER payload ⇒ CANNOT_VERIFY (payload_commitment)", async () => {
  const p = await stampedLog(3);
  const lines = readLines(p);
  const req: ClerkSubmitRequest = {
    submitter_id: SUBMITTER,
    channel: CHANNEL,
    declared_timestamp: lines[1].timestamp as number,
    payload: { ...entry(1), parameters: { n: 999 } },
  };
  lines[1].clerkReceipt = signReceipt(req, 50);
  writeRehashed(p, lines);
  assertRefusedAt(new LockedEvidenceLog({ path: p, clerk: route(new SigningClerk()) }), 1, /payload_commitment/);
});

checkAsync("a historical entry's CONTENT edited, its genuine receipt kept ⇒ CANNOT_VERIFY at it", async () => {
  const p = await stampedLog(3);
  const lines = readLines(p);
  lines[1].parameters = { n: 999, forged: true };
  writeRehashed(p, lines);
  assertRefusedAt(new LockedEvidenceLog({ path: p, clerk: route(new SigningClerk()) }), 1, /payload_commitment/);
});

checkAsync("a repeated key in a line whose receipt verifies for the LAST value ⇒ CANNOT_VERIFY at it", async () => {
  // JSON.parse keeps the last value, which the hash and the genuine receipt
  // cover; a reader of the file sees the first. Nothing is rehashed.
  const p = await stampedLog(3);
  const text = readFileSync(p, "utf8").split("\n");
  const edited = text[1].replace('"outcome":"ok"', '"outcome":"approved by security","outcome":"ok"');
  assert.notEqual(edited, text[1], "precondition: the edit applies");
  text[1] = edited;
  writeFileSync(p, text.join("\n"));
  assertRefusedAt(new LockedEvidenceLog({ path: p, clerk: route(new SigningClerk()) }), 1, /^line 1 is not stored as L0 writes it/);
});

checkAsync("every receipt stripped (hashes recomputed) ⇒ CANNOT_VERIFY at entry 0", async () => {
  const p = await stampedLog(3);
  const lines = readLines(p);
  for (const l of lines) delete l.clerkReceipt;
  writeRehashed(p, lines);
  assertRefusedAt(new LockedEvidenceLog({ path: p, clerk: route(new SigningClerk()) }), 0, /no clerk receipt/);
});

checkAsync("one receipt missing after stamped entries ⇒ CANNOT_VERIFY at it", async () => {
  const p = await stampedLog(3);
  const lines = readLines(p);
  delete lines[2].clerkReceipt;
  writeRehashed(p, lines);
  assertRefusedAt(new LockedEvidenceLog({ path: p, clerk: route(new SigningClerk()) }), 2, /no clerk receipt/);
});

checkAsync("a receipt signed by a FOREIGN key ⇒ CANNOT_VERIFY", async () => {
  const p = await stampedLog(3);
  const lines = readLines(p);
  const req: ClerkSubmitRequest = {
    submitter_id: SUBMITTER,
    channel: CHANNEL,
    declared_timestamp: lines[2].timestamp as number,
    payload: entry(2),
  };
  lines[2].clerkReceipt = signReceipt(req, 2, {}, OTHER_PRIV);
  writeRehashed(p, lines);
  assertRefusedAt(new LockedEvidenceLog({ path: p, clerk: route(new SigningClerk()) }), 2, /signature does not verify/);
});

checkAsync("the file reopened with a DIFFERENT clerk key ⇒ CANNOT_VERIFY at entry 0", async () => {
  const p = await stampedLog(2);
  const b = new LockedEvidenceLog({ path: p, clerk: route(new SigningClerk(), { clerkPublicKeyPem: OTHER_PUB }) });
  assertRefusedAt(b, 0, /signature does not verify/);
});

checkAsync("one receipt copied onto a second entry with the same content ⇒ CANNOT_VERIFY at the copy", async () => {
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p, clerk: route(new SigningClerk()) });
  await a.append(entry(1));
  await a.append(entry(1)); // same content, its own receipt
  const lines = readLines(p);
  lines[1].clerkReceipt = lines[0].clerkReceipt; // the receipt now stands twice
  writeRehashed(p, lines);
  assertRefusedAt(new LockedEvidenceLog({ path: p, clerk: route(new SigningClerk()) }), 1, /already committed/);
});

checkAsync("receipts booked for ANOTHER submitter or channel ⇒ CANNOT_VERIFY", async () => {
  const p = await stampedLog(2);
  assertRefusedAt(
    new LockedEvidenceLog({ path: p, clerk: route(new SigningClerk(), { submitterId: "node-b" }) }),
    0,
    /submitter_id/
  );
  assertRefusedAt(
    new LockedEvidenceLog({ path: p, clerk: route(new SigningClerk(), { channel: "other" }) }),
    0,
    /channel/
  );
});

checkAsync("a log written WITHOUT a clerk, reopened WITH one ⇒ CANNOT_VERIFY (start a new file)", async () => {
  const p = freshPath();
  const a = new LockedEvidenceLog({ path: p });
  a.append(entry(1));
  a.append(entry(2));
  const b = new LockedEvidenceLog({ path: p, clerk: route(new SigningClerk()) });
  assertRefusedAt(b, 0, /no clerk receipt/);
});

checkAsync("ILASKillStack on a forged file: status says clean:false and no bootstrap entry is suppressed", async () => {
  const p = freshPath();
  await ILASKillStack.create({ logPath: p, clerk: route(new SigningClerk()) });
  const lines = readLines(p);
  assert.equal(lines.length, 10);
  lines[4].parameters = { ...(lines[4].parameters as object), indistinguishable: true };
  writeRehashed(p, lines);
  const s = await ILASKillStack.create({ logPath: p, clerk: route(new SigningClerk()) });
  const d = s.status().logDurability;
  assert.equal(d.loadState, "CANNOT_VERIFY");
  assert.equal(d.clean, false);
  assert.equal(d.brokenAt, 4);
  assert.equal(d.entriesLoaded, 10);
  assert.equal(s.log.length, 20, "the replay guard was engaged on an unverified chain");
});

section("Receipts loaded WITHOUT a route are counted as unchecked (receiptsUnchecked)");

checkAsync("an honest stamped log reloaded without a route ⇒ clean (hash chain), receiptsUnchecked = every stamped entry", async () => {
  const p = await stampedLog(3);
  const d = new LockedEvidenceLog({ path: p }).getDurabilityInfo();
  assert.equal(d.loadState, "LOADED_VERIFIED");
  assert.equal(d.clean, true, "clean describes the hash chain");
  assert.equal(d.receiptsUnchecked, 3);
  const routed = new LockedEvidenceLog({ path: p, clerk: route(new SigningClerk()) }).getDurabilityInfo();
  assert.equal(routed.loadState, "LOADED_VERIFIED");
  assert.equal(routed.receiptsUnchecked, 0, "a route checked every receipt");
});

checkAsync("a receipt re-signed with ANOTHER key, hashes recomputed: no route ⇒ clean but counted unchecked; the route ⇒ CANNOT_VERIFY", async () => {
  const p = await stampedLog(3);
  const lines = readLines(p);
  const req: ClerkSubmitRequest = {
    submitter_id: SUBMITTER,
    channel: CHANNEL,
    declared_timestamp: lines[0].timestamp as number,
    payload: entry(0),
  };
  lines[0].clerkReceipt = signReceipt(req, 0, {}, OTHER_PRIV);
  writeRehashed(p, lines);
  const s = await ILASKillStack.create({ logPath: p, declarations: { clerk: "independent-operator: security" } });
  const d = s.status().logDurability;
  assert.equal(d.loadState, "LOADED_VERIFIED");
  assert.equal(d.receiptsUnchecked, 3, "the forged receipt sits on a clean load with nothing saying it was never checked");
  assertRefusedAt(new LockedEvidenceLog({ path: p, clerk: route(new SigningClerk()) }), 0, /signature does not verify/);
});

checkAsync("no receipts, or no path ⇒ receiptsUnchecked 0", async () => {
  const p = freshPath();
  const plain = new LockedEvidenceLog({ path: p });
  plain.append(entry(0));
  assert.equal(new LockedEvidenceLog({ path: p }).getDurabilityInfo().receiptsUnchecked, 0);
  const memory = new LockedEvidenceLog({ clerk: route(new SigningClerk()) });
  await memory.append(entry(0));
  assert.equal(memory.getDurabilityInfo().receiptsUnchecked, 0);
});

section("A write that fails part-way on the clerk path");

checkAsync("half the line, then ENOSPC ⇒ the append rejects L0WriteError, the file is cut back, the log stops; the restart is clean", async () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const fs = require("fs") as typeof import("fs");
  const p = freshPath();
  const clerk = new SigningClerk();
  const log = new LockedEvidenceLog({ path: p, clerk: route(clerk) });
  await log.append(entry(0));
  await log.append(entry(1));
  const before = readFileSync(p);
  const real = fs.writeSync;
  (fs as { writeSync: unknown }).writeSync = (fd: number, buf: Buffer, off: number, len: number) => {
    real(fd, buf, off, Math.floor(len / 2));
    throw Object.assign(new Error("ENOSPC: injected"), { code: "ENOSPC" });
  };
  let err: unknown = null;
  try {
    await log.append(entry(2));
  } catch (e) {
    err = e;
  } finally {
    (fs as { writeSync: unknown }).writeSync = real;
  }
  assert.ok(err instanceof L0WriteError, `got ${String(err)}`);
  assert.deepEqual(readFileSync(p), before, "a partial line was left in the file");
  assert.equal(log.length, 2);
  const seen = clerk.seen.length;
  let later: unknown = null;
  try {
    await log.append(entry(3));
  } catch (e) {
    later = e;
  }
  assert.ok(later instanceof L0WriteError, "the clerk path went on after a failed write");
  assert.equal(clerk.seen.length, seen, "submitted after the log stopped");
  const restarted = new LockedEvidenceLog({ path: p, clerk: route(new SigningClerk()) });
  assert.equal(restarted.getLoadState(), "LOADED_VERIFIED", String(restarted.getDurabilityInfo().lastError));
  assert.deepEqual(
    restarted.getAll().map((e) => e.hash),
    log.getAll().map((e) => e.hash)
  );
});

section("A receipt already on the loaded chain cannot commit again after a restart");

checkAsync("the client replays a receipt from the loaded chain ⇒ the append is refused", async () => {
  const p = await stampedLog(2);
  const old = readLines(p)[1].clerkReceipt as ClerkSubmissionReceipt;
  const replay: ClerkSubmitClient = { submit: async () => old };
  const b = new LockedEvidenceLog({ path: p, clerk: route(replay) });
  assert.equal(b.getLoadState(), "LOADED_VERIFIED");
  let err: unknown = null;
  try {
    await b.append(entry(1)); // same content and timestamp as the entry it was booked for
  } catch (e) {
    err = e;
  }
  assert.ok(err instanceof L0ClerkError, "a replayed receipt was committed");
  assert.match((err as Error).message, /already committed/);
  assert.equal(b.length, 2);
});

section("A bootstrap interrupted by a clerk failure is completed on restart");

checkAsync("clerk refuses request 4 during create(); the restart appends the 6 missing registrations", async () => {
  const p = freshPath();
  let firstErr: unknown = null;
  try {
    await ILASKillStack.create({ logPath: p, clerk: route(new SigningClerk((i) => i === 4)) });
  } catch (e) {
    firstErr = e;
  }
  assert.ok(firstErr instanceof L0ClerkError, "create() did not report the clerk failure");
  assert.equal(readLines(p).length, 4, "precondition: four bootstrap entries reached the disk");

  const clerk2 = new SigningClerk();
  const s = await ILASKillStack.create({ logPath: p, clerk: route(clerk2) });
  assert.equal(s.log.getLoadState(), "LOADED_VERIFIED");
  const ids = s.log
    .getAll()
    .filter((e) => e.eventType === "probe_registered")
    .map((e) => e.parameters.id);
  assert.equal(ids.length, 10, `registrations: ${ids.join(",")}`);
  assert.equal(new Set(ids).size, 10, "a probe was registered twice");
  assert.equal(clerk2.seen.length, 6, "the restart did not submit exactly the missing six");
  assert.equal(s.log.verify().valid, true);

  const clerk3 = new SigningClerk();
  const again = await ILASKillStack.create({ logPath: p, clerk: route(clerk3) });
  assert.equal(again.log.length, 10);
  assert.equal(clerk3.seen.length, 0, "a complete bootstrap was submitted again");
});

section("A durable log that cannot create its directory fails closed with a clerk too");

/**
 * A log path whose file is absent (ENOENT) but whose directory cannot be
 * created: the parent is a dangling symlink. Works the same as root.
 */
function uncreatableDirPath(): string {
  const dangling = freshPath();
  symlinkSync(join(root, `nowhere-${counter++}`), dangling);
  return join(dangling, "l0.jsonl");
}

checkAsync("directory cannot be created ⇒ the first append rejects L0WriteError and NOTHING is submitted", async () => {
  const p = uncreatableDirPath();
  const clerk = new SigningClerk();
  const log = new LockedEvidenceLog({ path: p, clerk: route(clerk) });
  let first: unknown = null;
  try {
    await log.append(entry(1));
  } catch (e) {
    first = e;
  }
  assert.ok(first instanceof L0WriteError, `got ${String(first)}`);
  let second: unknown = null;
  try {
    await log.append(entry(2));
  } catch (e) {
    second = e;
  }
  assert.ok(second instanceof L0WriteError, "the log kept going after a failed write");
  assert.equal(clerk.seen.length, 0, "a frame was submitted although the log could never commit it");
  assert.equal(log.length, 0);
  assert.equal(existsSync(p), false);
  const d = log.getDurabilityInfo();
  assert.equal(d.writeHealthy, false);
  assert.match(d.lastError ?? "", /log directory/);
});

checkAsync("directory cannot be created ⇒ ILASKillStack.create() rejects L0WriteError and submits no bootstrap frame", async () => {
  const before = unhandled.length;
  const p = uncreatableDirPath();
  const clerk = new SigningClerk();
  let err: unknown = null;
  try {
    await ILASKillStack.create({ logPath: p, clerk: route(clerk) });
  } catch (e) {
    err = e;
  }
  assert.ok(err instanceof L0WriteError, `got ${String(err)}`);
  assert.equal(clerk.seen.length, 0, "bootstrap frames were submitted although the log could never commit them");
  assert.equal(existsSync(p), false);
  await new Promise((r) => setTimeout(r, 25));
  assert.equal(unhandled.length, before, "an unhandled rejection");
});

// ── run ──────────────────────────────────────────────────────────────────────

let finished = false;
process.on("exit", () => {
  if (!finished) {
    console.error("\n  ✗ the run ended before every test finished (a promise was never settled)");
    process.exitCode = 1;
  }
});

void (async () => {
  for (const t of pending) await t();
  finished = true;
  await new Promise((r) => setTimeout(r, 25));
  if (unhandled.length > 0) {
    console.error(`  ✗ ${unhandled.length} unhandled rejection(s) during the run`);
    for (const u of unhandled) console.error(`    ${String(u)}`);
    failed++;
  }
  rmSync(root, { recursive: true, force: true });
  console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
})();
