// ──────────────────────────────────────────────────────────────────────────────
// ILAS — L0-through-clerk wiring: acceptance tests for the ClerkRoute seam.
// House style: standalone ts-node script, custom check() harness.
//   npx ts-node src/l0/l0.clerk.test.ts
//
// WHAT THESE TESTS ARE, AND WHAT THEY ARE NOT
//
//   They exercise the seam against a TEST DOUBLE that satisfies
//   `ClerkSubmitClient` structurally. Nothing here imports a clerk
//   implementation (packages/clerk included), reaches a socket, or starts a
//   clerk. A green run says: the wiring forwards what it declared it forwards,
//   refuses what it declared it refuses, and leaves the no-clerk path alone. It
//   says NOTHING about separation being real, or about a real clerk and ILAS
//   having ever spoken. Receipts here are signed with a public test key, so a
//   green run says only that the verification rule (docs/S4-WIRE-SPEC.md §7.3)
//   accepts and refuses what it should.
//
//   Every log below is in-memory: the wired path needs no directory, and a test
//   that quietly created one would hide that fact. The one exception says so:
//   committed entries are frozen, so tampering with a receipt is done where an
//   attacker would do it, in the file, inside a temporary directory this file
//   creates and removes.
//
//   An unhandled promise rejection is a failure of this file: one is trapped,
//   counted, and fails the run (a rejection must surface through the append,
//   settle() or create() promise, never by crashing the process).
//
//   Setup is per-body and explicit. There is no shared fixture.
// ──────────────────────────────────────────────────────────────────────────────

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as signEd25519 } from "crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { canonicalise, sha256Hex } from "./canonical";
import { verifyClerkReceipt } from "./clerk-verify";
import assert from "assert";
import {
  LockedEvidenceLog,
  L0ClerkError,
  L0PayloadError,
  recomputeHeadHashAt,
} from "./index";
import type { ClerkRoute, ClerkSubmitClient, ClerkSubmitRequest } from "./index";
import { ILASKillStack } from "../index";
import type { ClerkSubmissionReceipt, LogEntry } from "../types";

let passed = 0;
let failed = 0;

const unhandled: unknown[] = [];
process.on("unhandledRejection", (reason) => {
  unhandled.push(reason);
});

/** Let every pending rejection be reported, then require that none was unhandled. */
async function noUnhandledSince(before: number): Promise<void> {
  await new Promise((r) => setTimeout(r, 25));
  assert.equal(
    unhandled.length,
    before,
    `unhandled rejection(s): ${unhandled.slice(before).map(String).join("; ")}`
  );
}

const tmpRoot = mkdtempSync(join(tmpdir(), "ilas-l0-clerk-"));

// Every test — synchronous or not — is QUEUED and run in declaration order, so
// the printed transcript is the order the file reads in. A harness that let the
// sync results print before the async ones would produce a log that no longer
// matches the source, which is the sort of small lie a test file must not tell.
const pending: Array<() => Promise<void>> = [];

function section(title: string): void {
  pending.push(async () => {
    console.log(`\n── ${title} ──`);
  });
}

function checkAsync(name: string, fn: () => void | Promise<void>): void {
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

/** Synchronous test. Queued like the rest; the body must stay synchronous. */
function check(name: string, fn: () => void): void {
  checkAsync(name, fn);
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

// ── the double ────────────────────────────────────────────────────────────────
//
// All nineteen fields of ClerkSubmissionReceipt, because the seam validates a
// subset of them and a double that only carried the validated ones would let a
// future widening of confirmReceipt() pass unnoticed.

// Public TEST keys, from fixed seed bytes that are public on purpose
// (scripts/s4-test-vectors.ts uses the same two seeds). Never use them for a
// real clerk.
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const privFromSeed = (byte: number) =>
  createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.alloc(32, byte)]),
    format: "der",
    type: "pkcs8",
  });
const TEST_CLERK_PRIV = privFromSeed(0x42);
const OTHER_CLERK_PRIV = privFromSeed(0x43);
const TEST_CLERK_PUB_PEM = createPublicKey(TEST_CLERK_PRIV).export({
  type: "spki",
  format: "pem",
}) as string;
const ROUTE_SUBMITTER = "ilas-l0";
const ROUTE_CHANNEL = "l0-evidence";

/**
 * A SIGNED clerk receipt. The payload commitment is computed from the payload
 * the clerk was actually handed. `over` is applied before signing, so field
 * overrides are covered by the signature. `signature` and `receipt_hash` are
 * applied after signing, which is how a forged or broken receipt is built.
 */
function receipt(
  seq: number,
  declared: number | null,
  payload: unknown,
  over: Partial<ClerkSubmissionReceipt> = {},
  signer = TEST_CLERK_PRIV
): ClerkSubmissionReceipt {
  const { signature: sigOver, receipt_hash: hashOver, ...fieldOver } = over;
  const unsigned = {
    kind: "SUBMISSION",
    submitter_id: ROUTE_SUBMITTER,
    channel: ROUTE_CHANNEL,
    clerk_id: "clerk-double",
    clerk_boot_id: "boot-double",
    separation: "IN_PROCESS_NO_SEPARATION",
    separation_warning: "test double: buys nothing, and says so",
    clerk_principal: "<test double, no principal>",
    intake: "LOCAL_CALL",
    clerk_seq: seq,
    clerk_time: { wall_ms: 1_700_000_500_000 + seq, monotonic_ns: `${seq}000` },
    prev_receipt_hash: seq === 0 ? "0".repeat(64) : sha256Hex(`prev-${seq - 1}`),
    signature_alg: "ed25519",
    declared_timestamp: declared,
    payload_commitment: sha256Hex(canonicalise(payload)),
    payload_retained: false,
    payload_canonical: null,
    ...fieldOver,
  } as Omit<ClerkSubmissionReceipt, "receipt_hash" | "signature">;
  const preimage = canonicalise(unsigned);
  const signature = signEd25519(null, Buffer.from(preimage, "utf8"), signer).toString("base64");
  return {
    ...unsigned,
    receipt_hash: hashOver ?? sha256Hex(preimage),
    signature: sigOver ?? signature,
  } as ClerkSubmissionReceipt;
}

/** Records every request it is handed; answers per the strategy it was given. */
class ClerkDouble implements ClerkSubmitClient {
  readonly seen: ClerkSubmitRequest[] = [];
  private seq = 0;
  constructor(
    private readonly strategy: (
      req: ClerkSubmitRequest,
      seq: number
    ) => Promise<ClerkSubmissionReceipt> = (req, seq) =>
      Promise.resolve(receipt(seq, req.declared_timestamp ?? null, req.payload))
  ) {}
  submit(req: ClerkSubmitRequest): Promise<ClerkSubmissionReceipt> {
    this.seen.push(req);
    return this.strategy(req, this.seq++);
  }
}

function route(client: ClerkSubmitClient) {
  return { client, submitterId: ROUTE_SUBMITTER, channel: ROUTE_CHANNEL, clerkPublicKeyPem: TEST_CLERK_PUB_PEM };
}

/** The six payload fields of an entry: what a receipt binds. */
function payloadOf(e: LogEntry) {
  return {
    timestamp: e.timestamp,
    moduleId: e.moduleId,
    eventType: e.eventType,
    provenanceTag: e.provenanceTag,
    parameters: e.parameters,
    outcome: e.outcome,
  };
}

/** Settles after `ms`: with value()'s result, or rejected with what it throws. */
const later = <T>(ms: number, value: () => T): Promise<T> =>
  new Promise((res, rej) =>
    setTimeout(() => {
      try {
        res(value());
      } catch (err) {
        rej(err);
      }
    }, ms)
  );

async function rejects(p: Promise<unknown>): Promise<Error> {
  try {
    await p;
  } catch (err) {
    return err as Error;
  }
  throw new Error("expected a rejection; the promise resolved");
}

// ── 1 · the standalone direction: no clerk configured ────────────────────────
//
// The seam is OFFERED. With no route, L0 must behave as it did before the seam
// existed — including the synchronous commit timing every existing module and
// test depends on.

section("Standalone: no clerk configured");

check("no clerk ⇒ append commits SYNCHRONOUSLY (old timing preserved)", () => {
  const log = new LockedEvidenceLog();
  log.append(entry(1)); // deliberately not awaited
  assert.equal(log.length, 1, "entry must be on the chain before the microtask");
  assert.equal(log.verify().valid, true);
});

check("no clerk ⇒ no receipt is fabricated on the entry", () => {
  const log = new LockedEvidenceLog();
  log.append(entry(1));
  assert.equal(log.getEntry(0)!.clerkReceipt, undefined);
});

check("no clerk ⇒ the clerk clock source is empty, not absent", () => {
  const log = new LockedEvidenceLog();
  log.append(entry(1));
  log.append(entry(2));
  assert.deepEqual(log.getClerkClockSource(), []);
});

check("no clerk ⇒ durability surface reports a non-durable in-memory log", () => {
  const log = new LockedEvidenceLog();
  const d = log.getDurabilityInfo();
  assert.equal(d.durable, false);
  assert.equal(d.path, null);
  assert.equal(d.persisting, false);
  assert.equal(d.loadState, "IN_MEMORY");
});

// ── 2 · the wired direction: a route is configured ───────────────────────────

section("Wired: a ClerkRoute is configured");

checkAsync("wired ⇒ the frame is submitted with the route's identifiers", async () => {
  const c = new ClerkDouble();
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const input = entry(1);
  await log.append(input);
  assert.equal(c.seen.length, 1);
  assert.equal(c.seen[0].submitter_id, "ilas-l0");
  assert.equal(c.seen[0].channel, "l0-evidence");
  assert.equal(c.seen[0].declared_timestamp, input.timestamp);
  assert.deepEqual(c.seen[0].payload, input);
});

checkAsync("wired ⇒ the receipt is retained on the committed entry", async () => {
  const c = new ClerkDouble();
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const committed = await log.append(entry(1));
  assert.ok(committed.clerkReceipt, "entry carries no receipt");
  assert.equal(committed.clerkReceipt!.kind, "SUBMISSION");
  assert.equal(committed.clerkReceipt!.clerk_seq, 0);
  assert.equal(log.length, 1);
});

checkAsync("wired ⇒ NOTHING commits before the receipt confirms", async () => {
  let release: (r: ClerkSubmissionReceipt) => void = () => {};
  const c = new ClerkDouble(
    (req) =>
      new Promise<ClerkSubmissionReceipt>((res) => {
        release = res;
      })
  );
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const op = log.append(entry(1));
  assert.equal(log.length, 0, "committed before the clerk answered");
  release(receipt(0, 1_700_000_000_001, entry(1)));
  await op;
  assert.equal(log.length, 1);
});

checkAsync("wired ⇒ the receipt is INSIDE the hash (tamper on disk is detectable)", async () => {
  // Committed entries are frozen, so the receipt is rewritten where an attacker
  // would rewrite it: in the durable file.
  const path = join(mkdtempSync(join(tmpRoot, "inside-")), "l0.jsonl");
  const c = new ClerkDouble();
  const log = new LockedEvidenceLog({ path, clerk: route(c) });
  await log.append(entry(1));
  await log.append(entry(2));
  assert.equal(log.verify().valid, true);
  assert.equal(recomputeHeadHashAt(log.getAll(), 1), log.getEntry(1)!.hash);
  // Rewrite the retained receipt only — payload and stored hash untouched.
  const lines = readFileSync(path, "utf8").split("\n").filter((l) => l.trim());
  const line1 = JSON.parse(lines[1]);
  line1.clerkReceipt.clerk_seq = 99;
  lines[1] = JSON.stringify(line1);
  writeFileSync(path, lines.join("\n") + "\n");
  // Reloaded WITHOUT a route, only the hash chain can see it.
  const reloaded = new LockedEvidenceLog({ path });
  const v = reloaded.verify();
  assert.equal(v.valid, false, "a rewritten receipt left the chain verifying");
  assert.equal(v.brokenAt, 1);
  assert.equal(reloaded.getLoadState(), "CANNOT_VERIFY");
  assert.equal(reloaded.getDurabilityInfo().brokenAt, 1);
});

checkAsync("committed entries are FROZEN: entry, parameters and receipt cannot be changed", async () => {
  const c = new ClerkDouble();
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const committed = await log.append({ ...entry(1), parameters: { n: 1, tags: ["a"], nested: { x: 1 } } });
  assert.strictEqual(log.getEntry(0), committed);
  for (const [what, obj] of [
    ["entry", committed],
    ["parameters", committed.parameters],
    ["a nested array", committed.parameters.tags],
    ["a nested object", committed.parameters.nested],
    ["the receipt", committed.clerkReceipt],
    ["the receipt's clerk_time", committed.clerkReceipt!.clerk_time],
  ] as const) {
    assert.ok(Object.isFrozen(obj), `${what} is not frozen`);
  }
  assert.throws(() => {
    (committed.parameters as { n: number }).n = 2;
  }, TypeError);
  assert.throws(() => {
    (committed.clerkReceipt as { clerk_seq: number }).clerk_seq = 99;
  }, TypeError);
  assert.equal(log.verify().valid, true);
});

checkAsync("wired ⇒ the clock source exposes one stamp per stamped entry", async () => {
  const c = new ClerkDouble();
  const log = new LockedEvidenceLog({ clerk: route(c) });
  await log.append(entry(1));
  await log.append(entry(2));
  const stamps = log.getClerkClockSource();
  assert.equal(stamps.length, 2);
  assert.deepEqual(
    stamps.map((s) => s.sequenceNumber),
    [0, 1]
  );
  assert.deepEqual(
    stamps.map((s) => s.clerk_seq),
    [0, 1]
  );
});

checkAsync("wired ⇒ the exposed clock stamp is a COPY, not a handle", async () => {
  const c = new ClerkDouble();
  const log = new LockedEvidenceLog({ clerk: route(c) });
  await log.append(entry(1));
  const stamp = log.getClerkClockSource()[0];
  (stamp.clerk_time as { wall_ms: number }).wall_ms = 0;
  assert.notEqual(log.getEntry(0)!.clerkReceipt!.clerk_time.wall_ms, 0);
  assert.equal(log.verify().valid, true);
});

// ── 2b · one snapshot: what is submitted is what is verified and stored ──────

section("Snapshot: L0 reads the caller's entry once, at append()");

checkAsync("the clerk is handed exactly the six fields, JSON-normalised", async () => {
  const c = new ClerkDouble();
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const wide = { ...entry(1), parameters: { n: 1, ratio: NaN, gone: undefined }, note: "extra" };
  await log.append(wide);
  assert.deepStrictEqual(c.seen[0].payload, {
    timestamp: wide.timestamp,
    moduleId: "test",
    eventType: "unit",
    provenanceTag: "LaneA",
    parameters: { n: 1, ratio: null },
    outcome: "ok",
  });
  const stored = log.getEntry(0)!;
  const v = verifyClerkReceipt(
    stored.clerkReceipt as unknown as Record<string, unknown>,
    TEST_CLERK_PUB_PEM,
    payloadOf(stored)
  );
  assert.ok(v.ok, `the receipt does not bind the stored entry: ${v.reason}`);
});

checkAsync("an accessor in parameters is read ONCE; the stored entry is what the receipt binds", async () => {
  let reads = 0;
  const params = {} as Record<string, unknown>;
  Object.defineProperty(params, "verdict", {
    enumerable: true,
    get: () => (++reads <= 1 ? "clean" : "hard_alarm"),
  });
  const c = new ClerkDouble();
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const committed = await log.append({ ...entry(1), parameters: params });
  assert.equal(reads, 1, "the caller's object was read more than once");
  assert.deepEqual(committed.parameters, { verdict: "clean" });
  const v = verifyClerkReceipt(
    committed.clerkReceipt as unknown as Record<string, unknown>,
    TEST_CLERK_PUB_PEM,
    payloadOf(committed)
  );
  assert.ok(v.ok, v.reason);
});

checkAsync("changing the input AFTER append() and BEFORE the receipt changes nothing; the append lands", async () => {
  let release: () => void = () => {};
  const c = new ClerkDouble((req, seq) =>
    seq === 0
      ? new Promise<ClerkSubmissionReceipt>((res) => {
          release = () => res(receipt(seq, req.declared_timestamp ?? null, req.payload));
        })
      : Promise.resolve(receipt(seq, req.declared_timestamp ?? null, req.payload))
  );
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const input = { ...entry(1), parameters: { tags: ["a"] } };
  const op = log.append(input);
  input.parameters.tags.push("b");
  release();
  const committed = await op;
  assert.deepEqual(committed.parameters, { tags: ["a"] });
  await log.append(entry(2)); // the log did not stop
  assert.equal(log.length, 2);
  assert.equal(log.verify().valid, true);
});

checkAsync("changing the input AFTER commit cannot break verify()", async () => {
  const c = new ClerkDouble();
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const input = entry(1);
  await log.append(input);
  input.parameters.n = 42;
  assert.deepEqual(log.verify(), { valid: true });
  assert.equal(log.getEntry(0)!.parameters.n, 1);
});

checkAsync("one input object reused in a loop: every entry keeps its own content", async () => {
  const c = new ClerkDouble();
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const ev = { ...entry(0), parameters: { i: -1 } };
  for (let i = 0; i < 3; i++) {
    ev.parameters.i = i;
    ev.timestamp = 1_700_000_000_000 + i;
    await log.append(ev);
  }
  assert.deepEqual(log.getAll().map((e) => e.parameters.i), [0, 1, 2]);
  assert.equal(log.verify().valid, true);
});

checkAsync("NaN in parameters is stored as null and does NOT stop the log", async () => {
  const c = new ClerkDouble();
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const committed = await log.append({ ...entry(1), parameters: { previousValue: 1, newValue: NaN } });
  assert.deepEqual(committed.parameters, { previousValue: 1, newValue: null });
  await log.append(entry(2));
  assert.equal(log.length, 2);
});

checkAsync("a BigInt or a cycle ⇒ L0PayloadError, NOTHING submitted, and the log keeps working", async () => {
  const c = new ClerkDouble();
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const big = await rejects(log.append({ ...entry(1), parameters: { n: BigInt(1) } }));
  assert.ok(big instanceof L0PayloadError, `got ${big.name}`);
  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  const cyc = await rejects(log.append({ ...entry(2), parameters: cyclic }));
  assert.ok(cyc instanceof L0PayloadError, `got ${cyc.name}`);
  assert.equal(c.seen.length, 0, "a refused payload reached the clerk");
  await log.append(entry(3));
  assert.equal(log.length, 1);
});

checkAsync("a payload deeper than the canonical limit ⇒ L0PayloadError before submitting; the log keeps working", async () => {
  const c = new ClerkDouble();
  const log = new LockedEvidenceLog({ clerk: route(c) });
  let deep: unknown = 1;
  for (let i = 0; i < 80; i++) deep = [deep];
  const err = await rejects(log.append({ ...entry(1), parameters: { deep } }));
  assert.ok(err instanceof L0PayloadError, `got ${err.name}`);
  assert.equal(c.seen.length, 0);
  await log.append(entry(2));
  assert.equal(log.length, 1);
});

check("no clerk ⇒ a BigInt is refused with L0PayloadError, thrown at once, nothing committed", () => {
  const log = new LockedEvidenceLog();
  assert.throws(() => log.append({ ...entry(1), parameters: { n: BigInt(1) } }), L0PayloadError);
  assert.equal(log.length, 0);
  log.append(entry(2));
  assert.equal(log.length, 1);
});

checkAsync("enqueue of a refused payload: settle() reports it ONCE; it does not stop the log", async () => {
  const c = new ClerkDouble();
  const log = new LockedEvidenceLog({ clerk: route(c) });
  log.enqueue({ ...entry(1), parameters: { n: BigInt(1) } });
  log.enqueue(entry(2));
  const err = await rejects(log.settle());
  assert.ok(err instanceof L0PayloadError, `got ${err.name}`);
  assert.equal(log.length, 1);
  log.enqueue(entry(3));
  await log.settle();
  assert.equal(log.length, 2);
});

checkAsync("a refused payload never hides a clerk failure at settle()", async () => {
  const c = new ClerkDouble(() => Promise.reject(new Error("clerk down")));
  const log = new LockedEvidenceLog({ clerk: route(c) });
  log.enqueue({ ...entry(1), parameters: { n: BigInt(1) } }); // refused locally
  log.enqueue(entry(2)); // the clerk fails: the log stops
  const first = await rejects(log.settle());
  assert.ok(first instanceof L0ClerkError, `the stop was hidden behind ${first.name}`);
  const second = await rejects(log.settle());
  assert.ok(second instanceof L0ClerkError, "a stopped log stopped reporting its failure");
});

checkAsync("a timestamp that is not a number (a string, an object, or missing) ⇒ L0PayloadError, NOTHING submitted, the log goes on", async () => {
  // A clerk books a declared_timestamp that is a number or null only. Sent
  // anyway, such an entry is refused by the clerk (which would stop the log)
  // or booked as null and then refused here (an orphan receipt).
  const c = new ClerkDouble();
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const { timestamp: _t, ...noTimestamp } = entry(1);
  const cases: Array<[string, unknown]> = [
    ["a string", { ...entry(1), timestamp: "yesterday" }],
    ["an object", { ...entry(1), timestamp: {} }],
    ["missing", noTimestamp],
  ];
  for (const [label, bad] of cases) {
    const err = await rejects(log.append(bad as ReturnType<typeof entry>));
    assert.ok(err instanceof L0PayloadError, `${label}: got ${err.name}: ${err.message}`);
    assert.match(err.message, /timestamp/);
  }
  assert.equal(c.seen.length, 0, "an entry with an unbookable timestamp reached the clerk");
  await log.append(entry(2));
  // NaN is stored as null, as on disk, and declared as null.
  const nan = await log.append({ ...entry(3), timestamp: NaN });
  assert.equal(nan.timestamp, null);
  assert.equal(c.seen[1].declared_timestamp, null);
  assert.equal(log.length, 2);
});

// ── maxPayloadBytes: a client's size limit refuses one entry, not the log ────

/** The default double, plus a size limit. */
class LimitedDouble extends ClerkDouble {
  constructor(readonly maxPayloadBytes: number) {
    super();
  }
}

/** UTF-8 bytes of an entry's canonical form: what maxPayloadBytes bounds. */
const canonicalBytes = (e: object): number => Buffer.byteLength(canonicalise(e), "utf8");

checkAsync("maxPayloadBytes: one byte over ⇒ L0PayloadError, NOTHING submitted, the log goes on; exactly at the limit commits", async () => {
  // Two-byte characters: a limit counted in UTF-16 code units, or on anything
  // but the canonical bytes, would let the over-limit entry through.
  const sized = (s: string) => ({ ...entry(1), parameters: { s } });
  const atLimit = sized("é".repeat(300));
  const over = sized("é".repeat(300) + "a");
  const limit = canonicalBytes(atLimit);
  assert.equal(canonicalBytes(over), limit + 1);
  const c = new LimitedDouble(limit);
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const err = await rejects(log.append(over));
  assert.ok(err instanceof L0PayloadError, `got ${err.name}: ${err.message}`);
  assert.match(err.message, new RegExp(`${limit + 1} bytes`));
  assert.equal(c.seen.length, 0, "an oversized entry reached the clerk");
  const committed = await log.append(atLimit);
  assert.equal(committed.parameters.s, "é".repeat(300));
  await log.append(entry(2));
  assert.equal(log.length, 2, "an oversized entry stopped the log");
  assert.equal(c.seen.length, 2);
});

checkAsync("maxPayloadBytes: enqueue of an oversized entry ⇒ settle() reports it ONCE; the log goes on", async () => {
  const c = new LimitedDouble(300);
  const log = new LockedEvidenceLog({ clerk: route(c) });
  log.enqueue({ ...entry(1), parameters: { s: "x".repeat(400) } });
  log.enqueue(entry(2));
  const err = await rejects(log.settle());
  assert.ok(err instanceof L0PayloadError, `got ${err.name}`);
  await log.settle();
  log.enqueue(entry(3));
  await log.settle();
  assert.equal(log.length, 2);
  assert.equal(c.seen.length, 2);
});

checkAsync("maxPayloadBytes is read ONCE, when the log is built: changing it later changes nothing", async () => {
  let reads = 0;
  let value = 300;
  const inner = new ClerkDouble();
  const client: ClerkSubmitClient = {
    submit: (req) => inner.submit(req),
    get maxPayloadBytes() {
      reads++;
      return value;
    },
  };
  const log = new LockedEvidenceLog({ clerk: route(client) });
  assert.equal(reads, 1, `maxPayloadBytes read ${reads} times at construction`);
  value = 10_000_000;
  const err = await rejects(log.append({ ...entry(1), parameters: { s: "x".repeat(400) } }));
  assert.ok(err instanceof L0PayloadError, `got ${err.name}`);
  await log.append(entry(2));
  assert.equal(reads, 1, "maxPayloadBytes was read again after construction");
  assert.equal(inner.seen.length, 1);
});

check("maxPayloadBytes present but not a positive safe integer ⇒ the constructor throws L0ClerkError", () => {
  for (const bad of [0, -1, 1.5, NaN, Infinity, 2 ** 53, "1000", null, {}]) {
    const client = { submit: () => Promise.resolve(receipt(0, 1, {})), maxPayloadBytes: bad };
    const err = constructionError(route(client as unknown as ClerkSubmitClient));
    assert.ok(err instanceof L0ClerkError, `accepted maxPayloadBytes ${String(bad)}`);
    assert.match((err as Error).message, /maxPayloadBytes/);
  }
  assert.equal(constructionError(route(new ClerkDouble())), null, "a client without a limit was refused");
  assert.equal(constructionError(route(new LimitedDouble(1))), null);
  assert.equal(constructionError(route(new LimitedDouble(Number.MAX_SAFE_INTEGER))), null);
});

checkAsync("no maxPayloadBytes on the client ⇒ L0 sets no size limit", async () => {
  const c = new ClerkDouble();
  const log = new LockedEvidenceLog({ clerk: route(c) });
  await log.append({ ...entry(1), parameters: { s: "x".repeat(2 * 1024 * 1024) } });
  assert.equal(log.length, 1);
});

// ── 3 · order under out-of-order receipts (the appendBarrier) ────────────────

section("Order: receipts may return out of order; commits may not");

checkAsync("commits keep INVOCATION order when receipts resolve backwards", async () => {
  const gates: Array<() => void> = [];
  const c = new ClerkDouble(
    (req, seq) =>
      new Promise<ClerkSubmissionReceipt>((res) => {
        gates[seq] = () => res(receipt(seq, req.declared_timestamp ?? null, req.payload));
      })
  );
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const first = log.append(entry(1));
  const second = log.append(entry(2));
  // Answer the SECOND submission first, and let every microtask it releases run
  // to completion BEFORE the first is answered. Resolving both in one tick would
  // leave the ordering to microtask bookkeeping rather than to the barrier — the
  // test would then pass with the barrier removed, which is no test at all.
  gates[1]();
  await new Promise((r) => setTimeout(r, 0));
  gates[0]();
  await Promise.all([first, second]);
  assert.equal(log.length, 2);
  assert.equal(log.getEntry(0)!.parameters.n, 1, "invocation order was not kept");
  assert.equal(log.getEntry(1)!.parameters.n, 2);
  assert.equal(log.verify().valid, true);
});

checkAsync("both frames reach the clerk in invocation order too", async () => {
  const c = new ClerkDouble();
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const a = log.append(entry(1));
  const b = log.append(entry(2));
  await Promise.all([a, b]);
  assert.deepEqual(
    c.seen.map((r) => (r.payload as { parameters: { n: number } }).parameters.n),
    [1, 2]
  );
});

// ── 4 · failure is LOUD — silence is never safety ────────────────────────────

section("Failure: every clerk failure is visible, none is swallowed");

checkAsync("a rejecting clerk ⇒ L0ClerkError, and NOTHING is committed", async () => {
  const c = new ClerkDouble(() => Promise.reject(new Error("socket refused")));
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const err = await rejects(log.append(entry(1)));
  assert.ok(err instanceof L0ClerkError, `wrong error type: ${err.name}`);
  assert.match(err.message, /did not land/);
  assert.match(err.message, /socket refused/, "the cause is not named in the message");
  assert.equal(log.length, 0, "an unconfirmed entry reached the chain");
});

checkAsync("a clerk that THROWS synchronously still rejects, never throws out of append()", async () => {
  const c: ClerkSubmitClient = {
    submit() {
      throw new Error("client blew up before returning a promise");
    },
  };
  const log = new LockedEvidenceLog({ clerk: route(c) });
  let op: Promise<unknown>;
  try {
    op = log.append(entry(1)); // must NOT throw synchronously
  } catch (err) {
    throw new Error(`append() threw synchronously: ${(err as Error).message}`);
  }
  const err = await rejects(op);
  assert.ok(err instanceof L0ClerkError);
  assert.equal(log.length, 0);
});

checkAsync("a receipt whose declared_timestamp disagrees is REFUSED", async () => {
  const c = new ClerkDouble((req, seq) => Promise.resolve(receipt(seq, 1, req.payload)));
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const err = await rejects(log.append(entry(1)));
  assert.ok(err instanceof L0ClerkError);
  assert.match(err.message, /malformed or mismatched/);
  assert.equal(log.length, 0);
});

checkAsync("SEPARATE_PROCESS claimed over an observed LOCAL_CALL is REFUSED", async () => {
  const c = new ClerkDouble((req, seq) =>
    Promise.resolve(
      receipt(seq, req.declared_timestamp ?? null, req.payload, {
        separation: "SEPARATE_PROCESS",
        intake: "LOCAL_CALL",
      })
    )
  );
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const err = await rejects(log.append(entry(1)));
  assert.ok(err instanceof L0ClerkError);
  assert.equal(log.length, 0);
});

checkAsync("an unsigned receipt is REFUSED", async () => {
  const c = new ClerkDouble((req, seq) =>
    Promise.resolve(receipt(seq, req.declared_timestamp ?? null, req.payload, { signature: "" }))
  );
  const log = new LockedEvidenceLog({ clerk: route(c) });
  await rejects(log.append(entry(1)));
  assert.equal(log.length, 0);
});

checkAsync("a receipt of the wrong KIND is REFUSED", async () => {
  const c = new ClerkDouble((req, seq) =>
    Promise.resolve(
      receipt(seq, req.declared_timestamp ?? null, req.payload, {
        kind: "CADENCE",
      } as unknown as Partial<ClerkSubmissionReceipt>)
    )
  );
  const log = new LockedEvidenceLog({ clerk: route(c) });
  await rejects(log.append(entry(1)));
  assert.equal(log.length, 0);
});

// Each shape rule, one at a time, on a receipt that IS correctly signed by the
// configured key: only the named rule can refuse it.
const SHAPE_CASES: Array<[string, Record<string, unknown>, RegExp]> = [
  ["clerk_seq 1.5", { clerk_seq: 1.5 }, /clerk_seq is not an integer/],
  ["clerk_seq -1", { clerk_seq: -1 }, /clerk_seq is negative/],
  ["wall_ms a string", { clerk_time: { wall_ms: "yesterday", monotonic_ns: "1" } }, /wall_ms is not a finite number/],
  ["clerk_time missing", { clerk_time: undefined }, /wall_ms is not a finite number/],
  ["monotonic_ns an array", { clerk_time: { wall_ms: 1, monotonic_ns: ["1"] } }, /monotonic_ns is not a string/],
  ["monotonic_ns empty", { clerk_time: { wall_ms: 1, monotonic_ns: "" } }, /monotonic_ns is empty/],
  ["separation unknown", { separation: "AIR_GAPPED_HSM" }, /separation is not a known value/],
  ["intake unknown", { intake: "NOTARISED" }, /intake is not a known value/],
  ["another submitter", { submitter_id: "someone-else" }, /submitter_id does not name this route's submitter/],
  ["another channel", { channel: "other-channel" }, /channel does not name this route's channel/],
  ["no submitter_id", { submitter_id: undefined }, /submitter_id does not name/],
  ["no channel", { channel: undefined }, /channel does not name/],
];
for (const [name, over, reason] of SHAPE_CASES) {
  checkAsync(`a signed receipt with ${name} is REFUSED (shape rule)`, async () => {
    const c = new ClerkDouble((req, seq) =>
      Promise.resolve(
        receipt(seq, req.declared_timestamp ?? null, req.payload, over as Partial<ClerkSubmissionReceipt>)
      )
    );
    const log = new LockedEvidenceLog({ clerk: route(c) });
    const err = await rejects(log.append(entry(1)));
    assert.ok(err instanceof L0ClerkError);
    assert.match(err.message, /malformed or mismatched/);
    assert.match(err.message, reason);
    assert.equal(log.length, 0);
    assert.deepEqual(log.getClerkClockSource(), []);
  });
}

checkAsync("the SAME receipt returned for a second, identical entry is REFUSED (a receipt binds one entry)", async () => {
  let cached: Promise<ClerkSubmissionReceipt> | undefined;
  const c = new ClerkDouble((req, seq) => (cached ??= Promise.resolve(receipt(seq, req.declared_timestamp ?? null, req.payload))));
  const log = new LockedEvidenceLog({ clerk: route(c) });
  await log.append(entry(1));
  const err = await rejects(log.append(entry(1)));
  assert.ok(err instanceof L0ClerkError);
  assert.match(err.message, /already committed on this log/);
  assert.equal(log.length, 1);
  await rejects(log.append(entry(1))); // and the log has stopped
  assert.equal(c.seen.length, 2);
});

checkAsync("two appends in flight carrying the same receipt: only the first commits", async () => {
  const shared = receipt(0, entry(1).timestamp, entry(1));
  const c = new ClerkDouble(() => Promise.resolve(shared));
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const a = log.append(entry(1));
  const b = log.append(entry(1));
  await a;
  const err = await rejects(b);
  assert.match(err.message, /already committed on this log/);
  assert.equal(log.length, 1);
});

const SIG_VARIANTS: Array<[string, (s: string) => string]> = [
  ["unpadded", (s) => s.replace(/=+$/, "")],
  ["base64url", (s) => s.replace(/\+/g, "-").replace(/\//g, "_")],
  ["embedded whitespace", (s) => `${s.slice(0, 10)}\n \t${s.slice(10)}`],
  ["embedded junk", (s) => `${s.slice(0, 10)}!!!***${s.slice(10)}`],
  ["extra padding", (s) => `${s}=`],
  ["trailing data after the padding", (s) => `${s}AAAA`],
];
for (const [name, reencode] of SIG_VARIANTS) {
  checkAsync(`a correctly signed receipt whose signature is re-encoded (${name}) is REFUSED`, async () => {
    const c = new ClerkDouble((req, seq) => {
      const r = receipt(seq, req.declared_timestamp ?? null, req.payload);
      return Promise.resolve({ ...r, signature: reencode(r.signature) });
    });
    const log = new LockedEvidenceLog({ clerk: route(c) });
    const err = await rejects(log.append(entry(1)));
    assert.ok(err instanceof L0ClerkError);
    assert.match(err.message, /not canonical base64/);
    assert.equal(log.length, 0);
  });
}

check("verifyClerkReceipt refuses a configured key that is a PRIVATE key", () => {
  const r = receipt(0, 1, { x: 1 });
  const privPem = TEST_CLERK_PRIV.export({ type: "pkcs8", format: "pem" }) as string;
  const v = verifyClerkReceipt(r as unknown as Record<string, unknown>, privPem, { x: 1 });
  assert.equal(v.ok, false);
  assert.match(v.reason, /private key/);
  // control: the public half verifies
  assert.ok(verifyClerkReceipt(r as unknown as Record<string, unknown>, TEST_CLERK_PUB_PEM, { x: 1 }).ok);
});

for (const [name, value] of [
  ["null", null],
  ["undefined", undefined],
] as const) {
  checkAsync(`a client resolving ${name} ⇒ L0ClerkError; nothing commits; the log stops`, async () => {
    const c = new ClerkDouble(() => Promise.resolve(value as unknown as ClerkSubmissionReceipt));
    const log = new LockedEvidenceLog({ clerk: route(c) });
    const first = await rejects(log.append(entry(1)));
    assert.ok(first instanceof L0ClerkError, `got ${first.name}: ${first.message}`);
    const second = await rejects(log.append(entry(2)));
    assert.ok(second instanceof L0ClerkError, `got ${second.name}`);
    assert.equal(c.seen.length, 1, "submitted after the log had stopped");
    assert.equal(log.length, 0);
    const queued = new LockedEvidenceLog({ clerk: route(new ClerkDouble(() => Promise.resolve(value as unknown as ClerkSubmissionReceipt))) });
    queued.enqueue(entry(1));
    const settled = await rejects(queued.settle());
    assert.ok(settled instanceof L0ClerkError, `settle(): got ${settled.name}`);
  });
}

checkAsync("a receipt whose field getter throws ⇒ L0ClerkError, not the getter's error", async () => {
  const c = new ClerkDouble((req, seq) => {
    const r = receipt(seq, req.declared_timestamp ?? null, req.payload) as unknown as Record<string, unknown>;
    Object.defineProperty(r, "separation", {
      enumerable: true,
      get: () => {
        throw new RangeError("getter blew up");
      },
    });
    return Promise.resolve(r as unknown as ClerkSubmissionReceipt);
  });
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const err = await rejects(log.append(entry(1)));
  assert.ok(err instanceof L0ClerkError, `got ${err.name}`);
  assert.equal(log.length, 0);
});

// ── 5 · the barrier after a failure ──────────────────────────────────────────
//
// After a clerk failure the log is fail-closed for the life of the process:
// every later append is refused before anything is submitted, so the clerk
// never books a frame this log has already decided it will not commit.
// Recovery is a restart.

section("After a failure: the log stops, and stops talking to the clerk");

checkAsync("a clerk failure stops the log: every later append is refused (fail closed)", async () => {
  let failNext = true;
  const c = new ClerkDouble((req, seq) => {
    if (failNext) {
      failNext = false;
      return Promise.reject(new Error("one transient hiccup"));
    }
    return Promise.resolve(receipt(seq, req.declared_timestamp ?? null, req.payload));
  });
  const log = new LockedEvidenceLog({ clerk: route(c) });
  await rejects(log.append(entry(1)));
  // The clerk is healthy again from here on — the log is not.
  await rejects(log.append(entry(2)));
  await rejects(log.append(entry(3)));
  assert.equal(log.length, 0, "chain grew after poisoning");
});

checkAsync("once a failure is known, no further frames are sent to the clerk", async () => {
  const c = new ClerkDouble((req, seq) =>
    seq === 0
      ? Promise.reject(new Error("first one fails"))
      : Promise.resolve(receipt(seq, req.declared_timestamp ?? null, req.payload))
  );
  const log = new LockedEvidenceLog({ clerk: route(c) });
  await rejects(log.append(entry(1)));
  const err = await rejects(log.append(entry(2)));
  assert.ok(err instanceof L0ClerkError, "the refusal names the clerk failure");
  assert.equal(c.seen.length, 1, "a frame reached the clerk after the log had stopped");
  assert.equal(log.length, 0);
});

checkAsync("an append ALREADY IN FLIGHT when an earlier receipt fails is refused too", async () => {
  const c = new ClerkDouble((req, seq) =>
    Promise.resolve(
      seq === 0
        ? receipt(-5, req.declared_timestamp ?? null, req.payload, { clerk_seq: -5 }) // signed, invalid clerk_seq
        : receipt(seq, req.declared_timestamp ?? null, req.payload)
    )
  );
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const a = log.append(entry(1));
  const b = log.append(entry(2)); // issued before A is checked: only the in-barrier guard can stop it
  await rejects(a);
  const err = await rejects(b);
  assert.ok(err instanceof L0ClerkError);
  assert.equal(log.length, 0, "an in-flight append committed after an earlier clerk failure");
  assert.deepEqual(log.getClerkClockSource(), []);
});

checkAsync("an append in flight when an earlier SUBMISSION rejects is refused too", async () => {
  const c = new ClerkDouble((req, seq) =>
    seq === 0
      ? later(5, () => {
          throw new Error("socket refused");
        })
      : Promise.resolve(receipt(seq, req.declared_timestamp ?? null, req.payload))
  );
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const a = log.append(entry(1));
  const b = log.append(entry(2));
  await rejects(a);
  await rejects(b);
  assert.equal(log.length, 0);
});

// The failure must surface through the append/settle()/create() promises.
// Node (15+) ends the process on an unhandled rejection, so a rejected
// submission that L0 left unobserved would crash the caller instead.

checkAsync("two appends against a client that rejects AT ONCE: both reject, nothing is left unhandled", async () => {
  const before = unhandled.length;
  const c = new ClerkDouble(() => Promise.reject(new Error("down")));
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const results = await Promise.allSettled([log.append(entry(1)), log.append(entry(2))]);
  for (const r of results) {
    assert.equal(r.status, "rejected");
    assert.ok((r as PromiseRejectedResult).reason instanceof L0ClerkError);
  }
  await noUnhandledSince(before);
});

checkAsync("two appends against a client that rejects LATER (clerk down): nothing is left unhandled", async () => {
  const before = unhandled.length;
  const c = new ClerkDouble(() =>
    later(5, () => {
      throw new Error("ECONNREFUSED");
    })
  );
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const results = await Promise.allSettled([log.append(entry(1)), log.append(entry(2))]);
  assert.ok(results.every((r) => r.status === "rejected"));
  await noUnhandledSince(before);
});

checkAsync("two enqueues against a rejecting client: settle() rejects, nothing is left unhandled", async () => {
  const before = unhandled.length;
  const c = new ClerkDouble(() => Promise.reject(new Error("down")));
  const log = new LockedEvidenceLog({ clerk: route(c) });
  log.enqueue(entry(1));
  log.enqueue(entry(2));
  const err = await rejects(log.settle());
  assert.ok(err instanceof L0ClerkError);
  await noUnhandledSince(before);
});

checkAsync("a delayed VALID append, then one whose submit() rejects at once: the first commits, nothing unhandled", async () => {
  const before = unhandled.length;
  const c = new ClerkDouble((req, seq) =>
    seq === 0
      ? later(10, () => receipt(seq, req.declared_timestamp ?? null, req.payload))
      : Promise.reject(new Error("payload refused"))
  );
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const a = log.append(entry(1));
  const b = log.append(entry(2));
  await a;
  await rejects(b);
  assert.equal(log.length, 1);
  await noUnhandledSince(before);
});

checkAsync("ILASKillStack.create() with a refusing clerk rejects with L0ClerkError; the process lives on", async () => {
  const before = unhandled.length;
  for (const client of [
    new ClerkDouble(() => Promise.reject(new Error("not on this clerk's list"))),
    {
      submit(): Promise<ClerkSubmissionReceipt> {
        throw new Error("clerk is closed");
      },
    },
    new ClerkDouble(() =>
      later(2, () => {
        throw new Error("ECONNREFUSED");
      })
    ),
  ]) {
    const err = await rejects(ILASKillStack.create({ clerk: route(client) }));
    assert.ok(err instanceof L0ClerkError, `got ${err.name}`);
  }
  await noUnhandledSince(before);
});

// A client (or a payload's toJSON) can throw or reject with ANY value, not only
// an Error. String() itself throws for some of them. None may crash the process,
// leave append() synchronously, or slip past the stop.

/** Failure values String() cannot convert, and a Symbol, which it can. */
function unprintables(): Array<[string, unknown]> {
  const { proxy, revoke } = Proxy.revocable({}, {});
  revoke();
  return [
    ["a null-prototype object", Object.create(null)],
    ["{toString: 1, valueOf: 1} from JSON", JSON.parse('{"toString":1,"valueOf":1}')],
    [
      "an object whose toString throws",
      {
        toString(): string {
          throw new Error("toString refused");
        },
      },
    ],
    ["a revoked Proxy", proxy],
    ["a Symbol", Symbol("clerk")],
  ];
}

checkAsync("submit() REJECTS with an unprintable value ⇒ L0ClerkError, the log stops, nothing is left unhandled", async () => {
  const before = unhandled.length;
  for (const [label, value] of unprintables()) {
    const c = new ClerkDouble(() => Promise.reject(value));
    const log = new LockedEvidenceLog({ clerk: route(c) });
    const first = await rejects(log.append(entry(1)));
    assert.ok(first instanceof L0ClerkError, `${label}: got ${first.name}: ${first.message}`);
    const second = await rejects(log.append(entry(2)));
    assert.ok(second instanceof L0ClerkError, `${label}: the stop was not recorded`);
    assert.equal(c.seen.length, 1, `${label}: a frame was submitted after the log had stopped`);
    assert.equal(log.length, 0);
  }
  await noUnhandledSince(before);
});

checkAsync("submit() THROWS an unprintable value ⇒ append() rejects (never throws), L0ClerkError, the log stops", async () => {
  const before = unhandled.length;
  for (const [label, value] of unprintables()) {
    let first = true;
    const c = new ClerkDouble((req, seq) => {
      if (first) {
        first = false;
        throw value;
      }
      return Promise.resolve(receipt(seq, req.declared_timestamp ?? null, req.payload));
    });
    const log = new LockedEvidenceLog({ clerk: route(c) });
    let op: Promise<unknown>;
    try {
      op = log.append(entry(1));
    } catch {
      throw new Error(`${label}: append() threw synchronously`);
    }
    const err = await rejects(op);
    assert.ok(err instanceof L0ClerkError, `${label}: got ${err.name}`);
    await rejects(log.append(entry(2))); // the clerk is healthy again; the log is not
    assert.equal(c.seen.length, 1, `${label}: a frame was submitted after the log had stopped`);
    assert.equal(log.length, 0);
  }
  await noUnhandledSince(before);
});

checkAsync("an unprintable clerk failure under ILASKillStack: the constructor does not throw; ready() and create() reject L0ClerkError", async () => {
  const before = unhandled.length;
  for (const [label, value] of unprintables()) {
    for (const mode of ["throws", "rejects"] as const) {
      const client: ClerkSubmitClient = {
        submit(): Promise<ClerkSubmissionReceipt> {
          if (mode === "throws") throw value;
          return Promise.reject(value);
        },
      };
      let stack: ILASKillStack;
      try {
        stack = new ILASKillStack({ clerk: route(client) });
      } catch {
        throw new Error(`${label}, ${mode}: the ILASKillStack constructor threw`);
      }
      const ready = await rejects(stack.ready());
      assert.ok(ready instanceof L0ClerkError, `${label}, ${mode}: ready() gave ${ready.name}`);
      const created = await rejects(ILASKillStack.create({ clerk: route(client) }));
      assert.ok(created instanceof L0ClerkError, `${label}, ${mode}: create() gave ${created.name}`);
    }
  }
  await noUnhandledSince(before);
});

checkAsync("a toJSON that throws an unprintable value ⇒ L0PayloadError (no clerk: thrown; clerk: rejected); the log goes on", async () => {
  const before = unhandled.length;
  for (const [label, value] of unprintables()) {
    const bad = {
      ...entry(1),
      parameters: {
        x: {
          toJSON(): never {
            throw value;
          },
        },
      },
    };
    const plain = new LockedEvidenceLog();
    assert.throws(() => plain.append(bad), L0PayloadError, `${label}: no clerk`);
    assert.equal(plain.length, 0);

    const c = new ClerkDouble();
    const log = new LockedEvidenceLog({ clerk: route(c) });
    const err = await rejects(log.append(bad));
    assert.ok(err instanceof L0PayloadError, `${label}: got ${err.name}`);
    assert.equal(c.seen.length, 0);
    await log.append(entry(2));
    assert.equal(log.length, 1, `${label}: the refusal stopped the log`);

    const queued = new LockedEvidenceLog({ clerk: route(new ClerkDouble()) });
    queued.enqueue(bad);
    queued.enqueue(entry(3));
    const settled = await rejects(queued.settle());
    assert.ok(settled instanceof L0PayloadError, `${label}: settle() gave ${settled.name}`);
    await queued.settle(); // reported once: a refused payload is not a stop
    assert.equal(queued.length, 1);
  }
  await noUnhandledSince(before);
});

// A failed submission stops further SUBMISSIONS at once, not only once the
// barrier reaches it: appends issued after it was seen are refused before
// anything is sent. Appends issued earlier keep their place and still commit.

checkAsync("submit() THROWS while an earlier append is pending ⇒ later appends are not even submitted", async () => {
  const c = new ClerkDouble((req, seq) => {
    if (seq === 0) return later(30, () => receipt(seq, req.declared_timestamp ?? null, req.payload));
    if (seq === 1) throw new Error("refused synchronously");
    return Promise.resolve(receipt(seq, req.declared_timestamp ?? null, req.payload));
  });
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const e0 = log.append(entry(0));
  const e1 = rejects(log.append(entry(1)));
  const rest = [2, 3, 4, 5].map((n) => rejects(log.append(entry(n))));
  await e0;
  await e1;
  for (const p of rest) assert.ok((await p) instanceof L0ClerkError);
  assert.deepEqual(
    c.seen.map((r) => (r.payload as { parameters: { n: number } }).parameters.n),
    [0, 1],
    "frames were submitted after a submission had already failed"
  );
  assert.equal(log.length, 1);
  assert.equal(log.getEntry(0)!.parameters.n, 0, "the earlier append did not commit");
});

checkAsync("submit() REJECTS while an earlier append is pending ⇒ an append a tick later is not submitted", async () => {
  const c = new ClerkDouble((req, seq) => {
    if (seq === 0) return later(30, () => receipt(seq, req.declared_timestamp ?? null, req.payload));
    if (seq === 1) return Promise.reject(new Error("refused"));
    return Promise.resolve(receipt(seq, req.declared_timestamp ?? null, req.payload));
  });
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const e0 = log.append(entry(0));
  const e1 = rejects(log.append(entry(1)));
  await new Promise((r) => setTimeout(r, 0));
  const e2 = log.append(entry(2));
  assert.ok((await rejects(e2)) instanceof L0ClerkError);
  await e0;
  await e1;
  assert.equal(c.seen.length, 2, "a frame was submitted after a rejection had been seen");
  assert.equal(log.length, 1);
});

// ── 6 · the synchronous-module seam: enqueue() + settle() ────────────────────

section("enqueue()/settle(): the chokepoint synchronous callers must await");

checkAsync("enqueue ⇒ settle() resolves once every receipt has landed", async () => {
  const c = new ClerkDouble();
  const log = new LockedEvidenceLog({ clerk: route(c) });
  log.enqueue(entry(1));
  log.enqueue(entry(2));
  assert.equal(log.length, 0, "enqueue committed before settle()");
  await log.settle();
  assert.equal(log.length, 2);
  assert.equal(log.verify().valid, true);
});

checkAsync("enqueue ⇒ a clerk failure surfaces at settle(), never silently", async () => {
  const c = new ClerkDouble(() => Promise.reject(new Error("clerk down")));
  const log = new LockedEvidenceLog({ clerk: route(c) });
  log.enqueue(entry(1));
  const err = await rejects(log.settle());
  assert.ok(err instanceof L0ClerkError, `wrong error type: ${err.name}`);
  assert.equal(log.length, 0);
});

checkAsync("no clerk ⇒ enqueue() commits synchronously and settle() is a no-op", async () => {
  const log = new LockedEvidenceLog();
  log.enqueue(entry(1));
  assert.equal(log.length, 1, "the unwired path lost its synchronous timing");
  await log.settle();
  assert.equal(log.length, 1);
});

// ── 7 · the wired path performs no deployment act ────────────────────────────

section("The wiring creates nothing ");

checkAsync("a clerk route alone opens no file and claims no directory", async () => {
  const c = new ClerkDouble();
  const log = new LockedEvidenceLog({ clerk: route(c) });
  await log.append(entry(1));
  const d = log.getDurabilityInfo();
  assert.equal(d.durable, false, "a clerk route turned durability on by itself");
  assert.equal(d.path, null);
  assert.equal(d.persisting, false);
  assert.equal(d.writeHealthy, true);
  assert.equal(d.lastError, null);
});

// ── Wiring: the clerk route is checked when the log is built ─────────────────
section("Wiring: a clerk route without a usable key fails at construction");

function constructionError(route: unknown): unknown {
  try {
    new LockedEvidenceLog({ clerk: route as ClerkRoute });
  } catch (err) {
    return err;
  }
  return null;
}

check("no clerkPublicKeyPem ⇒ the constructor throws L0ClerkError", () => {
  const { clerkPublicKeyPem: _drop, ...noKey } = route(new ClerkDouble());
  const err = constructionError(noKey);
  assert.ok(err instanceof L0ClerkError, "missing key was accepted at construction");
  assert.match((err as Error).message, /clerkPublicKeyPem/);
});

check("an empty or unreadable key ⇒ the constructor throws", () => {
  assert.ok(constructionError({ ...route(new ClerkDouble()), clerkPublicKeyPem: "" }) instanceof L0ClerkError);
  assert.ok(
    constructionError({ ...route(new ClerkDouble()), clerkPublicKeyPem: "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n" }) instanceof L0ClerkError
  );
});

check("a non-Ed25519 key (RSA) ⇒ the constructor throws", () => {
  const rsa = generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey.export({
    type: "spki",
    format: "pem",
  }) as string;
  const err = constructionError({ ...route(new ClerkDouble()), clerkPublicKeyPem: rsa });
  assert.ok(err instanceof L0ClerkError);
  assert.match((err as Error).message, /rsa/i);
});

check("a client without submit() ⇒ the constructor throws", () => {
  assert.ok(constructionError({ ...route(new ClerkDouble()), client: {} }) instanceof L0ClerkError);
});

check("a PRIVATE key given as clerkPublicKeyPem ⇒ the constructor throws, naming a private key", () => {
  const pkcs8 = TEST_CLERK_PRIV.export({ type: "pkcs8", format: "pem" }) as string;
  const err = constructionError({ ...route(new ClerkDouble()), clerkPublicKeyPem: pkcs8 });
  assert.ok(err instanceof L0ClerkError, "a private key was accepted as the clerk's public key");
  assert.match((err as Error).message, /private key/i);
  assert.match((err as Error).message, /public key/i);
});

check("missing or empty submitterId / channel ⇒ the constructor throws", () => {
  for (const bad of [
    { submitterId: undefined },
    { submitterId: "" },
    { submitterId: 42 },
    { channel: undefined },
    { channel: "" },
  ]) {
    const err = constructionError({ ...route(new ClerkDouble()), ...bad });
    assert.ok(err instanceof L0ClerkError, `accepted ${JSON.stringify(bad)}`);
  }
});

checkAsync("the route is copied: swapping the key on the caller's object later changes nothing", async () => {
  const c = new ClerkDouble((req, seq) =>
    Promise.resolve(receipt(seq, req.declared_timestamp ?? null, req.payload))
  );
  const r = route(c);
  const log = new LockedEvidenceLog({ clerk: r });
  (r as { clerkPublicKeyPem: string }).clerkPublicKeyPem = createPublicKey(OTHER_CLERK_PRIV).export({
    type: "spki",
    format: "pem",
  }) as string;
  await log.append(entry(1));
  assert.equal(log.length, 1, "the log followed a key swapped after construction");
});

checkAsync("the route is read once: getters that empty submitterId / channel after the check change nothing", async () => {
  // A double that signs receipts naming NO submitter and NO channel: only a
  // route binding that went blank after the check would accept them.
  const c = new ClerkDouble((req, seq) =>
    Promise.resolve(
      receipt(seq, req.declared_timestamp ?? null, req.payload, {
        submitter_id: undefined,
        channel: undefined,
      } as unknown as Partial<ClerkSubmissionReceipt>)
    )
  );
  const reads = { client: 0, submitterId: 0, channel: 0, clerkPublicKeyPem: 0 };
  const r = {
    get client() {
      reads.client++;
      return c;
    },
    get submitterId() {
      return reads.submitterId++ === 0 ? ROUTE_SUBMITTER : undefined;
    },
    get channel() {
      return reads.channel++ === 0 ? ROUTE_CHANNEL : undefined;
    },
    get clerkPublicKeyPem() {
      reads.clerkPublicKeyPem++;
      return TEST_CLERK_PUB_PEM;
    },
  };
  const log = new LockedEvidenceLog({ clerk: r as unknown as ClerkRoute });
  assert.deepEqual(reads, { client: 1, submitterId: 1, channel: 1, clerkPublicKeyPem: 1 }, "a route field was read more than once");
  const err = await rejects(log.append(entry(1)));
  assert.ok(err instanceof L0ClerkError, `got ${err.name}`);
  assert.match(err.message, /submitter_id does not name this route's submitter/);
  assert.equal(log.length, 0);
  assert.equal(c.seen[0].submitter_id, ROUTE_SUBMITTER, "the clerk was not handed the checked submitter_id");
  assert.equal(c.seen[0].channel, ROUTE_CHANNEL, "the clerk was not handed the checked channel");
  assert.deepEqual(reads, { client: 1, submitterId: 1, channel: 1, clerkPublicKeyPem: 1 }, "the route was read again after construction");
});

check("a route whose field cannot be read (its getter throws) ⇒ the constructor throws L0ClerkError", () => {
  const thrower = (value: unknown) => {
    const base = route(new ClerkDouble());
    return Object.defineProperty({ ...base }, "channel", {
      enumerable: true,
      get() {
        throw value;
      },
    });
  };
  for (const [label, value] of unprintables()) {
    const err = constructionError(thrower(value));
    assert.ok(err instanceof L0ClerkError, `${label}: the constructor threw something else`);
  }
});

// ── G1: the clerk signature is verified, not just shape-checked ──────────────
section("G1: the clerk signature and payload binding are verified");

checkAsync("G1: a correctly signed receipt for THIS payload COMMITS", async () => {
  const c = new ClerkDouble((req, seq) =>
    Promise.resolve(receipt(seq, req.declared_timestamp ?? null, req.payload))
  );
  const log = new LockedEvidenceLog({ clerk: route(c) });
  await log.append(entry(1));
  assert.equal(log.length, 1);
  assert.equal(log.verify().valid, true);
});

checkAsync("G1: a receipt signed by a DIFFERENT key is REFUSED", async () => {
  const c = new ClerkDouble((req, seq) =>
    Promise.resolve(receipt(seq, req.declared_timestamp ?? null, req.payload, {}, OTHER_CLERK_PRIV))
  );
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const err = await rejects(log.append(entry(1)));
  assert.ok(err instanceof L0ClerkError, "must be a clerk error");
  assert.match(err.message, /signature does not verify/);
  assert.equal(log.length, 0);
});

checkAsync("G1: a field altered AFTER signing is REFUSED", async () => {
  const c = new ClerkDouble((req, seq) => {
    const r = receipt(seq, req.declared_timestamp ?? null, req.payload);
    return Promise.resolve({ ...r, clerk_id: "forged-clerk" });
  });
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const err = await rejects(log.append(entry(1)));
  assert.ok(err instanceof L0ClerkError);
  assert.match(err.message, /receipt_hash does not match/);
  assert.equal(log.length, 0);
});

checkAsync("G1: a valid receipt for a DIFFERENT payload is REFUSED", async () => {
  const c = new ClerkDouble((req, seq) =>
    Promise.resolve(
      receipt(seq, req.declared_timestamp ?? null, {
        ...(req.payload as object),
        parameters: { n: 999 },
      })
    )
  );
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const err = await rejects(log.append(entry(1)));
  assert.ok(err instanceof L0ClerkError);
  assert.match(err.message, /payload_commitment does not match/);
  assert.equal(log.length, 0);
});

checkAsync("G1: a forged signature (bytes not from the clerk) is REFUSED", async () => {
  const c = new ClerkDouble((req, seq) =>
    Promise.resolve(
      receipt(seq, req.declared_timestamp ?? null, req.payload, {
        signature: Buffer.alloc(64, 7).toString("base64"),
      })
    )
  );
  const log = new LockedEvidenceLog({ clerk: route(c) });
  const err = await rejects(log.append(entry(1)));
  assert.ok(err instanceof L0ClerkError);
  assert.match(err.message, /signature does not verify/);
  assert.equal(log.length, 0);
});

// ── run ──────────────────────────────────────────────────────────────────────

// A test that waits on a promise nobody settles would let the event loop drain
// and the process end with code 0 before the summary. That is a failure.
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
  rmSync(tmpRoot, { recursive: true, force: true });
  console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
})();
