// ──────────────────────────────────────────────────────────────────────────────
// L0 through a real clerk, end to end.
//   npx ts-node packages/clerk/src/l0-clerk-e2e.test.ts
//
// One scenario, in the order a deployment meets it:
//   · clerkd runs as a SEPARATE CHILD PROCESS (cli.ts run);
//   · ILAS is given the clerk's public key, read from the clerk's own key file;
//   · receipts come back in the REVERSE of call order, and L0 still commits in
//     call order;
//   · every receipt verifies against that key, and the clerk's book verifies;
//   · the durable L0 file reloads clean with the receipts inside, and the clerk
//     stamps can still be read from it;
//   · each refusal (clerk down, mismatched receipt, wrong key, a valid receipt
//     for a different entry, no key at all) leaves L0 unchanged, and is refused
//     for the reason it claims to test;
//   · an entry at the socket client's maxPayloadBytes commits even with the
//     longest names and timestamp (its request line is exactly the clerk's
//     line limit); one byte more is refused by L0 before submitting, and the
//     log goes on.
//
// The child runs under the same OS account as this test. That shows the wire
// works across a process boundary. It shows nothing about independence, which
// is a deployment fact (docs/S4-WIRE-SPEC.md §2).
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { generateKeyPairSync } from "crypto";
import { join } from "path";
import { canonicalise } from "../../../src/l0/canonical";
import { LockedEvidenceLog, L0ClerkError, L0PayloadError } from "../../../src/l0/index";
import type { ClerkRoute, ClerkSubmitClient, ClerkSubmitRequest } from "../../../src/l0/index";
import { verifyClerkReceipt } from "../../../src/l0/clerk-verify";
import type { ClerkSubmissionReceipt, LogEntry } from "../../../src/types";
import { verifyBookFile } from "./book";
import { SocketClerkClient } from "./client";
import { loadPublicKeyPem } from "./keys";
import { MAX_LINE_BYTES, MAX_NAME_LENGTH, MAX_PAYLOAD_BYTES } from "./wire";
import { checkAsync, makeClerkFixture, rejects, runAll, section, startChildClerkd } from "./test-support";
import type { ChildClerkd, ClerkFixture } from "./test-support";

/** Holds the first request; on the second, submits the second THEN the first. */
class ReorderingClient implements ClerkSubmitClient {
  private held:
    | { req: ClerkSubmitRequest; resolve: (r: ClerkSubmissionReceipt) => void; reject: (e: unknown) => void }
    | undefined;

  constructor(private readonly inner: ClerkSubmitClient) {}

  submit(req: ClerkSubmitRequest): Promise<ClerkSubmissionReceipt> {
    if (this.held === undefined) {
      return new Promise((resolve, reject) => {
        this.held = { req, resolve, reject };
      });
    }
    const first = this.held;
    this.held = undefined;
    return this.inner.submit(req).then(async (second) => {
      try {
        first.resolve(await this.inner.submit(first.req));
      } catch (err) {
        first.reject(err);
      }
      return second;
    });
  }
}

/** The exact payload L0 submitted for an entry (what payload_commitment binds). */
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

const common = { moduleId: "m", provenanceTag: "LaneA" as const, parameters: {}, outcome: "ok" };

let fx: ClerkFixture;
let child: ChildClerkd | undefined;
let clerkKey: string;
let logPath: string;
let r0: ClerkSubmissionReceipt;

function route(client: ClerkSubmitClient, key: string = clerkKey): ClerkRoute {
  return { client, submitterId: "ilas-l0", channel: "ilas-evidence", clerkPublicKeyPem: key };
}

section("A real clerk in a separate process stamps L0");

checkAsync("ILAS reads the clerk's key from the clerk's own key file", async () => {
  fx = makeClerkFixture();
  logPath = join(fx.dir, "l0.jsonl");
  clerkKey = loadPublicKeyPem(fx.publicKeyPath);
  assert.equal(clerkKey, fx.publicKeyPem, "the key file is not the key the clerk was made with");
  child = await startChildClerkd(fx.configPath);
});

checkAsync("receipts return in reverse order; L0 still commits in call order", async () => {
  const socket = new SocketClerkClient({ socketPath: fx.socketPath, timeoutMs: 10_000 });
  const log = new LockedEvidenceLog({ path: logPath, clerk: route(new ReorderingClient(socket)) });
  const a = log.append({ ...common, timestamp: 1_000, eventType: "a" });
  const b = log.append({ ...common, timestamp: 2_000, eventType: "b" });
  await Promise.all([a, b]);
  await log.settle();

  assert.equal(log.length, 2);
  const [e0, e1] = log.getAll();
  assert.deepEqual([e0.eventType, e1.eventType], ["a", "b"], "commit order is not call order");
  r0 = e0.clerkReceipt!;
  const r1 = e1.clerkReceipt!;
  assert.equal(r0.separation, "SEPARATE_PROCESS");
  assert.equal(r0.intake, "SOCKET");
  assert.ok(r0.clerk_seq > r1.clerk_seq, "the harness did not reverse the clerk's order");
});

checkAsync("every receipt verifies against the clerk's key, bound to its own entry", async () => {
  const log = new LockedEvidenceLog({ path: logPath });
  for (const e of log.getAll()) {
    const v = verifyClerkReceipt(
      e.clerkReceipt as unknown as Record<string, unknown>,
      clerkKey,
      payloadOf(e)
    );
    assert.ok(v.ok, `seq ${e.sequenceNumber}: ${v.reason}`);
  }
});

checkAsync("the clerk's book verifies against the same key", async () => {
  const book = verifyBookFile(fx.bookPath, clerkKey);
  assert.ok(book.ok, book.reason);
  assert.equal(book.count, 2);
});

section("The durable L0 file reloads with its receipts");

checkAsync("reload ⇒ LOADED_VERIFIED, verify() valid, clerk stamps readable", async () => {
  const reloaded = new LockedEvidenceLog({ path: logPath });
  assert.equal(reloaded.getLoadState(), "LOADED_VERIFIED");
  assert.equal(reloaded.verify().valid, true);
  const stamps = reloaded.getClerkClockSource();
  assert.equal(stamps.length, 2);
  assert.deepEqual(
    stamps.map((s) => s.sequenceNumber),
    [0, 1]
  );
  assert.equal(stamps[0].clerk_seq, r0.clerk_seq);
  assert.ok(stamps.every((s) => s.separation === "SEPARATE_PROCESS" && s.intake === "SOCKET"));
});

section("Refusals leave L0 unchanged, for the reason they name");

checkAsync("clerk unavailable ⇒ refused as a submission failure", async () => {
  const log = new LockedEvidenceLog({
    clerk: route({ submit: async () => { throw new Error("clerk unavailable"); } }),
  });
  const err = await rejects(log.append({ ...common, timestamp: 3_000, eventType: "c" }));
  assert.ok(err instanceof L0ClerkError);
  assert.match(err.message, /clerk submission failed/);
  assert.equal(log.length, 0);
});

checkAsync("SEPARATE_PROCESS claimed over LOCAL_CALL ⇒ refused as mismatched", async () => {
  const log = new LockedEvidenceLog({
    clerk: route({
      submit: async () => ({ ...r0, declared_timestamp: 4_000, separation: "SEPARATE_PROCESS", intake: "LOCAL_CALL" }),
    }),
  });
  const err = await rejects(log.append({ ...common, timestamp: 4_000, eventType: "d" }));
  assert.ok(err instanceof L0ClerkError);
  assert.match(err.message, /malformed or mismatched receipt/);
  assert.equal(log.length, 0);
});

checkAsync("a valid receipt replayed for a different entry ⇒ refused by the payload binding", async () => {
  const log = new LockedEvidenceLog({ clerk: route({ submit: async () => r0 }) });
  // Same timestamp as r0's entry, different content: only the binding can tell.
  const err = await rejects(log.append({ ...common, timestamp: 1_000, eventType: "not-a" }));
  assert.ok(err instanceof L0ClerkError);
  assert.match(err.message, /payload_commitment does not match/);
  assert.equal(log.length, 0);
});

checkAsync("the real clerk, but ILAS given a WRONG key ⇒ refused on the signature", async () => {
  const wrong = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }) as string;
  const socket = new SocketClerkClient({ socketPath: fx.socketPath, timeoutMs: 10_000 });
  const log = new LockedEvidenceLog({ clerk: route(socket, wrong) });
  const err = await rejects(log.append({ ...common, timestamp: 5_000, eventType: "e" }));
  assert.ok(err instanceof L0ClerkError);
  assert.match(err.message, /signature does not verify/);
  assert.equal(log.length, 0);
  // The clerk did book that arrival: it signed what it received. The node
  // refused it, so the two records now differ by one receipt, which an
  // operator can see by comparing the book with the log (spec §7.4).
  assert.equal(verifyBookFile(fx.bookPath, clerkKey).count, 3);
});

checkAsync("no key at all ⇒ the log cannot even be built", async () => {
  const socket = new SocketClerkClient({ socketPath: fx.socketPath, timeoutMs: 10_000 });
  const { clerkPublicKeyPem: _none, ...noKey } = route(socket);
  let err: unknown = null;
  try {
    new LockedEvidenceLog({ clerk: noKey as ClerkRoute });
  } catch (e) {
    err = e;
  }
  assert.ok(err instanceof L0ClerkError, "a route without the clerk's key was accepted");
  assert.match((err as Error).message, /clerkPublicKeyPem/);
});

section("Payload size: L0 refuses what the socket client could not deliver");

// The longest names and timestamp a request can carry (wire.ts, MAX_PAYLOAD_BYTES):
// every code unit of each name is 6 bytes in JSON, the timestamp 25.
const WORST_SUBMITTER = "\u0001".repeat(MAX_NAME_LENGTH);
const WORST_CHANNEL = "\ud800".repeat(MAX_NAME_LENGTH);
const WORST_TIMESTAMP = -0.0000012345678901234567;

/** An L0 entry whose canonical payload (what L0 measures and submits) is exactly `bytes` bytes. */
function entryOfSize(bytes: number, eventType: string) {
  const at = (pad: string) => ({ ...common, timestamp: WORST_TIMESTAMP, eventType, parameters: { pad } });
  const base = Buffer.byteLength(canonicalise(at("")), "utf8");
  const e = at("x".repeat(bytes - base));
  assert.equal(Buffer.byteLength(canonicalise(e), "utf8"), bytes);
  return e;
}

/** The socket client, recording the byte length of every request line it is asked to send. */
function measuring(socket: SocketClerkClient, lines: number[], declare = true): ClerkSubmitClient {
  const submit = (req: ClerkSubmitRequest) => {
    // The line encodeRequest writes (same fields, same order), measured even when it is too long to send.
    const { submitter_id, channel, declared_timestamp = null, payload } = req;
    lines.push(Buffer.byteLength(JSON.stringify({ submitter_id, channel, declared_timestamp, payload }), "utf8"));
    return socket.submit(req);
  };
  return declare ? { maxPayloadBytes: socket.maxPayloadBytes, submit } : { submit };
}

function bigRoute(client: ClerkSubmitClient): ClerkRoute {
  return { client, submitterId: WORST_SUBMITTER, channel: WORST_CHANNEL, clerkPublicKeyPem: clerkKey };
}

checkAsync("at maxPayloadBytes and one byte under, with the longest names and timestamp, entries commit; the line is exactly MAX_LINE_BYTES", async () => {
  const socket = new SocketClerkClient({ socketPath: fx.socketPath, timeoutMs: 10_000 });
  assert.equal(socket.maxPayloadBytes, MAX_PAYLOAD_BYTES);
  const lines: number[] = [];
  const bigLog = join(fx.dir, "l0-big.jsonl");
  const log = new LockedEvidenceLog({ path: bigLog, clerk: bigRoute(measuring(socket, lines)) });
  const booked = verifyBookFile(fx.bookPath, clerkKey).count;
  await log.append(entryOfSize(MAX_PAYLOAD_BYTES - 1, "under"));
  await log.append(entryOfSize(MAX_PAYLOAD_BYTES, "at"));
  assert.deepEqual(lines, [MAX_LINE_BYTES - 1, MAX_LINE_BYTES]);
  assert.equal(log.length, 2);
  assert.equal(verifyBookFile(fx.bookPath, clerkKey).count, booked + 2);
  const reloaded = new LockedEvidenceLog({ path: bigLog });
  assert.equal(reloaded.getLoadState(), "LOADED_VERIFIED");
  assert.deepEqual(reloaded.getAll().map((e) => e.eventType), ["under", "at"]);
});

checkAsync("one byte over is refused with L0PayloadError before submitting; nothing is booked or committed, and the log goes on", async () => {
  const socket = new SocketClerkClient({ socketPath: fx.socketPath, timeoutMs: 10_000 });
  const lines: number[] = [];
  const log = new LockedEvidenceLog({ clerk: bigRoute(measuring(socket, lines)) });
  const booked = verifyBookFile(fx.bookPath, clerkKey).count;
  const err = await rejects(log.append(entryOfSize(MAX_PAYLOAD_BYTES + 1, "over")));
  assert.ok(err instanceof L0PayloadError, `got ${err.name}: ${err.message}`);
  assert.match(err.message, new RegExp(`${MAX_PAYLOAD_BYTES + 1} bytes .* at most ${MAX_PAYLOAD_BYTES}`));
  assert.deepEqual(lines, [], "the refused entry reached the client");
  assert.equal(log.length, 0);
  assert.equal(verifyBookFile(fx.bookPath, clerkKey).count, booked);
  // Not a stop: the next entry, at the limit, goes through the same route.
  await log.append(entryOfSize(MAX_PAYLOAD_BYTES, "after"));
  assert.equal(log.length, 1);
  assert.equal(log.getAll()[0].eventType, "after");
  assert.equal(verifyBookFile(fx.bookPath, clerkKey).count, booked + 1);
});

checkAsync("without the declared limit, the same entry stops the log instead (why the client declares it)", async () => {
  const socket = new SocketClerkClient({ socketPath: fx.socketPath, timeoutMs: 10_000 });
  const lines: number[] = [];
  const log = new LockedEvidenceLog({ clerk: bigRoute(measuring(socket, lines, false)) });
  const err = await rejects(log.append(entryOfSize(MAX_PAYLOAD_BYTES + 1, "over")));
  assert.ok(err instanceof L0ClerkError, `got ${err.name}: ${err.message}`);
  assert.match(err.message, /at most 1048576 bytes per line/);
  assert.deepEqual(lines, [MAX_LINE_BYTES + 1]);
  const next = await rejects(log.append({ ...common, timestamp: 6_000, eventType: "small" }));
  assert.ok(next instanceof L0ClerkError, "the log did not stop");
});

checkAsync("clerkd stops cleanly", async () => {
  const done = await child!.stop("SIGTERM");
  child = undefined;
  assert.equal(done.code, 0, `clerkd exit ${done.code} ${done.signal}`);
});

runAll();
