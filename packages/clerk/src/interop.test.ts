// ──────────────────────────────────────────────────────────────────────────────
// Reference clerk — interop with ILAS core.
//   npx ts-node packages/clerk/src/interop.test.ts
//
// ILAS's LockedEvidenceLog, with a ClerkRoute whose client is this package's
// SocketClerkClient, against clerkd started as a SEPARATE CHILD PROCESS via
// the CLI (`cli.ts run --config ...`). Also ILASKillStack.create() end to end
// with the socket client and with the in-process client.
//
// The child runs under the same OS account as this test. That is enough to
// show the wire works across a process boundary; it shows nothing about
// independence, which is a deployment fact.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { existsSync, readFileSync } from "fs";
import { userInfo } from "os";
import { join } from "path";
import { LockedEvidenceLog, L0ClerkError } from "../../../src/l0/index";
import type { ClerkRoute } from "../../../src/l0/index";
import { verifyClerkReceipt } from "../../../src/l0/clerk-verify";
import { ILASKillStack } from "../../../src/index";
import type { LogEntry } from "../../../src/types";
import { verifyBookFile } from "./book";
import { main } from "./cli";
import { InProcessClerkClient, SocketClerkClient } from "./client";
import { generateClerkKeyFiles, loadClerkPrivateKey } from "./keys";
import {
  checkAsync,
  entry,
  makeClerkFixture,
  rejects,
  runAll,
  section,
  startChildClerkd,
  tempDir,
} from "./test-support";
import type { ChildClerkd, ClerkFixture } from "./test-support";

function routeFor(f: ClerkFixture, publicKeyPem = f.publicKeyPem): ClerkRoute {
  return {
    client: new SocketClerkClient({ socketPath: f.socketPath, timeoutMs: 10_000 }),
    submitterId: "ilas-node",
    channel: "l0-evidence",
    clerkPublicKeyPem: publicKeyPem,
  };
}

/** The payload L0 submitted for an entry: the entry minus what L0 adds. */
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

function assertEveryReceiptVerifies(entries: readonly LogEntry[], publicKeyPem: string): void {
  for (const e of entries) {
    assert.ok(e.clerkReceipt, `entry ${e.sequenceNumber} has no receipt`);
    const v = verifyClerkReceipt(
      e.clerkReceipt as unknown as Record<string, unknown>,
      publicKeyPem,
      payloadOf(e)
    );
    assert.ok(v.ok, `entry ${e.sequenceNumber}: ${v.reason}`);
  }
}

let fx: ClerkFixture;
let child: ChildClerkd | null = null;
let log: LockedEvidenceLog;
const bootIds: string[] = [];

section("clerkd as a separate child process");

checkAsync("clerkd starts from the CLI and says where it listens", async () => {
  fx = makeClerkFixture({ allowed_submitters: ["ilas-node"] });
  child = await startChildClerkd(fx.configPath);
  assert.ok(existsSync(fx.socketPath));
  assert.match(child.stdout.join(""), /next clerk_seq 0/);
  assert.notEqual(child.child.pid, process.pid);
}, 90_000);

checkAsync("several appends through the socket all commit; every receipt verifies; log.verify() is valid", async () => {
  log = new LockedEvidenceLog({ clerk: routeFor(fx) });
  for (let i = 0; i < 3; i++) await log.append(entry(i));
  // and a burst, not awaited one by one
  await Promise.all([log.append(entry(3)), log.append(entry(4)), log.append(entry(5))]);
  assert.equal(log.length, 6);
  assert.deepEqual(log.getAll().map((e) => e.parameters.n), [0, 1, 2, 3, 4, 5]);
  assert.deepEqual(log.getAll().map((e) => e.clerkReceipt!.clerk_seq), [0, 1, 2, 3, 4, 5]);
  assertEveryReceiptVerifies(log.getAll(), fx.publicKeyPem);
  assert.equal(log.verify().valid, true);
  const r = log.getEntry(0)!.clerkReceipt!;
  assert.equal(r.separation, "SEPARATE_PROCESS");
  assert.equal(r.intake, "SOCKET");
  assert.equal(r.separation_warning, null);
  assert.equal(r.clerk_principal, userInfo().username);
  bootIds.push(r.clerk_boot_id);
});

checkAsync("the clerk's book holds the same receipts L0 retained", async () => {
  const lines = readFileSync(fx.bookPath, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(lines.length, 6);
  lines.forEach((r, i) => assert.deepEqual(r, log.getEntry(i)!.clerkReceipt));
});

checkAsync("a wrong clerk public key on the route ⇒ the append is refused, nothing commits", async () => {
  const stranger = generateClerkKeyFiles(join(tempDir(), "k"));
  const wrong = new LockedEvidenceLog({ clerk: routeFor(fx, stranger.publicKeyPem) });
  const bookBefore = verifyBookFile(fx.bookPath, fx.publicKeyPem).count;
  const err = await rejects(wrong.append(entry(100)));
  assert.ok(err instanceof L0ClerkError, `got ${err.name}`);
  assert.match(err.message, /signature does not verify/);
  assert.equal(wrong.length, 0);
  // The clerk did its part: it booked and signed the submission. The node
  // refused the receipt afterwards. A clerk's book can therefore hold receipts
  // the node never committed; on the node's side they show as clerk_seq gaps.
  assert.equal(verifyBookFile(fx.bookPath, fx.publicKeyPem).count, bookBefore + 1);
});

checkAsync("a submitter id not on the clerk's list ⇒ L0ClerkError naming the refusal", async () => {
  const other = new LockedEvidenceLog({ clerk: { ...routeFor(fx), submitterId: "intruder" } });
  const err = await rejects(other.append(entry(101)));
  assert.ok(err instanceof L0ClerkError);
  assert.match(err.message, /not on this clerk's list/);
  assert.equal(other.length, 0);
});

checkAsync("SIGTERM stops clerkd cleanly: exit 0, socket removed, book verifies", async () => {
  const before = verifyBookFile(fx.bookPath, fx.publicKeyPem);
  const { code } = await child!.stop("SIGTERM");
  child = null;
  assert.equal(code, 0);
  assert.equal(existsSync(fx.socketPath), false, "socket left behind");
  assert.equal(existsSync(`${fx.bookPath}.lock`), false, "lock left behind");
  const v = verifyBookFile(fx.bookPath, fx.publicKeyPem);
  assert.ok(v.ok, v.reason);
  assert.equal(v.count, before.count);
}, 30_000);

checkAsync("clerk not running ⇒ L0ClerkError, nothing commits", async () => {
  const down = new LockedEvidenceLog({ clerk: routeFor(fx) });
  const err = await rejects(down.append(entry(200)));
  assert.ok(err instanceof L0ClerkError, `got ${err.name}`);
  assert.match(err.message, /cannot reach the clerk/);
  assert.equal(down.length, 0);
});

checkAsync("clerk restarted ⇒ clerk_seq continues, the chain links across, the book verifies", async () => {
  // 6 receipts this log committed + 1 the wrong-key log was refused = 7.
  const stopped = verifyBookFile(fx.bookPath, fx.publicKeyPem);
  assert.equal(stopped.count, 7);
  child = await startChildClerkd(fx.configPath);
  assert.match(child.stdout.join(""), /next clerk_seq 7/);
  const committed = await log.append(entry(6));
  const r = committed.clerkReceipt!;
  assert.equal(r.clerk_seq, 7, "the sequence restarted instead of continuing");
  assert.equal(r.prev_receipt_hash, stopped.head, "the first receipt after restart does not link to the book head");
  assert.notEqual(r.clerk_boot_id, bootIds[0], "a restart must have a new boot id");
  bootIds.push(r.clerk_boot_id);
  assert.equal(log.verify().valid, true);
  assertEveryReceiptVerifies(log.getAll(), fx.publicKeyPem);
  const v = verifyBookFile(fx.bookPath, fx.publicKeyPem);
  assert.ok(v.ok, v.reason);
  assert.equal(v.count, 8);
}, 90_000);

checkAsync("clerk killed hard (SIGKILL) ⇒ a new start clears the stale socket and lock and continues", async () => {
  const { signal } = await child!.stop("SIGKILL");
  child = null;
  assert.equal(signal, "SIGKILL");
  assert.ok(existsSync(fx.socketPath), "SIGKILL should leave the socket file");
  assert.ok(existsSync(`${fx.bookPath}.lock`), "SIGKILL should leave the lock file");
  child = await startChildClerkd(fx.configPath);
  const committed = await log.append(entry(7));
  assert.equal(committed.clerkReceipt!.clerk_seq, 8);
  assert.equal(log.verify().valid, true);
  assert.ok(verifyBookFile(fx.bookPath, fx.publicKeyPem).ok);
}, 90_000);

checkAsync("a durable L0 log with a clerk route reloads as LOADED_VERIFIED, receipts intact", async () => {
  const path = join(tempDir(), "l0.jsonl");
  const a = new LockedEvidenceLog({ path, clerk: routeFor(fx) });
  await a.append(entry(300));
  await a.append(entry(301));
  const b = new LockedEvidenceLog({ path, clerk: routeFor(fx) });
  assert.equal(b.getLoadState(), "LOADED_VERIFIED");
  assert.equal(b.length, 2);
  assertEveryReceiptVerifies(b.getAll(), fx.publicKeyPem);
  await b.append(entry(302));
  assert.equal(b.verify().valid, true);
});

// ── ILASKillStack end to end ─────────────────────────────────────────────────

section("ILASKillStack.create() with a clerk route");

checkAsync("socket client: create() settles every bootstrap receipt; status carries the declaration", async () => {
  const stack = await ILASKillStack.create({
    clerk: routeFor(fx),
    declarations: { clerk: "self-operated" },
  });
  const entries = stack.log.getAll();
  assert.ok(entries.length >= 10, `expected the bootstrap entries, saw ${entries.length}`);
  assertEveryReceiptVerifies(entries, fx.publicKeyPem);
  assert.equal(stack.log.verify().valid, true);
  const status = stack.status();
  assert.equal(status.declarations.clerk, "self-operated");
  assert.equal(status.declarations.verified, false);
  assert.deepEqual(status.declarations.warnings, []);
  // The operator compares this with what the clerk's own CLI prints for its key.
  const printed: string[] = [];
  const code = await main(["fingerprint", "--pub", fx.publicKeyPath], { out: (l) => printed.push(l), err: () => undefined });
  assert.equal(code, 0);
  assert.equal(status.declarations.keys.clerk, printed.join("\n"), "status() and `clerk fingerprint` name different keys");
  assert.ok(entries.every((e) => e.clerkReceipt!.separation === "SEPARATE_PROCESS"));
  // Work after start-up also goes through the clerk.
  const before = stack.log.length;
  stack.canary.plantCanary("medium");
  await stack.settleEvidence();
  assert.ok(stack.log.length > before, "planting a canary appended nothing");
  assertEveryReceiptVerifies(stack.log.getAll(), fx.publicKeyPem);
}, 60_000);

checkAsync("in-process client: create() works; receipts say IN_PROCESS_NO_SEPARATION", async () => {
  const dir = tempDir();
  const keys = generateClerkKeyFiles(join(dir, "keys"));
  const client = InProcessClerkClient.open({
    clerkId: "in-process",
    privateKey: loadClerkPrivateKey(keys.privateKeyPath),
    bookPath: join(dir, "book.jsonl"),
  });
  try {
    const stack = await ILASKillStack.create({
      clerk: { client, submitterId: "ilas-node", channel: "l0", clerkPublicKeyPem: keys.publicKeyPem },
      declarations: { clerk: "self-operated" },
    });
    const entries = stack.log.getAll();
    assert.ok(entries.length >= 10);
    assertEveryReceiptVerifies(entries, keys.publicKeyPem);
    for (const e of entries) {
      assert.equal(e.clerkReceipt!.separation, "IN_PROCESS_NO_SEPARATION");
      assert.equal(e.clerkReceipt!.intake, "LOCAL_CALL");
      assert.match(e.clerkReceipt!.separation_warning ?? "", /no separation/);
    }
    assert.equal(stack.log.verify().valid, true);
    assert.equal(stack.status().declarations.clerk, "self-operated");
    assert.equal(verifyBookFile(join(dir, "book.jsonl"), keys.publicKeyPem).count, entries.length);
  } finally {
    client.close();
  }
});

section("Teardown");

checkAsync("the child clerkd stops with exit code 0", async () => {
  const { code } = await child!.stop("SIGTERM");
  child = null;
  assert.equal(code, 0);
  assert.ok(verifyBookFile(fx.bookPath, fx.publicKeyPem).ok);
}, 30_000);

runAll(600_000);
