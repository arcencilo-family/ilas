// ──────────────────────────────────────────────────────────────────────────────
// Reference witness ⇄ ILAS core, in-process.
//   npx ts-node packages/witness/src/interop.test.ts
//
// The node side is ILAS core, unchanged: LockedEvidenceLog, HeadCommitEmitter,
// FileDropWitness (the file-drop client, configured with this witness's public
// key) and ContinuityVerifier. The witness side is this package. They share
// nothing but directories, the wire format, and a public key file.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { mkdirSync, readdirSync, writeFileSync } from "fs";
import { join } from "path";

import { LockedEvidenceLog } from "../../../src/l0";
import {
  ContinuityVerifier,
  FileDropWitness,
  HeadCommitEmitter,
  MAX_SUBMITTER_ID_BYTES as CLIENT_MAX_SUBMITTER_ID_BYTES,
  submitterIdProblem as clientSubmitterIdProblem,
} from "../../../src/s4";
import { ILASKillStack } from "../../../src/index";

import {
  MAX_SUBMITTER_ID_BYTES as WITNESS_MAX_SUBMITTER_ID_BYTES,
  submitterIdProblem as witnessSubmitterIdProblem,
} from "./commit";
import { ConfigError, parseConfig } from "./config";
import type { WitnessConfig } from "./config";
import { generateKeyFiles, loadPrivateKeyFile } from "./keys";
import { betweenTests, cleanUp, tempDir } from "./test-support";
import { ReferenceWitness } from "./witness";

let passed = 0;
let failed = 0;
const pending: Array<() => Promise<void>> = [];

function section(title: string): void {
  pending.push(async () => {
    console.log(`── ${title} ──`);
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

// Removed however the run ends, SIGINT and SIGTERM included (test-support).
const ROOT = tempDir("ilas-witness-interop-");
let counter = 0;

function entry(n: number, outcome = "ok") {
  return {
    timestamp: 1_700_000_000_000 + n,
    moduleId: "test",
    eventType: "unit",
    provenanceTag: "LaneA" as const,
    parameters: { n },
    outcome,
  };
}

/** A log holding entries 0..n-1; `alter` changes the outcome of one entry. */
async function chain(n: number, alter?: number): Promise<LockedEvidenceLog> {
  const log = new LockedEvidenceLog();
  for (let i = 0; i < n; i++) await log.append(entry(i, i === alter ? "REWRITTEN" : "ok"));
  return log;
}

interface Wire {
  /** The shared intake. */
  readonly intake: string;
  readonly pubPath: string;
  readonly privPath: string;
  readonly otherPubPath: string;
  readonly witness: ReferenceWitness;
  outbox(id: string): string;
  /** Where `id`'s client writes: its own intake when the wire has them, else the shared one. */
  intakeOf(id: string): string;
  client(id: string, publicKeyPath?: string, outboxOf?: string): FileDropWitness;
}

/**
 * A witness serving `ids`, with its key made by the package's own keygen. With
 * `ownIntakes`, every submitter also gets an intake directory of its own (the
 * shared intake stays configured, so that anything dropped there is seen).
 */
function wire(ids: string[], options: { ownIntakes?: boolean } = {}): Wire {
  const dir = join(ROOT, `wire-${counter++}`);
  const intake = join(dir, "intake");
  mkdirSync(intake, { recursive: true });
  mkdirSync(join(dir, "store"), { recursive: true });
  const outboxes = new Map(ids.map((id) => [id, join(dir, "outbox", id)]));
  for (const o of outboxes.values()) mkdirSync(o, { recursive: true });
  const ownIntakes = new Map<string, string>();
  if (options.ownIntakes === true) {
    for (const id of ids) {
      const own = join(dir, `intake-${id}`);
      mkdirSync(own);
      ownIntakes.set(id, own);
    }
  }
  const keys = generateKeyFiles(join(dir, "keys"));
  const other = generateKeyFiles(join(dir, "other-keys"));
  const config: WitnessConfig = {
    witnessSetId: "set-a",
    intakeDir: intake,
    storePath: join(dir, "store", "witness-store.jsonl"),
    privateKeyPath: keys.privateKeyPath,
    submitters: ids.map((id) => {
      const own = ownIntakes.get(id);
      return own === undefined
        ? { id, outboxDir: outboxes.get(id)! }
        : { id, outboxDir: outboxes.get(id)!, intakeDir: own };
    }),
    pollIntervalMs: 1000,
  };
  const witness = ReferenceWitness.open({
    config,
    privateKey: loadPrivateKeyFile(keys.privateKeyPath),
  });
  const intakeOf = (id: string): string => ownIntakes.get(id) ?? intake;
  return {
    intake,
    pubPath: keys.publicKeyPath,
    privPath: keys.privateKeyPath,
    otherPubPath: other.publicKeyPath,
    witness,
    outbox: (id) => outboxes.get(id)!,
    intakeOf,
    client: (id, publicKeyPath = keys.publicKeyPath, outboxOf = id) =>
      new FileDropWitness({
        id: "set-a",
        intakeDir: intakeOf(id),
        outboxDir: outboxes.get(outboxOf)!,
        submitterId: id,
        publicKeyPath,
      }),
  };
}

/**
 * A node that appends `count` entries, emitting a HEAD_COMMIT after each and
 * letting the witness process the intake between emits. Returns the node's log.
 */
async function runNode(
  w: Wire,
  id: string,
  count: number
): Promise<{ log: LockedEvidenceLog; emitter: HeadCommitEmitter }> {
  const log = new LockedEvidenceLog();
  const emitter = new HeadCommitEmitter(log, w.client(id));
  for (let i = 0; i < count; i++) {
    await log.append(entry(i));
    emitter.emit();
    const events = w.witness.pollOnce();
    assert.deepEqual(events.map((e) => e.kind), ["RETAINED"], `poll after emit ${i}`);
  }
  return { log, emitter };
}

// ── one node ──────────────────────────────────────────────────────────────────

section("one node: emits, witness processes between them, client verifies");

checkAsync("VERIFIED_HISTORICAL with one receipt per distinct head", async () => {
  const w = wire(["node-a"]);
  const { log, emitter } = await runNode(w, "node-a", 5);

  // A cadence emit with no new entries re-sends the same head: no new receipt.
  emitter.emit();
  assert.deepEqual(w.witness.pollOnce().map((e) => e.kind), ["DUPLICATE"]);
  assert.deepEqual(readdirSync(w.intake), [], "every commit was consumed");

  const client = w.client("node-a");
  const report = new ContinuityVerifier(log, client).verify();
  assert.equal(report.status, "VERIFIED_HISTORICAL");
  assert.equal(report.receiptsChecked, 5);
  const d = client.getLastFetchDiagnostics();
  assert.deepEqual(
    { found: d.found, verified: d.verified, dropped: d.dropped },
    { found: 5, verified: 5, dropped: 0 },
    `client diagnostics: ${JSON.stringify(d.dropReasons)}`
  );
});

checkAsync("the node's chain rebuilt SHORTER ⇒ MISMATCH", async () => {
  const w = wire(["node-a"]);
  await runNode(w, "node-a", 6);
  const shorter = await chain(3);
  const report = new ContinuityVerifier(shorter, w.client("node-a")).verify();
  assert.equal(report.status, "MISMATCH");
  assert.deepEqual(
    report.mismatches.map((m) => m.seq_no),
    [3, 4, 5],
    "every receipt beyond the rebuilt end is a finding"
  );
});

checkAsync("the node's chain rebuilt DIFFERENT ⇒ MISMATCH from the altered entry on", async () => {
  const w = wire(["node-a"]);
  await runNode(w, "node-a", 6);
  const different = await chain(6, 2);
  const report = new ContinuityVerifier(different, w.client("node-a")).verify();
  assert.equal(report.status, "MISMATCH");
  assert.deepEqual(report.mismatches.map((m) => m.seq_no), [2, 3, 4, 5]);
});

checkAsync("a rewritten node that keeps emitting: both heads at one seq_no are signed; still MISMATCH", async () => {
  const w = wire(["node-a"]);
  await runNode(w, "node-a", 4);
  const rewritten = await chain(4, 1);
  new HeadCommitEmitter(rewritten, w.client("node-a")).emit();
  const events = w.witness.pollOnce();
  assert.equal(events.length, 1);
  const e = events[0];
  assert.ok(e.kind === "RETAINED", `expected RETAINED, got ${e.kind}`);
  if (e.kind === "RETAINED") {
    assert.equal(e.seq_no, 3);
    assert.deepEqual(e.conflicts.map((c) => c.kind), ["SAME_SEQ_DIFFERENT_HEAD"]);
  }
  const report = new ContinuityVerifier(rewritten, w.client("node-a")).verify();
  assert.equal(report.receiptsChecked, 5, "the rewrite's own receipt is returned too");
  assert.equal(report.status, "MISMATCH", "the earlier receipts do not reproduce on the rewrite");
  assert.deepEqual(report.mismatches.map((m) => m.seq_no), [1, 2, 3]);
});

checkAsync("client configured with the WRONG public key ⇒ REJECTED_RECEIPTS (a usable key refused every receipt)", async () => {
  const w = wire(["node-a"]);
  const { log } = await runNode(w, "node-a", 4);
  const client = w.client("node-a", w.otherPubPath);
  const report = new ContinuityVerifier(log, client).verify();
  assert.equal(report.status, "REJECTED_RECEIPTS", "a key that checks and refuses is a finding, not silence");
  assert.equal(report.receiptsChecked, 0);
  assert.equal(report.rejectedReceipts, 4);
  assert.ok(report.rejectReasons.every((r) => r.includes("does not verify")), JSON.stringify(report.rejectReasons));
  const d = client.getLastFetchDiagnostics();
  assert.equal(d.found, 4);
  assert.equal(d.dropped, 4, "every genuine receipt is dropped under the wrong key");
});

checkAsync("client with NO public key ⇒ CANNOT_VERIFY_CONTINUITY (nothing could be checked)", async () => {
  const w = wire(["node-a"]);
  const { log } = await runNode(w, "node-a", 2);
  const client = new FileDropWitness({
    id: "set-a",
    intakeDir: w.intake,
    outboxDir: w.outbox("node-a"),
    submitterId: "node-a",
  });
  const report = new ContinuityVerifier(log, client).verify();
  assert.equal(report.status, "CANNOT_VERIFY_CONTINUITY");
  assert.equal(report.rejectedReceipts, 0);
});

checkAsync("client given the witness's PRIVATE key file as its public key ⇒ refused, CANNOT_VERIFY_CONTINUITY", async () => {
  const w = wire(["node-a"]);
  const { log } = await runNode(w, "node-a", 2);
  const client = w.client("node-a", w.privPath);
  const report = new ContinuityVerifier(log, client).verify();
  assert.equal(report.status, "CANNOT_VERIFY_CONTINUITY", "the misplaced key is not used");
  assert.equal(report.receiptsChecked, 0);
  const d = client.getLastFetchDiagnostics();
  assert.equal(d.keyAvailable, false);
  assert.ok(d.dropReasons.some((r) => /PRIVATE key/.test(r)), JSON.stringify(d.dropReasons));
});

checkAsync("an EMPTY chain's commit (seq -1, genesis hash) is retained and reproduces, before and after appends", async () => {
  const w = wire(["node-a"]);
  const log = new LockedEvidenceLog();
  const client = w.client("node-a");
  const emitter = new HeadCommitEmitter(log, client);
  const first = emitter.emit();
  assert.equal(first.seq_no, -1);
  assert.equal(first.head_hash, "0".repeat(64));
  assert.deepEqual(w.witness.pollOnce().map((e) => e.kind), ["RETAINED"]);
  const onEmpty = new ContinuityVerifier(log, client).verify();
  assert.equal(onEmpty.status, "VERIFIED_HISTORICAL");
  assert.equal(onEmpty.receiptsChecked, 1);
  await log.append(entry(0));
  assert.equal(new ContinuityVerifier(log, client).verify().status, "VERIFIED_HISTORICAL", "-1 reproduces on any chain");
  emitter.emit();
  assert.deepEqual(w.witness.pollOnce().map((e) => e.kind), ["RETAINED"]);
  const grown = new ContinuityVerifier(log, client).verify();
  assert.equal(grown.status, "VERIFIED_HISTORICAL");
  assert.equal(grown.receiptsChecked, 2);
});

// ── two nodes ─────────────────────────────────────────────────────────────────

section("two submitters: each client sees only its own receipts");

checkAsync("interleaved nodes ⇒ separate outboxes, each VERIFIED_HISTORICAL on its own chain", async () => {
  const w = wire(["node-a", "node-b"]);
  const logA = new LockedEvidenceLog();
  const logB = new LockedEvidenceLog();
  const emitA = new HeadCommitEmitter(logA, w.client("node-a"));
  const emitB = new HeadCommitEmitter(logB, w.client("node-b"));
  for (let i = 0; i < 4; i++) {
    await logA.append(entry(i));
    await logB.append(entry(100 + i));
    await logB.append(entry(200 + i));
    emitA.emit();
    emitB.emit();
    const kinds = w.witness.pollOnce().map((e) => e.kind);
    assert.deepEqual(kinds, ["RETAINED", "RETAINED"]);
  }

  const clientA = w.client("node-a");
  const clientB = w.client("node-b");
  const receiptsA = clientA.retrieveReceipts();
  const receiptsB = clientB.retrieveReceipts();
  assert.equal(receiptsA.length, 4);
  assert.equal(receiptsB.length, 4);
  const headsA = new Set(logA.getAll().map((e) => e.hash));
  const headsB = new Set(logB.getAll().map((e) => e.hash));
  assert.ok(receiptsA.every((r) => headsA.has(r.head_hash)), "A sees only A's heads");
  assert.ok(receiptsB.every((r) => headsB.has(r.head_hash)), "B sees only B's heads");

  assert.equal(new ContinuityVerifier(logA, clientA).verify().status, "VERIFIED_HISTORICAL");
  assert.equal(new ContinuityVerifier(logB, clientB).verify().status, "VERIFIED_HISTORICAL");

  // Why the outboxes must never be shared (gap G2): B's client pointed at A's
  // outbox accepts every one of A's receipts by signature — nothing in a
  // receipt names its submitter — and then reports A's heads as B's mismatches.
  const misdirected = w.client("node-b", w.pubPath, "node-a");
  assert.equal(misdirected.retrieveReceipts().length, 4, "the signatures alone do not tell them apart");
  assert.equal(new ContinuityVerifier(logB, misdirected).verify().status, "MISMATCH");
});

/** node-a with 3 entries, one commit retained; returns its log and a verifying client. */
async function nodeAWitnessed(w: Wire): Promise<{ log: LockedEvidenceLog; client: FileDropWitness }> {
  const log = new LockedEvidenceLog();
  for (let i = 0; i < 3; i++) await log.append(entry(i));
  const client = w.client("node-a");
  new HeadCommitEmitter(log, client).emit();
  assert.deepEqual(w.witness.pollOnce().map((e) => e.kind), ["RETAINED"]);
  assert.equal(new ContinuityVerifier(log, client).verify().status, "VERIFIED_HISTORICAL");
  return { log, client };
}

const FORGED = JSON.stringify({ seq_no: 1, head_hash: "ab".repeat(32), ts: 1, witness_set_id: "set-a" }) + "\n";

checkAsync("SHARED intake: the identity is the file name, so another intake writer can submit as node-a (the known limit)", async () => {
  const w = wire(["node-a", "node-b"]);
  const { log, client } = await nodeAWitnessed(w);
  // node-b's account can write the shared intake, so it can write node-a's name.
  writeFileSync(join(w.intake, "node-a"), FORGED);
  const events = w.witness.pollOnce();
  assert.equal(events.length, 1);
  assert.ok(events[0].kind === "RETAINED" && events[0].submitterId === "node-a", "attributed to node-a");
  const report = new ContinuityVerifier(log, client).verify();
  assert.equal(report.status, "MISMATCH", "node-a's untouched chain now reads MISMATCH");
  assert.deepEqual(report.mismatches.map((m) => m.seq_no), [1]);
});

checkAsync("OWN intakes: the same attempt, in the shared intake or in node-b's own, is UNDECLARED; node-a stays VERIFIED_HISTORICAL", async () => {
  const w = wire(["node-a", "node-b"], { ownIntakes: true });
  const { log, client } = await nodeAWitnessed(w);
  assert.ok(readdirSync(w.intakeOf("node-a")).length === 0, "node-a's client wrote to its own intake, consumed");
  writeFileSync(join(w.intake, "node-a"), FORGED);
  writeFileSync(join(w.intakeOf("node-b"), "node-a"), FORGED);
  const events = w.witness.pollOnce();
  assert.deepEqual(events.map((e) => e.kind), ["UNDECLARED", "UNDECLARED"]);
  assert.equal(w.witness.records().length, 1, "nothing retained for the forgeries");
  const report = new ContinuityVerifier(log, client).verify();
  assert.equal(report.status, "VERIFIED_HISTORICAL");
  assert.equal(report.receiptsChecked, 1);
  // node-b's own client still works, through its own intake.
  const logB = await chain(2);
  const clientB = w.client("node-b");
  new HeadCommitEmitter(logB, clientB).emit();
  assert.deepEqual(w.witness.pollOnce().map((e) => e.kind), ["RETAINED"]);
  assert.equal(new ContinuityVerifier(logB, clientB).verify().status, "VERIFIED_HISTORICAL");
});

// ── the kill stack ────────────────────────────────────────────────────────────

section("wiring into ILASKillStack, as the README shows it");

checkAsync("ILASKillStack + FileDropWitness + this witness ⇒ continuity VERIFIED_HISTORICAL, declaration carried", async () => {
  const w = wire(["node-a"]);
  const stack = await ILASKillStack.create({
    witness: w.client("node-a"),
    declarations: { witness: "self-witnessed" },
  });
  assert.equal(stack.status().continuity, "CANNOT_VERIFY_CONTINUITY", "before any receipt");
  const commit = stack.emitStartupCommit();
  assert.ok(commit.seq_no >= 0, "the stack's chain is not empty at the startup commit");
  assert.deepEqual(w.witness.pollOnce().map((e) => e.kind), ["RETAINED"]);
  const status = stack.status();
  assert.equal(status.continuity, "VERIFIED_HISTORICAL");
  // ILAS names the witness key in the format the witness prints at keygen and
  // in its STARTED line: the operator compares the two by eye.
  assert.match(w.witness.startup.publicKeyFingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(status.declarations, {
    witness: "self-witnessed",
    clerk: null,
    verified: false,
    warnings: [],
    keys: { clerk: null, witness: w.witness.startup.publicKeyFingerprint },
  });
});

checkAsync("across a restart, receipts reproduce only over a DURABLE log (logPath); an in-memory chain reads MISMATCH", async () => {
  const w = wire(["node-a"]);
  const logPath = join(ROOT, `durable-${counter++}`, "l0.jsonl");
  const options = () => ({
    witness: w.client("node-a"),
    declarations: { witness: "self-witnessed" },
    logPath,
  });
  const first = await ILASKillStack.create(options());
  first.emitStartupCommit();
  assert.deepEqual(w.witness.pollOnce().map((e) => e.kind), ["RETAINED"]);
  assert.equal(first.status().continuity, "VERIFIED_HISTORICAL");

  // A restart: a new stack over the same log file.
  const restarted = await ILASKillStack.create(options());
  const st = restarted.status();
  assert.equal(st.logDurability.loadState, "LOADED_VERIFIED");
  assert.equal(st.continuity, "VERIFIED_HISTORICAL", "the retained receipt reproduces on the reloaded chain");

  // The same without logPath: every start builds a new chain, with new
  // timestamps, so the receipt retained before the restart cannot reproduce.
  const memoryWire = wire(["node-a"]);
  const memory = await ILASKillStack.create({ witness: memoryWire.client("node-a") });
  memory.emitStartupCommit();
  assert.deepEqual(memoryWire.witness.pollOnce().map((e) => e.kind), ["RETAINED"]);
  assert.equal(memory.status().continuity, "VERIFIED_HISTORICAL", "within one process it reproduces");
  await new Promise((resolve) => setTimeout(resolve, 5)); // a later clock for the rebuilt chain
  const memoryRestarted = await ILASKillStack.create({ witness: memoryWire.client("node-a") });
  assert.equal(memoryRestarted.status().logDurability.loadState, "IN_MEMORY");
  assert.equal(memoryRestarted.status().continuity, "MISMATCH");
});

// ─────────────────────────────────────────────────────────────────────────────

section("submitter ids: the witness declares exactly the ids the client can write as");

/** Ids at and around every rule of either side. */
function idCorpus(): string[] {
  const ids = [
    "node-a", "", ".", "..", "...", "a/b", "a\\b", "a\0b", ".hidden", "a.b", "a b", " ", "-", "~",
    "\ud800", "a\udc00", "\udc00\ud800", "😀", "a b", "a b", "﻿",
    "n".repeat(236), "n".repeat(237), "n".repeat(238), "n".repeat(255), "n".repeat(256),
    "€".repeat(79), "€".repeat(80), "é".repeat(118), "é".repeat(119), "😀".repeat(59), "😀".repeat(60),
  ];
  for (let code = 0; code <= 0xa0; code++) ids.push(`x${String.fromCharCode(code)}y`);
  return ids;
}

checkAsync("the witness's config rule and the client's constructor refuse the same ids", async () => {
  const base = join(ROOT, `ids-${counter++}`);
  const disagreements: string[] = [];
  const ruleMismatches: string[] = [];
  const show = (id: string): string =>
    JSON.stringify(id.length > 20 ? `${id.slice(0, 8)}…(${Buffer.byteLength(id)} bytes)` : id);
  for (const id of idCorpus()) {
    let witnessAccepts = true;
    try {
      parseConfig(
        {
          witnessSetId: "set-a",
          intakeDir: "intake",
          storePath: "store/s.jsonl",
          privateKeyPath: "keys/k",
          submitters: [{ id, outboxDir: "outbox" }],
        },
        base
      );
    } catch (error) {
      if (!(error instanceof ConfigError)) throw error;
      witnessAccepts = false;
    }
    let clientAccepts = true;
    try {
      new FileDropWitness({ id: "set-a", intakeDir: base, outboxDir: base, submitterId: id });
    } catch {
      clientAccepts = false;
    }
    if (witnessAccepts !== clientAccepts) {
      disagreements.push(`${show(id)}: witness config accepts ${witnessAccepts}, client ${clientAccepts}`);
    }
    if ((witnessSubmitterIdProblem(id) === null) !== witnessAccepts) ruleMismatches.push(`witness ${show(id)}`);
    if ((clientSubmitterIdProblem(id) === null) !== clientAccepts) ruleMismatches.push(`client ${show(id)}`);
  }
  assert.deepEqual(disagreements, [], "the witness's config and the client accept the same ids");
  assert.deepEqual(ruleMismatches, [], "each side's exported rule is the one it applies");
  assert.equal(WITNESS_MAX_SUBMITTER_ID_BYTES, CLIENT_MAX_SUBMITTER_ID_BYTES);
});

checkAsync("the longest id either side accepts (237 bytes) goes end to end: retained, VERIFIED_HISTORICAL", async () => {
  const id = "n".repeat(WITNESS_MAX_SUBMITTER_ID_BYTES);
  const w = wire([id]);
  const { log } = await runNode(w, id, 2);
  const report = new ContinuityVerifier(log, w.client(id)).verify();
  assert.equal(report.status, "VERIFIED_HISTORICAL");
  assert.equal(report.receiptsChecked, 2);
});

// ── run ──────────────────────────────────────────────────────────────────────

void (async () => {
  try {
    for (const t of pending) {
      await t();
      // A signal that arrived during a test is handled here (see test-support).
      await betweenTests();
    }
  } finally {
    cleanUp();
  }
  console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
})();
