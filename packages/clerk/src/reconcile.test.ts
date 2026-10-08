// ──────────────────────────────────────────────────────────────────────────────
// Reference clerk — `reconcile`: the clerk's book against a node's L0 log.
//   npx ts-node packages/clerk/src/reconcile.test.ts
//
// The logs here are written by ILAS's own LockedEvidenceLog through a clerk
// route, so they are exactly what a node leaves on disk. The clerk is an
// in-process core: what matters is the book it writes, not the transport.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { spawnSync } from "child_process";
import { generateKeyPairSync } from "crypto";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "fs";
import { dirname, join } from "path";
import { L0ClerkError, LockedEvidenceLog, recomputeHeadHashAt } from "../../../src/l0/index";
import type { ClerkSubmitClient } from "../../../src/l0/index";
import type { LogEntry } from "../../../src/types";
import { EXIT_GAPS, main } from "./cli";
import { InProcessClerkClient } from "./client";
import { ClerkCore } from "./core";
import { loadClerkPrivateKey } from "./keys";
import { checkAsync, makeClerkFixture, rejects, runAll, section, spawnCli } from "./test-support";
import type { ClerkFixture } from "./test-support";

async function cli(args: string[]): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(args, { out: (l) => out.push(l), err: (l) => err.push(l) });
  return { code, out: out.join("\n"), err: err.join("\n") };
}

const SUBMITTER = "node-a";
const CHANNEL = "l0";

interface Setup {
  f: ClerkFixture;
  core: ClerkCore;
  client: InProcessClerkClient;
  logPath: string;
}

function setup(): Setup {
  const f = makeClerkFixture();
  const core = ClerkCore.open({
    clerkId: "reconcile-test",
    privateKey: loadClerkPrivateKey(f.privateKeyPath),
    bookPath: f.bookPath,
    separation: "IN_PROCESS_NO_SEPARATION",
  });
  return { f, core, client: new InProcessClerkClient(core), logPath: join(f.dir, "node", "l0.jsonl") };
}

function routeOf(client: ClerkSubmitClient, key: string) {
  return { client, submitterId: SUBMITTER, channel: CHANNEL, clerkPublicKeyPem: key };
}

function entry(n: number) {
  return { timestamp: 1_700_000_000_000 + n, moduleId: "m", eventType: `e${n}`, provenanceTag: "LaneA" as const, parameters: { n }, outcome: "ok" };
}

/** A durable L0 log at `logPath` with `n` entries, each stamped by the clerk; closed again. */
async function writeLog(s: Setup, n: number, from = 0, logPath = s.logPath): Promise<void> {
  const log = new LockedEvidenceLog({ path: logPath, clerk: routeOf(s.client, s.f.publicKeyPem) });
  try {
    for (let i = from; i < from + n; i++) await log.append(entry(i));
    await log.settle();
  } finally {
    log.close();
  }
}

function args(s: Setup, logs: string[] = [s.logPath]): string[] {
  return [
    "reconcile",
    "--book", s.f.bookPath,
    ...logs.flatMap((l) => ["--log", l]),
    "--pub", s.f.publicKeyPath,
    "--submitter", SUBMITTER,
    "--channel", CHANNEL,
  ];
}

function bookLines(s: Setup): string[] {
  return readFileSync(s.f.bookPath, "utf8").trim().split("\n");
}

const ROUTE_TEXT = `submitter_id "${SUBMITTER}" on channel "${CHANNEL}"`;

section("Book and log agree");

checkAsync("every receipt on the log is in the book and the other way round ⇒ exit 0, says so", async () => {
  const s = setup();
  await writeLog(s, 3);
  // Another submitter's receipt in the same book is not this node's business.
  s.core.submit({ submitter_id: "node-b", channel: CHANNEL, payload: { other: true } });
  const r = await cli(args(s));
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(r.out, new RegExp(`book verifies: 4 receipt\\(s\\), head [0-9a-f]{64}; 3 booked for ${ROUTE_TEXT}`));
  assert.match(r.out, /l0\.jsonl: 3 entries, 3 with a clerk receipt, 0 without \(not compared\)/);
  assert.match(r.out, /on no log entry: 0$/m);
  assert.match(r.out, /not among the book's receipts for .*: 0$/m);
  assert.equal(refusedCount(r.out), 0, r.out);
  assert.match(r.out, /^no gaps:/m);
  s.core.close();
});

checkAsync("receipts spread over several logs of the node are found in each; with one log missing, the rest are gaps", async () => {
  const s = setup();
  const second = join(s.f.dir, "node", "l0-2.jsonl");
  await writeLog(s, 2);
  await writeLog(s, 2, 2, second); // a new log file, same route
  assert.equal((await cli(args(s, [s.logPath, second]))).code, 0);
  const r = await cli(args(s));
  assert.equal(r.code, EXIT_GAPS, r.out + r.err);
  assert.match(r.out, /on no log entry: 2$/m);
  assert.match(r.out, /^ {2}clerk_seq 2 {2}receipt_hash [0-9a-f]{64}$/m);
  assert.match(r.out, /^ {2}clerk_seq 3 {2}receipt_hash [0-9a-f]{64}$/m);
  s.core.close();
});

section("A receipt the clerk booked and the node never committed");

checkAsync("a receipt booked but refused by L0 ⇒ exit 3, listed by clerk_seq and receipt_hash", async () => {
  const s = setup();
  await writeLog(s, 3);
  // The node given a wrong clerk key: the clerk books, L0 refuses the receipt.
  const wrong = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }) as string;
  const refusing = new LockedEvidenceLog({ clerk: routeOf(s.client, wrong) });
  const err = await rejects(refusing.append(entry(3)));
  assert.ok(err instanceof L0ClerkError, `got ${err.name}: ${err.message}`);
  assert.equal(s.core.nextSeq, 4, "precondition: the clerk booked the refused submission");
  const refused = JSON.parse(bookLines(s)[3]) as { clerk_seq: number; receipt_hash: string };
  const r = await cli(args(s));
  assert.equal(r.code, EXIT_GAPS, r.out + r.err);
  assert.match(r.out, /on no log entry: 1$/m);
  assert.ok(r.out.includes(`\n  clerk_seq 3  receipt_hash ${refused.receipt_hash}\n`), r.out);
  assert.match(r.out, /not among the book's receipts for .*: 0$/m);
  assert.match(r.out, /^gaps: 1 booked receipt\(s\) on no log entry, 0 log entries whose receipt is not in the book/m);
  s.core.close();
});

checkAsync("entries a log holds without receipts are counted, not compared; the clerk's receipts for them are gaps", async () => {
  const s = setup();
  // A node that began its log without a clerk, while the clerk booked for it.
  const log = new LockedEvidenceLog({ path: s.logPath });
  await log.append(entry(0));
  await log.append(entry(1));
  log.close();
  s.core.submit({ submitter_id: SUBMITTER, channel: CHANNEL, payload: entry(0) });
  s.core.submit({ submitter_id: SUBMITTER, channel: CHANNEL, payload: entry(1) });
  const r = await cli(args(s));
  assert.equal(r.code, EXIT_GAPS, r.out + r.err);
  assert.match(r.out, /l0\.jsonl: 2 entries, 0 with a clerk receipt, 2 without \(not compared\)/);
  assert.match(r.out, /on no log entry: 2$/m);
  s.core.close();
});

section("A log entry whose receipt the book does not hold");

checkAsync("a book cut back after the log took its receipt ⇒ exit 3, the entry listed as not in the book", async () => {
  const s = setup();
  await writeLog(s, 3);
  s.core.close();
  const lines = bookLines(s);
  const last = JSON.parse(lines[2]) as { receipt_hash: string };
  writeFileSync(s.f.bookPath, lines.slice(0, 2).join("\n") + "\n"); // still verifies on its own
  const r = await cli(args(s));
  assert.equal(r.code, EXIT_GAPS, r.out + r.err);
  assert.match(r.out, /book verifies: 2 receipt\(s\)/);
  assert.match(r.out, /on no log entry: 0$/m);
  assert.match(r.out, /not among the book's receipts for .*: 1$/m);
  assert.ok(
    r.out.includes(`l0.jsonl entry 2 (sequenceNumber 2): clerk_seq 2, receipt_hash ${last.receipt_hash}: not in the book`),
    r.out
  );
});

section("A log entry whose receipt fails ILAS's receipt rules (L0 refuses the log)");

const REFUSED_COUNT = /fails ILAS's receipt rules for that entry and .* \(L0 refuses such a log\): (\d+)$/m;

function refusedCount(out: string): number {
  const m = REFUSED_COUNT.exec(out);
  assert.ok(m !== null, `no count of refused entries in:\n${out}`);
  return Number(m[1]);
}

/** The log's entries as parsed objects. */
function logEntries(path: string): Array<Record<string, unknown>> {
  return readFileSync(path, "utf8").trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
}

/**
 * Write `entries` to `path` as a log whose hash chain holds: sequence numbers
 * 0.., each previousHash and hash recomputed with L0's own chain rule. Only
 * the receipt rules can then tell what was changed.
 */
function writeRelinked(path: string, entries: Array<Record<string, unknown>>): void {
  for (let i = 0; i < entries.length; i++) {
    entries[i].sequenceNumber = i;
    if (i > 0) entries[i].previousHash = entries[i - 1].hash;
    const h = recomputeHeadHashAt(entries as unknown as LogEntry[], i);
    assert.ok(h !== null);
    entries[i].hash = h;
  }
  writeFileSync(path, entries.map((e) => JSON.stringify(e)).join("\n") + "\n");
}

/** How L0 itself loads the log at `path` with this node's route. */
function l0Loads(s: Setup, path: string): { loadState: string; lastError: string | null } {
  const log = new LockedEvidenceLog({ path, clerk: routeOf(s.client, s.f.publicKeyPem) });
  try {
    const d = log.getDurabilityInfo();
    return { loadState: d.loadState, lastError: d.lastError };
  } finally {
    log.close();
  }
}

checkAsync("an entry changed under its receipt, with the chain re-linked ⇒ exit 3: listed as failing the receipt check, its booking as on no entry; L0 refuses the same file", async () => {
  const s = setup();
  await writeLog(s, 3);
  const copy = join(s.f.dir, "node", "copy.jsonl");
  // Control: the same re-linking without a change is a log both accept.
  writeRelinked(copy, logEntries(s.logPath));
  assert.equal((await cli(args(s, [copy]))).code, 0);
  assert.equal(l0Loads(s, copy).loadState, "LOADED_VERIFIED");
  const entries = logEntries(s.logPath);
  entries[1].outcome = "TAMPERED";
  writeRelinked(copy, entries);
  const receipt = entries[1].clerkReceipt as { receipt_hash: string };
  const r = await cli(args(s, [copy]));
  assert.equal(r.code, EXIT_GAPS, r.out + r.err);
  assert.equal(refusedCount(r.out), 1, r.out);
  assert.ok(
    r.out.includes(
      `copy.jsonl entry 1 (sequenceNumber 1): clerk_seq 1, receipt_hash ${receipt.receipt_hash}: ` +
        `fails ILAS's receipt check: payload_commitment does not match the submitted payload`
    ),
    r.out
  );
  assert.match(r.out, /on no log entry: 1$/m);
  assert.ok(r.out.includes(`\n  clerk_seq 1  receipt_hash ${receipt.receipt_hash}\n`), r.out);
  assert.match(r.out, /not among the book's receipts for .*: 0$/m);
  assert.match(r.out, /^gaps: 1 booked receipt\(s\) on no log entry, 0 log entries whose receipt is not in the book, 1 log entry whose receipt fails ILAS's receipt rules/m);
  const l0 = l0Loads(s, copy);
  assert.equal(l0.loadState, "CANNOT_VERIFY");
  assert.match(l0.lastError ?? "", /clerk receipt check failed at index 1/);
  s.core.close();
});

checkAsync("one receipt on two entries of a log, with the chain re-linked ⇒ exit 3: the second listed as a reused receipt; L0 refuses the same file", async () => {
  const s = setup();
  await writeLog(s, 3);
  const copy = join(s.f.dir, "node", "copy.jsonl");
  const entries = logEntries(s.logPath);
  entries.push(JSON.parse(JSON.stringify(entries[1])) as Record<string, unknown>); // entry 1 again, as entry 3
  writeRelinked(copy, entries);
  const r = await cli(args(s, [copy]));
  assert.equal(r.code, EXIT_GAPS, r.out + r.err);
  assert.match(r.out, /copy\.jsonl: 4 entries, 4 with a clerk receipt/);
  assert.equal(refusedCount(r.out), 1, r.out);
  assert.match(r.out, /copy\.jsonl entry 3 \(sequenceNumber 3\): clerk_seq 1, receipt_hash [0-9a-f]{64}: the same receipt as entry 1 of this log; a receipt binds one entry/);
  assert.match(r.out, /on no log entry: 0$/m);
  const l0 = l0Loads(s, copy);
  assert.equal(l0.loadState, "CANNOT_VERIFY");
  assert.match(l0.lastError ?? "", /clerk receipt check failed at index 3: .*already committed on this log/);
  s.core.close();
});

checkAsync("a log stamped by another clerk ⇒ exit 3, each entry listed as failing the signature check", async () => {
  const s = setup();
  const other = setup();
  await writeLog(other, 2, 0, s.logPath); // the other clerk stamps this node's log
  const r = await cli(args(s));
  assert.equal(r.code, EXIT_GAPS, r.out + r.err);
  assert.equal(refusedCount(r.out), 2, r.out);
  assert.match(r.out, /not among the book's receipts for .*: 0$/m);
  assert.match(r.out, /entry 0 \(sequenceNumber 0\): clerk_seq 0, receipt_hash [0-9a-f]{64}: fails ILAS's receipt check: signature does not verify/);
  s.core.close();
  other.core.close();
});

checkAsync("a receipt this clerk signed for another submitter or channel fails the route binding ⇒ exit 3; it is never called booked", async () => {
  const s = setup();
  const log = new LockedEvidenceLog({
    path: s.logPath,
    clerk: { client: s.client, submitterId: "node-b", channel: CHANNEL, clerkPublicKeyPem: s.f.publicKeyPem },
  });
  await log.append(entry(0));
  log.close();
  const second = join(s.f.dir, "node", "l0-other-channel.jsonl");
  const log2 = new LockedEvidenceLog({
    path: second,
    clerk: { client: s.client, submitterId: SUBMITTER, channel: "other", clerkPublicKeyPem: s.f.publicKeyPem },
  });
  await log2.append(entry(1));
  log2.close();
  // A receipt for node-b from ANOTHER book, signed with this same key: this book does not hold it.
  const foreign = join(s.f.dir, "node", "l0-foreign.jsonl");
  const otherBook = InProcessClerkClient.open({
    clerkId: "same-key-other-book",
    privateKey: loadClerkPrivateKey(s.f.privateKeyPath),
    bookPath: join(s.f.dir, "other-book.jsonl"),
  });
  const log3 = new LockedEvidenceLog({
    path: foreign,
    clerk: { client: otherBook, submitterId: "node-b", channel: CHANNEL, clerkPublicKeyPem: s.f.publicKeyPem },
  });
  await log3.append(entry(2));
  log3.close();
  otherBook.close();
  const r = await cli(args(s, [s.logPath, second, foreign]));
  assert.equal(r.code, EXIT_GAPS, r.out + r.err);
  assert.equal(refusedCount(r.out), 3, r.out);
  assert.match(r.out, /l0\.jsonl entry 0 .*: submitter_id "node-b" does not name the reconciled submitter/);
  assert.match(r.out, /l0-other-channel\.jsonl entry 0 .*: channel "other" does not name the reconciled channel/);
  assert.match(r.out, /l0-foreign\.jsonl entry 0 .*: submitter_id "node-b" does not name the reconciled submitter/);
  assert.doesNotMatch(r.out, /booked for submitter_id "node-b"/);
  s.core.close();
});

section("Errors: nothing is compared");

checkAsync("a tampered book ⇒ exit 1, the break named, no comparison printed", async () => {
  const s = setup();
  await writeLog(s, 3);
  s.core.close();
  const lines = bookLines(s);
  const r1 = JSON.parse(lines[1]) as Record<string, unknown>;
  r1.payload_commitment = "0".repeat(64);
  writeFileSync(s.f.bookPath, [lines[0], JSON.stringify(r1), lines[2]].join("\n") + "\n");
  const r = await cli(args(s));
  assert.equal(r.code, 1, r.out + r.err);
  assert.match(r.err, /book does NOT verify: receipt 1: receipt_hash does not match .*1 receipt\(s\) verified before the break.*nothing was compared/);
  assert.doesNotMatch(r.out, /gaps|on no log entry/);
});

checkAsync("the wrong clerk key, a private key as --pub, or a missing book ⇒ exit 1", async () => {
  const s = setup();
  await writeLog(s, 1);
  s.core.close();
  const other = makeClerkFixture();
  const withPub = (pub: string) => args(s).map((a, i, all) => (all[i - 1] === "--pub" ? pub : a));
  const wrongKey = await cli(withPub(other.publicKeyPath));
  assert.equal(wrongKey.code, 1);
  assert.match(wrongKey.err, /book does NOT verify: receipt 0: signature does not verify/);
  const priv = await cli(withPub(s.f.privateKeyPath));
  assert.equal(priv.code, 1);
  assert.match(priv.err, /holds a private key; give only the public key/);
  const noBook = await cli(args(s).map((a) => (a === s.f.bookPath ? join(s.f.dir, "absent.jsonl") : a)));
  assert.equal(noBook.code, 1);
  assert.match(noBook.err, /cannot open book/);
});

checkAsync("a log that cannot be read as entries ⇒ exit 1 with the line; a whole last line without its newline is read", async () => {
  const s = setup();
  await writeLog(s, 3);
  s.core.close();
  const good = readFileSync(s.logPath);
  // The last line lost its newline only: L0 loads such a log, and so does this.
  writeFileSync(s.logPath, good.subarray(0, good.length - 1));
  assert.equal((await cli(args(s))).code, 0);
  // A torn last line.
  writeFileSync(s.logPath, good);
  appendFileSync(s.logPath, '{"sequenceNumber":3,"hash":"ab');
  const torn = await cli(args(s));
  assert.equal(torn.code, 1, torn.out);
  assert.match(torn.err, /torn final line at index 3/);
  // Damage in the middle; blank lines are skipped, as L0 skips them.
  const lines = good.toString("utf8").trim().split("\n");
  writeFileSync(s.logPath, [lines[0], "", "not json", lines[1]].join("\n") + "\n");
  const bad = await cli(args(s));
  assert.equal(bad.code, 1, bad.out);
  assert.match(bad.err, /line at index 1 is not valid JSON/);
  writeFileSync(s.logPath, [lines[0], "[1,2]"].join("\n") + "\n");
  assert.match((await cli(args(s))).err, /line at index 1 is not a JSON object/);
  const missing = await cli(args(s, [join(s.f.dir, "absent.jsonl")]));
  assert.equal(missing.code, 1);
  assert.match(missing.err, /cannot read log .*absent\.jsonl/);
});

checkAsync("a FIFO or a directory at --log or --book ⇒ exit 1 at once, never a hang", async () => {
  const s = setup();
  await writeLog(s, 1);
  s.core.close();
  const fifo = join(s.f.dir, "fifo");
  const mk = spawnSync("mkfifo", [fifo]);
  assert.equal(mk.status, 0, `mkfifo failed: ${String(mk.stderr)}`);
  const dir = join(s.f.dir, "a-directory");
  mkdirSync(dir);
  for (const [what, path] of [["FIFO", fifo], ["directory", dir]] as const) {
    const t0 = Date.now();
    const log = await cli(args(s, [path]));
    assert.equal(log.code, 1, `${what} as --log: ${log.out}`);
    assert.match(log.err, /is not a regular file/);
    const book = await cli(args(s).map((a) => (a === s.f.bookPath ? path : a)));
    assert.equal(book.code, 1, `${what} as --book: ${book.out}`);
    assert.match(book.err, /cannot open book: .* is not a regular file/);
    assert.ok(Date.now() - t0 < 5000);
  }
}, 20_000);

checkAsync("usage errors exit 2: a missing flag, an unknown one, a flag other than --log given twice", async () => {
  const s = setup();
  s.core.close();
  const full = args(s);
  const without = (flag: string) => {
    const i = full.indexOf(flag);
    return [...full.slice(0, i), ...full.slice(i + 2)];
  };
  for (const a of [
    without("--submitter"),
    without("--channel"),
    without("--log"),
    [...full, "--extra", "x"],
    [...full, "--book", s.f.bookPath],
    [...full, "--submitter", "node-b"],
  ]) {
    const r = await cli(a);
    assert.equal(r.code, 2, `${JSON.stringify(a.slice(1))} exited ${r.code}`);
    assert.match(r.err, /usage:/);
  }
});

section("The log is read as data");

checkAsync("reconcile beside a live L0 writer: the log file and its writer lock are byte-identical afterwards, and L0 goes on", async () => {
  const s = setup();
  const live = new LockedEvidenceLog({ path: s.logPath, clerk: routeOf(s.client, s.f.publicKeyPem) });
  try {
    await live.append(entry(0));
    await live.append(entry(1));
    const lockPath = `${s.logPath}.lock`;
    const snapshot = () => ({
      log: readFileSync(s.logPath),
      mtimeMs: statSync(s.logPath).mtimeMs,
      lock: existsSync(lockPath) ? readFileSync(lockPath) : null,
      dir: readdirSync(dirname(s.logPath)).sort(),
    });
    const before = snapshot();
    assert.equal((await cli(args(s))).code, 0);
    s.core.submit({ submitter_id: SUBMITTER, channel: CHANNEL, payload: { stray: 1 } }); // a gap, for the exit-3 path
    assert.equal((await cli(args(s))).code, EXIT_GAPS);
    const after = snapshot();
    assert.ok(after.log.equals(before.log), "reconcile changed the log file");
    assert.equal(after.mtimeMs, before.mtimeMs, "reconcile touched the log file");
    assert.deepEqual(after.lock, before.lock, "reconcile changed the writer lock");
    assert.deepEqual(after.dir, before.dir, "reconcile created or removed a file beside the log");
    // The writer still owns its log.
    await live.append(entry(2));
    assert.equal(live.length, 3);
    assert.equal(live.getDurabilityInfo().writeHealthy, true);
  } finally {
    live.close();
    s.core.close();
  }
});

checkAsync("run as its own process: exit 3 for gaps reaches the caller, exit 0 when there are none", async () => {
  const s = setup();
  await writeLog(s, 2);
  s.core.submit({ submitter_id: SUBMITTER, channel: CHANNEL, payload: { stray: 1 } });
  s.core.close();
  const gaps = spawnCli(args(s));
  const g = await gaps.exited;
  assert.equal(g.code, EXIT_GAPS, gaps.stderr.join("") + gaps.stdout.join(""));
  assert.match(gaps.stdout.join(""), /^ {2}clerk_seq 2 {2}receipt_hash [0-9a-f]{64}$/m);
  writeFileSync(s.f.bookPath, bookLines(s).slice(0, 2).join("\n") + "\n");
  const none = spawnCli(args(s));
  assert.equal((await none.exited).code, 0, none.stderr.join(""));
}, 90_000);

runAll();
