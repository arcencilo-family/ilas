// ──────────────────────────────────────────────────────────────────────────────
// ILAS — S-4 FileDropWitness acceptance tests (sections 1–10)
// House style: standalone ts-node script, custom check() harness.
//   npx ts-node src/s4/file-drop-witness.test.ts
//
// No import edge to any witness implementation (packages/witness included), in
// production or here. The signing key is generated in-test; the canonical
// preimage is pinned as a literal string taken from docs/S4-WIRE-SPEC.md §4 and
// written by hand rather than imported, exactly as the wire itself is.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { spawnSync } from "child_process";
import { createHash, generateKeyPairSync, sign } from "crypto";
import type { KeyObject } from "crypto";
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  truncateSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import { join, resolve } from "path";

import { ILASKillStack } from "../index";
import { LockedEvidenceLog, recomputeHeadHashAt } from "../l0";
import { publicKeyFingerprint } from "../l0/fingerprint";
import {
  ContinuityVerifier,
  FileDropWitness,
  FILE_DROP_WITNESS_IS_A_CLIENT_NOT_A_WITNESS,
  HeadCommitEmitter,
  INDEPENDENCE_IS_A_DEPLOYMENT_FACT,
  MAX_RECEIPT_BYTES,
  MAX_SUBMITTER_ID_BYTES,
  SUBMISSION_IS_NOT_RETENTION,
  UNVERIFIED_RECEIPTS_ARE_DROPPED,
  canonicalReceiptPreimage,
  submitterIdProblem,
} from "./index";
import type { HeadCommit, Witness, WitnessReceipt } from "./index";

let passed = 0;
let failed = 0;
function check(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${(err as Error).message}`);
    failed++;
  }
}

const root = mkdtempSync(join(tmpdir(), "ilas-s4-filedrop-"));
let counter = 0;

/** A fresh (intake, outbox, log) triple per test — no cross-test contamination. */
function freshWire(): { intake: string; outbox: string; logPath: string } {
  const n = counter++;
  const intake = join(root, `intake-${n}`);
  const outbox = join(root, `outbox-${n}`);
  mkdirSync(intake, { recursive: true });
  mkdirSync(outbox, { recursive: true });
  return { intake, outbox, logPath: join(root, `log-${n}.jsonl`) };
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

// ── the witness's key material, generated here; never imported ────────────────

const witnessKeys = generateKeyPairSync("ed25519");
const attackerKeys = generateKeyPairSync("ed25519");

const witnessPubPath = join(root, "witness-pub.pem");
writeFileSync(
  witnessPubPath,
  witnessKeys.publicKey.export({ type: "spki", format: "pem" }) as string
);

const witnessPrivPath = join(root, "witness-priv.pem");
writeFileSync(
  witnessPrivPath,
  witnessKeys.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
  { mode: 0o600 }
);

const attackerPubPath = join(root, "attacker-pub.pem");
writeFileSync(
  attackerPubPath,
  attackerKeys.publicKey.export({ type: "spki", format: "pem" }) as string
);

const rsaPubPath = join(root, "witness-pub-rsa.pem");
writeFileSync(
  rsaPubPath,
  generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({
    type: "spki",
    format: "pem",
  }) as string
);

/** Sign a receipt exactly as docs/S4-WIRE-SPEC.md §4 specifies. */
function signedReceipt(
  seq_no: number,
  head_hash: string,
  witness_ts: number,
  key: KeyObject
): WitnessReceipt {
  const preimage = canonicalReceiptPreimage({ seq_no, head_hash, witness_ts });
  return {
    seq_no,
    head_hash,
    witness_ts,
    witness_sig: sign(null, Buffer.from(preimage, "utf8"), key).toString("base64"),
  };
}

/** Drop a receipt into an outbox, named the way packages/witness names receipts. */
function placeReceipt(outbox: string, recordSeq: number, receipt: WitnessReceipt): void {
  writeFileSync(receiptPath(outbox, recordSeq), JSON.stringify(receipt) + "\n", "utf8");
}

function receiptPath(outbox: string, recordSeq: number): string {
  return join(outbox, `receipt-${String(recordSeq).padStart(12, "0")}.json`);
}

/** A client on wire `w`, keyed with `publicKeyPath` (the witness key by default; null = none). */
function clientOn(
  w: { intake: string; outbox: string },
  publicKeyPath: string | null = witnessPubPath
): FileDropWitness {
  return new FileDropWitness({
    id: "witness-set-a",
    intakeDir: w.intake,
    outboxDir: w.outbox,
    submitterId: "ilas-node-a",
    publicKeyPath: publicKeyPath ?? undefined,
  });
}

/** Intake entries other than the drop file itself: temporary files left behind. */
function strays(intake: string): string[] {
  return readdirSync(intake).filter((n) => n !== "ilas-node-a");
}

/** Repository root: where ts-node and tsconfig.json are found for a child process. */
const REPO_ROOT = resolve(__dirname, "..", "..");

// ── 1 · submit() writes a parseable commit file ───────────────────────────────

console.log("── 1: submit() drops a parseable, exactly-shaped commit ──");

check("1a: submit() writes one file whose bytes parse to the four frozen fields", () => {
  const w = freshWire();
  const client = new FileDropWitness({
    id: "witness-set-a",
    intakeDir: w.intake,
    outboxDir: w.outbox,
    submitterId: "ilas-node-a",
    publicKeyPath: witnessPubPath,
  });
  const commit: HeadCommit = {
    seq_no: 7,
    head_hash: "cd".repeat(32),
    ts: 1_700_000_000_123,
    witness_set_id: "witness-set-a",
  };
  client.submit(commit);

  const names = readdirSync(w.intake);
  assert.equal(names.length, 1, "exactly one drop file");
  const parsed = JSON.parse(readFileSync(join(w.intake, names[0]), "utf8"));
  assert.deepEqual(Object.keys(parsed).sort(), [
    "head_hash",
    "seq_no",
    "ts",
    "witness_set_id",
  ]);
  assert.deepEqual(parsed, commit, "the commit round-trips with no envelope");
  assert.equal(client.getSubmitDiagnostics().written, 1);
  assert.equal(client.getSubmitDiagnostics().failed, 0);
});

check(
  "1b: TRADE-OFF — the drop filename is the submitterId, not a seq_no-sortable name",
  () => {
    // A name sortable by seq_no would let a witness that polls in lexical order
    // consume the drops in order. But a witness may use the WHOLE FILENAME as the
    // presented submitter id and match it exactly against its configured
    // submitters (the reference witness in packages/witness does). A seq-varying
    // name is then never a declared submitter: no drop is accepted and no receipt
    // is ever signed. The two properties cannot both hold; the id wins, and this
    // test pins the choice so it cannot drift back silently.
    const w = freshWire();
    const client = new FileDropWitness({
      id: "witness-set-a",
      intakeDir: w.intake,
      outboxDir: w.outbox,
      submitterId: "ilas-node-a",
      publicKeyPath: witnessPubPath,
    });
    client.submit({ seq_no: 1, head_hash: "aa".repeat(32), ts: 1, witness_set_id: "witness-set-a" });
    client.submit({ seq_no: 2, head_hash: "bb".repeat(32), ts: 2, witness_set_id: "witness-set-a" });

    const names = readdirSync(w.intake).sort();
    assert.deepEqual(names, ["ilas-node-a"], "one file, named for the submitter id");
    // At most one file exists, so lexical poll order IS arrival order. The cost is
    // named in the code: an unconsumed drop is overwritten, and the newer commit —
    // constraining a longer prefix — is the one that survives.
    const parsed = JSON.parse(readFileSync(join(w.intake, "ilas-node-a"), "utf8"));
    assert.equal(parsed.seq_no, 2, "the newer commit is the one retained");
  }
);

check("1c: a submitterId that is a path is refused at construction, not at emit time", () => {
  const w = freshWire();
  assert.throws(
    () =>
      new FileDropWitness({
        id: "x",
        intakeDir: w.intake,
        outboxDir: w.outbox,
        submitterId: "../escape",
      }),
    /bare filename/
  );
});

check('1d: a submitterId starting with "." is refused (the witness ignores dot names)', () => {
  const w = freshWire();
  assert.throws(
    () =>
      new FileDropWitness({
        id: "x",
        intakeDir: w.intake,
        outboxDir: w.outbox,
        submitterId: ".ilas-node-a",
      }),
    /must not start with "\."/
  );
});

// Other accounts can write the intake (the witness deletes what it consumes;
// other nodes of the set drop there too), so the drop name can hold a plant.

const PLANT_COMMIT: HeadCommit = {
  seq_no: 3,
  head_hash: "5e".repeat(32),
  ts: 1_700_000_000_003,
  witness_set_id: "witness-set-a",
};

check("1e: a SYMLINK planted at the drop name is replaced, never written through", () => {
  const w = freshWire();
  const victim = join(root, `victim-${counter++}.jsonl`);
  const victimBytes = '{"the node\'s own durable chain":"must survive"}\n';
  writeFileSync(victim, victimBytes);
  const target = join(w.intake, "ilas-node-a");
  symlinkSync(victim, target);

  const client = clientOn(w);
  client.submit(PLANT_COMMIT);

  assert.equal(readFileSync(victim, "utf8"), victimBytes, "the link's target is untouched");
  const st = lstatSync(target);
  assert.ok(st.isFile() && !st.isSymbolicLink(), "the link itself was replaced by a file");
  assert.deepEqual(JSON.parse(readFileSync(target, "utf8")), PLANT_COMMIT);
  const d = client.getSubmitDiagnostics();
  assert.deepEqual([d.written, d.failed], [1, 0]);
  assert.deepEqual(strays(w.intake), [], "no temporary file is left behind");
});

check("1f: a HARD LINK planted at the drop name is replaced; the linked file is untouched", () => {
  const w = freshWire();
  const victim = join(root, `victim-${counter++}.jsonl`);
  const victimBytes = "a file the node can write, hard-linked into the intake\n";
  writeFileSync(victim, victimBytes);
  const target = join(w.intake, "ilas-node-a");
  linkSync(victim, target);

  const client = clientOn(w);
  client.submit(PLANT_COMMIT);

  assert.equal(readFileSync(victim, "utf8"), victimBytes, "the linked file is untouched");
  assert.notEqual(statSync(target).ino, statSync(victim).ino, "the drop is a new file");
  assert.deepEqual(JSON.parse(readFileSync(target, "utf8")), PLANT_COMMIT);
  assert.deepEqual(strays(w.intake), []);
});

check("1g: a FIFO planted at the drop name (no reader) neither blocks submit() nor is opened", () => {
  const w = freshWire();
  const target = join(w.intake, "ilas-node-a");
  const mk = spawnSync("mkfifo", [target], { encoding: "utf8" });
  assert.equal(mk.status, 0, `mkfifo is needed for this test: ${mk.stderr ?? String(mk.error)}`);
  assert.ok(lstatSync(target).isFIFO(), "precondition: a FIFO stands at the drop name");

  // In a child process: a submit() that blocks is killed by the timeout instead
  // of hanging this run.
  const started = Date.now();
  const child = spawnSync(
    process.execPath,
    [
      "-r",
      "ts-node/register",
      join(__dirname, "submit-child.fixture.ts"),
      w.intake,
      w.outbox,
      "ilas-node-a",
      JSON.stringify(PLANT_COMMIT),
    ],
    {
      cwd: REPO_ROOT,
      env: { ...process.env, TS_NODE_TRANSPILE_ONLY: "true" },
      encoding: "utf8",
      timeout: 30_000,
      killSignal: "SIGKILL",
    }
  );
  assert.equal(
    child.signal,
    null,
    `the child was killed (${child.signal}) after ${Date.now() - started} ms: ` +
      `submit() blocked on the FIFO`
  );
  assert.equal(child.status, 0, `child failed: ${child.stderr}`);
  const d = JSON.parse(child.stdout.trim().split("\n").pop() ?? "{}");
  assert.deepEqual([d.written, d.failed], [1, 0], JSON.stringify(d));
  const st = lstatSync(target);
  assert.ok(st.isFile(), "the FIFO was replaced by a regular file");
  assert.deepEqual(JSON.parse(readFileSync(target, "utf8")), PLANT_COMMIT);
  assert.deepEqual(strays(w.intake), []);
});

check("1h: a directory at the drop name ⇒ recorded failure, no temporary file left", () => {
  const w = freshWire();
  mkdirSync(join(w.intake, "ilas-node-a"));
  const client = clientOn(w);
  assert.doesNotThrow(() => client.submit(PLANT_COMMIT));
  const d = client.getSubmitDiagnostics();
  assert.deepEqual([d.attempted, d.written, d.failed], [1, 0, 1]);
  assert.ok(d.failureReasons[0].startsWith("seq 3: "), d.failureReasons[0]);
  assert.deepEqual(strays(w.intake), [], "the temporary file was removed");
});

// A submitter id is a file name twice over: <id>, and ".<id>.<12 hex>.tmp".

check("1i: ids no file name can hold are refused at construction, not at every submit", () => {
  assert.equal(MAX_SUBMITTER_ID_BYTES, 255 - 18, "255-byte file name less the temp name's 18");
  const w = freshWire();
  const refused: readonly [string, string, RegExp][] = [
    ["NUL", "a\0b", /control character/],
    ["newline", "a\nb", /control character/],
    ["DEL", "a\x7fb", /control character/],
    ["U+0085, a control", "a\u0085b", /control character/],
    ["lone high surrogate", "a\uD800b", /well-formed Unicode/],
    ["lone low surrogate", "a\uDC00b", /well-formed Unicode/],
    ["238 ASCII bytes", "n".repeat(238), /at most 237 bytes in UTF-8, is 238/],
    ["238 bytes of 2-byte characters", "é".repeat(119), /at most 237 bytes in UTF-8, is 238/],
    ["255 bytes", "n".repeat(255), /at most 237 bytes/],
  ];
  const notRefused = refused.filter(([, id, reason]) => {
    if (submitterIdProblem(id) === null) return true;
    try {
      new FileDropWitness({ id: "x", intakeDir: w.intake, outboxDir: w.outbox, submitterId: id });
      return true;
    } catch (error) {
      return !reason.test((error as Error).message);
    }
  });
  const labels = notRefused.map(([label]) => label);
  assert.deepEqual(labels, [], `not refused at construction for its reason: ${labels.join("; ")}`);
  assert.deepEqual(readdirSync(w.intake), [], "nothing was written");
});

check("1j: ids at the 237-byte bound construct and submit end to end", () => {
  for (const id of ["n".repeat(237), "é".repeat(118) + "n", "node-ä-🙂"]) {
    assert.equal(submitterIdProblem(id), null, `${Buffer.byteLength(id)} bytes is accepted`);
    const w = freshWire();
    const client = new FileDropWitness({
      id: "witness-set-a",
      intakeDir: w.intake,
      outboxDir: w.outbox,
      submitterId: id,
    });
    client.submit(PLANT_COMMIT);
    const d = client.getSubmitDiagnostics();
    assert.deepEqual([d.written, d.failed], [1, 0], JSON.stringify(d.failureReasons));
    assert.deepEqual(readdirSync(w.intake), [id], "one drop file, named exactly by the id");
    assert.deepEqual(JSON.parse(readFileSync(join(w.intake, id), "utf8")), PLANT_COMMIT);
  }
});

// ── 2 · a genuine signed receipt verifies ─────────────────────────────────────

console.log("── 2: a genuine signed receipt verifies and is returned ──");

check("2a: the canonical signed string is pinned, not guessed", () => {
  // The preimage fixed by docs/S4-WIRE-SPEC.md §4:
  //   [String(seq_no), head_hash, String(witness_ts)].join(" ")
  const h = "ab".repeat(32);
  assert.equal(
    canonicalReceiptPreimage({ seq_no: 4, head_hash: h, witness_ts: 1_700_000_000_000 }),
    `4 ${h} 1700000000000`
  );
  // The empty-chain head commits at seq -1; the preimage must carry it verbatim.
  assert.equal(
    canonicalReceiptPreimage({ seq_no: -1, head_hash: "0".repeat(64), witness_ts: 5 }),
    `-1 ${"0".repeat(64)} 5`
  );
});

check("2b: a receipt signed by the witness key is returned, diagnostics clean", () => {
  const w = freshWire();
  const client = new FileDropWitness({
    id: "witness-set-a",
    intakeDir: w.intake,
    outboxDir: w.outbox,
    submitterId: "ilas-node-a",
    publicKeyPath: witnessPubPath,
  });
  const r = signedReceipt(3, "ef".repeat(32), 1_700_000_000_777, witnessKeys.privateKey);
  placeReceipt(w.outbox, 1, r);

  const got = client.retrieveReceipts();
  assert.equal(got.length, 1);
  assert.deepEqual(got[0], r);
  const d = client.getLastFetchDiagnostics();
  assert.deepEqual(
    { found: d.found, verified: d.verified, dropped: d.dropped, keyAvailable: d.keyAvailable },
    { found: 1, verified: 1, dropped: 0, keyAvailable: true }
  );
  assert.deepEqual(d.dropReasons, []);
});

check("2c: an RSA key where ed25519 is required ⇒ no key, empty, nothing thrown", () => {
  const w = freshWire();
  const client = new FileDropWitness({
    id: "witness-set-a",
    intakeDir: w.intake,
    outboxDir: w.outbox,
    submitterId: "ilas-node-a",
    publicKeyPath: rsaPubPath,
  });
  placeReceipt(w.outbox, 1, signedReceipt(0, "aa".repeat(32), 1, witnessKeys.privateKey));
  assert.deepEqual(client.retrieveReceipts(), []);
  const d = client.getLastFetchDiagnostics();
  assert.equal(d.keyAvailable, false);
  assert.ok(
    d.dropReasons.some((r) => r.includes("not ed25519")),
    "the reason names the key type"
  );
});

check("2d: a PRIVATE key at publicKeyPath is refused, not quietly used as the public half", () => {
  const w = freshWire();
  const client = clientOn(w, witnessPrivPath);
  placeReceipt(w.outbox, 0, signedReceipt(0, "aa".repeat(32), 1, witnessKeys.privateKey));

  assert.deepEqual(client.retrieveReceipts(), [], "a genuine receipt is not returned");
  const d = client.getLastFetchDiagnostics();
  assert.equal(d.keyAvailable, false);
  assert.equal(d.rejected, 0, "no usable key ⇒ nothing was checkable ⇒ nothing rejected");
  assert.ok(
    d.dropReasons.some((r) => r.includes("PRIVATE key") && r.includes("PUBLIC key")),
    `the reason tells the operator what to give instead: ${JSON.stringify(d.dropReasons)}`
  );

  const log = new LockedEvidenceLog();
  log.append(entry(0));
  assert.equal(new ContinuityVerifier(log, client).verify().status, "CANNOT_VERIFY_CONTINUITY");
});

// The key file is re-read on every fetch, so whoever can put something at
// publicKeyPath decides what that read meets. It must never stop the node.

check("2e: a FIFO at publicKeyPath blocks neither the fetch nor publicKeyFingerprint(); it is no key", () => {
  const w = freshWire();
  placeReceipt(w.outbox, 0, signedReceipt(0, "aa".repeat(32), 1, witnessKeys.privateKey));
  const keyFifo = join(root, `key-fifo-${counter++}.pem`);
  const mk = spawnSync("mkfifo", [keyFifo], { encoding: "utf8" });
  assert.equal(mk.status, 0, `mkfifo is needed for this test: ${mk.stderr ?? String(mk.error)}`);

  // In a child process: a read that blocks opening the FIFO is killed by the
  // timeout instead of hanging this run. No outbox entry has the name given,
  // so the fixture swaps nothing in; the FIFO it would use is never made.
  const started = Date.now();
  const child = spawnSync(
    process.execPath,
    [
      "-r",
      "ts-node/register",
      join(__dirname, "fetch-child.fixture.ts"),
      w.outbox,
      keyFifo,
      "no-entry-has-this-name",
      join(root, `never-made-${counter++}`),
    ],
    {
      cwd: REPO_ROOT,
      env: { ...process.env, TS_NODE_TRANSPILE_ONLY: "true" },
      encoding: "utf8",
      timeout: 30_000,
      killSignal: "SIGKILL",
    }
  );
  assert.equal(
    child.signal,
    null,
    `the child was killed (${child.signal}) after ${Date.now() - started} ms: ` +
      `opening the FIFO at publicKeyPath blocked`
  );
  assert.equal(child.status, 0, `child failed: ${child.stderr}`);
  const d = JSON.parse(child.stdout.trim().split("\n").pop() ?? "{}");
  assert.equal(d.swapped, false, "precondition: nothing was swapped into the outbox");
  assert.deepEqual(
    [d.found, d.verified, d.rejected, d.keyAvailable],
    [1, 0, 0, false],
    `no key, so the genuine receipt is not returned and nothing counts as rejected: ${JSON.stringify(d)}`
  );
  assert.ok(
    d.dropReasons.some((r: string) => /^cannot read witness public key: .*not a regular file/.test(r)),
    JSON.stringify(d.dropReasons)
  );
  assert.equal(d.keyFingerprint, null, "no usable key, no fingerprint");
});

check("2f: a device or an oversized file at publicKeyPath is refused unread; a link to the key is followed", () => {
  const w = freshWire();
  placeReceipt(w.outbox, 0, signedReceipt(0, "aa".repeat(32), 1, witnessKeys.privateKey));
  const device = join(root, `key-device-${counter++}.pem`);
  symlinkSync("/dev/null", device);
  const huge = join(root, `key-huge-${counter++}.pem`);
  writeFileSync(huge, "");
  truncateSync(huge, 64 * 1024 * 1024);

  for (const [path, reason] of [
    [device, "is not a regular file; not read"],
    [huge, "is 67108864 bytes, more than 65536; not read"],
  ] as const) {
    const client = clientOn(w, path);
    assert.deepEqual(client.retrieveReceipts(), [], reason);
    const d = client.getLastFetchDiagnostics();
    assert.deepEqual([d.keyAvailable, d.rejected], [false, 0], reason);
    assert.ok(
      d.dropReasons.some((r) => r.startsWith("cannot read witness public key: ") && r.includes(reason)),
      `wanted "${reason}": ${JSON.stringify(d.dropReasons)}`
    );
    assert.equal(client.publicKeyFingerprint(), null, reason);
  }

  // The operator chooses publicKeyPath; a link is a fair way to rotate the key.
  const link = join(root, `key-link-${counter++}.pem`);
  symlinkSync(witnessPubPath, link);
  const linked = clientOn(w, link);
  assert.equal(linked.retrieveReceipts().length, 1, "a symbolic link to the key file is followed");
  assert.equal(linked.getLastFetchDiagnostics().keyAvailable, true);
});

check("2g: publicKeyFingerprint() names the key in use in the shared format, re-read; null without a usable key", () => {
  const w = freshWire();
  // The format, computed here by hand: "sha256:" + hex SHA-256 of the SPKI DER.
  const expected =
    "sha256:" +
    createHash("sha256")
      .update(witnessKeys.publicKey.export({ type: "spki", format: "der" }))
      .digest("hex");
  assert.equal(
    publicKeyFingerprint(readFileSync(witnessPubPath, "utf8")),
    expected,
    "precondition: the shared helper prints the same format"
  );
  const asWitness: Witness = clientOn(w);
  assert.equal(asWitness.publicKeyFingerprint?.(), expected, "through the Witness interface");

  // Re-read like the key itself: a key replaced in place is the one reported.
  const rotating = join(root, `key-rotating-${counter++}.pem`);
  writeFileSync(rotating, readFileSync(witnessPubPath));
  const client = clientOn(w, rotating);
  assert.equal(client.publicKeyFingerprint(), expected);
  writeFileSync(rotating, readFileSync(attackerPubPath));
  const attackerPrint = publicKeyFingerprint(readFileSync(attackerPubPath, "utf8"));
  assert.notEqual(attackerPrint, expected, "precondition: two keys, two fingerprints");
  assert.equal(client.publicKeyFingerprint(), attackerPrint);

  const none: readonly [string, string | null][] = [
    ["no publicKeyPath", null],
    ["a PRIVATE key", witnessPrivPath],
    ["an RSA key", rsaPubPath],
    ["a missing file", join(root, "no-such-key.pem")],
  ];
  for (const [label, path] of none) {
    assert.equal(clientOn(w, path).publicKeyFingerprint(), null, label);
  }
});

// ── 3 · the forgery test ──────────────────────────────────────────────────────

console.log("── 3: a well-shaped receipt with a bad signature is DROPPED ──");

check("3: valid shape + attacker signature ⇒ not returned, drop + reason recorded", () => {
  const w = freshWire();
  const client = new FileDropWitness({
    id: "witness-set-a",
    intakeDir: w.intake,
    outboxDir: w.outbox,
    submitterId: "ilas-node-a",
    publicKeyPath: witnessPubPath,
  });
  const forged = signedReceipt(2, "11".repeat(32), 42, attackerKeys.privateKey);
  placeReceipt(w.outbox, 0, forged);
  // A receipt whose fields were edited after the witness signed them: same failure.
  const tampered = signedReceipt(3, "22".repeat(32), 43, witnessKeys.privateKey);
  placeReceipt(w.outbox, 1, { ...tampered, head_hash: "33".repeat(32) });

  const got = client.retrieveReceipts();
  assert.deepEqual(got, [], "no forged receipt reaches the predicate");
  const d = client.getLastFetchDiagnostics();
  assert.equal(d.found, 2);
  assert.equal(d.verified, 0);
  assert.equal(d.dropped, 2);
  assert.equal(d.keyAvailable, true);
  assert.equal(d.dropReasons.length, 2, "each drop is a separate, visible finding");
  assert.ok(
    d.dropReasons.every((r) => r.includes("does not verify")),
    `reasons name the signature failure: ${JSON.stringify(d.dropReasons)}`
  );
});

check("3b: only CANONICAL base64 of a 64-byte signature is accepted, as the witness writes it", () => {
  const w = freshWire();
  const client = clientOn(w);
  // A genuine signature whose base64 holds a '+' or '/', so the URL-safe
  // respelling below really differs from it.
  let genuine = signedReceipt(3, "ab".repeat(32), 1_700_000_000_123, witnessKeys.privateKey);
  for (let ts = 1_700_000_000_124; !/[+/]/.test(genuine.witness_sig); ts++) {
    genuine = signedReceipt(3, "ab".repeat(32), ts, witnessKeys.privateKey);
  }
  const sig = genuine.witness_sig;
  assert.ok(sig.length === 88 && sig.endsWith("=="), "precondition: padded 88-char base64");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const last = sig[85]; // carries 2 data bits; its 4 low bits are unused
  const padBits = alphabet[alphabet.indexOf(last) ^ 1];
  const variants: Record<string, string> = {
    nopad: sig.replace(/=+$/, ""),
    junk: sig.replace(/==$/, "") + "!!==",
    whitespace: sig.slice(0, 10) + " \n " + sig.slice(10),
    urlsafe: sig.replace(/\+/g, "-").replace(/\//g, "_"),
    padbits: sig.slice(0, 85) + padBits + "==",
    trailing: sig + "AAAA",
  };
  for (const [label, text] of Object.entries(variants)) {
    assert.notEqual(text, sig, `${label} differs from the genuine spelling`);
    assert.ok(
      Buffer.from(text, "base64").subarray(0, 64).equals(Buffer.from(sig, "base64")),
      `${label} decodes leniently to the genuine signature bytes`
    );
  }
  placeReceipt(w.outbox, 0, genuine);
  Object.values(variants).forEach((text, i) =>
    placeReceipt(w.outbox, i + 1, { ...genuine, witness_sig: text })
  );

  const got = client.retrieveReceipts();
  assert.deepEqual(got, [genuine], "only the canonical spelling is returned");
  const d = client.getLastFetchDiagnostics();
  assert.equal(d.found, 7);
  assert.equal(d.dropped, 6);
  assert.equal(d.rejected, 6, "each respelling is a rejected receipt");
  assert.equal(
    d.dropReasons.filter((r) => r.includes("not the canonical base64")).length,
    6,
    JSON.stringify(d.dropReasons)
  );
});

// ── 4 · the disarm test ───────────────────────────────────────────────────────

console.log("── 4: forgeries matching a rewritten chain cannot disarm the alarm ──");

check("4: forged receipts for a rewritten chain ⇒ none returned ⇒ REJECTED_RECEIPTS", () => {
  const w = freshWire();
  const original = new LockedEvidenceLog({ path: w.logPath });
  for (let i = 0; i < 5; i++) original.append(entry(i));

  const client = new FileDropWitness({
    id: "witness-set-a",
    intakeDir: w.intake,
    outboxDir: w.outbox,
    submitterId: "ilas-node-a",
    publicKeyPath: witnessPubPath,
  });

  // Genuine receipts for the ORIGINAL chain, as the witness signed them.
  placeReceipt(w.outbox, 0, signedReceipt(2, original.getEntry(2)!.hash, 10, witnessKeys.privateKey));
  placeReceipt(w.outbox, 1, signedReceipt(4, original.getEntry(4)!.hash, 20, witnessKeys.privateKey));
  assert.equal(
    new ContinuityVerifier(original, client).verify().status,
    "VERIFIED_HISTORICAL",
    "precondition: the genuine receipts reproduce"
  );

  // The adversary rewrites the chain on disk...
  const lines = readFileSync(w.logPath, "utf8").split("\n").filter((l) => l.trim());
  const rewritten = JSON.parse(lines[1]);
  rewritten.outcome = "REWRITTEN";
  lines[1] = JSON.stringify(rewritten);
  writeFileSync(w.logPath, lines.join("\n") + "\n");
  const tamperedLog = new LockedEvidenceLog({ path: w.logPath });

  // ...deletes the genuine receipts and writes forgeries whose head_hash matches
  // the REWRITTEN chain. The forger recomputes those heads the way the predicate
  // does, from the payloads — the stored hash fields are exactly what recompute
  // refuses to trust. This is the disarm: to a reader that does not check
  // signatures, every receipt now reproduces and MISMATCH becomes VERIFIED_HISTORICAL.
  for (const name of readdirSync(w.outbox)) unlinkSync(join(w.outbox, name));
  const rewrittenEntries = tamperedLog.getAll();
  const forgeries = [
    signedReceipt(2, recomputeHeadHashAt(rewrittenEntries, 2)!, 10, attackerKeys.privateKey),
    signedReceipt(4, recomputeHeadHashAt(rewrittenEntries, 4)!, 20, attackerKeys.privateKey),
  ];
  forgeries.forEach((r, i) => placeReceipt(w.outbox, i, r));

  // Control: a reader that trusts what it is handed IS disarmed by exactly this.
  class TrustingReader implements Witness {
    readonly id = "trusting";
    submit(_c: HeadCommit): void {}
    retrieveReceipts(): WitnessReceipt[] {
      return [...forgeries];
    }
  }
  assert.equal(
    new ContinuityVerifier(tamperedLog, new TrustingReader()).verify().status,
    "VERIFIED_HISTORICAL",
    "control: an unverified reader is disarmed by these forgeries"
  );

  // The client is not: no forgery is returned, and the refusals are a finding.
  const report = new ContinuityVerifier(tamperedLog, client).verify();
  assert.notEqual(report.status, "VERIFIED_HISTORICAL", "the alarm must not disarm");
  assert.equal(report.status, "REJECTED_RECEIPTS");
  assert.equal(report.receiptsChecked, 0, "no forgery reached the predicate at all");
  assert.equal(report.rejectedReceipts, 2);
  assert.equal(report.rejectReasons.length, 2);
  const d = client.getLastFetchDiagnostics();
  assert.equal(d.found, 2);
  assert.equal(d.dropped, 2);
  assert.equal(d.verified, 0);
});

/**
 * A node with `n` entries whose witness signed a genuine receipt for every head
 * (receipt-<i>.json holds seq i), plus the chain rewritten at entry `at`, read
 * back from disk the way an adversary's edit would be.
 */
function witnessedNode(n: number, at: number) {
  const w = freshWire();
  const log = new LockedEvidenceLog({ path: w.logPath });
  for (let i = 0; i < n; i++) log.append(entry(i));
  for (let i = 0; i < n; i++) {
    placeReceipt(w.outbox, i, signedReceipt(i, log.getEntry(i)!.hash, 100 + i, witnessKeys.privateKey));
  }
  const lines = readFileSync(w.logPath, "utf8").split("\n").filter((l) => l.trim());
  const changed = JSON.parse(lines[at]);
  changed.outcome = "REWRITTEN";
  lines[at] = JSON.stringify(changed);
  const rewrittenPath = join(root, `rewritten-${counter++}.jsonl`);
  writeFileSync(rewrittenPath, lines.join("\n") + "\n");
  const rewritten = new LockedEvidenceLog({ path: rewrittenPath });
  return { w, log, rewritten, client: clientOn(w) };
}

check("4b: the rewritten entry's receipt FORGED, the rest genuine ⇒ REJECTED_RECEIPTS, not VERIFIED", () => {
  const { w, log, rewritten, client } = witnessedNode(5, 4);
  assert.equal(new ContinuityVerifier(log, client).verify().status, "VERIFIED_HISTORICAL");
  assert.equal(
    new ContinuityVerifier(rewritten, client).verify().status,
    "MISMATCH",
    "precondition: the genuine receipt for seq 4 catches the rewrite"
  );

  // The outbox writer edits receipt 4 to name the rewritten head, keeping the
  // witness's signature: it no longer verifies, so the client refuses it.
  const r4 = JSON.parse(readFileSync(receiptPath(w.outbox, 4), "utf8"));
  r4.head_hash = recomputeHeadHashAt(rewritten.getAll(), 4);
  writeFileSync(receiptPath(w.outbox, 4), JSON.stringify(r4) + "\n");

  const report = new ContinuityVerifier(rewritten, client).verify();
  assert.equal(report.status, "REJECTED_RECEIPTS", "the alarm does not disarm to VERIFIED_HISTORICAL");
  assert.equal(report.receiptsChecked, 4, "the four genuine receipts still reproduce");
  assert.deepEqual(report.mismatches, []);
  assert.equal(report.rejectedReceipts, 1);
  assert.ok(report.rejectReasons[0].includes("does not verify"), report.rejectReasons[0]);
  assert.deepEqual(client.retrievalIssues(), {
    rejected: 1,
    reasons: client.getLastFetchDiagnostics().dropReasons,
  });
});

check("4c: a CORRUPTED receipt file beside genuine ones ⇒ REJECTED_RECEIPTS", () => {
  const { w, log, client } = witnessedNode(4, 0);
  const bytes = readFileSync(receiptPath(w.outbox, 2), "utf8");
  writeFileSync(receiptPath(w.outbox, 2), bytes.slice(0, 30)); // torn write, bit rot, ...

  const report = new ContinuityVerifier(log, client).verify();
  assert.equal(report.status, "REJECTED_RECEIPTS");
  assert.equal(report.receiptsChecked, 3);
  assert.equal(report.rejectedReceipts, 1);
  assert.ok(report.rejectReasons[0].includes("malformed JSON"), report.rejectReasons[0]);
});

check("4d: MISMATCH takes precedence over rejected receipts, and both are reported", () => {
  const { w, rewritten, client } = witnessedNode(5, 2);
  writeFileSync(receiptPath(w.outbox, 0), "{not json}\n");

  const report = new ContinuityVerifier(rewritten, client).verify();
  assert.equal(report.status, "MISMATCH");
  assert.deepEqual(report.mismatches.map((m) => m.seq_no), [2, 3, 4]);
  assert.equal(report.rejectedReceipts, 1, "the rejection is still carried in the report");
});

check("4e: KNOWN LIMIT — receipts DELETED, nothing forged ⇒ no trace here (VERIFIED_HISTORICAL)", () => {
  // Pinned so the limit stays named: this client cannot see a receipt that is
  // not there. The witness's own start-up check of its outbox is what restores
  // a deleted receipt and so re-arms the alarm.
  const { w, rewritten, client } = witnessedNode(5, 4);
  unlinkSync(receiptPath(w.outbox, 4));
  const report = new ContinuityVerifier(rewritten, client).verify();
  assert.equal(report.status, "VERIFIED_HISTORICAL");
  assert.equal(report.receiptsChecked, 4);
  assert.equal(report.rejectedReceipts, 0);
});

check("4f: a usable but WRONG public key ⇒ every genuine receipt refused ⇒ REJECTED_RECEIPTS", () => {
  const { w, log } = witnessedNode(3, 0);
  const client = clientOn(w, attackerPubPath);
  const report = new ContinuityVerifier(log, client).verify();
  assert.equal(report.status, "REJECTED_RECEIPTS", "nothing in the channel verifies: a finding");
  assert.equal(report.receiptsChecked, 0);
  assert.equal(report.rejectedReceipts, 3);
});

check("4g: ILASKillStack.status().continuity carries REJECTED_RECEIPTS", () => {
  const w = freshWire();
  placeReceipt(w.outbox, 0, signedReceipt(0, "11".repeat(32), 1, attackerKeys.privateKey));
  const stack = new ILASKillStack({ witness: clientOn(w) });
  assert.equal(stack.status().continuity, "REJECTED_RECEIPTS");
});

// ── 5 · no public key ─────────────────────────────────────────────────────────

console.log("── 5: no public key ⇒ verify nothing ⇒ return nothing ──");

check("5: no publicKeyPath ⇒ empty, keyAvailable false, reasons recorded, no throw", () => {
  const w = freshWire();
  const client = new FileDropWitness({
    id: "witness-set-a",
    intakeDir: w.intake,
    outboxDir: w.outbox,
    submitterId: "ilas-node-a",
  });
  placeReceipt(w.outbox, 0, signedReceipt(1, "aa".repeat(32), 1, witnessKeys.privateKey));
  placeReceipt(w.outbox, 1, signedReceipt(2, "bb".repeat(32), 2, witnessKeys.privateKey));

  const got = client.retrieveReceipts();
  assert.deepEqual(got, [], "genuine receipts are still not returned unverified");
  const d = client.getLastFetchDiagnostics();
  assert.equal(d.keyAvailable, false);
  assert.equal(d.found, 2, "an operator can still see what is sitting there");
  assert.equal(d.dropped, 2);
  assert.equal(d.verified, 0);
  assert.ok(d.dropReasons.some((r) => r.includes("no publicKeyPath was injected")));

  const log = new LockedEvidenceLog({ path: w.logPath });
  for (let i = 0; i < 3; i++) log.append(entry(i));
  assert.equal(
    new ContinuityVerifier(log, client).verify().status,
    "CANNOT_VERIFY_CONTINUITY",
    "the correct closure: we cannot speak to continuity"
  );
});

check("5b: no key + a corrupted file ⇒ nothing was checkable ⇒ CANNOT_VERIFY, not REJECTED", () => {
  const w = freshWire();
  const client = clientOn(w, null);
  placeReceipt(w.outbox, 0, signedReceipt(1, "aa".repeat(32), 1, witnessKeys.privateKey));
  writeFileSync(receiptPath(w.outbox, 1), "{not json}\n");
  const log = new LockedEvidenceLog();
  log.append(entry(0));
  const report = new ContinuityVerifier(log, client).verify();
  assert.equal(report.status, "CANNOT_VERIFY_CONTINUITY");
  assert.equal(report.rejectedReceipts, 0);
  assert.equal(client.getLastFetchDiagnostics().dropped, 2);
  assert.deepEqual(client.retrievalIssues(), { rejected: 0, reasons: [] });
});

// ── 6 · absent / unreadable outbox ────────────────────────────────────────────

console.log("── 6: an absent or unreadable outbox ⇒ empty, never a throw ──");

check("6a: outbox does not exist ⇒ empty, reason recorded, nothing thrown", () => {
  const w = freshWire();
  const client = new FileDropWitness({
    id: "witness-set-a",
    intakeDir: w.intake,
    outboxDir: join(root, `no-such-outbox-${counter++}`),
    submitterId: "ilas-node-a",
    publicKeyPath: witnessPubPath,
  });
  assert.deepEqual(client.retrieveReceipts(), []);
  const d = client.getLastFetchDiagnostics();
  assert.equal(d.found, 0);
  assert.equal(d.keyAvailable, true, "the key was readable; the outbox was not");
  assert.ok(d.dropReasons.some((r) => r.includes("outbox unreadable")));
});

check("6b: outbox path is a file, not a directory ⇒ empty, nothing thrown", () => {
  const w = freshWire();
  const notADir = join(root, `outbox-is-a-file-${counter++}`);
  writeFileSync(notADir, "not a directory\n");
  const client = new FileDropWitness({
    id: "witness-set-a",
    intakeDir: w.intake,
    outboxDir: notADir,
    submitterId: "ilas-node-a",
    publicKeyPath: witnessPubPath,
  });
  assert.deepEqual(client.retrieveReceipts(), []);
  assert.ok(
    client.getLastFetchDiagnostics().dropReasons.some((r) => r.includes("outbox unreadable"))
  );
});

// ── 7 · malformed outbox contents ─────────────────────────────────────────────

console.log("── 7: junk in the outbox is dropped; the good receipts still arrive ──");

check("7: malformed JSON and wrong shapes drop with reasons; valid receipts survive", () => {
  const w = freshWire();
  const client = new FileDropWitness({
    id: "witness-set-a",
    intakeDir: w.intake,
    outboxDir: w.outbox,
    submitterId: "ilas-node-a",
    publicKeyPath: witnessPubPath,
  });
  const good = signedReceipt(9, "de".repeat(32), 99, witnessKeys.privateKey);
  writeFileSync(join(w.outbox, "receipt-000000000000.json"), "{not json}\n", "utf8");
  writeFileSync(
    join(w.outbox, "receipt-000000000001.json"),
    JSON.stringify({ seq_no: 1, head_hash: "aa" }) + "\n",
    "utf8"
  );
  // Extra unsigned fields are attacker copy riding on a genuine signature.
  placeReceipt(w.outbox, 2, {
    ...signedReceipt(5, "cc".repeat(32), 55, witnessKeys.privateKey),
    note: "trust me",
  } as unknown as WitnessReceipt);
  placeReceipt(w.outbox, 3, good);
  mkdirSync(join(w.outbox, "a-subdirectory"), { recursive: true });

  const got = client.retrieveReceipts();
  assert.deepEqual(got, [good], "only the checkable, checked receipt is returned");
  const d = client.getLastFetchDiagnostics();
  assert.equal(d.found, 4, "the subdirectory is not counted as a receipt");
  assert.equal(d.verified, 1);
  assert.equal(d.dropped, 3);
  assert.ok(d.dropReasons.some((r) => r.includes("malformed JSON")));
  assert.equal(
    d.dropReasons.filter((r) => r.includes("not a WITNESS_RECEIPT shape")).length,
    2,
    "a missing field and an extra field are both shape drops"
  );
  assert.equal(d.rejected, 3, "with a usable key, every drop is a rejection");
  assert.equal(client.retrievalIssues().rejected, 3);
});

// A writer of the outbox is the adversary: it can put anything at a receipt's
// name, including between the moment the client looks and the moment it opens.

check("7b: a FIFO renamed onto a receipt's name just before the open is refused, never blocks", () => {
  const w = freshWire();
  const name = "receipt-000000000000.json";
  placeReceipt(w.outbox, 0, signedReceipt(0, "aa".repeat(32), 1, witnessKeys.privateKey));
  const fifo = join(root, `fifo-${counter++}`);
  const mk = spawnSync("mkfifo", [fifo], { encoding: "utf8" });
  assert.equal(mk.status, 0, `mkfifo is needed for this test: ${mk.stderr ?? String(mk.error)}`);

  // In a child process: a fetch that blocks opening the FIFO is killed by the
  // timeout instead of hanging this run.
  const started = Date.now();
  const child = spawnSync(
    process.execPath,
    ["-r", "ts-node/register", join(__dirname, "fetch-child.fixture.ts"), w.outbox, witnessPubPath, name, fifo],
    {
      cwd: REPO_ROOT,
      env: { ...process.env, TS_NODE_TRANSPILE_ONLY: "true" },
      encoding: "utf8",
      timeout: 30_000,
      killSignal: "SIGKILL",
    }
  );
  assert.equal(
    child.signal,
    null,
    `the child was killed (${child.signal}) after ${Date.now() - started} ms: ` +
      `retrieveReceipts() blocked opening the FIFO`
  );
  assert.equal(child.status, 0, `child failed: ${child.stderr}`);
  const d = JSON.parse(child.stdout.trim().split("\n").pop() ?? "{}");
  assert.equal(d.swapped, true, "precondition: the FIFO was swapped in before the open");
  assert.deepEqual([d.found, d.verified, d.rejected], [1, 0, 1], JSON.stringify(d));
  assert.ok(
    d.dropReasons.some((r: string) => r.startsWith(`${name}: not a regular file when opened (a FIFO)`)),
    JSON.stringify(d.dropReasons)
  );
});

check("7c: a 64 MiB sparse file is refused unread; the genuine receipt beside it still arrives", () => {
  const w = freshWire();
  const good = signedReceipt(1, "ab".repeat(32), 7, witnessKeys.privateKey);
  writeFileSync(receiptPath(w.outbox, 0), "");
  truncateSync(receiptPath(w.outbox, 0), 64 * 1024 * 1024);
  placeReceipt(w.outbox, 1, good);

  const client = clientOn(w);
  assert.deepEqual(client.retrieveReceipts(), [good]);
  const d = client.getLastFetchDiagnostics();
  assert.deepEqual([d.found, d.verified, d.rejected], [2, 1, 1]);
  assert.ok(
    d.dropReasons[0].includes("67108864 bytes") && d.dropReasons[0].includes("at most 4096"),
    d.dropReasons[0]
  );
});

check("7d: the size cap, both sides: 4096 bytes is read, 4097 is refused", () => {
  assert.equal(MAX_RECEIPT_BYTES, 4096);
  const w = freshWire();
  const padded = (r: WitnessReceipt, size: number) => {
    const json = JSON.stringify(r);
    return json + " ".repeat(size - Buffer.byteLength(json)); // JSON allows trailing space
  };
  const atCap = signedReceipt(1, "c1".repeat(32), 1, witnessKeys.privateKey);
  const overCap = signedReceipt(2, "c2".repeat(32), 2, witnessKeys.privateKey);
  writeFileSync(receiptPath(w.outbox, 0), padded(atCap, MAX_RECEIPT_BYTES));
  writeFileSync(receiptPath(w.outbox, 1), padded(overCap, MAX_RECEIPT_BYTES + 1));
  assert.equal(statSync(receiptPath(w.outbox, 1)).size, 4097, "precondition");

  const client = clientOn(w);
  assert.deepEqual(client.retrieveReceipts(), [atCap], "only the file at the cap is returned");
  const d = client.getLastFetchDiagnostics();
  assert.deepEqual([d.found, d.verified, d.rejected], [2, 1, 1]);
  assert.ok(d.dropReasons[0].includes("is 4097 bytes"), d.dropReasons[0]);
});

check("7e: a symbolic link in the outbox is refused, not followed, even to a genuine receipt", () => {
  const w = freshWire();
  const elsewhere = join(root, `elsewhere-${counter++}`);
  mkdirSync(elsewhere);
  const genuine = signedReceipt(4, "e4".repeat(32), 4, witnessKeys.privateKey);
  placeReceipt(elsewhere, 0, genuine);
  symlinkSync(receiptPath(elsewhere, 0), receiptPath(w.outbox, 0));
  symlinkSync(elsewhere, join(w.outbox, "link-to-a-directory"));
  symlinkSync(join(root, "no-such-file"), receiptPath(w.outbox, 1));

  const client = clientOn(w);
  assert.deepEqual(client.retrieveReceipts(), [], "nothing is read through a link");
  const d = client.getLastFetchDiagnostics();
  assert.deepEqual([d.found, d.verified, d.rejected], [3, 0, 3]);
  assert.ok(
    d.dropReasons.length === 3 && d.dropReasons.every((r) => r.includes("a symbolic link; not followed")),
    JSON.stringify(d.dropReasons)
  );
});

check("7f: a directory the client cannot open (as the witness's staging is) is skipped unopened", () => {
  const w = freshWire();
  const staging = join(w.outbox, ".staging");
  mkdirSync(staging, { mode: 0o000 });
  const good = signedReceipt(0, "f0".repeat(32), 1, witnessKeys.privateKey);
  placeReceipt(w.outbox, 0, good);
  try {
    const client = clientOn(w);
    assert.deepEqual(client.retrieveReceipts(), [good]);
    const d = client.getLastFetchDiagnostics();
    assert.deepEqual([d.found, d.rejected], [1, 0], JSON.stringify(d));
  } finally {
    chmodSync(staging, 0o700);
  }
});

// ── 8 · a submit() write failure ──────────────────────────────────────────────

console.log("── 8: a failed drop is recorded, never thrown into the emitter ──");

check("8: unwritable intake ⇒ diagnostics record the failure, submit() does not throw", () => {
  const w = freshWire();
  const blocker = join(root, `blocker-${counter++}`);
  writeFileSync(blocker, "a file where a directory would have to be\n");
  const client = new FileDropWitness({
    id: "witness-set-a",
    intakeDir: join(blocker, "intake"),
    outboxDir: w.outbox,
    submitterId: "ilas-node-a",
    publicKeyPath: witnessPubPath,
  });

  const log = new LockedEvidenceLog({ path: w.logPath });
  log.append(entry(0));
  const emitter = new HeadCommitEmitter(log, client);
  // The emitter's path must survive a dead wire.
  assert.doesNotThrow(() => emitter.emitStartupCommit());
  assert.doesNotThrow(() => emitter.emit());
  assert.equal(emitter.getCommits().length, 2, "the emitter kept its own record");

  const d = client.getSubmitDiagnostics();
  assert.equal(d.attempted, 2);
  assert.equal(d.written, 0);
  assert.equal(d.failed, 2);
  assert.equal(d.failureReasons.length, 2);
  assert.ok(d.failureReasons.every((r) => r.startsWith("seq ")), "each names its commit");
});

// ── 9 · end to end, against the real predicate ────────────────────────────────

console.log("── 9: end to end — the client arms the alarm it exists to arm ──");

check("9: emitter + client + genuine receipts ⇒ VERIFIED_HISTORICAL; tamper ⇒ MISMATCH", () => {
  const w = freshWire();
  const log = new LockedEvidenceLog({ path: w.logPath });
  for (let i = 0; i < 6; i++) log.append(entry(i));

  const client = new FileDropWitness({
    id: "witness-set-a",
    intakeDir: w.intake,
    outboxDir: w.outbox,
    submitterId: "ilas-node-a",
    publicKeyPath: witnessPubPath,
  });
  const emitter = new HeadCommitEmitter(log, client);
  const commit = emitter.emitStartupCommit();
  assert.equal(commit.seq_no, 5);
  assert.equal(commit.witness_set_id, "witness-set-a", "the commit names the witness set");

  // The drop reached the wire, and says exactly what the witness's validator wants.
  const dropped = JSON.parse(readFileSync(join(w.intake, "ilas-node-a"), "utf8"));
  assert.deepEqual(dropped, commit);
  assert.equal(client.getSubmitDiagnostics().written, 1);

  // The witness signs and files receipts for two of the heads it retained.
  placeReceipt(w.outbox, 1, signedReceipt(3, log.getEntry(3)!.hash, 111, witnessKeys.privateKey));
  placeReceipt(
    w.outbox,
    2,
    signedReceipt(commit.seq_no, commit.head_hash, 222, witnessKeys.privateKey)
  );

  const clean = new ContinuityVerifier(log, client).verify();
  assert.equal(clean.status, "VERIFIED_HISTORICAL");
  assert.equal(clean.receiptsChecked, 2);
  assert.deepEqual(clean.mismatches, []);

  // Now rewrite an entry the receipts constrain, and reload the chain from disk.
  const lines = readFileSync(w.logPath, "utf8").split("\n").filter((l) => l.trim());
  const mid = JSON.parse(lines[2]);
  mid.outcome = "TAMPERED";
  lines[2] = JSON.stringify(mid);
  writeFileSync(w.logPath, lines.join("\n") + "\n");

  const reloaded = new LockedEvidenceLog({ path: w.logPath });
  const alarm = new ContinuityVerifier(reloaded, client).verify();
  assert.equal(alarm.status, "MISMATCH", "the alarm fires on the rewritten chain");
  assert.equal(alarm.receiptsChecked, 2);
  assert.equal(alarm.mismatches.length, 2, "both receipts are independent constraints");
  assert.deepEqual(
    alarm.mismatches.map((m) => m.seq_no).sort((a, b) => a - b),
    [3, 5]
  );
  assert.equal(client.getLastFetchDiagnostics().dropped, 0, "genuine receipts, no drops");
});

// ── 10 · the self-description ─────────────────────────────────────────────────

console.log("── 10: the self-description claims nothing the code cannot hold ──");

const SELF_DESCRIPTION: readonly [string, string][] = [
  ["FILE_DROP_WITNESS_IS_A_CLIENT_NOT_A_WITNESS", FILE_DROP_WITNESS_IS_A_CLIENT_NOT_A_WITNESS],
  ["SUBMISSION_IS_NOT_RETENTION", SUBMISSION_IS_NOT_RETENTION],
  ["UNVERIFIED_RECEIPTS_ARE_DROPPED", UNVERIFIED_RECEIPTS_ARE_DROPPED],
  ["INDEPENDENCE_IS_A_DEPLOYMENT_FACT", INDEPENDENCE_IS_A_DEPLOYMENT_FACT],
];

// Banned as PHRASES, not as words: the honest text has to be able to say
// "independent" and "complete" in order to deny them. What is banned is the claim.
const BANNED_CLAIMS = [
  "anchor is done",
  "anchor is complete",
  "anchor is now",
  "anchor is finished",
  "s-4 complete",
  "s-4-complete",
  "s4 complete",
  "fully anchored",
  "fully independent",
  "fully verified",
  "certified independent",
  "proven independent",
  "independence is established",
  "independence is verified",
  "independence is attested",
  "is now safe",
  "it is safe",
  "safe to assume",
  "guarantee",
  "no longer needed",
  "this is a witness",
];

check("10a: every constant is exported, non-empty, and denies something", () => {
  for (const [name, text] of SELF_DESCRIPTION) {
    assert.equal(typeof text, "string", `${name} is a string`);
    assert.ok(text.length > 80, `${name} is not a stub (${text.length} chars)`);
    assert.ok(
      /\b(not|cannot|never)\b/i.test(text),
      `${name} must state what it does NOT claim`
    );
  }
});

check("10b: no constant claims the anchor is complete, independent, safe, or done", () => {
  for (const [name, text] of SELF_DESCRIPTION) {
    const lower = text.toLowerCase();
    for (const claim of BANNED_CLAIMS) {
      assert.ok(!lower.includes(claim), `${name} must not contain "${claim}"`);
    }
  }
});

check("10c: the production source itself makes no such claim either", () => {
  const source = readFileSync(join(__dirname, "file-drop-witness.ts"), "utf8").toLowerCase();
  for (const claim of BANNED_CLAIMS) {
    assert.ok(!source.includes(claim), `file-drop-witness.ts must not contain "${claim}"`);
  }
  assert.ok(
    source.includes("deployment fact"),
    "the source must carry the independence-is-a-deployment-fact distinction"
  );
  assert.ok(
    source.includes("wire, not the store") || source.includes("wire, not a store"),
    "the source must carry the wire-not-store distinction"
  );
});

check("10d: NullWitness is still the thing you get when you wire nothing", () => {
  // The honest default has to survive: witness.ts ships only the interface and
  // NullWitness, and a stack wired with no witness relies on that.
  const witnessSource = readFileSync(join(__dirname, "witness.ts"), "utf8");
  assert.ok(witnessSource.includes("export class NullWitness"), "NullWitness still ships");
  assert.ok(existsSync(join(__dirname, "witness.ts")));
});

// ── cleanup ───────────────────────────────────────────────────────────────────
rmSync(root, { recursive: true, force: true });

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
