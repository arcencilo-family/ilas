// ──────────────────────────────────────────────────────────────────────────────
// Reference witness — unit tests of the core, in-process, in temp directories.
//   npx ts-node packages/witness/src/witness.test.ts
//
// Covers: config refusals, key files and their permission check, HEAD_COMMIT
// validation, intake processing (declared / undeclared / refused / half-written
// / duplicate / rewrite / rollback / overwrite race), the store (append, verify,
// fail-closed start), outbox reconciliation, symlinks and FIFOs planted in an
// outbox or its staging directory (run in a child process where the witness
// could block), and halting on a failed append.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { spawnSync } from "child_process";
import { generateKeyPairSync } from "crypto";
import type { KeyObject } from "crypto";
import {
  appendFileSync,
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import { join } from "path";

import { publicKeyFingerprint as ilasFingerprint } from "../../../src/l0/fingerprint";
import { checkHeadCommit, GENESIS_HASH } from "./commit";
import { ConfigError, loadConfigFile, parseConfig } from "./config";
import type { WitnessConfig } from "./config";
import {
  generateKeyFiles,
  KeyFileError,
  loadPrivateKeyFile,
  loadPublicKeyFile,
  publicKeyFingerprint,
} from "./keys";
import { receiptBytes, signReceipt, verifyReceipt } from "./receipt";
import {
  readStore,
  receiptOf,
  recordHash,
  recordLine,
  signRecord,
  StoreBroken,
  SubmitterHistory,
  verifyRecordSig,
} from "./store";
import type { StoreRecord, UnhashedRecord } from "./store";
import { ReferenceWitness, WitnessHalted, WitnessRefusal } from "./witness";
import type { PollEvent } from "./witness";

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

const ROOT = mkdtempSync(join(tmpdir(), "ilas-witness-unit-"));
let counter = 0;

const witnessKeys = generateKeyPairSync("ed25519");
const otherKeys = generateKeyPairSync("ed25519");

function hash(n: number): string {
  return n.toString(16).padStart(2, "0").repeat(32);
}

function commit(seq_no: number, head_hash: string, ts = 1_000 + seq_no, setId = "set-a") {
  return { seq_no, head_hash, ts, witness_set_id: setId };
}

interface Rig {
  readonly dir: string;
  readonly intake: string;
  readonly storePath: string;
  readonly config: WitnessConfig;
  outbox(id: string): string;
  open(options?: { key?: KeyObject; clock?: () => number }): ReferenceWitness;
  drop(id: string, content: unknown): void;
  receiptNames(id: string): string[];
}

function rig(ids: string[] = ["node-a"]): Rig {
  const dir = join(ROOT, `rig-${counter++}`);
  const intake = join(dir, "intake");
  const storeDir = join(dir, "store");
  mkdirSync(intake, { recursive: true });
  mkdirSync(storeDir, { recursive: true });
  const outboxes = new Map(ids.map((id) => [id, join(dir, "outbox", id)]));
  for (const o of outboxes.values()) mkdirSync(o, { recursive: true });
  const storePath = join(storeDir, "witness-store.jsonl");
  const config: WitnessConfig = {
    witnessSetId: "set-a",
    intakeDir: intake,
    storePath,
    privateKeyPath: join(dir, "keys", "witness.key"),
    submitters: ids.map((id) => ({ id, outboxDir: outboxes.get(id)! })),
    pollIntervalMs: 1000,
  };
  let ms = 1_700_000_000_000;
  return {
    dir,
    intake,
    storePath,
    config,
    outbox: (id) => outboxes.get(id)!,
    open: (options) =>
      ReferenceWitness.open({
        config,
        privateKey: options?.key ?? witnessKeys.privateKey,
        clock: options?.clock ?? (() => ms++),
      }),
    drop: (id, content) =>
      writeFileSync(
        join(intake, id),
        typeof content === "string" ? content : JSON.stringify(content) + "\n"
      ),
    receiptNames: (id) =>
      readdirSync(outboxes.get(id)!)
        .filter((n) => n.startsWith("receipt-"))
        .sort(),
  };
}

function kinds(events: PollEvent[]): string[] {
  return events.map((e) => e.kind);
}

function refusalCode(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    if (error instanceof WitnessRefusal) return error.code;
    throw error;
  }
  throw new Error("expected a WitnessRefusal, but nothing was thrown");
}

function storeLines(path: string): string[] {
  return readFileSync(path, "utf8").split("\n").filter((l) => l.length > 0);
}

// ── config ────────────────────────────────────────────────────────────────────

console.log("── config ──");

function baseConfig(): Record<string, unknown> {
  return {
    witnessSetId: "set-a",
    intakeDir: "intake",
    storePath: "store/witness-store.jsonl",
    privateKeyPath: "keys/witness.key",
    submitters: [
      { id: "node-a", outboxDir: "outbox/node-a" },
      { id: "node-b", outboxDir: "outbox/node-b" },
    ],
  };
}

check("a valid config parses; relative paths resolve against the base dir", () => {
  const base = join(ROOT, `cfg-${counter++}`);
  const c = parseConfig(baseConfig(), base);
  assert.equal(c.intakeDir, join(base, "intake"));
  assert.equal(c.submitters[1].outboxDir, join(base, "outbox", "node-b"));
  assert.equal(c.pollIntervalMs, 1000, "default poll interval");
});

const configRefusals: [string, (c: Record<string, unknown>) => void, RegExp][] = [
  [
    "two submitters share an outbox",
    (c) => {
      c.submitters = [
        { id: "node-a", outboxDir: "outbox/shared" },
        { id: "node-b", outboxDir: "outbox/x/../shared" },
      ];
    },
    /same directory/,
  ],
  ["an outbox equals the intake", (c) => {
    c.submitters = [{ id: "node-a", outboxDir: "intake" }];
  }, /same directory/],
  ["an outbox nested in the intake", (c) => {
    c.submitters = [{ id: "node-a", outboxDir: "intake/out" }];
  }, /nested/],
  ["a submitter id declared twice", (c) => {
    c.submitters = [
      { id: "node-a", outboxDir: "o1" },
      { id: "node-a", outboxDir: "o2" },
    ];
  }, /declared twice/],
  ["a submitter id that is a path", (c) => {
    c.submitters = [{ id: "../escape", outboxDir: "o1" }];
  }, /path separator/],
  ["a submitter id of ..", (c) => {
    c.submitters = [{ id: "..", outboxDir: "o1" }];
  }, /must not be/],
  ["an unknown key", (c) => {
    c.outbox = "typo";
  }, /unknown config key/],
  ["a missing key", (c) => {
    delete c.storePath;
  }, /missing required config key storePath/],
  ["no submitters", (c) => {
    c.submitters = [];
  }, /non-empty array/],
  ["a submitter with an extra key", (c) => {
    c.submitters = [{ id: "node-a", outboxDir: "o1", extra: 1 }];
  }, /exactly the keys/],
  ["the store inside an outbox", (c) => {
    c.storePath = "outbox/node-a/store.jsonl";
  }, /storePath must not lie inside/],
  ["the private key inside the intake", (c) => {
    c.privateKeyPath = "intake/witness.key";
  }, /privateKeyPath must not lie inside/],
  ["pollIntervalMs out of range", (c) => {
    c.pollIntervalMs = 1;
  }, /pollIntervalMs/],
  ["an empty witnessSetId", (c) => {
    c.witnessSetId = "";
  }, /witnessSetId/],
  ["a submitter id starting with a dot (the witness ignores dot names)", (c) => {
    c.submitters = [{ id: ".node-a", outboxDir: "o1" }];
  }, /must not start with "\."/],
  // ── per-submitter intakes: a submitter's identity is the intake path it is read from
  ["two submitters given one own intake", (c) => {
    c.submitters = [
      { id: "node-a", outboxDir: "outbox/node-a", intakeDir: "in/shared" },
      { id: "node-b", outboxDir: "outbox/node-b", intakeDir: "in/x/../shared" },
    ];
  }, /same directory as intakeDir of submitter "node-a".*own intake must be its alone/],
  ["a submitter's own intake that is the shared intake", (c) => {
    c.submitters = [{ id: "node-a", outboxDir: "outbox/node-a", intakeDir: "intake" }];
  }, /intakeDir of submitter "node-a" is the same directory as intakeDir .*own intake must be its alone/],
  ["a submitter's own intake that is another submitter's outbox", (c) => {
    c.submitters = [
      { id: "node-a", outboxDir: "outbox/node-a", intakeDir: "outbox/node-b" },
      { id: "node-b", outboxDir: "outbox/node-b" },
    ];
  }, /same directory.*no outbox may be an intake/],
  ["a submitter's own intake nested in an outbox", (c) => {
    c.submitters = [{ id: "node-a", outboxDir: "outbox/node-a", intakeDir: "outbox/node-a/in" }];
  }, /nested/],
  ["two own intakes nested in each other", (c) => {
    c.submitters = [
      { id: "node-a", outboxDir: "outbox/node-a", intakeDir: "in-a" },
      { id: "node-b", outboxDir: "outbox/node-b", intakeDir: "in-a/b" },
    ];
  }, /nested/],
  ["the store inside a submitter's own intake", (c) => {
    c.submitters = [{ id: "node-a", outboxDir: "outbox/node-a", intakeDir: "in-a" }];
    c.storePath = "in-a/witness-store.jsonl";
  }, /storePath must not lie inside the intakeDir of submitter "node-a"/],
  ["the private key inside a submitter's own intake", (c) => {
    c.submitters = [{ id: "node-a", outboxDir: "outbox/node-a", intakeDir: "in-a" }];
    c.privateKeyPath = "in-a/witness.key";
  }, /privateKeyPath must not lie inside the intakeDir of submitter "node-a"/],
  ["no shared intake for a submitter without its own", (c) => {
    delete c.intakeDir;
    c.submitters = [
      { id: "node-a", outboxDir: "outbox/node-a", intakeDir: "in-a" },
      { id: "node-b", outboxDir: "outbox/node-b" },
    ];
  }, /missing required config key intakeDir: submitter\(s\) "node-b"/],
  ["an own intakeDir that is not a string", (c) => {
    c.submitters = [{ id: "node-a", outboxDir: "o1", intakeDir: 5 }];
  }, /submitters\[0\]\.intakeDir must be a non-empty string/],
  // ── the ids the node's client refuses: no config may declare one
  ["a submitter id with a control character", (c) => {
    c.submitters = [{ id: "node\ta", outboxDir: "o1" }];
  }, /submitters\[0\]\.id must not contain a control character/],
  ["a submitter id with a C1 control character (U+0085)", (c) => {
    c.submitters = [{ id: "node\u0085a", outboxDir: "o1" }];
  }, /control character/],
  ["a submitter id with a lone surrogate", (c) => {
    c.submitters = [{ id: "node-\ud800", outboxDir: "o1" }];
  }, /well-formed Unicode/],
  ["a submitter id of 238 bytes (the client's temporary name would not fit 255)", (c) => {
    c.submitters = [{ id: "n".repeat(238), outboxDir: "o1" }];
  }, /at most 237 bytes in UTF-8, is 238/],
  ["a submitter id of 80 three-byte characters (240 bytes)", (c) => {
    c.submitters = [{ id: "€".repeat(80), outboxDir: "o1" }];
  }, /at most 237 bytes in UTF-8, is 240/],
];

check("a submitter id of exactly 237 bytes is accepted", () => {
  const base = join(ROOT, `cfg-${counter++}`);
  const c = baseConfig();
  c.submitters = [{ id: "n".repeat(237), outboxDir: "o1" }];
  assert.equal(parseConfig(c, base).submitters[0].id, "n".repeat(237));
});

check("per-submitter intakes parse; the shared intake is then optional", () => {
  const base = join(ROOT, `cfg-${counter++}`);
  const c = baseConfig();
  delete c.intakeDir;
  c.submitters = [
    { id: "node-a", outboxDir: "outbox/node-a", intakeDir: "in-a" },
    { id: "node-b", outboxDir: "outbox/node-b", intakeDir: "in-b" },
  ];
  const parsed = parseConfig(c, base);
  assert.equal(parsed.intakeDir, undefined);
  assert.equal(parsed.submitters[0].intakeDir, join(base, "in-a"));
  assert.equal(parsed.submitters[1].intakeDir, join(base, "in-b"));

  // Mixed: one submitter with its own intake, one on the shared intake.
  const mixed = baseConfig();
  mixed.submitters = [
    { id: "node-a", outboxDir: "outbox/node-a", intakeDir: "in-a" },
    { id: "node-b", outboxDir: "outbox/node-b" },
  ];
  const m = parseConfig(mixed, base);
  assert.equal(m.intakeDir, join(base, "intake"));
  assert.equal(m.submitters[1].intakeDir, undefined);
});

for (const [label, mutate, pattern] of configRefusals) {
  check(`config refused: ${label}`, () => {
    const base = join(ROOT, `cfg-${counter++}`);
    const c = baseConfig();
    mutate(c);
    assert.throws(() => parseConfig(c, base), (e: unknown) => e instanceof ConfigError && pattern.test(e.message));
  });
}

check("config refused: two outboxes that are one directory through a symlink", () => {
  const base = join(ROOT, `cfg-${counter++}`);
  mkdirSync(join(base, "real"), { recursive: true });
  symlinkSync(join(base, "real"), join(base, "alias"));
  const c = baseConfig();
  c.submitters = [
    { id: "node-a", outboxDir: "real" },
    { id: "node-b", outboxDir: "alias" },
  ];
  assert.throws(() => parseConfig(c, base), /same directory/);
});

check("loadConfigFile: invalid JSON is a ConfigError naming the file", () => {
  const p = join(ROOT, `cfg-${counter++}.json`);
  writeFileSync(p, "{ not json");
  assert.throws(() => loadConfigFile(p), (e: unknown) => e instanceof ConfigError && e.message.includes(p));
});

// ── keys ──────────────────────────────────────────────────────────────────────

console.log("── key files ──");

check("keygen writes witness.key at mode 0600 and a matching witness.pub.pem", () => {
  const out = join(ROOT, `keys-${counter++}`);
  const files = generateKeyFiles(out);
  assert.equal(statSync(files.privateKeyPath).mode & 0o777, 0o600);
  assert.equal(files.privateKeyMode, 0o600, "the mode is the one read back");
  const priv = loadPrivateKeyFile(files.privateKeyPath);
  const pub = loadPublicKeyFile(files.publicKeyPath);
  assert.equal(priv.asymmetricKeyType, "ed25519");
  // ILAS's format, so that the operator's print and the node's can be compared.
  assert.match(files.fingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.equal(files.fingerprint, ilasFingerprint(readFileSync(files.publicKeyPath, "utf8")));
  assert.equal(publicKeyFingerprint(pub), files.fingerprint, "the same from the loaded key");
  // The pair belongs together: a receipt signed by one verifies under the other.
  const r = signReceipt({ seq_no: 1, head_hash: hash(1), witness_ts: 5 }, priv);
  assert.equal(verifyReceipt(r, pub), true);
});

check("keygen refuses to overwrite an existing key", () => {
  const out = join(ROOT, `keys-${counter++}`);
  generateKeyFiles(out);
  const before = readFileSync(join(out, "witness.key"), "utf8");
  assert.throws(() => generateKeyFiles(out), (e: unknown) => e instanceof KeyFileError && /refusing to overwrite/.test(e.message));
  assert.equal(readFileSync(join(out, "witness.key"), "utf8"), before, "the key is untouched");
});

for (const mode of [0o640, 0o604, 0o660, 0o644]) {
  check(`a private key file at mode ${mode.toString(8)} is refused, and the message says why`, () => {
    const out = join(ROOT, `keys-${counter++}`);
    const files = generateKeyFiles(out);
    chmodSync(files.privateKeyPath, mode);
    assert.throws(
      () => loadPrivateKeyFile(files.privateKeyPath),
      (e: unknown) =>
        e instanceof KeyFileError &&
        e.message.includes(`mode is 0${mode.toString(8)}`) &&
        e.message.includes("group or others") &&
        e.message.includes("chmod 600")
    );
  });
}

check("a non-ed25519 private key is refused", () => {
  const p = join(ROOT, `rsa-${counter++}.key`);
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  writeFileSync(p, rsa.privateKey.export({ type: "pkcs8", format: "pem" }) as string, { mode: 0o600 });
  assert.throws(() => loadPrivateKeyFile(p), /ed25519 only/);
});

check("a missing private key file is refused (there is no default key)", () => {
  assert.throws(() => loadPrivateKeyFile(join(ROOT, "no-such.key")), /cannot open private key file/);
});

check("keygen fails, and leaves no key behind, when the 0600 mode does not stick", () => {
  // A file system without POSIX permissions (a Windows drive under WSL mounted
  // without metadata) accepts chmod and keeps its own mode. Stand-in: a chmod
  // that sets 0644 whatever it is asked for. keys.ts calls fs.chmodSync through
  // the module object, so replacing it here reaches it.
  const fsModule: typeof import("fs") = require("fs");
  const realChmod = fsModule.chmodSync;
  const out = join(ROOT, `keys-${counter++}`);
  fsModule.chmodSync = ((path: Parameters<typeof realChmod>[0]) =>
    realChmod(path, 0o644)) as typeof realChmod;
  try {
    assert.throws(
      () => generateKeyFiles(out),
      (e: unknown) =>
        e instanceof KeyFileError &&
        /mode reads back as 0644, not 0600/.test(e.message) &&
        /does not keep POSIX permissions/.test(e.message) &&
        /removed again/.test(e.message)
    );
  } finally {
    fsModule.chmodSync = realChmod;
  }
  assert.equal(existsSync(join(out, "witness.key")), false, "the exposed private key was removed");
  assert.equal(existsSync(join(out, "witness.pub.pem")), false, "no public half without a private one");
});

check("keygen fails, and leaves no key behind, when chmod itself throws EPERM", () => {
  // What setattr_prepare returns on a FAT/exFAT mount owned by another account
  // that this account can write (or a FUSE mount, or an LSM, refusing chmod).
  const fsModule: typeof import("fs") = require("fs");
  const realChmod = fsModule.chmodSync;
  const out = join(ROOT, `keys-${counter++}`);
  fsModule.chmodSync = ((path: Parameters<typeof realChmod>[0]) => {
    const error = new Error(`EPERM: operation not permitted, chmod '${String(path)}'`) as NodeJS.ErrnoException;
    error.code = "EPERM";
    error.syscall = "chmod";
    throw error;
  }) as typeof realChmod;
  try {
    assert.throws(
      () => generateKeyFiles(out),
      (e: unknown) =>
        e instanceof KeyFileError &&
        /setting its mode to 0600 failed \(EPERM/.test(e.message) &&
        /removed again/.test(e.message)
    );
  } finally {
    fsModule.chmodSync = realChmod;
  }
  assert.equal(existsSync(join(out, "witness.key")), false, "the private key was removed");
  assert.equal(existsSync(join(out, "witness.pub.pem")), false, "no public half was written");
});

check("keygen fails, and leaves no partial key behind, when writing the key fails", () => {
  const fsModule: typeof import("fs") = require("fs");
  const realWrite = fsModule.writeFileSync;
  const out = join(ROOT, `keys-${counter++}`);
  // Only the write through the new key file's descriptor fails (ENOSPC, EIO).
  fsModule.writeFileSync = ((file: Parameters<typeof realWrite>[0], ...rest: unknown[]) => {
    if (typeof file === "number") {
      realWrite(file, "-----BEGIN PRIVATE KEY-----\n");
      const error = new Error("ENOSPC: no space left on device, write") as NodeJS.ErrnoException;
      error.code = "ENOSPC";
      throw error;
    }
    return (realWrite as (...a: unknown[]) => void)(file, ...rest);
  }) as typeof realWrite;
  try {
    assert.throws(
      () => generateKeyFiles(out),
      (e: unknown) =>
        e instanceof KeyFileError && /could not write .*ENOSPC/.test(e.message) && /removed again/.test(e.message)
    );
  } finally {
    fsModule.writeFileSync = realWrite;
  }
  assert.equal(existsSync(join(out, "witness.key")), false, "the partial private key was removed");
  assert.equal(existsSync(join(out, "witness.pub.pem")), false);
});

check("a public key file that holds a PRIVATE key is refused, and the message says to give only the public key", () => {
  const files = generateKeyFiles(join(ROOT, `keys-${counter++}`));
  assert.throws(
    () => loadPublicKeyFile(files.privateKeyPath),
    (e: unknown) =>
      e instanceof KeyFileError && /holds a PRIVATE key/.test(e.message) && /PUBLIC key file/.test(e.message)
  );
  assert.equal(loadPublicKeyFile(files.publicKeyPath).asymmetricKeyType, "ed25519", "the public file loads");
});

check("ReferenceWitness.open refuses a key object that is not Ed25519 (RSA)", () => {
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const r = rig();
  assert.equal(refusalCode(() => r.open({ key: rsa.privateKey })), "KEY_NOT_ED25519");
  assert.equal(existsSync(r.storePath), false, "refused before any store was created");
});

// ── HEAD_COMMIT validation ────────────────────────────────────────────────────

console.log("── HEAD_COMMIT validation ──");

check("a valid commit is accepted and returned with its keys in order", () => {
  const r = checkHeadCommit({ witness_set_id: "set-a", ts: 1, head_hash: hash(1), seq_no: 0 }, "set-a");
  assert.ok(r.ok);
  if (r.ok) assert.deepEqual(Object.keys(r.commit), ["seq_no", "head_hash", "ts", "witness_set_id"]);
});

check("the empty chain (seq -1, genesis hash) is accepted", () => {
  assert.ok(checkHeadCommit(commit(-1, GENESIS_HASH), "set-a").ok);
});

const badCommits: [string, unknown, RegExp][] = [
  ["an extra key", { ...commit(1, hash(1)), note: "x" }, /keys must be exactly/],
  ["a missing key", { seq_no: 1, head_hash: hash(1), ts: 1 }, /keys must be exactly/],
  ["seq_no -2", commit(-2, hash(1)), /seq_no/],
  ["seq_no 1.5", commit(1.5, hash(1)), /seq_no/],
  ["seq_no beyond safe integers", commit(2 ** 53, hash(1)), /seq_no/],
  ["seq_no as a string", { ...commit(1, hash(1)), seq_no: "1" }, /seq_no/],
  ["uppercase head_hash", commit(1, hash(1).toUpperCase().replace(/^0/, "A")), /head_hash/],
  ["63-char head_hash", commit(1, hash(1).slice(1)), /head_hash/],
  ["ts NaN", { ...commit(1, hash(1)), ts: NaN }, /ts must be/],
  ["ts Infinity", { ...commit(1, hash(1)), ts: Infinity }, /ts must be/],
  ["another witness set", commit(1, hash(1), 1, "set-b"), /addressed to witness set "set-b"/],
  ["seq -1 without the genesis hash", commit(-1, hash(1)), /genesis/],
  ["the genesis hash at seq 0", commit(0, GENESIS_HASH), /genesis/],
  ["an array", [1, 2, 3, 4], /not a JSON object/],
];
for (const [label, value, pattern] of badCommits) {
  check(`refused: ${label}`, () => {
    const r = checkHeadCommit(value, "set-a");
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, pattern);
  });
}

// ── intake processing ─────────────────────────────────────────────────────────

console.log("── intake processing ──");

check("a valid commit is retained, signed, written to its outbox, and the intake file removed", () => {
  const r = rig();
  const w = r.open();
  r.drop("node-a", commit(4, hash(4)));
  const events = w.pollOnce();
  assert.deepEqual(kinds(events), ["RETAINED"]);
  const e = events[0];
  assert.ok(e.kind === "RETAINED" && e.index === 0 && e.seq_no === 4 && e.conflicts.length === 0);

  assert.equal(existsSync(join(r.intake, "node-a")), false, "intake file consumed");
  const names = r.receiptNames("node-a");
  assert.deepEqual(names, ["receipt-000000000000.json"]);
  const receipt = JSON.parse(readFileSync(join(r.outbox("node-a"), names[0]), "utf8"));
  assert.deepEqual(Object.keys(receipt), ["seq_no", "head_hash", "witness_ts", "witness_sig"]);
  assert.equal(receipt.seq_no, 4);
  assert.equal(receipt.head_hash, hash(4));
  assert.equal(verifyReceipt(receipt, witnessKeys.publicKey), true);
  assert.equal(verifyReceipt(receipt, otherKeys.publicKey), false);

  const records = w.records();
  assert.equal(records.length, 1);
  const rec = records[0];
  assert.deepEqual(Object.keys(JSON.parse(storeLines(r.storePath)[0])), [
    "index", "prev_hash", "submitter_id", "commit", "witness_ts", "witness_sig", "conflicts", "hash",
    "record_sig",
  ]);
  assert.equal(rec.prev_hash, GENESIS_HASH, "the first record links to 64 zeros");
  assert.equal(rec.submitter_id, "node-a");
  assert.deepEqual(rec.commit, commit(4, hash(4)));
  assert.equal(rec.witness_ts, receipt.witness_ts, "the receipt carries the record's witness time");
  assert.equal(rec.hash, recordHash(rec));
  assert.equal(verifyRecordSig(rec, witnessKeys.publicKey), true, "the record is signed whole");
  assert.equal(verifyRecordSig(rec, otherKeys.publicKey), false);
});

check("only declared submitters are processed; anything else is left alone and reported once", () => {
  const r = rig();
  const w = r.open();
  writeFileSync(join(r.intake, "stranger"), JSON.stringify(commit(1, hash(1))) + "\n");
  writeFileSync(join(r.intake, "notes.txt"), "hello\n");
  const first = w.pollOnce();
  assert.deepEqual(
    first.map((e) => (e.kind === "UNDECLARED" ? e.name : e.kind)).sort(),
    ["notes.txt", "stranger"]
  );
  assert.deepEqual(w.pollOnce(), [], "a standing condition is not re-reported every poll");
  assert.ok(existsSync(join(r.intake, "stranger")) && existsSync(join(r.intake, "notes.txt")));
  assert.equal(w.records().length, 0, "nothing retained");
  assert.deepEqual(r.receiptNames("node-a"), []);
});

check("dot names in an intake (the client's temporary files) are never read and never reported", () => {
  const r = rig();
  const w = r.open();
  const tmp = join(r.intake, ".node-a.0123456789ab.tmp");
  writeFileSync(tmp, JSON.stringify(commit(1, hash(1))) + "\n");
  writeFileSync(join(r.intake, ".hidden"), "not a commit\n");
  assert.deepEqual(w.pollOnce(), [], "silently ignored");
  assert.deepEqual(w.pollOnce(), []);
  assert.ok(existsSync(tmp) && existsSync(join(r.intake, ".hidden")), "left alone");
  assert.equal(w.records().length, 0);
  // Renamed onto the submitter's name, as the client does once the write is complete.
  renameSync(tmp, join(r.intake, "node-a"));
  assert.deepEqual(kinds(w.pollOnce()), ["RETAINED"]);
});

/** A rig whose node-a reads from its own intake directory; node-b stays on the shared one. */
function ownIntakeRig(): { r: Rig; ownA: string; w: ReferenceWitness } {
  const r = rig(["node-a", "node-b"]);
  const ownA = join(r.dir, "intake-node-a");
  mkdirSync(ownA);
  const config: WitnessConfig = {
    ...r.config,
    submitters: [
      { id: "node-a", outboxDir: r.outbox("node-a"), intakeDir: ownA },
      { id: "node-b", outboxDir: r.outbox("node-b") },
    ],
  };
  let ms = 1_700_000_000_000;
  const w = ReferenceWitness.open({ config, privateKey: witnessKeys.privateKey, clock: () => ms++ });
  return { r, ownA, w };
}

check("a submitter with its own intake is read only from there; its name anywhere else is UNDECLARED", () => {
  const { r, ownA, w } = ownIntakeRig();
  // Another writer of the shared intake drops a commit under node-a's name, and
  // one under node-b's name into node-a's own intake.
  writeFileSync(join(r.intake, "node-a"), JSON.stringify(commit(1, hash(1))) + "\n");
  writeFileSync(join(ownA, "node-b"), JSON.stringify(commit(1, hash(2))) + "\n");
  const first = w.pollOnce();
  assert.deepEqual(
    first.map((e) => (e.kind === "UNDECLARED" ? `${e.intakeDir}|${e.name}` : e.kind)).sort(),
    [`${r.intake}|node-a`, `${ownA}|node-b`].sort()
  );
  assert.deepEqual(w.pollOnce(), [], "reported once");
  assert.equal(w.records().length, 0, "neither is retained");
  assert.deepEqual(r.receiptNames("node-a"), []);
  assert.deepEqual(r.receiptNames("node-b"), []);
  assert.ok(existsSync(join(r.intake, "node-a")) && existsSync(join(ownA, "node-b")), "left alone");

  // node-a's own commit, in its own intake, is retained for node-a.
  writeFileSync(join(ownA, "node-a"), JSON.stringify(commit(2, hash(3))) + "\n");
  const second = w.pollOnce();
  assert.deepEqual(kinds(second), ["RETAINED"]);
  assert.ok(second[0].kind === "RETAINED" && second[0].submitterId === "node-a" && second[0].seq_no === 2);
  assert.equal(existsSync(join(ownA, "node-a")), false, "consumed");
  // node-b is still served from the shared intake.
  r.drop("node-b", commit(1, hash(4)));
  const third = w.pollOnce();
  assert.deepEqual(kinds(third), ["RETAINED"]);
  assert.ok(third[0].kind === "RETAINED" && third[0].submitterId === "node-b");
  assert.deepEqual(w.records().map((x) => x.submitter_id), ["node-a", "node-b"]);
});

check("start refused: a submitter's own intake directory is missing (it is not created)", () => {
  const { r, ownA } = ownIntakeRig();
  rmSync(ownA, { recursive: true });
  const config: WitnessConfig = {
    ...r.config,
    submitters: [
      { id: "node-a", outboxDir: r.outbox("node-a"), intakeDir: ownA },
      { id: "node-b", outboxDir: r.outbox("node-b") },
    ],
  };
  assert.throws(
    () => ReferenceWitness.open({ config, privateKey: witnessKeys.privateKey }),
    (e: unknown) =>
      e instanceof WitnessRefusal && e.code === "DIRECTORY_MISSING" && /intakeDir of submitter "node-a"/.test(e.message)
  );
  assert.equal(existsSync(ownA), false);
});

check("a commit addressed to another witness set is refused, not signed, and left in place", () => {
  const r = rig();
  const w = r.open();
  r.drop("node-a", commit(1, hash(1), 1, "set-b"));
  const events = w.pollOnce();
  assert.deepEqual(kinds(events), ["REFUSED"]);
  assert.ok(events[0].kind === "REFUSED" && /set-b/.test(events[0].reason));
  assert.equal(w.records().length, 0);
  assert.deepEqual(r.receiptNames("node-a"), []);
  assert.ok(existsSync(join(r.intake, "node-a")));
  assert.deepEqual(w.pollOnce(), [], "reported once");
});

check("a commit with an extra key is refused", () => {
  const r = rig();
  const w = r.open();
  r.drop("node-a", { ...commit(1, hash(1)), extra: true });
  assert.deepEqual(kinds(w.pollOnce()), ["REFUSED"]);
  assert.equal(w.records().length, 0);
});

check("a half-written file is not signed; it is read again and retained once complete", () => {
  const r = rig();
  const w = r.open();
  const full = JSON.stringify(commit(2, hash(2))) + "\n";
  r.drop("node-a", full.slice(0, 30));
  assert.deepEqual(kinds(w.pollOnce()), ["DEFERRED"]);
  assert.equal(w.records().length, 0);
  r.drop("node-a", full);
  assert.deepEqual(kinds(w.pollOnce()), ["RETAINED"]);
  assert.equal(w.records().length, 1);
});

check("an unparseable file is reported MALFORMED only when unchanged across polls, and only once", () => {
  const r = rig();
  const w = r.open();
  r.drop("node-a", "{\"seq_no\": 1, \"head_");
  assert.deepEqual(kinds(w.pollOnce()), ["DEFERRED"]);
  const second = w.pollOnce();
  assert.deepEqual(kinds(second), ["MALFORMED"]);
  assert.ok(second[0].kind === "MALFORMED" && second[0].byteLength === 20);
  assert.deepEqual(w.pollOnce(), [], "not re-reported");
  assert.ok(existsSync(join(r.intake, "node-a")), "left in place");
  r.drop("node-a", "{\"seq_no\": 1, \"head_hash");
  assert.deepEqual(kinds(w.pollOnce()), ["DEFERRED"], "changed bytes start over");
  assert.equal(w.records().length, 0);
});

check("an identical commit already retained produces no new record and no duplicate receipt", () => {
  const r = rig();
  const w = r.open();
  r.drop("node-a", commit(3, hash(3)));
  w.pollOnce();
  r.drop("node-a", commit(3, hash(3)));
  const events = w.pollOnce();
  assert.deepEqual(kinds(events), ["DUPLICATE"]);
  assert.ok(events[0].kind === "DUPLICATE" && events[0].priorIndex === 0);
  // The node's own ts is not part of what a receipt attests: a re-emit of the
  // same head with a later ts is the same head.
  r.drop("node-a", commit(3, hash(3), 999_999));
  assert.deepEqual(kinds(w.pollOnce()), ["DUPLICATE"]);
  assert.equal(w.records().length, 1);
  assert.deepEqual(r.receiptNames("node-a"), ["receipt-000000000000.json"]);
  assert.equal(existsSync(join(r.intake, "node-a")), false, "duplicates are consumed too");
});

check("same seq_no, different head_hash: both retained and signed, the second carries a note", () => {
  const r = rig();
  const w = r.open();
  r.drop("node-a", commit(5, hash(5)));
  w.pollOnce();
  r.drop("node-a", commit(5, hash(55)));
  const events = w.pollOnce();
  assert.deepEqual(kinds(events), ["RETAINED"]);
  const e = events[0];
  assert.ok(e.kind === "RETAINED");
  if (e.kind === "RETAINED") {
    assert.deepEqual(e.conflicts, [
      { kind: "SAME_SEQ_DIFFERENT_HEAD", prior_index: 0, prior_head_hash: hash(5) },
    ]);
  }
  assert.equal(r.receiptNames("node-a").length, 2, "both are signed");
  assert.deepEqual(w.records()[1].conflicts, (e as { conflicts: unknown }).conflicts, "the note is in the store");
});

check("a lower seq_no than before (rollback) is retained and signed with a note", () => {
  const r = rig();
  const w = r.open();
  r.drop("node-a", commit(9, hash(9)));
  w.pollOnce();
  r.drop("node-a", commit(4, hash(4)));
  const events = w.pollOnce();
  assert.deepEqual(kinds(events), ["RETAINED"]);
  assert.deepEqual(w.records()[1].conflicts, [
    { kind: "SEQ_LOWER_THAN_RETAINED", prior_index: 0, prior_seq_no: 9 },
  ]);
  assert.equal(r.receiptNames("node-a").length, 2);
});

check("a rollback to a head already retained is a DUPLICATE: no new record, the file is consumed", () => {
  const r = rig();
  const w = r.open();
  for (const [seq, h] of [[0, 1], [2, 2], [3, 3]]) {
    r.drop("node-a", commit(seq, hash(h)));
    assert.deepEqual(kinds(w.pollOnce()), ["RETAINED"]);
  }
  // Back to seq 2 with head hash(2), which index 1 retained: the store cannot hold one head
  // twice for a submitter, so nothing new is written ...
  r.drop("node-a", commit(2, hash(2), 99_999));
  const back = w.pollOnce();
  assert.deepEqual(kinds(back), ["DUPLICATE"]);
  assert.ok(back[0].kind === "DUPLICATE" && back[0].priorIndex === 1);
  assert.equal(w.records().length, 3);
  assert.equal(r.receiptNames("node-a").length, 3);
  assert.equal(existsSync(join(r.intake, "node-a")), false, "consumed");
  // ... and the rollback stays visible through the receipt for seq 3 (index 2),
  // which a chain back at seq 2 no longer reproduces. A rollback to a head not
  // retained before is a new record with a note:
  r.drop("node-a", commit(1, hash(9)));
  const lower = w.pollOnce();
  assert.deepEqual(kinds(lower), ["RETAINED"]);
  assert.deepEqual(w.records()[3].conflicts, [
    { kind: "SEQ_LOWER_THAN_RETAINED", prior_index: 2, prior_seq_no: 3 },
  ]);
});

check("receipts go only to their submitter's outbox, under names that sort in store order", () => {
  const r = rig(["node-a", "node-b"]);
  const w = r.open();
  for (let i = 0; i < 3; i++) {
    r.drop("node-a", commit(i, hash(10 + i)));
    r.drop("node-b", commit(i, hash(20 + i)));
    w.pollOnce();
  }
  const a = r.receiptNames("node-a");
  const b = r.receiptNames("node-b");
  assert.equal(a.length, 3);
  assert.equal(b.length, 3);
  const heads = (id: string, names: string[]) =>
    names.map((n) => JSON.parse(readFileSync(join(r.outbox(id), n), "utf8")).head_hash);
  assert.deepEqual(heads("node-a", a), [hash(10), hash(11), hash(12)], "a's own heads, in order");
  assert.deepEqual(heads("node-b", b), [hash(20), hash(21), hash(22)], "b's own heads, in order");
  const indices = (names: string[]) => names.map((n) => Number(n.slice(8, 20)));
  for (const list of [indices(a), indices(b)]) {
    assert.deepEqual([...list].sort((x, y) => x - y), list, "name order is store order");
  }
});

check("an intake file overwritten after it was read is not removed; the newer commit is retained next", () => {
  const r = rig();
  let ms = 1_700_000_000_000;
  let overwrite = true;
  // The clock is read between validating a commit and retaining it, which is
  // exactly the window in which the node's client may overwrite the file.
  const w = r.open({
    clock: () => {
      if (overwrite) {
        overwrite = false;
        r.drop("node-a", commit(8, hash(8)));
      }
      return ms++;
    },
  });
  r.drop("node-a", commit(7, hash(7)));
  const first = w.pollOnce();
  assert.deepEqual(kinds(first), ["RETAINED", "INTAKE_LEFT"]);
  assert.ok(existsSync(join(r.intake, "node-a")), "the newer commit was not deleted");
  const second = w.pollOnce();
  assert.deepEqual(kinds(second), ["RETAINED"]);
  assert.deepEqual(w.records().map((x) => x.commit.seq_no), [7, 8]);
  assert.equal(existsSync(join(r.intake, "node-a")), false);
});

check("a symlink named like a submitter is not followed", () => {
  const r = rig();
  const w = r.open();
  const target = join(r.dir, "elsewhere.json");
  writeFileSync(target, JSON.stringify(commit(1, hash(1))) + "\n");
  symlinkSync(target, join(r.intake, "node-a"));
  assert.deepEqual(kinds(w.pollOnce()), ["NOT_A_FILE"]);
  assert.equal(w.records().length, 0);
});

check("a FIFO named like a submitter does not block the poll", () => {
  const r = rig();
  const w = r.open();
  const made = spawnSync("mkfifo", [join(r.intake, "node-a")], { timeout: 5000 });
  if (made.status !== 0) {
    console.log("    (mkfifo unavailable; skipped)");
    return;
  }
  assert.deepEqual(kinds(w.pollOnce()), ["NOT_A_FILE"]);
});

check("an oversized file is refused without being read into a commit", () => {
  const r = rig();
  const w = r.open();
  r.drop("node-a", " ".repeat(5000) + JSON.stringify(commit(1, hash(1))));
  const events = w.pollOnce();
  assert.deepEqual(kinds(events), ["REFUSED"]);
  assert.equal(w.records().length, 0);
});

check("a receipt that cannot be written is retried each poll; the record is already retained", () => {
  const r = rig();
  const w = r.open();
  chmodSync(r.outbox("node-a"), 0o555);
  try {
    r.drop("node-a", commit(1, hash(1)));
    const events = w.pollOnce();
    assert.deepEqual(kinds(events), ["RECEIPT_PENDING", "RETAINED"]);
    assert.ok(events[1].kind === "RETAINED" && events[1].receiptFile === null);
    assert.equal(w.records().length, 1, "retained before the outbox was touched");
    assert.equal(existsSync(join(r.intake, "node-a")), false, "the commit is consumed");
    assert.deepEqual(w.pollOnce(), [], "the same failure is not re-reported");
  } finally {
    chmodSync(r.outbox("node-a"), 0o755);
  }
  assert.deepEqual(kinds(w.pollOnce()), ["RECEIPT_WRITTEN"]);
  assert.equal(r.receiptNames("node-a").length, 1);
});

check("a different file planted at the next receipt name after start is never overwritten; the receipt stays pending", () => {
  const r = rig();
  const w = r.open();
  const path = join(r.outbox("node-a"), "receipt-000000000000.json");
  const planted = '{"planted":true}\n';
  writeFileSync(path, planted);
  r.drop("node-a", commit(1, hash(1)));
  const events = w.pollOnce();
  assert.deepEqual(kinds(events), ["RECEIPT_PENDING", "RETAINED"]);
  assert.ok(events[0].kind === "RECEIPT_PENDING" && /already exists with different content/.test(events[0].detail));
  assert.ok(events[1].kind === "RETAINED" && events[1].receiptFile === null, "not reported as written");
  assert.equal(readFileSync(path, "utf8"), planted, "the planted file is untouched");
  assert.deepEqual(w.pollOnce(), [], "the same failure is not re-reported");
  unlinkSync(path);
  assert.deepEqual(kinds(w.pollOnce()), ["RECEIPT_WRITTEN"]);
  assert.equal(readFileSync(path, "utf8"), receiptBytes(receiptOf(w.records()[0])));
});

/**
 * Open the witness on `r` in a child process, so that a witness blocked on a
 * planted FIFO fails the test instead of hanging the suite (the child is
 * SIGKILLed after 30 s). Prints "REFUSED <code>" or "OPENED"; in "poll" mode
 * it then plants a FIFO at receipt 0 (after start: at start one would be
 * refused earlier, as OUTBOX_AHEAD_OF_STORE), drops a commit, polls once and
 * prints the event kinds.
 */
function openInChild(r: Rig, mode: "open" | "poll"): { out: string; timedOut: boolean } {
  const js = `
    const { ReferenceWitness, WitnessRefusal } = require(${JSON.stringify(join(__dirname, "witness"))});
    const { createPrivateKey } = require("crypto");
    const { execFileSync } = require("child_process");
    const { writeFileSync } = require("fs");
    const a = JSON.parse(process.argv[1]);
    try {
      const w = ReferenceWitness.open({ config: a.config, privateKey: createPrivateKey(a.pem) });
      console.log("OPENED");
      if (a.mode === "poll") {
        execFileSync("mkfifo", [a.fifo]);
        writeFileSync(a.intakeFile, JSON.stringify(a.commit) + "\\n");
        console.log(w.pollOnce().map((e) => e.kind).join(","));
      }
    } catch (e) {
      console.log(e instanceof WitnessRefusal ? "REFUSED " + e.code : "THREW " + e);
    }`;
  const arg = JSON.stringify({
    config: r.config,
    pem: witnessKeys.privateKey.export({ type: "pkcs8", format: "pem" }),
    mode,
    intakeFile: join(r.intake, "node-a"),
    commit: commit(9, hash(9)),
    fifo: join(r.outbox("node-a"), "receipt-000000000000.json"),
  });
  const res = spawnSync(process.execPath, ["-r", require.resolve("ts-node/register"), "-e", js, arg], {
    cwd: ROOT, // nothing it does lands in the repository
    timeout: 30_000,
    killSignal: "SIGKILL",
    encoding: "utf8",
    env: {
      ...process.env,
      TS_NODE_TRANSPILE_ONLY: "true",
      TS_NODE_PROJECT: join(__dirname, "..", "tsconfig.json"),
    },
  });
  return { out: (res.stdout ?? "").trim() + (res.stderr ? ` | stderr: ${res.stderr.trim()}` : ""), timedOut: res.error !== undefined };
}

function mkfifo(path: string): boolean {
  const made = spawnSync("mkfifo", [path], { timeout: 5000 });
  if (made.status !== 0) console.log("    (mkfifo unavailable; skipped)");
  return made.status === 0;
}

check("a FIFO planted at the next receipt name leaves that receipt pending; the poll is not blocked", () => {
  const r = rig();
  const path = join(r.outbox("node-a"), "receipt-000000000000.json");
  if (!mkfifo(join(r.dir, "probe.fifo"))) return;
  const res = openInChild(r, "poll");
  assert.equal(res.timedOut, false, `the witness blocked on the FIFO while writing the receipt: ${res.out}`);
  assert.equal(res.out, "OPENED\nRECEIPT_PENDING,RETAINED");
  assert.equal(storeLines(r.storePath).length, 1, "the record is retained");
  assert.ok(lstatSync(path).isFIFO(), "the FIFO is not overwritten");
});

check("a symlink at the next receipt name is not written through, even to a file with the right bytes", () => {
  const r = rig();
  const witness_ts = 1_700_000_000_000;
  const w = r.open({ clock: () => witness_ts });
  const path = join(r.outbox("node-a"), "receipt-000000000000.json");
  // Ed25519 is deterministic: these are the very bytes the witness will sign.
  const right = receiptBytes(signReceipt({ seq_no: 1, head_hash: hash(1), witness_ts }, witnessKeys.privateKey));
  const target = join(r.dir, "elsewhere.json");
  writeFileSync(target, right);
  symlinkSync(target, path);
  r.drop("node-a", commit(1, hash(1)));
  const events = w.pollOnce();
  assert.deepEqual(kinds(events), ["RECEIPT_PENDING", "RETAINED"], "a link is not taken for the receipt");
  assert.ok(events[0].kind === "RECEIPT_PENDING" && /symbolic link, not a regular file/.test(events[0].detail));
  assert.ok(events[1].kind === "RETAINED" && events[1].receiptFile === null);
  assert.equal(readFileSync(target, "utf8"), right, "the link's target is untouched");
  assert.ok(lstatSync(path).isSymbolicLink(), "the link is left where it is");
});

check("a .staging symlink planted by an outbox writer is not followed: the store survives, the receipt stays pending", () => {
  const r = rig();
  const w = r.open();
  r.drop("node-a", commit(0, hash(1)));
  w.pollOnce(); // record 0; its receipt write creates .staging
  const outbox = r.outbox("node-a");
  const staging = join(outbox, ".staging");
  const attacker = join(r.dir, "attacker");
  mkdirSync(attacker);
  rmSync(staging, { recursive: true });
  symlinkSync(attacker, staging);
  // The temporary name the witness used to use: <receipt name>.<pid>.tmp, pid from STARTED.
  const planted = join(attacker, `receipt-000000000001.json.${process.pid}.tmp`);
  symlinkSync(r.storePath, planted);

  r.drop("node-a", commit(1, hash(2)));
  const events = w.pollOnce();
  assert.deepEqual(kinds(events), ["RECEIPT_PENDING", "RETAINED"]);
  assert.ok(events[0].kind === "RECEIPT_PENDING" && /\.staging is a symbolic link, not a directory/.test(events[0].detail));
  assert.ok(events[1].kind === "RETAINED" && events[1].receiptFile === null);
  const store = readStore(r.storePath, { publicKey: w.publicKey });
  assert.equal(store.records.length, 2, "the store still holds both records and verifies");
  assert.equal(existsSync(join(outbox, "receipt-000000000001.json")), false, "no receipt renamed in through the link");
  assert.deepEqual(readdirSync(attacker), [`receipt-000000000001.json.${process.pid}.tmp`], "nothing created in the link's target");
  assert.ok(lstatSync(planted).isSymbolicLink(), "the planted link is untouched");

  // At the next start the missing receipt cannot be restored: refused, loudly.
  assert.equal(refusalCode(() => r.open()), "OUTBOX_UNWRITABLE");
  // Once the link is gone, the witness makes its own staging directory again.
  unlinkSync(staging);
  const again = r.open();
  assert.deepEqual(again.startup.receiptsRestored.map((x) => x.index), [1]);
  assert.ok(lstatSync(staging).isDirectory());
});

check("a link planted in the staging directory at a predictable name is never opened: the store survives", () => {
  const r = rig();
  const w = r.open();
  r.drop("node-a", commit(0, hash(1)));
  w.pollOnce();
  const staging = join(r.outbox("node-a"), ".staging");
  assert.ok(lstatSync(staging).isDirectory());
  const planted = join(staging, `receipt-000000000001.json.${process.pid}.tmp`);
  symlinkSync(r.storePath, planted);
  r.drop("node-a", commit(1, hash(2)));
  const events = w.pollOnce();
  assert.deepEqual(kinds(events), ["RETAINED"]);
  assert.equal(readStore(r.storePath, { publicKey: w.publicKey }).records.length, 2, "the store verifies");
  const receipt = join(r.outbox("node-a"), "receipt-000000000001.json");
  assert.ok(lstatSync(receipt).isFile(), "the receipt is a regular file of the witness's own");
  assert.equal(readFileSync(receipt, "utf8"), receiptBytes(receiptOf(w.records()[1])));
});

check("a clock that returns a non-integer halts the witness before anything is written; it stays halted", () => {
  const r = rig();
  let calls = 0;
  // Bad once, sane afterwards: the halt must hold even when the cause is gone.
  const w = r.open({ clock: () => (++calls === 1 ? 1.5 : 1_700_000_000_000) });
  r.drop("node-a", commit(1, hash(1)));
  assert.throws(() => w.pollOnce(), WitnessHalted);
  assert.equal(readFileSync(r.storePath, "utf8"), "");
  assert.equal(w.isHalted(), true);
  assert.throws(() => w.pollOnce(), WitnessHalted, "halted stays halted, even once the clock is sane");
  assert.equal(readFileSync(r.storePath, "utf8"), "", "nothing retained after the halt");
  assert.equal(w.records().length, 0);
  assert.ok(existsSync(join(r.intake, "node-a")), "the commit is still in the intake");
  assert.deepEqual(r.receiptNames("node-a"), []);
});

// ── the store ─────────────────────────────────────────────────────────────────

console.log("── the store: durable, chained, fail-closed ──");

/** A rig with `n` retained commits for node-a, closed again. */
function filled(n: number, ids: string[] = ["node-a"]): Rig {
  const r = rig(ids);
  const w = r.open();
  for (let i = 0; i < n; i++) {
    r.drop(ids[i % ids.length], commit(i, hash(30 + i)));
    w.pollOnce();
  }
  return r;
}

check("a store re-opens and verifies; records chain from genesis", () => {
  const r = filled(4);
  const w = r.open();
  assert.equal(w.startup.storeCreated, false);
  assert.equal(w.startup.records, 4);
  const recs = w.records();
  assert.equal(recs[0].prev_hash, GENESIS_HASH);
  for (let i = 1; i < recs.length; i++) assert.equal(recs[i].prev_hash, recs[i - 1].hash);
  assert.equal(readStore(r.storePath, { publicKey: witnessKeys.publicKey }).records.length, 4);
});

check("a first start creates an empty store and says so", () => {
  const r = rig();
  const w = r.open();
  assert.equal(w.startup.storeCreated, true);
  assert.equal(readFileSync(r.storePath, "utf8"), "");
});

function tamper(r: Rig, edit: (lines: string[]) => string[], trailingNewline = true): void {
  const lines = edit(storeLines(r.storePath));
  writeFileSync(r.storePath, lines.join("\n") + (trailingNewline && lines.length > 0 ? "\n" : ""));
}

/**
 * What anyone who can write the store file can do WITHOUT the key: edit the
 * records, then renumber, relink, recompute every conflict note and every hash,
 * so that the file is consistent with itself again. Fields this cannot
 * recompute (signatures) are carried over as they were.
 */
function rewriteWithoutKey(
  path: string,
  edit: (records: Record<string, unknown>[]) => Record<string, unknown>[]
): void {
  const records = edit(storeLines(path).map((l) => JSON.parse(l) as Record<string, unknown>));
  const history = new SubmitterHistory();
  let prev = GENESIS_HASH;
  const lines = records.map((rec, i) => {
    const submitter = rec.submitter_id as string;
    const c = rec.commit as StoreRecord["commit"];
    rec.index = i;
    rec.prev_hash = prev;
    rec.conflicts = history.conflictsFor(submitter, c);
    rec.hash = recordHash(rec as unknown as UnhashedRecord);
    history.add(submitter, c, i);
    prev = rec.hash as string;
    return JSON.stringify(rec);
  });
  writeFileSync(path, lines.join("\n") + "\n");
}

/** Append a copy of record `from`, re-indexed, re-linked and signed whole WITH the witness key. */
function appendSignedCopy(r: Rig, from: number, conflicts: StoreRecord["conflicts"]): void {
  const lines = storeLines(r.storePath);
  const src = JSON.parse(lines[from]) as StoreRecord;
  const last = JSON.parse(lines[lines.length - 1]) as StoreRecord;
  const unhashed: UnhashedRecord = {
    index: lines.length,
    prev_hash: last.hash,
    submitter_id: src.submitter_id,
    commit: src.commit,
    witness_ts: src.witness_ts,
    witness_sig: src.witness_sig,
    conflicts,
  };
  const copy = signRecord({ ...unhashed, hash: recordHash(unhashed) }, witnessKeys.privateKey);
  appendFileSync(r.storePath, recordLine(copy) + "\n");
}

const storeBreaks: [string, (r: Rig) => void, RegExp][] = [
  ["an edited field (hash no longer matches)", (r) =>
    tamper(r, (l) => {
      const rec = JSON.parse(l[1]);
      rec.commit.ts += 1;
      l[1] = JSON.stringify(rec);
      return l;
    }), /line 2: hash does not match/],
  ["a removed middle record", (r) => tamper(r, (l) => [l[0], l[2], l[3]]), /line 2: index/],
  ["a last line without its newline", (r) => tamper(r, (l) => l, false), /cut short/],
  ["garbage appended", (r) => appendFileSync(r.storePath, "{oops\n"), /line 5: not valid JSON/],
  ["a reformatted line", (r) =>
    tamper(r, (l) => {
      l[0] = JSON.stringify(JSON.parse(l[0]), null, 1).replace(/\n/g, "");
      return l;
    }), /exact serialisation/],
  // The duplicate-head rule holds even for records signed with the key: the
  // store never holds one head twice for a submitter.
  ["a signed replay of the last record (a head repeated for one submitter)", (r) =>
    appendSignedCopy(r, 3, []), /line 5: repeats the head already retained for this submitter at index 3/],
  ["a signed replay of record 0 carrying the rollback note its history implies", (r) =>
    appendSignedCopy(r, 0, [{ kind: "SEQ_LOWER_THAN_RETAINED", prior_index: 3, prior_seq_no: 3 }]),
    /line 5: repeats the head already retained for this submitter at index 0/],
  // Rewrites by someone without the key, with every hash recomputed.
  ["a field changed and every hash recomputed", (r) =>
    rewriteWithoutKey(r.storePath, (recs) => {
      (recs[1].commit as { ts: number }).ts = 42;
      return recs;
    }), /line 2: record_sig does not verify/],
  ["a middle record removed, the rest renumbered and re-hashed", (r) =>
    rewriteWithoutKey(r.storePath, (recs) => [recs[0], recs[2], recs[3]]),
    /line 2: record_sig does not verify/],
  ["two records swapped and re-hashed", (r) =>
    rewriteWithoutKey(r.storePath, (recs) => [recs[0], recs[2], recs[1], recs[3]]),
    /line 2: record_sig does not verify/],
  ["a record without its record_sig (unsigned)", (r) =>
    tamper(r, (l) => {
      const { record_sig: _dropped, ...unsigned } = JSON.parse(l[0]) as StoreRecord;
      l[0] = JSON.stringify(unsigned);
      return l;
    }), /line 1: record has no record_sig/],
  ["a record_sig made by another key", (r) =>
    tamper(r, (l) => {
      const rec = JSON.parse(l[2]) as StoreRecord;
      l[2] = recordLine(signRecord(rec, otherKeys.privateKey));
      return l;
    }), /line 3: record_sig does not verify/],
];
for (const [label, breakIt, pattern] of storeBreaks) {
  check(`start refused (fail closed): ${label}`, () => {
    const r = filled(4);
    breakIt(r);
    let message = "";
    assert.equal(
      refusalCode(() => {
        try {
          return r.open();
        } catch (e) {
          message = (e as Error).message;
          throw e;
        }
      }),
      "STORE_BROKEN"
    );
    assert.match(message, pattern);
    assert.match(message, /Refusing to run/);
  });
}

check("start refused: the store was signed by a different key", () => {
  const r = filled(2);
  assert.equal(refusalCode(() => r.open({ key: otherKeys.privateKey })), "STORE_BROKEN");
});

check("start refused: the store holds commits for another witness set", () => {
  const r = filled(2);
  const changed = { ...r.config, witnessSetId: "set-z" };
  assert.throws(
    () => ReferenceWitness.open({ config: changed, privateKey: witnessKeys.privateKey }),
    (e: unknown) => e instanceof WitnessRefusal && e.code === "STORE_BROKEN" && /set-a/.test(e.message)
  );
});

check("a rewritten store whose conflict note was stripped does not verify", () => {
  const r = rig();
  const w = r.open();
  r.drop("node-a", commit(5, hash(5)));
  w.pollOnce();
  r.drop("node-a", commit(5, hash(6)));
  w.pollOnce();
  const recs = w.records();
  assert.equal(recs[1].conflicts.length, 1);
  // Re-hash the second record without its note, as a careless rewrite would.
  const stripped = { ...recs[1], conflicts: [] };
  const rehashed: StoreRecord = { ...stripped, hash: recordHash(stripped) };
  writeFileSync(r.storePath, recordLine(recs[0]) + "\n" + recordLine(rehashed) + "\n");
  assert.throws(() => readStore(r.storePath), (e: unknown) => e instanceof StoreBroken && /conflict notes/.test(e.message));
});

check("re-attributing a record to another submitter without the key: verify and start both refuse", () => {
  // Both nodes at the same sequence numbers: 0:a 1:b 2:a 3:b 4:a 5:b, seq 0, 0, 1, 1, 2, 2.
  const r = rig(["node-a", "node-b"]);
  const w = r.open();
  for (let i = 0; i < 3; i++) {
    r.drop("node-a", commit(i, hash(10 + i)));
    r.drop("node-b", commit(i, hash(20 + i)));
    assert.deepEqual(kinds(w.pollOnce()), ["RETAINED", "RETAINED"]);
  }
  assert.equal(readStore(r.storePath, { publicKey: witnessKeys.publicKey }).records.length, 6, "genuine store verifies");
  // Record 4 (node-a) is moved to node-b, and everything is recomputed: on its
  // own terms the file is consistent again, and it would accuse node-b of a
  // rewrite (same seq_no as record 5, different head).
  rewriteWithoutKey(r.storePath, (recs) => {
    recs[4].submitter_id = "node-b";
    return recs;
  });
  const keyless = readStore(r.storePath);
  assert.equal(keyless.records[5].conflicts.length, 1, "the forged accusation is self-consistent");
  assert.throws(
    () => readStore(r.storePath, { publicKey: witnessKeys.publicKey }),
    (e: unknown) => e instanceof StoreBroken && /line 5: record_sig does not verify/.test(e.message)
  );
  assert.equal(refusalCode(() => r.open()), "STORE_BROKEN");
});

check("a witness_sig or record_sig that is not canonical base64 does not verify", () => {
  const receipt = signReceipt({ seq_no: 1, head_hash: hash(1), witness_ts: 5 }, witnessKeys.privateKey);
  assert.equal(verifyReceipt(receipt, witnessKeys.publicKey), true);
  const unpadded = receipt.witness_sig.replace(/=+$/, "");
  assert.notEqual(unpadded, receipt.witness_sig, "an Ed25519 signature's base64 ends in padding");
  assert.equal(verifyReceipt({ ...receipt, witness_sig: unpadded }, witnessKeys.publicKey), false);
  assert.equal(verifyReceipt({ ...receipt, witness_sig: ` ${receipt.witness_sig}` }, witnessKeys.publicKey), false);

  // In the store: a record whose witness_sig is re-spelled, and which is
  // otherwise hashed and signed whole with the right key, is still refused.
  const r = filled(1);
  const rec = JSON.parse(storeLines(r.storePath)[0]) as StoreRecord;
  const { hash: _h, record_sig: _s, ...rest } = rec;
  const respelled: UnhashedRecord = { ...rest, witness_sig: rec.witness_sig.replace(/=+$/, "") };
  const resigned = signRecord({ ...respelled, hash: recordHash(respelled) }, witnessKeys.privateKey);
  writeFileSync(r.storePath, recordLine(resigned) + "\n");
  assert.throws(
    () => readStore(r.storePath, { publicKey: witnessKeys.publicKey }),
    (e: unknown) => e instanceof StoreBroken && /witness_sig does not verify/.test(e.message)
  );
  assert.equal(verifyRecordSig({ ...rec, record_sig: rec.record_sig.replace(/=+$/, "") }, witnessKeys.publicKey), false);
});

check("readStore on an absent file reports it absent rather than throwing", () => {
  const c = readStore(join(ROOT, "nothing-here.jsonl"));
  assert.equal(c.exists, false);
});

check("another writer appending to the store halts the witness; nothing more is appended", () => {
  const r = rig();
  const w = r.open();
  r.drop("node-a", commit(1, hash(1)));
  w.pollOnce();
  appendFileSync(r.storePath, "x");
  const sizeBefore = statSync(r.storePath).size;
  r.drop("node-a", commit(2, hash(2)));
  assert.throws(() => w.pollOnce(), (e: unknown) => e instanceof WitnessHalted && /Something else has written/.test(e.message));
  assert.equal(statSync(r.storePath).size, sizeBefore, "nothing appended");
  assert.ok(existsSync(join(r.intake, "node-a")), "the commit was not consumed");
  assert.equal(r.receiptNames("node-a").length, 1, "no receipt for an unretained commit");
  assert.throws(() => w.pollOnce(), WitnessHalted, "halted stays halted");
});

check("a halt mid-poll still reports what that poll had already retained", () => {
  const r = rig(["node-a", "node-b"]);
  let calls = 0;
  let ms = 1_700_000_000_000;
  // The second clock read belongs to node-b's commit; something else writes to
  // the store just before that append.
  const w = r.open({
    clock: () => {
      if (++calls === 2) appendFileSync(r.storePath, "x");
      return ms++;
    },
  });
  r.drop("node-a", commit(1, hash(1)));
  r.drop("node-b", commit(1, hash(2)));
  let halted: WitnessHalted | null = null;
  try {
    w.pollOnce();
  } catch (e) {
    if (e instanceof WitnessHalted) halted = e;
    else throw e;
  }
  assert.ok(halted !== null, "the poll halted");
  assert.deepEqual(halted!.events.map((e) => e.kind), ["RETAINED"]);
  assert.ok(halted!.events[0].kind === "RETAINED" && halted!.events[0].submitterId === "node-a");
  assert.equal(r.receiptNames("node-a").length, 1);
  assert.ok(existsSync(join(r.intake, "node-b")), "node-b's commit was not consumed");
});

check("an unwritable store halts the witness and leaves the commit in the intake", () => {
  const r = rig();
  const w = r.open();
  chmodSync(r.storePath, 0o444);
  try {
    r.drop("node-a", commit(1, hash(1)));
    assert.throws(() => w.pollOnce(), WitnessHalted);
    assert.ok(existsSync(join(r.intake, "node-a")));
    assert.deepEqual(r.receiptNames("node-a"), []);
  } finally {
    chmodSync(r.storePath, 0o644);
  }
  // The store is writable again; the witness does not quietly resume.
  assert.throws(() => w.pollOnce(), WitnessHalted, "halted stays halted once the store is writable again");
  assert.equal(readFileSync(r.storePath, "utf8"), "");
  assert.equal(w.records().length, 0);
  assert.ok(existsSync(join(r.intake, "node-a")));
});

// ── outbox ⇄ store at start ───────────────────────────────────────────────────

console.log("── outboxes are checked against the store at start ──");

check("a receipt missing from an outbox is rebuilt from the store, byte for byte", () => {
  const r = filled(3);
  const path = join(r.outbox("node-a"), "receipt-000000000001.json");
  const before = readFileSync(path, "utf8");
  unlinkSync(path);
  const w = r.open();
  assert.deepEqual(w.startup.receiptsRestored.map((x) => x.index), [1]);
  assert.equal(readFileSync(path, "utf8"), before);
  assert.equal(before, receiptBytes(receiptOf(w.records()[1])));
});

check("start refused: an outbox holds receipts beyond the end of a truncated store", () => {
  const r = filled(4);
  // A clean prefix: it verifies on its own, which is exactly why the outbox is checked.
  tamper(r, (l) => l.slice(0, 2));
  assert.equal(readStore(r.storePath).records.length, 2, "the prefix verifies by itself");
  assert.equal(refusalCode(() => r.open()), "OUTBOX_AHEAD_OF_STORE");
});

check("start refused: the store was removed but the outbox still holds receipts", () => {
  const r = filled(2);
  unlinkSync(r.storePath);
  assert.equal(refusalCode(() => r.open()), "OUTBOX_AHEAD_OF_STORE");
  assert.equal(existsSync(r.storePath), false, "no new store was started over the old one");
});

check("start refused: a receipt file differs from the store", () => {
  const r = filled(2);
  const path = join(r.outbox("node-a"), "receipt-000000000000.json");
  const rec = JSON.parse(readFileSync(path, "utf8"));
  rec.witness_ts += 1;
  writeFileSync(path, JSON.stringify(rec) + "\n");
  assert.equal(refusalCode(() => r.open()), "OUTBOX_MISMATCH");
});

check("start refused: outboxes swapped between submitters", () => {
  const r = filled(2, ["node-a", "node-b"]);
  const swapped: WitnessConfig = {
    ...r.config,
    submitters: [
      { id: "node-a", outboxDir: r.outbox("node-b") },
      { id: "node-b", outboxDir: r.outbox("node-a") },
    ],
  };
  assert.throws(
    () => ReferenceWitness.open({ config: swapped, privateKey: witnessKeys.privateKey }),
    (e: unknown) => e instanceof WitnessRefusal && e.code === "OUTBOX_MISMATCH"
  );
});

check("leftover staging files are cleared; foreign outbox files are reported, not touched", () => {
  const r = filled(1);
  const staging = join(r.outbox("node-a"), ".staging");
  mkdirSync(staging, { recursive: true });
  writeFileSync(join(staging, "receipt-000000000009.json.123.tmp"), "{");
  writeFileSync(join(r.outbox("node-a"), "README"), "someone else's file\n");
  const w = r.open();
  assert.deepEqual(readdirSync(staging), []);
  assert.deepEqual(w.startup.foreignOutboxFiles, [join(r.outbox("node-a"), "README")]);
  assert.ok(existsSync(join(r.outbox("node-a"), "README")));
});

check("start refused (OUTBOX_UNREADABLE), not blocked: a FIFO stands at a receipt's name", () => {
  const r = filled(1);
  const path = join(r.outbox("node-a"), "receipt-000000000000.json");
  unlinkSync(path);
  if (!mkfifo(path)) return;
  const res = openInChild(r, "open");
  assert.equal(res.timedOut, false, `the witness blocked on the FIFO at start-up: ${res.out}`);
  assert.equal(res.out, "REFUSED OUTBOX_UNREADABLE");
  assert.ok(lstatSync(path).isFIFO(), "the FIFO is left where it was, not replaced");
});

check("start refused (OUTBOX_UNREADABLE): a symlink at a receipt's name, even to the right bytes", () => {
  const r = filled(1);
  const path = join(r.outbox("node-a"), "receipt-000000000000.json");
  const elsewhere = join(r.dir, "elsewhere.json");
  renameSync(path, elsewhere);
  symlinkSync(elsewhere, path);
  assert.throws(
    () => r.open(),
    (e: unknown) =>
      e instanceof WitnessRefusal &&
      e.code === "OUTBOX_UNREADABLE" &&
      e.message.includes(path) &&
      /symbolic link, not a regular file/.test(e.message)
  );
  assert.ok(lstatSync(path).isSymbolicLink(), "left alone");
});

check("a .staging that is a symlink is not followed at start: its target's files stay; it is reported", () => {
  const r = filled(1);
  const staging = join(r.outbox("node-a"), ".staging");
  rmSync(staging, { recursive: true, force: true });
  const victim = join(r.dir, "victim");
  mkdirSync(victim);
  const precious = join(victim, "receipt-000000000009.json.123.tmp");
  writeFileSync(precious, "not the witness's\n");
  symlinkSync(victim, staging);
  const w = r.open();
  assert.ok(existsSync(precious), "nothing deleted through the link");
  assert.deepEqual(w.startup.foreignOutboxFiles, [staging], "reported, so an operator sees it");
  assert.ok(lstatSync(staging).isSymbolicLink(), "and left alone");
});

check("only the witness's own staging files are cleared from a real staging directory", () => {
  const r = filled(1);
  const staging = join(r.outbox("node-a"), ".staging");
  const ours = ["receipt-000000000009.json.123.tmp", "receipt-000000000001.json.0a1b2c3d4e5f.tmp"];
  const other = "notes.tmp";
  for (const n of [...ours, other]) writeFileSync(join(staging, n), "x");
  r.open();
  assert.deepEqual(readdirSync(staging), [other]);
});

check("start refused: a missing intake or outbox directory is not created", () => {
  const r = rig();
  rmSync(r.outbox("node-a"), { recursive: true });
  assert.equal(refusalCode(() => r.open()), "DIRECTORY_MISSING");
  assert.equal(existsSync(r.outbox("node-a")), false);
  const r2 = rig();
  rmSync(r2.intake, { recursive: true });
  assert.equal(refusalCode(() => r2.open()), "DIRECTORY_MISSING");
});

check("records for a submitter no longer in the config are kept and counted", () => {
  const r = filled(2, ["node-a", "node-b"]);
  const fewer: WitnessConfig = { ...r.config, submitters: [r.config.submitters[0]] };
  const w = ReferenceWitness.open({ config: fewer, privateKey: witnessKeys.privateKey });
  assert.equal(w.startup.recordsForUndeclaredSubmitters, 1);
  assert.equal(w.records().length, 2);
});

// ── cleanup ───────────────────────────────────────────────────────────────────

rmSync(ROOT, { recursive: true, force: true });

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
