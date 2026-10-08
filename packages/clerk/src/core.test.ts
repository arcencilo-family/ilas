// ──────────────────────────────────────────────────────────────────────────────
// Reference clerk — core, book and key tests.
//   npx ts-node packages/clerk/src/core.test.ts
//
// Everything here runs in one process against real files in a temp
// directory. Receipts are checked with this package's own verifier AND with
// ILAS's verifyClerkReceipt, which is the check a node actually applies.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { spawnSync } from "child_process";
import { createPublicKey, generateKeyPairSync, sign as ed25519Sign } from "crypto";
import fs = require("fs"); // the module object itself, so a test can stand in for chmodSync
import { chmodSync, closeSync, existsSync, openSync, readFileSync, statSync, writeFileSync, writeSync } from "fs";
import { userInfo } from "os";
import { join, relative } from "path";
import { canonicalise, sha256Hex } from "../../../src/l0/canonical";
import { verifyClerkReceipt } from "../../../src/l0/clerk-verify";
import { LockedEvidenceLog, L0ClerkError } from "../../../src/l0/index";
import type { ClerkSubmitClient } from "../../../src/l0/index";
import { BookChecker, BookLockError, BookVerificationError, MAX_BOOK_LINE_BYTES, verifyBookFile } from "./book";
import { InProcessClerkClient } from "./client";
import { ClerkCore, ClerkStoppedError, IN_PROCESS_WARNING } from "./core";
import {
  ClerkKeyError,
  generateClerkKeyFiles,
  loadClerkPrivateKey,
  loadPublicKeyPem,
} from "./keys";
import {
  GENESIS_RECEIPT_HASH,
  RECEIPT_FORM,
  receiptPreimage,
  signReceipt,
  verifyReceipt,
} from "./receipt";
import type { ClerkReceipt, UnsignedClerkReceipt } from "./receipt";
import { ClerkRequestError } from "./wire";
import {
  check,
  checkAsync,
  entry,
  rejects,
  runAll,
  section,
  tempDir,
  throws,
} from "./test-support";

function keysIn(dir: string) {
  const k = generateClerkKeyFiles(join(dir, "keys"));
  return { ...k, privateKey: loadClerkPrivateKey(k.privateKeyPath) };
}

function openCore(dir: string, extra: Partial<Parameters<typeof ClerkCore.open>[0]> = {}) {
  const k = keysIn(dir);
  const bookPath = join(dir, "book.jsonl");
  const core = ClerkCore.open({
    clerkId: "unit-clerk",
    privateKey: k.privateKey,
    bookPath,
    separation: "IN_PROCESS_NO_SEPARATION",
    ...extra,
  });
  return { core, bookPath, publicKeyPem: k.publicKeyPem, privateKey: k.privateKey };
}

function request(n: number) {
  const payload = entry(n);
  return { submitter_id: "ilas-node", channel: "l0", declared_timestamp: payload.timestamp, payload };
}

function bookLines(path: string): string[] {
  return readFileSync(path, "utf8").split("\n").filter((l) => l.length > 0);
}

function writeLines(path: string, lines: string[]): void {
  writeFileSync(path, lines.map((l) => l + "\n").join(""));
}

/** An object nested `depth` levels deep: more than 64 has no canonical form. */
function nested(depth: number): Record<string, unknown> {
  const top: Record<string, unknown> = {};
  let cur = top;
  for (let i = 1; i < depth; i++) {
    const next: Record<string, unknown> = {};
    cur.d = next;
    cur = next;
  }
  return top;
}

/** The same 64 signature bytes, written with the unused low bits of the last character set. */
function withTrailingBits(signature: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const last = alphabet.indexOf(signature[85]);
  const altered = signature.slice(0, 85) + alphabet[last | 1] + "==";
  assert.ok(Buffer.from(altered, "base64").equals(Buffer.from(signature, "base64")), "not the same bytes");
  assert.notEqual(altered, signature);
  return altered;
}

const ALL_ILAS_FIELDS = [
  "kind",
  "clerk_id",
  "clerk_boot_id",
  "separation",
  "separation_warning",
  "clerk_principal",
  "intake",
  "clerk_seq",
  "clerk_time",
  "prev_receipt_hash",
  "receipt_hash",
  "signature",
  "signature_alg",
  "declared_timestamp",
  "payload_commitment",
  "payload_retained",
  "payload_canonical",
];

// ── keys ─────────────────────────────────────────────────────────────────────

section("Keys: generated per run, 0600, refused when others can read them");

check("keygen writes clerk.key with mode 0600 and a matching clerk.pub.pem", () => {
  const dir = tempDir();
  const k = generateClerkKeyFiles(join(dir, "k"));
  assert.equal(statSync(k.privateKeyPath).mode & 0o777, 0o600);
  assert.equal(statSync(join(dir, "k")).mode & 0o777, 0o700, "key directory not 0700");
  assert.equal(loadPublicKeyPem(k.publicKeyPath), k.publicKeyPem);
  const priv = loadClerkPrivateKey(k.privateKeyPath);
  const sig = ed25519Sign(null, Buffer.from("x"), priv);
  assert.equal(sig.length, 64);
});

check("keygen refuses to overwrite an existing key", () => {
  const dir = tempDir();
  generateClerkKeyFiles(dir);
  const before = readFileSync(join(dir, "clerk.key"), "utf8");
  const err = throws(() => generateClerkKeyFiles(dir));
  assert.ok(err instanceof ClerkKeyError);
  assert.match(err.message, /refusing to overwrite/);
  assert.equal(readFileSync(join(dir, "clerk.key"), "utf8"), before);
});

check("a private key readable by group or others is refused, and the reason is given", () => {
  const dir = tempDir();
  const k = generateClerkKeyFiles(dir);
  for (const mode of [0o644, 0o640, 0o604, 0o660]) {
    chmodSync(k.privateKeyPath, mode);
    const err = throws(() => loadClerkPrivateKey(k.privateKeyPath));
    assert.ok(err instanceof ClerkKeyError, `mode ${mode.toString(8)} not refused`);
    assert.match(err.message, new RegExp(`mode 0${mode.toString(8)}`));
    assert.match(err.message, /chmod 600/);
  }
  chmodSync(k.privateKeyPath, 0o600);
  loadClerkPrivateKey(k.privateKeyPath);
});

check("a non-ed25519 private key is refused", () => {
  const dir = tempDir();
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const p = join(dir, "ec.key");
  writeFileSync(p, privateKey.export({ type: "pkcs8", format: "pem" }) as string, { mode: 0o600 });
  const err = throws(() => loadClerkPrivateKey(p));
  assert.match(err.message, /ed25519 only/);
});

check("a private key file given where the public key belongs is refused", () => {
  const dir = tempDir();
  const k = generateClerkKeyFiles(dir);
  const err = throws(() => loadPublicKeyPem(k.privateKeyPath));
  assert.match(err.message, /holds a private key; give only the public key/);
});

check("keygen fails, and removes the key again, when the key file does not keep mode 0600", () => {
  // Stand-in for a mount without POSIX permissions: chmod "succeeds" and the
  // file ends up readable by others anyway.
  const realChmod = fs.chmodSync;
  fs.chmodSync = (p: fs.PathLike, _mode: fs.Mode) => realChmod(p, 0o644);
  let err: Error;
  const dir = join(tempDir(), "k");
  try {
    err = throws(() => generateClerkKeyFiles(dir));
  } finally {
    fs.chmodSync = realChmod;
  }
  assert.ok(err instanceof ClerkKeyError, `got ${err.name}: ${err.message}`);
  assert.match(err.message, /has mode 0644 after it was written/);
  assert.match(err.message, /does not keep POSIX file permissions/);
  assert.match(err.message, /The key file was removed again/);
  assert.equal(existsSync(join(dir, "clerk.key")), false, "the exposed key was left behind");
  assert.equal(existsSync(join(dir, "clerk.pub.pem")), false, "a public key was written for a refused key");
  // On a normal filesystem the same call succeeds and reports the mode it read back.
  const ok = generateClerkKeyFiles(join(tempDir(), "k2"));
  assert.equal(ok.privateKeyMode, 0o600);
});

/** An error shaped like the one fs throws for a refused system call. */
function errno(code: string, syscall: string, path: string): NodeJS.ErrnoException {
  const e = new Error(`${code}: refused by the test, ${syscall} '${path}'`) as NodeJS.ErrnoException;
  e.code = code;
  e.syscall = syscall;
  e.path = path;
  return e;
}

check("keygen fails, and leaves no key behind, when chmod itself is refused (EPERM)", () => {
  // Stand-in for a FAT/exFAT mount owned by another account (or a mount that
  // refuses chmod): the file is created with whatever mode the mount gives it,
  // and chmod throws.
  const realChmod = fs.chmodSync;
  fs.chmodSync = (p: fs.PathLike, mode: fs.Mode) => {
    if (String(p).endsWith("clerk.key")) throw errno("EPERM", "chmod", String(p));
    realChmod(p, mode);
  };
  const dir = join(tempDir(), "k");
  let err: Error;
  try {
    err = throws(() => generateClerkKeyFiles(dir));
  } finally {
    fs.chmodSync = realChmod;
  }
  assert.ok(err instanceof ClerkKeyError, `got ${err.name}: ${err.message}`);
  assert.match(err.message, /setting its mode to 0600 failed \(EPERM/);
  assert.match(err.message, /cannot set POSIX permissions there/);
  assert.match(err.message, /The key file was removed again/);
  assert.deepEqual(fs.readdirSync(dir), [], "a key file was left behind");
});

check("keygen leaves no partial key behind when writing it fails part way", () => {
  // The first write lands half the key; the next one fails, as on a full disk.
  const realWrite = fs.writeSync;
  let calls = 0;
  (fs as { writeSync: unknown }).writeSync = (fd: number, buf: Buffer, off: number, len: number) => {
    calls++;
    if (calls === 1) return realWrite(fd, buf, off, Math.floor(len / 2));
    throw errno("ENOSPC", "write", "<fd>");
  };
  const dir = join(tempDir(), "k");
  let err: Error;
  try {
    err = throws(() => generateClerkKeyFiles(dir));
  } finally {
    (fs as { writeSync: unknown }).writeSync = realWrite;
  }
  assert.ok(calls >= 2, "the stand-in write was not used");
  assert.ok(err instanceof ClerkKeyError, `got ${err.name}: ${err.message}`);
  assert.match(err.message, /clerk\.key was created, but writing it failed \(ENOSPC/);
  assert.match(err.message, /The key file was removed again/);
  assert.deepEqual(fs.readdirSync(dir), [], "a partial key file was left behind");
});

check("keygen removes the private key again when the public key cannot be written, and touches no file it did not create", () => {
  // clerk.pub.pem appears between keygen's check and its write (another
  // keygen, say): the exclusive create fails, and that file is not keygen's.
  const realOpen = fs.openSync;
  let planted = false;
  (fs as { openSync: unknown }).openSync = (p: fs.PathLike, flags: fs.OpenMode, mode?: fs.Mode) => {
    if (!planted && String(p).endsWith("clerk.pub.pem")) {
      planted = true; // writeFileSync opens through fs.openSync too
      writeFileSync(p, "someone else's file\n");
    }
    return realOpen(p, flags, mode);
  };
  const dir = join(tempDir(), "k");
  let err: Error;
  try {
    err = throws(() => generateClerkKeyFiles(dir));
  } finally {
    (fs as { openSync: unknown }).openSync = realOpen;
  }
  assert.ok(err instanceof ClerkKeyError, `got ${err.name}: ${err.message}`);
  assert.match(err.message, /EEXIST/);
  assert.match(err.message, /The private key .*clerk\.key was removed again/);
  assert.equal(existsSync(join(dir, "clerk.key")), false, "a private key without its public half was left behind");
  assert.equal(readFileSync(join(dir, "clerk.pub.pem"), "utf8"), "someone else's file\n");
});

check("a private key is refused wherever this package takes the clerk's public key", () => {
  const dir = tempDir();
  const { core, bookPath, privateKey, publicKeyPem } = openCore(dir);
  const r = core.submit(request(0));
  core.close();
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const verdict = verifyReceipt(r, privatePem);
  assert.equal(verdict.ok, false, "a receipt verified against a private key");
  assert.match(verdict.reason, /give only the public key/);
  assert.match(throws(() => verifyBookFile(bookPath, privatePem)).message, /give only the public key/);
  assert.match(throws(() => new BookChecker(privateKey)).message, /give only the public key/);
  // The public half still verifies both.
  assert.ok(verifyReceipt(r, publicKeyPem).ok);
  assert.ok(verifyBookFile(bookPath, createPublicKey(privateKey)).ok);
});

// ── receipts and the chain ───────────────────────────────────────────────────

section("Receipts: fields, chain, sequence, signatures");

check("a receipt carries every ClerkSubmissionReceipt field, plus form, submitter and channel", () => {
  const { core } = openCore(tempDir());
  try {
    const r = core.submit(request(1));
    for (const f of ALL_ILAS_FIELDS) assert.ok(f in r, `missing ${f}`);
    assert.equal(r.receipt_form, RECEIPT_FORM);
    assert.equal(r.kind, "SUBMISSION");
    assert.equal(r.signature_alg, "ed25519");
    assert.equal(r.submitter_id, "ilas-node");
    assert.equal(r.channel, "l0");
    assert.equal(r.clerk_id, "unit-clerk");
    assert.equal(r.declared_timestamp, entry(1).timestamp);
    assert.equal(r.payload_retained, false);
    assert.equal(r.payload_canonical, null);
    assert.equal(r.payload_commitment, sha256Hex(canonicalise(entry(1))));
    assert.match(r.clerk_time.monotonic_ns, /^\d+$/);
    assert.ok(Number.isInteger(r.clerk_time.wall_ms));
    assert.match(r.clerk_boot_id, /^[0-9a-f]{32}$/);
  } finally {
    core.close();
  }
});

check("receipt_hash and signature cover every other field (preimage = canonical record)", () => {
  const { core, publicKeyPem } = openCore(tempDir());
  try {
    const r = core.submit(request(1));
    assert.equal(r.receipt_hash, sha256Hex(receiptPreimage(r as unknown as Record<string, unknown>)));
    for (const field of ["submitter_id", "channel", "receipt_form", "clerk_principal", "separation_warning"]) {
      const forged = { ...r, [field]: "forged" };
      assert.equal(verifyReceipt(forged, publicKeyPem).ok, false, `${field} is not covered`);
    }
  } finally {
    core.close();
  }
});

check("in-process receipts say IN_PROCESS_NO_SEPARATION / LOCAL_CALL, with a warning", () => {
  const { core } = openCore(tempDir());
  try {
    const r = core.submit(request(1));
    assert.equal(r.separation, "IN_PROCESS_NO_SEPARATION");
    assert.equal(r.intake, "LOCAL_CALL");
    assert.equal(r.separation_warning, IN_PROCESS_WARNING);
    assert.match(r.separation_warning!, /no separation/);
    assert.equal(r.clerk_principal, userInfo().username);
  } finally {
    core.close();
  }
});

check("receipts chain from genesis and clerk_seq counts up from 0", () => {
  const { core } = openCore(tempDir());
  try {
    const rs: ClerkReceipt[] = [];
    for (let i = 0; i < 5; i++) rs.push(core.submit(request(i)));
    assert.equal(rs[0].prev_receipt_hash, GENESIS_RECEIPT_HASH);
    for (let i = 0; i < rs.length; i++) {
      assert.equal(rs[i].clerk_seq, i);
      if (i > 0) assert.equal(rs[i].prev_receipt_hash, rs[i - 1].receipt_hash);
      if (i > 0) {
        assert.ok(BigInt(rs[i].clerk_time.monotonic_ns) >= BigInt(rs[i - 1].clerk_time.monotonic_ns));
      }
    }
    assert.equal(core.nextSeq, 5);
    assert.equal(core.head, rs[4].receipt_hash);
  } finally {
    core.close();
  }
});

check("every receipt verifies with ILAS's verifyClerkReceipt and with this package's verifier", () => {
  const { core, publicKeyPem } = openCore(tempDir());
  try {
    for (let i = 0; i < 4; i++) {
      const r = core.submit(request(i));
      const ilas = verifyClerkReceipt(r as unknown as Record<string, unknown>, publicKeyPem, entry(i));
      assert.ok(ilas.ok, `ILAS refused receipt ${i}: ${ilas.reason}`);
      const own = verifyReceipt(r, publicKeyPem, { value: entry(i) });
      assert.ok(own.ok, own.reason);
      assert.equal(verifyClerkReceipt(r as unknown as Record<string, unknown>, publicKeyPem, entry(i + 1)).ok, false);
    }
  } finally {
    core.close();
  }
});

check("declared_timestamp is echoed, and is null when the request has none", () => {
  const { core } = openCore(tempDir());
  try {
    const a = core.submit({ submitter_id: "s", channel: "c", declared_timestamp: 42.5, payload: {} });
    assert.equal(a.declared_timestamp, 42.5);
    const b = core.submit({ submitter_id: "s", channel: "c", payload: {} });
    assert.equal(b.declared_timestamp, null);
  } finally {
    core.close();
  }
});

check("the book is one JSON receipt per line, mode 0600, and each line equals the returned receipt", () => {
  const { core, bookPath } = openCore(tempDir());
  try {
    const rs = [core.submit(request(1)), core.submit(request(2))];
    assert.equal(statSync(bookPath).mode & 0o777, 0o600);
    const lines = bookLines(bookPath);
    assert.equal(lines.length, 2);
    lines.forEach((l, i) => assert.deepEqual(JSON.parse(l), rs[i]));
  } finally {
    core.close();
  }
});

check("retain_payload keeps the canonical payload, and the book check ties it to the commitment", () => {
  const { core, bookPath, publicKeyPem } = openCore(tempDir(), { retainPayload: true });
  let r: ClerkReceipt;
  try {
    r = core.submit(request(3));
  } finally {
    core.close();
  }
  assert.equal(r.payload_retained, true);
  assert.equal(r.payload_canonical, canonicalise(entry(3)));
  assert.ok(verifyBookFile(bookPath, publicKeyPem).ok);
});

// ── restart ──────────────────────────────────────────────────────────────────

section("Restart: the sequence and chain continue; one writer per book");

check("after close and reopen, clerk_seq continues and the first new receipt links to the old head", () => {
  const dir = tempDir();
  const k = keysIn(dir);
  const bookPath = join(dir, "book.jsonl");
  const opts = { clerkId: "c", privateKey: k.privateKey, bookPath, separation: "IN_PROCESS_NO_SEPARATION" as const };
  const a = ClerkCore.open(opts);
  assert.equal(a.bookState, "NEW");
  a.submit(request(0));
  const last = a.submit(request(1));
  a.close();
  const b = ClerkCore.open(opts);
  try {
    assert.equal(b.bookState, "LOADED_VERIFIED");
    assert.equal(b.nextSeq, 2);
    assert.notEqual(b.bootId, a.bootId, "boot id must change per start");
    const next = b.submit(request(2));
    assert.equal(next.clerk_seq, 2);
    assert.equal(next.prev_receipt_hash, last.receipt_hash);
  } finally {
    b.close();
  }
  const v = verifyBookFile(bookPath, k.publicKeyPem);
  assert.ok(v.ok, v.reason);
  assert.equal(v.count, 3);
});

check("a second core on the same book is refused while the first holds it", () => {
  const dir = tempDir();
  const k = keysIn(dir);
  const opts = {
    clerkId: "c",
    privateKey: k.privateKey,
    bookPath: join(dir, "book.jsonl"),
    separation: "IN_PROCESS_NO_SEPARATION" as const,
  };
  const a = ClerkCore.open(opts);
  try {
    const err = throws(() => ClerkCore.open(opts));
    assert.ok(err instanceof BookLockError, `got ${err.name}: ${err.message}`);
    assert.match(err.message, new RegExp(`process ${process.pid}`));
  } finally {
    a.close();
  }
  ClerkCore.open(opts).close(); // released on close
});

check("a lock left by a process that no longer exists is taken over", () => {
  const dir = tempDir();
  const k = keysIn(dir);
  const bookPath = join(dir, "book.jsonl");
  const gone = spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"], {
    encoding: "utf8",
    timeout: 10_000,
  });
  writeFileSync(`${bookPath}.lock`, `${gone.stdout}\n`);
  const core = ClerkCore.open({ clerkId: "c", privateKey: k.privateKey, bookPath, separation: "IN_PROCESS_NO_SEPARATION" });
  try {
    const [pid, token] = readFileSync(`${bookPath}.lock`, "utf8").trim().split("\n");
    assert.equal(pid, String(process.pid));
    assert.match(token, /^[0-9a-f]{32}$/);
  } finally {
    core.close();
  }
  assert.equal(existsSync(`${bookPath}.lock`), false, "close() left the lock behind");
});

check("a lock naming this process's pid that this process did not take is taken over (a restarted container)", () => {
  // A clerk that is pid 1 in its container crashes; the next start is pid 1
  // again and finds its predecessor's lock naming its own pid.
  const dir = tempDir();
  const k = keysIn(dir);
  const bookPath = join(dir, "book.jsonl");
  const opts = { clerkId: "c", privateKey: k.privateKey, bookPath, separation: "IN_PROCESS_NO_SEPARATION" as const };
  for (const left of [`${process.pid}\n`, `${process.pid}\n${"ab".repeat(16)}\n`]) {
    writeFileSync(`${bookPath}.lock`, left);
    const core = ClerkCore.open(opts);
    try {
      const lock = readFileSync(`${bookPath}.lock`, "utf8");
      assert.notEqual(lock, left, "the stale lock was not replaced");
      assert.equal(lock.split("\n")[0], String(process.pid));
      // ...and the lock it took is live: a second open in this process is refused.
      const err = throws(() => ClerkCore.open(opts));
      assert.ok(err instanceof BookLockError, `got ${err.name}: ${err.message}`);
    } finally {
      core.close();
    }
  }
});

check("a lock this process holds is refused under another spelling of the same path", () => {
  const dir = tempDir();
  const k = keysIn(dir);
  const bookPath = join(dir, "book.jsonl");
  const a = ClerkCore.open({ clerkId: "c", privateKey: k.privateKey, bookPath, separation: "IN_PROCESS_NO_SEPARATION" });
  try {
    const err = throws(() =>
      ClerkCore.open({
        clerkId: "c",
        privateKey: k.privateKey,
        bookPath: relative(process.cwd(), bookPath),
        separation: "IN_PROCESS_NO_SEPARATION",
      })
    );
    assert.ok(err instanceof BookLockError, `got ${err.name}: ${err.message}`);
    assert.match(err.message, new RegExp(`process ${process.pid}`));
  } finally {
    a.close();
  }
});

check("a lock naming another live process is refused, and left as it is", () => {
  const dir = tempDir();
  const k = keysIn(dir);
  const bookPath = join(dir, "book.jsonl");
  const lock = `${process.ppid}\n${"cd".repeat(16)}\n`; // the parent process is alive while this test runs
  writeFileSync(`${bookPath}.lock`, lock);
  const err = throws(() =>
    ClerkCore.open({ clerkId: "c", privateKey: k.privateKey, bookPath, separation: "IN_PROCESS_NO_SEPARATION" })
  );
  assert.ok(err instanceof BookLockError, `got ${err.name}: ${err.message}`);
  assert.match(err.message, new RegExp(`in use by process ${process.ppid}`));
  assert.equal(readFileSync(`${bookPath}.lock`, "utf8"), lock);
});

check("a lock file that names no process is refused, and left as it is", () => {
  const dir = tempDir();
  const k = keysIn(dir);
  const bookPath = join(dir, "book.jsonl");
  for (const text of ["held-by-someone\n", "", `${process.pid}\nnot-a-token\n`]) {
    writeFileSync(`${bookPath}.lock`, text);
    const err = throws(() =>
      ClerkCore.open({ clerkId: "c", privateKey: k.privateKey, bookPath, separation: "IN_PROCESS_NO_SEPARATION" })
    );
    assert.ok(err instanceof BookLockError, `${JSON.stringify(text)}: got ${err.name}: ${err.message}`);
    assert.match(err.message, /names no process/);
    assert.equal(readFileSync(`${bookPath}.lock`, "utf8"), text);
  }
});

check("a book signed by a different key is refused (the key and the book belong together)", () => {
  const dir = tempDir();
  const { bookPath, core } = openCore(dir);
  core.submit(request(0));
  core.close();
  const other = generateClerkKeyFiles(join(dir, "other"));
  const err = throws(() =>
    ClerkCore.open({
      clerkId: "c",
      privateKey: loadClerkPrivateKey(other.privateKeyPath),
      bookPath,
      separation: "IN_PROCESS_NO_SEPARATION",
    })
  );
  assert.ok(err instanceof BookVerificationError);
  assert.match(err.message, /signature does not verify/);
});

// ── tamper: the clerk refuses to start ───────────────────────────────────────

section("Tamper: a book that does not verify makes start refuse (fail closed)");

/** Build a 4-receipt book, apply `mutate` to its lines, and try to reopen. */
function tamperCase(name: string, mutate: (lines: string[], bookPath: string) => void, expect: RegExp): void {
  check(name, () => {
    const dir = tempDir();
    const k = keysIn(dir);
    const bookPath = join(dir, "book.jsonl");
    const opts = { clerkId: "c", privateKey: k.privateKey, bookPath, separation: "IN_PROCESS_NO_SEPARATION" as const };
    const core = ClerkCore.open(opts);
    for (let i = 0; i < 4; i++) core.submit(request(i));
    core.close();
    const lines = bookLines(bookPath);
    mutate(lines, bookPath);
    const tampered = readFileSync(bookPath);
    const err = throws(() => ClerkCore.open(opts));
    assert.ok(err instanceof BookVerificationError, `expected a refusal, got ${err.name}: ${err.message}`);
    assert.match(err.message, expect);
    assert.ok(readFileSync(bookPath).equals(tampered), "a refused start changed the book");
    assert.equal(verifyBookFile(bookPath, k.publicKeyPem).ok, false);
    // The refusal released the lock: once the operator replaces the book, it opens.
    writeFileSync(bookPath, "");
    ClerkCore.open(opts).close();
  });
}

tamperCase(
  "a field edited in a middle receipt",
  (lines, p) => {
    const r = JSON.parse(lines[1]);
    r.channel = "rewritten";
    lines[1] = JSON.stringify(r);
    writeLines(p, lines);
  },
  /receipt 1: receipt_hash does not match/
);

tamperCase(
  "a field edited and receipt_hash recomputed (the signature still breaks)",
  (lines, p) => {
    const r = JSON.parse(lines[2]);
    r.declared_timestamp = 0;
    r.receipt_hash = sha256Hex(receiptPreimage(r));
    lines[2] = JSON.stringify(r);
    writeLines(p, lines);
  },
  /receipt 2: signature does not verify/
);

tamperCase(
  "a middle receipt deleted",
  (lines, p) => writeLines(p, [lines[0], lines[2], lines[3]]),
  /receipt 1: clerk_seq is 2, expected 1/
);

tamperCase(
  "two receipts swapped",
  (lines, p) => writeLines(p, [lines[0], lines[2], lines[1], lines[3]]),
  /receipt 1: clerk_seq/
);

tamperCase(
  "the last receipt repeated",
  (lines, p) => writeLines(p, [...lines, lines[3]]),
  /receipt 4: clerk_seq is 3, expected 4/
);

tamperCase(
  "a torn last write (no trailing newline)",
  (lines, p) => writeFileSync(p, lines.join("\n")),
  /receipt 3: last line has no newline/
);

tamperCase(
  "a line that is not JSON",
  (lines, p) => writeLines(p, [...lines, "{not json"]),
  /receipt 4: line is not valid JSON/
);

tamperCase(
  "an empty line in the middle",
  (lines, p) => writeLines(p, [lines[0], "", lines[1]]),
  /receipt 1: empty line/
);

tamperCase(
  "invalid UTF-8 bytes in a line",
  (lines, p) => {
    writeFileSync(p, Buffer.concat([Buffer.from(lines[0] + "\n"), Buffer.from([0xff, 0xfe, 0x0a])]));
  },
  /receipt 1: line is not valid UTF-8/
);

tamperCase(
  "a receipt re-signed by another key (valid signature, wrong signer)",
  (lines, p) => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const r = JSON.parse(lines[1]);
    const pre = receiptPreimage(r);
    r.receipt_hash = sha256Hex(pre);
    r.signature = ed25519Sign(null, Buffer.from(pre, "utf8"), privateKey).toString("base64");
    lines[1] = JSON.stringify(r);
    writeLines(p, lines);
  },
  /receipt 1: signature does not verify/
);

tamperCase(
  "a forged line whose record cannot be canonicalised (an extra field 70 levels deep; no key needed)",
  (lines, p) => {
    const r = JSON.parse(lines[1]);
    r.channel = "FORGED";
    r.extra = nested(70);
    r.receipt_hash = "a".repeat(64);
    r.signature = Buffer.alloc(64).toString("base64");
    lines[1] = JSON.stringify(r);
    writeLines(p, lines);
  },
  /receipt 1: verification error: structure deeper than 64 levels/
);

tamperCase(
  "a signature with its padding stripped (same bytes to Node's decoder)",
  (lines, p) => {
    const r = JSON.parse(lines[1]);
    r.signature = (r.signature as string).replace(/=+$/, "");
    lines[1] = JSON.stringify(r);
    writeLines(p, lines);
  },
  /receipt 1: signature is missing or is not 64 bytes of base64/
);

tamperCase(
  "a signature with characters appended (same bytes to Node's decoder)",
  (lines, p) => {
    const r = JSON.parse(lines[1]);
    r.signature = `${r.signature}!!`;
    lines[1] = JSON.stringify(r);
    writeLines(p, lines);
  },
  /receipt 1: signature is missing or is not 64 bytes of base64/
);

tamperCase(
  "a signature rewritten with the unused bits of its last character set (same bytes)",
  (lines, p) => {
    const r = JSON.parse(lines[1]);
    r.signature = withTrailingBits(r.signature as string);
    lines[1] = JSON.stringify(r);
    writeLines(p, lines);
  },
  /receipt 1: signature is not canonical base64/
);

tamperCase(
  "a line longer than the book's line limit",
  (_lines, p) => {
    const fd = openSync(p, "a");
    try {
      const mib = Buffer.alloc(1 << 20, 0x78);
      for (let written = 0; written <= MAX_BOOK_LINE_BYTES; written += mib.length) writeSync(fd, mib);
      writeSync(fd, "\n");
    } finally {
      closeSync(fd);
    }
  },
  /receipt 4: line longer than 16777216 bytes/
);

check("verifyReceipt refuses signature text that only decodes to the right bytes", () => {
  const { core, publicKeyPem } = openCore(tempDir());
  let r: ClerkReceipt;
  try {
    r = core.submit(request(0));
  } finally {
    core.close();
  }
  assert.ok(verifyReceipt(r, publicKeyPem).ok);
  for (const [signature, expect] of [
    [r.signature.replace(/=+$/, ""), /not 64 bytes of base64/],
    [`${r.signature}!!`, /not 64 bytes of base64/],
    [withTrailingBits(r.signature), /not canonical base64/],
  ] as const) {
    assert.ok(Buffer.from(signature, "base64").equals(Buffer.from(r.signature, "base64")));
    const v = verifyReceipt({ ...r, signature }, publicKeyPem);
    assert.equal(v.ok, false, `accepted signature text ${JSON.stringify(signature)}`);
    assert.match(v.reason, expect);
  }
});

// ── chain rules hold even for records signed with the right key ──────────────

section("Chain rules: correctly signed records that break the chain are refused");

/**
 * Two genuine receipts, then a third built by `shape` and signed with the
 * clerk's own key. Only the chain rules can catch these.
 */
function signedChainCase(name: string, shape: (r: Record<string, unknown>, prev: ClerkReceipt[]) => void, expect: RegExp): void {
  check(name, () => {
    const dir = tempDir();
    const { core, bookPath, privateKey, publicKeyPem } = openCore(dir);
    const genuine = [core.submit(request(0)), core.submit(request(1))];
    core.close();
    const { receipt_hash: _h, signature: _s, ...base } = genuine[1] as unknown as Record<string, unknown>;
    const draft: Record<string, unknown> = { ...base, clerk_seq: 2, prev_receipt_hash: genuine[1].receipt_hash };
    shape(draft, genuine);
    const forged = signReceipt(draft as unknown as UnsignedClerkReceipt, privateKey);
    assert.ok(verifyReceipt(forged, publicKeyPem).ok, "the forged record must carry a valid signature");
    writeLines(bookPath, [...bookLines(bookPath), JSON.stringify(forged)]);
    const v = verifyBookFile(bookPath, publicKeyPem);
    assert.equal(v.ok, false, "the book check accepted a broken chain");
    assert.equal(v.brokenAt, 2);
    assert.match(v.reason, expect);
  });
}

signedChainCase(
  "prev_receipt_hash naming the wrong receipt",
  (r, prev) => {
    r.prev_receipt_hash = prev[0].receipt_hash;
  },
  /prev_receipt_hash does not name the previous receipt/
);

signedChainCase(
  "clerk_seq skipping a number",
  (r) => {
    r.clerk_seq = 3;
  },
  /clerk_seq is 3, expected 2/
);

signedChainCase(
  "monotonic time going backwards within one boot",
  (r) => {
    r.clerk_time = { wall_ms: 1, monotonic_ns: "1" };
  },
  /monotonic_ns went backwards/
);

signedChainCase(
  "a retained payload that does not match its commitment",
  (r) => {
    r.payload_retained = true;
    r.payload_canonical = '{"other":true}';
  },
  /retained payload does not match/
);

signedChainCase(
  "an unknown receipt_form",
  (r) => {
    r.receipt_form = "SOMETHING-ELSE-9";
  },
  /unknown receipt_form/
);

signedChainCase(
  "a kind other than SUBMISSION",
  (r) => {
    r.kind = "OTHER";
  },
  /kind is not SUBMISSION/
);

signedChainCase(
  "a payload_commitment that is not 64 lowercase hex characters",
  (r) => {
    r.payload_commitment = "not-hex";
  },
  /payload_commitment is not 64 lowercase hex characters/
);

signedChainCase(
  "a payload_canonical although payload_retained is false",
  (r) => {
    r.payload_retained = false;
    r.payload_canonical = "{}";
  },
  /payload_canonical is set although payload_retained is false/
);

signedChainCase(
  "a payload_retained that is not a boolean",
  (r) => {
    r.payload_retained = "yes";
  },
  /payload_retained is not a boolean/
);

signedChainCase(
  "a monotonic_ns that is not a decimal string (hex parses as a BigInt)",
  (r) => {
    r.clerk_time = { wall_ms: 1, monotonic_ns: "0x7fffffffffffffffff" };
  },
  /clerk_time is malformed/
);

signedChainCase(
  "a wall_ms that is not a number",
  (r) => {
    r.clerk_time = { wall_ms: "1", monotonic_ns: (r.clerk_time as { monotonic_ns: string }).monotonic_ns };
  },
  /clerk_time is malformed/
);

check("a boot id that reappears after a later boot is refused", () => {
  const dir = tempDir();
  const k = keysIn(dir);
  const bookPath = join(dir, "book.jsonl");
  const opts = { clerkId: "c", privateKey: k.privateKey, bookPath, separation: "IN_PROCESS_NO_SEPARATION" as const };
  const a = ClerkCore.open(opts);
  const first = a.submit(request(0));
  a.close();
  const b = ClerkCore.open(opts);
  const second = b.submit(request(1));
  b.close();
  const { receipt_hash: _h, signature: _s, ...base } = second as unknown as Record<string, unknown>;
  const forged = signReceipt(
    {
      ...(base as unknown as UnsignedClerkReceipt),
      clerk_seq: 2,
      prev_receipt_hash: second.receipt_hash,
      clerk_boot_id: first.clerk_boot_id,
    },
    k.privateKey
  );
  writeLines(bookPath, [...bookLines(bookPath), JSON.stringify(forged)]);
  const v = verifyBookFile(bookPath, k.publicKeyPem);
  assert.equal(v.ok, false);
  assert.match(v.reason, /receipt 2: clerk_boot_id reappears/);
});

// ── refusals: nothing is booked ──────────────────────────────────────────────

section("Refusals: a refused request books nothing");

check("an allowlist accepts listed submitter ids and refuses others (a name check)", () => {
  const { core } = openCore(tempDir(), { allowedSubmitters: ["ilas-node"] });
  try {
    core.submit(request(0));
    const err = throws(() => core.submit({ ...request(1), submitter_id: "someone-else" }));
    assert.ok(err instanceof ClerkRequestError);
    assert.match(err.message, /not on this clerk's list/);
    assert.equal(core.nextSeq, 1);
  } finally {
    core.close();
  }
});

check("malformed requests are refused and nothing is booked", () => {
  const { core, bookPath } = openCore(tempDir());
  try {
    const bad: unknown[] = [
      null,
      [],
      "x",
      { channel: "c", payload: {} },
      { submitter_id: "", channel: "c", payload: {} },
      { submitter_id: "s", channel: 7, payload: {} },
      { submitter_id: "s".repeat(257), channel: "c", payload: {} },
      { submitter_id: "s", channel: "c" },
      { submitter_id: "s", channel: "c", payload: undefined },
      { submitter_id: "s", channel: "c", declared_timestamp: "1", payload: {} },
      { submitter_id: "s", channel: "c", declared_timestamp: NaN, payload: {} },
      { submitter_id: "s", channel: "c", payload: {}, extra: 1 },
    ];
    for (const b of bad) {
      const err = throws(() => core.submit(b));
      assert.ok(err instanceof ClerkRequestError, `${JSON.stringify(b)} gave ${err.name}`);
    }
    assert.equal(core.nextSeq, 0);
    assert.equal(readFileSync(bookPath, "utf8"), "");
  } finally {
    core.close();
  }
});

check("a payload with no canonical form is refused before anything is signed", () => {
  const { core } = openCore(tempDir());
  try {
    const deep: Record<string, unknown> = {};
    let cur = deep;
    for (let i = 0; i < 70; i++) {
      const next: Record<string, unknown> = {};
      cur.d = next;
      cur = next;
    }
    for (const payload of [[1, undefined], { n: NaN }, { n: BigInt(1) }, { f: () => 1 }, deep]) {
      const err = throws(() => core.submit({ submitter_id: "s", channel: "c", payload }));
      assert.ok(err instanceof ClerkRequestError);
      assert.match(err.message, /no canonical form/);
    }
    assert.equal(core.nextSeq, 0);
  } finally {
    core.close();
  }
});

check("a failed book write stops the clerk: that request and every later one is refused", () => {
  const dir = tempDir();
  const { core, bookPath, publicKeyPem } = openCore(dir);
  core.submit(request(0));
  // Fault injection: point the book at a closed descriptor so the next write fails.
  const book = (core as unknown as { book: { fd: number } }).book;
  const realFd = book.fd;
  book.fd = -1;
  try {
    const err = throws(() => core.submit(request(1)));
    assert.ok(err instanceof ClerkStoppedError, `got ${err.name}`);
    assert.ok(core.failure !== null);
    book.fd = realFd;
    const again = throws(() => core.submit(request(2)));
    assert.ok(again instanceof ClerkStoppedError, "a stopped clerk signed again");
  } finally {
    book.fd = realFd;
    core.close();
  }
  const v = verifyBookFile(bookPath, publicKeyPem);
  assert.ok(v.ok, v.reason);
  assert.equal(v.count, 1);
});

// ── the in-process client ────────────────────────────────────────────────────

section("InProcessClerkClient");

checkAsync("submit() resolves with a receipt that ILAS verifies", async () => {
  const dir = tempDir();
  const k = keysIn(dir);
  const client = InProcessClerkClient.open({
    clerkId: "c",
    privateKey: k.privateKey,
    bookPath: join(dir, "book.jsonl"),
  });
  try {
    const r = await client.submit(request(5));
    assert.ok(verifyClerkReceipt(r as unknown as Record<string, unknown>, k.publicKeyPem, entry(5)).ok);
    assert.equal(r.separation, "IN_PROCESS_NO_SEPARATION");
  } finally {
    client.close();
  }
});

checkAsync("a refused submission rejects (it never throws synchronously)", async () => {
  const dir = tempDir();
  const k = keysIn(dir);
  const client = InProcessClerkClient.open({ clerkId: "c", privateKey: k.privateKey, bookPath: join(dir, "b.jsonl") });
  try {
    let p: Promise<unknown>;
    try {
      p = client.submit({ submitter_id: "", channel: "c", payload: {} });
    } catch (err) {
      throw new Error(`threw synchronously: ${(err as Error).message}`);
    }
    await p.then(
      () => assert.fail("resolved"),
      (err: Error) => assert.ok(err instanceof ClerkRequestError)
    );
  } finally {
    client.close();
  }
});

checkAsync("a receipt from this clerk passes ILAS's route binding: submitter_id and channel are the route's", async () => {
  const dir = tempDir();
  const k = keysIn(dir);
  const client = InProcessClerkClient.open({ clerkId: "c", privateKey: k.privateKey, bookPath: join(dir, "b.jsonl") });
  try {
    const log = new LockedEvidenceLog({
      clerk: { client, submitterId: "node-7", channel: "evidence-a", clerkPublicKeyPem: k.publicKeyPem },
    });
    const committed = await log.append(entry(1));
    const r = committed.clerkReceipt!;
    assert.equal(r.submitter_id, "node-7");
    assert.equal(r.channel, "evidence-a");
    assert.ok(verifyReceipt(r, k.publicKeyPem).ok, "the fields ILAS binds are not signed");
    assert.equal(log.length, 1);
  } finally {
    client.close();
  }
});

checkAsync("a receipt this clerk booked for another submitter or channel is refused by ILAS", async () => {
  const dir = tempDir();
  const k = keysIn(dir);
  const client = InProcessClerkClient.open({ clerkId: "c", privateKey: k.privateKey, bookPath: join(dir, "b.jsonl") });
  try {
    for (const [field, value, expect] of [
      ["submitter_id", "someone-else", /submitter_id/],
      ["channel", "another-channel", /channel/],
    ] as const) {
      // A client that books under another name: the clerk signs a valid
      // receipt for that name, and ILAS must not take it for this route.
      const misbooking: ClerkSubmitClient = {
        submit: (req) => client.submit({ ...req, [field]: value }),
      };
      const log = new LockedEvidenceLog({
        clerk: { client: misbooking, submitterId: "node-7", channel: "evidence-a", clerkPublicKeyPem: k.publicKeyPem },
      });
      const err = await rejects(log.append(entry(2)));
      assert.ok(err instanceof L0ClerkError, `${field}: got ${err.name}: ${err.message}`);
      assert.match(err.message, expect);
      assert.equal(log.length, 0);
    }
  } finally {
    client.close();
  }
});

check("InProcessClerkClient will not wrap a core that claims SEPARATE_PROCESS", () => {
  const dir = tempDir();
  const { core } = openCore(dir, { separation: "SEPARATE_PROCESS" });
  try {
    const err = throws(() => new InProcessClerkClient(core));
    assert.match(err.message, /IN_PROCESS_NO_SEPARATION/);
  } finally {
    core.close();
  }
});

runAll();
