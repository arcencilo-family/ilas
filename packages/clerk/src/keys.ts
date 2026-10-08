// ──────────────────────────────────────────────────────────────────────────────
// Reference clerk — Ed25519 key files.
//
// There is no default key. A key is made by `keygen`, by whoever operates the
// clerk, and the node is given only the public half.
//
// The private key file is written with mode 0600 (keygen fails if the mode
// read back is anything else) and refused on load if group or other users
// have any access to it. Mode 0600 keeps OTHER accounts out. It
// does not keep out processes running under the SAME account as the clerk;
// if the node runs under that account, it can read the key. Which account runs
// the clerk is a deployment decision this code cannot make or check.
// ──────────────────────────────────────────────────────────────────────────────

import { createPrivateKey, createPublicKey, generateKeyPairSync } from "crypto";
import type { KeyObject } from "crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  statSync,
  unlinkSync,
  writeSync,
} from "fs";
import { join } from "path";
import { openRegularFileForReading } from "./book";
import { holdsPrivateKeyMaterial } from "./receipt";

export const PRIVATE_KEY_FILE = "clerk.key";
export const PUBLIC_KEY_FILE = "clerk.pub.pem";

export class ClerkKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ClerkKeyError";
  }
}

function octal(mode: number): string {
  return "0" + (mode & 0o777).toString(8).padStart(3, "0");
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Remove a file keygen created itself; returns the sentence that says how that went. */
function removeAgain(path: string, what: string): string {
  try {
    unlinkSync(path);
    return `The ${what} was removed again.`;
  } catch (err) {
    return `Removing it failed (${messageOf(err)}); delete ${path} by hand.`;
  }
}

/**
 * Create `path`, write `contents`, set `mode` and return the permission bits
 * read back. Once the file exists, any failure (a write that fails part way,
 * a chmod the file system refuses) removes it again and throws ClerkKeyError:
 * keygen leaves a complete file or none.
 */
function writeNewFile(path: string, contents: string, mode: number, what: string): number {
  // "wx": fail if the file exists. A key is never silently replaced, and a
  // file this call did not create is never removed: the open stays outside
  // the cleanup below.
  const fd = openSync(path, "wx", mode);
  let step = "writing it";
  try {
    try {
      const buf = Buffer.from(contents, "utf8");
      let off = 0;
      while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    // The create mode is filtered by the umask; set it explicitly.
    step = `setting its mode to ${octal(mode)}`;
    chmodSync(path, mode);
    step = "reading its mode back";
    return statSync(path).mode & 0o777;
  } catch (err) {
    const hint = step.startsWith("setting")
      ? " This account cannot set POSIX permissions there (for example on a FAT or exFAT " +
        "mount owned by another account, or a mount that refuses chmod), so other accounts " +
        "may be able to read the file. Generate the key in a directory on a file system " +
        "that keeps permissions."
      : "";
    throw new ClerkKeyError(
      `${path} was created, but ${step} failed (${messageOf(err)}).${hint} ${removeAgain(path, what)}`
    );
  }
}

export interface GeneratedKeyFiles {
  privateKeyPath: string;
  /** The private key file's permission bits as read back after writing (always 0o600). */
  privateKeyMode: number;
  publicKeyPath: string;
  publicKeyPem: string;
}

/**
 * Generate a fresh Ed25519 key pair into `outDir`: clerk.key (PKCS#8 PEM,
 * mode 0600) and clerk.pub.pem (SPKI PEM, mode 0644). Refuses if either file
 * already exists. Creates `outDir` with mode 0700 if it does not exist.
 *
 * The private key's mode is read back after writing. On a filesystem that
 * does not keep POSIX permissions (a Windows drive mounted in WSL, some
 * network or FAT mounts) chmod either does not take or is refused, and other
 * accounts may be able to read the key: then the key file is removed again
 * and ClerkKeyError is thrown, before the public key is written. If writing
 * either file fails, neither is left behind.
 */
export function generateClerkKeyFiles(outDir: string): GeneratedKeyFiles {
  const privateKeyPath = join(outDir, PRIVATE_KEY_FILE);
  const publicKeyPath = join(outDir, PUBLIC_KEY_FILE);
  for (const p of [privateKeyPath, publicKeyPath]) {
    if (existsSync(p)) {
      throw new ClerkKeyError(`${p} already exists; refusing to overwrite a key file`);
    }
  }
  mkdirSync(outDir, { recursive: true, mode: 0o700 });
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }) as string;
  const privateKeyMode = writeNewFile(privateKeyPath, privatePem, 0o600, "key file");
  if (privateKeyMode !== 0o600) {
    const removed = removeAgain(privateKeyPath, "key file");
    throw new ClerkKeyError(
      `${privateKeyPath} has mode ${octal(privateKeyMode)} after it was written and set to 0600: ` +
        `this filesystem does not keep POSIX file permissions (for example a Windows drive ` +
        `mounted in WSL), so other accounts may be able to read the key. ${removed} ` +
        `Generate the key in a directory on a filesystem that keeps permissions.`
    );
  }
  try {
    writeNewFile(publicKeyPath, publicKeyPem, 0o644, "public key file");
  } catch (err) {
    // A private key without its public half is of no use to anyone, and it
    // would make the next keygen into this directory refuse.
    throw new ClerkKeyError(
      `${messageOf(err)} ${removeAgain(privateKeyPath, `private key ${privateKeyPath}`)}`
    );
  }
  return { privateKeyPath, privateKeyMode, publicKeyPath, publicKeyPem };
}

/**
 * Load the clerk's private key. Refuses a file that group or other users can
 * access in any way, a file that is not a regular file, and a key that is not
 * Ed25519 — each with the reason.
 *
 * The file is opened without blocking (a FIFO at the path is refused at once,
 * not waited on), and its type and mode are read from the open descriptor, so
 * what is checked is the file that is read.
 */
export function loadClerkPrivateKey(path: string): KeyObject {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  } catch (err) {
    throw new ClerkKeyError(
      (err as NodeJS.ErrnoException).code === "ENXIO"
        ? `clerk private key ${path} is not a regular file` // a socket
        : `cannot read clerk private key ${path}: ${messageOf(err)}`
    );
  }
  let text: string;
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) {
      throw new ClerkKeyError(`clerk private key ${path} is not a regular file`);
    }
    if ((st.mode & 0o077) !== 0) {
      throw new ClerkKeyError(
        `clerk private key ${path} has mode ${octal(st.mode)}: group or other users can ` +
          `access it. Anyone who can read this file can sign receipts as this clerk, so ` +
          `the clerk refuses to use it. Restrict it to its owner (chmod 600 ${path}).`
      );
    }
    try {
      text = readFileSync(fd, "utf8");
    } catch (err) {
      throw new ClerkKeyError(`cannot read clerk private key ${path}: ${messageOf(err)}`);
    }
  } finally {
    closeSync(fd);
  }
  let key: KeyObject;
  try {
    key = createPrivateKey(text);
  } catch (err) {
    throw new ClerkKeyError(`${path} is not a readable PEM private key: ${(err as Error).message}`);
  }
  if (key.asymmetricKeyType !== "ed25519") {
    throw new ClerkKeyError(
      `${path} holds a ${String(key.asymmetricKeyType)} key; the clerk signs with ed25519 only`
    );
  }
  return key;
}

/** The SPKI PEM of the public half of `privateKey`. */
export function publicKeyPemOf(privateKey: KeyObject): string {
  return createPublicKey(privateKey).export({ type: "spki", format: "pem" }) as string;
}

/**
 * Load an Ed25519 public key from a PEM file. Returns its SPKI PEM. Anything
 * at `path` that is not a regular file (a FIFO, a socket, a directory, a
 * device) is refused at once; a FIFO is never waited on.
 */
export function loadPublicKeyPem(path: string): string {
  let text: string;
  try {
    const fd = openRegularFileForReading(path);
    try {
      text = readFileSync(fd, "utf8");
    } finally {
      closeSync(fd);
    }
  } catch (err) {
    const message =
      (err as NodeJS.ErrnoException).code === "ENXIO" ? `${path} is not a regular file` : messageOf(err);
    throw new ClerkKeyError(`cannot read public key ${path}: ${message}`);
  }
  if (holdsPrivateKeyMaterial(text)) {
    // createPublicKey would quietly derive the public half; say what happened instead.
    throw new ClerkKeyError(`${path} holds a private key; give only the public key (clerk.pub.pem)`);
  }
  let key: KeyObject;
  try {
    key = createPublicKey(text);
  } catch (err) {
    throw new ClerkKeyError(`${path} is not a readable PEM public key: ${(err as Error).message}`);
  }
  if (key.asymmetricKeyType !== "ed25519") {
    throw new ClerkKeyError(`${path} holds a ${String(key.asymmetricKeyType)} key, not ed25519`);
  }
  return key.export({ type: "spki", format: "pem" }) as string;
}
