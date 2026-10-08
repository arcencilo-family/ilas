// ──────────────────────────────────────────────────────────────────────────────
// Reference witness — command line.
//
//   keygen --out <dir>                 new Ed25519 key: <dir>/witness.key (0600)
//                                      and <dir>/witness.pub.pem; never overwrites
//   run --config <file> [--once]       open the store, then poll the intakes every
//                                      pollIntervalMs until SIGINT or SIGTERM
//                                      (--once: a single poll, then exit)
//   verify --store <path> --pub <pem>  re-check the whole store: chain, hashes,
//                                      conflict notes, and every signature
//   fingerprint --pub <pem>            print the public key's fingerprint, as
//                                      keygen did: compare the node's copy of
//                                      the key with the operator's
//
// `run` writes one JSON object per line to stdout (see README). Problems that
// stop a command go to stderr; a halt is reported on both.
//
// Exit codes: 0 success or clean shutdown; 1 refused, halted, or verification
// failed; 2 usage error.
//
// Signals. Start `run` so that this node process is the one that gets SIGTERM:
// `node node_modules/ts-node/dist/bin.js packages/witness/src/cli.ts run …`,
// or exec'd by a supervisor. Under npx it is npm → sh -c → node, and a SIGTERM
// sent to npx may stop npx and the shell without ever reaching the witness.
// `run` never stops itself because of how it was launched: a witness that
// outlives whatever started it may be meant to. When npm or npx started it
// (npm_command=exec, or npm_lifecycle_event set), `run` (not `run --once`)
// writes one warning line to stderr at start, naming the direct command. Every
// path in that command is absolute (node, ts-node's bin.js, this cli.ts and the
// config), so it works from whatever directory it is run in.
//
// Key files (--pub, the config's privateKeyPath), the config and the store are
// opened without blocking and refused unless they are regular files: a FIFO
// given for one of them makes the command exit 1 at once, never hang.
// ──────────────────────────────────────────────────────────────────────────────

import { existsSync } from "fs";
import { join, resolve } from "path";
import { loadConfigFile } from "./config";
import {
  generateKeyFiles,
  loadPrivateKeyFile,
  loadPublicKeyFile,
  octalMode,
  publicKeyFingerprint,
} from "./keys";
import { readStore } from "./store";
import type { StoreContents } from "./store";
import { ReferenceWitness, WitnessHalted } from "./witness";
import type { PollEvent } from "./witness";

const USAGE = [
  "usage:",
  "  cli keygen --out <dir>",
  "  cli run --config <file> [--once]",
  "  cli verify --store <path> --pub <pem>",
  "  cli fingerprint --pub <pem>",
].join("\n");

class UsageError extends Error {}

type Flags = Record<string, string | true>;

function parseFlags(args: string[], spec: Record<string, "value" | "flag">): Flags {
  const flags: Flags = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!arg.startsWith("--")) throw new UsageError(`unexpected argument ${JSON.stringify(arg)}`);
    const name = arg.slice(2);
    const kind = spec[name];
    if (kind === undefined) throw new UsageError(`unknown option --${name}`);
    if (name in flags) throw new UsageError(`--${name} given twice`);
    if (kind === "flag") {
      flags[name] = true;
    } else {
      const value = args[i + 1];
      if (value === undefined || value.startsWith("--")) {
        throw new UsageError(`--${name} needs a value`);
      }
      flags[name] = value;
      i++;
    }
  }
  return flags;
}

function required(flags: Flags, name: string): string {
  const value = flags[name];
  if (typeof value !== "string") throw new UsageError(`--${name} is required`);
  return value;
}

function emit(event: string, fields: Record<string, unknown> = {}): void {
  process.stdout.write(JSON.stringify({ t: new Date().toISOString(), event, ...fields }) + "\n");
}

function emitPollEvent(e: PollEvent): void {
  const { kind, ...fields } = e;
  emit(kind, fields);
}

// ── keygen ────────────────────────────────────────────────────────────────────

function keygen(args: string[]): number {
  const flags = parseFlags(args, { out: "value" });
  const files = generateKeyFiles(required(flags, "out"));
  process.stdout.write(
    [
      // The mode as read back from the file system, not the one asked for.
      `wrote ${files.privateKeyPath} (private, mode ${octalMode(files.privateKeyMode)})`,
      `wrote ${files.publicKeyPath} (public)`,
      // The clerk's keygen prints the same line, in the same format.
      `public key fingerprint: ${files.fingerprint}`,
      "The private key stays with whoever operates this witness. Give only the",
      "public key file to the operator of each node that will verify its receipts.",
    ].join("\n") + "\n"
  );
  return 0;
}

// ── run ───────────────────────────────────────────────────────────────────────

/** True when npm started this process: `npx`/`npm exec`, or an npm script. */
function launchedByNpm(env: NodeJS.ProcessEnv): boolean {
  return env.npm_command === "exec" || env.npm_lifecycle_event !== undefined;
}

/** `word` as one shell word: unchanged when it is plain, else single-quoted. */
function shellWord(word: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(word) ? word : `'${word.replace(/'/g, `'\\''`)}'`;
}

/**
 * ts-node's bin.js, absolute: that of the ts-node running this file (npx may
 * have fetched one outside the repository), else the one resolved from here,
 * else where the repository's own install puts it.
 */
function tsNodeBin(): string {
  for (const loaded of Object.keys(require.cache)) {
    const dist = /^(.*[\\/]ts-node[\\/]dist)[\\/]index\.js$/.exec(loaded);
    if (dist !== null && existsSync(join(dist[1], "bin.js"))) return join(dist[1], "bin.js");
  }
  try {
    return require.resolve("ts-node/dist/bin.js");
  } catch {
    return resolve(__dirname, "..", "..", "..", "node_modules", "ts-node", "dist", "bin.js");
  }
}

/**
 * The command that starts this `run` with node as the process to signal. Every
 * path in it is absolute, so it works from any directory.
 */
function directCommand(configArg: string): string {
  // Compiled to JavaScript, this file needs no ts-node.
  const runner = __filename.endsWith(".ts") ? [tsNodeBin()] : [];
  return [process.execPath, ...runner, __filename, "run", "--config", resolve(configArg)]
    .map(shellWord)
    .join(" ");
}

function run(args: string[]): Promise<number> {
  const flags = parseFlags(args, { config: "value", once: "flag" });
  const configArg = required(flags, "config");
  const config = loadConfigFile(configArg);
  const privateKey = loadPrivateKeyFile(config.privateKeyPath);
  const witness = ReferenceWitness.open({ config, privateKey });

  if (flags.once !== true && launchedByNpm(process.env)) {
    process.stderr.write(
      `warning: this witness (pid ${process.pid}) was started through npm/npx; a signal ` +
        `sent to npx may not reach it, so stopping npx can leave it running. Signal pid ` +
        `${process.pid}, or start it directly: ${directCommand(configArg)}\n`
    );
  }

  emit("STARTED", {
    pid: process.pid,
    witnessSetId: config.witnessSetId,
    submitters: config.submitters.map((s) => s.id),
    records: witness.startup.records,
    storeCreated: witness.startup.storeCreated,
    publicKeyFingerprint: witness.startup.publicKeyFingerprint,
    pollIntervalMs: config.pollIntervalMs,
  });
  for (const r of witness.startup.receiptsRestored) emit("RECEIPT_RESTORED", r);
  for (const path of witness.startup.foreignOutboxFiles) emit("FOREIGN_OUTBOX_FILE", { path });
  if (witness.startup.recordsForUndeclaredSubmitters > 0) {
    emit("RECORDS_FOR_UNDECLARED_SUBMITTERS", {
      count: witness.startup.recordsForUndeclaredSubmitters,
    });
  }

  return new Promise<number>((resolve) => {
    let timer: NodeJS.Timeout | null = null;
    let finished = false;

    const finish = (code: number, event: string, fields: Record<string, unknown>): void => {
      if (finished) return;
      finished = true;
      if (timer !== null) clearTimeout(timer);
      process.off("SIGINT", onSigint);
      process.off("SIGTERM", onSigterm);
      emit(event, fields);
      resolve(code);
    };
    // pollOnce() is synchronous, so a signal is handled between polls, never
    // in the middle of an append or a receipt write.
    const onSigint = (): void => finish(0, "STOPPED", { signal: "SIGINT" });
    const onSigterm = (): void => finish(0, "STOPPED", { signal: "SIGTERM" });
    process.on("SIGINT", onSigint);
    process.on("SIGTERM", onSigterm);

    const tick = (): void => {
      timer = null;
      try {
        for (const e of witness.pollOnce()) emitPollEvent(e);
      } catch (error) {
        if (error instanceof WitnessHalted) for (const e of error.events) emitPollEvent(e);
        const detail = error instanceof Error ? error.message : String(error);
        // stdout carries the event log; stderr carries why the process exits 1.
        process.stderr.write(`error: the witness halted: ${detail}\n`);
        finish(1, "HALTED", { detail });
        return;
      }
      if (flags.once === true) {
        finish(0, "STOPPED", { signal: null });
        return;
      }
      if (!finished) timer = setTimeout(tick, config.pollIntervalMs);
    };
    tick();
  });
}

// ── verify ────────────────────────────────────────────────────────────────────

function verifyCommand(args: string[]): number {
  const flags = parseFlags(args, { store: "value", pub: "value" });
  const storePath = required(flags, "store");
  const publicKey = loadPublicKeyFile(required(flags, "pub"));

  let contents: StoreContents;
  try {
    contents = readStore(storePath, { publicKey });
  } catch (error) {
    process.stdout.write(
      `FAIL: ${storePath} does not verify: ${error instanceof Error ? error.message : String(error)}\n`
    );
    return 1;
  }
  if (!contents.exists) {
    process.stdout.write(`FAIL: no store at ${storePath}\n`);
    return 1;
  }

  const perSubmitter = new Map<string, number>();
  let notes = 0;
  for (const r of contents.records) {
    perSubmitter.set(r.submitter_id, (perSubmitter.get(r.submitter_id) ?? 0) + 1);
    notes += r.conflicts.length;
  }
  const head = contents.records.length === 0 ? "(empty)" : contents.records[contents.records.length - 1].hash;
  const lines = [
    `OK: ${contents.records.length} record(s) verify: chain links, record hashes, ` +
      `record signatures, receipt signatures, conflict notes`,
    `public key fingerprint: ${publicKeyFingerprint(publicKey)}`,
    `last record hash: ${head}`,
    ...[...perSubmitter].map(([id, n]) => `submitter ${JSON.stringify(id)}: ${n} record(s)`),
    `conflict notes: ${notes}`,
  ];
  for (const r of contents.records) {
    for (const c of r.conflicts) {
      lines.push(
        `  record ${r.index} (${JSON.stringify(r.submitter_id)}, seq ${r.commit.seq_no}): ` +
          (c.kind === "SAME_SEQ_DIFFERENT_HEAD"
            ? `same seq_no as record ${c.prior_index}, different head_hash`
            : `seq_no lower than record ${c.prior_index} (seq ${c.prior_seq_no})`)
      );
    }
  }
  process.stdout.write(lines.join("\n") + "\n");
  return 0;
}

// ── fingerprint ───────────────────────────────────────────────────────────────

/**
 * Print the fingerprint of a public key file, alone on one line, in the format
 * keygen printed it. loadPublicKeyFile() refuses a file holding a private key
 * rather than fingerprint the public half derived from it (exit 1).
 */
function fingerprintCommand(args: string[]): number {
  const flags = parseFlags(args, { pub: "value" });
  const publicKey = loadPublicKeyFile(required(flags, "pub"));
  process.stdout.write(publicKeyFingerprint(publicKey) + "\n");
  return 0;
}

// ── entry ─────────────────────────────────────────────────────────────────────

export async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  try {
    switch (command) {
      case "keygen":
        return keygen(rest);
      case "run":
        return await run(rest);
      case "verify":
        return verifyCommand(rest);
      case "fingerprint":
        return fingerprintCommand(rest);
      case undefined:
      case "help":
      case "--help":
        process.stdout.write(USAGE + "\n");
        return command === undefined ? 2 : 0;
      default:
        throw new UsageError(`unknown command ${JSON.stringify(command)}`);
    }
  } catch (error) {
    if (error instanceof UsageError) {
      process.stderr.write(`error: ${error.message}\n${USAGE}\n`);
      return 2;
    }
    process.stderr.write(`error: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

if (require.main === module) {
  void main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
