// ──────────────────────────────────────────────────────────────────────────────
// Reference clerk — command line.
//
//   npx ts-node packages/clerk/src/cli.ts keygen --out <dir>
//   node node_modules/ts-node/dist/bin.js packages/clerk/src/cli.ts run --config <file>
//   npx ts-node packages/clerk/src/cli.ts verify --book <path> --pub <pem>
//   npx ts-node packages/clerk/src/cli.ts fingerprint --pub <pem>
//   npx ts-node packages/clerk/src/cli.ts reconcile --book <path> --log <l0.jsonl>
//       [--log <l0.jsonl> ...] --pub <pem> --submitter <id> --channel <ch>
//   node node_modules/ts-node/dist/bin.js packages/clerk/src/cli.ts ping
//       --socket <path> [--timeout-ms N]
//
// `run` is started without npx: npx runs the command under `sh -c`, and a
// SIGTERM sent to the npx process then never reaches clerkd (see README §6).
// Started through npm or npx anyway, `run` says so in one warning line on
// stderr, naming the direct command with absolute paths. It does not stop
// itself over how it was launched.
//
// `ping` sends clerkd one probe request that it refuses (so nothing is
// booked) and exits 0 once a well-formed answer arrives in time. A socket
// file with nothing listening on it, a listener that does not answer in time
// or that answers something other than a clerkd response line all exit 1.
//
// Exit codes: 0 success; 1 failure (including a book that does not verify, and
// a clerkd that does not answer a ping); 2 usage error; 3 reconcile found gaps
// between the book and the log.
// ──────────────────────────────────────────────────────────────────────────────

import { resolve } from "path";
import { publicKeyFingerprint } from "../../../src/l0/fingerprint";
import { verifyBookFile } from "./book";
import { DEFAULT_PING_TIMEOUT_MS, MAX_TIMER_MS, pingClerkd } from "./client";
import { loadConfigFile } from "./config";
import { generateClerkKeyFiles, loadPublicKeyPem } from "./keys";
import { reconcileBookAndLogs, reconcileFoundNoGaps } from "./reconcile";
import type { LogOnlyEntry, ReconcileReport } from "./reconcile";
import { startClerkd } from "./server";

export interface CliIO {
  out: (line: string) => void;
  err: (line: string) => void;
}

const USAGE = [
  "usage:",
  "  clerk keygen --out <dir>                 write clerk.key (0600) and clerk.pub.pem",
  "  clerk run --config <file>                run clerkd until SIGINT or SIGTERM",
  "  clerk verify --book <path> --pub <pem>   check every receipt and the chain",
  "  clerk fingerprint --pub <pem>            print the public key's fingerprint",
  "  clerk reconcile --book <path> --log <l0.jsonl> [--log <l0.jsonl> ...]",
  "        --pub <pem> --submitter <id> --channel <ch>",
  "                                           list receipts booked for that submitter and",
  "                                           channel that no log entry carries, log",
  "                                           entries whose receipt is not in the book, and",
  "                                           log entries whose receipt fails ILAS's",
  "                                           receipt rules (exit 3 if there are any)",
  `  clerk ping --socket <path> [--timeout-ms N]`,
  `                                           exit 0 if clerkd answers a probe on the socket`,
  `                                           within N ms (default ${DEFAULT_PING_TIMEOUT_MS}); nothing is booked`,
].join("\n");

/** Exit code of `reconcile` when the book and the log differ. */
export const EXIT_GAPS = 3;
/** `ping`: clerkd answered, but it has stopped and refuses every request. */
export const EXIT_STOPPED = 4;

class UsageError extends Error {}

/**
 * Every flag in `required` exactly once, those in `repeatable` once or more,
 * those in `optional` at most once; nothing else. Values in the order given.
 */
function flagLists(
  args: readonly string[],
  required: readonly string[],
  repeatable: readonly string[] = [],
  optional: readonly string[] = []
): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const name = a.slice(2);
    if (!a.startsWith("--") || !(required.includes(name) || optional.includes(name))) {
      throw new UsageError(`unexpected argument ${JSON.stringify(a)}`);
    }
    const v = args[i + 1];
    if (v === undefined || v.startsWith("--")) throw new UsageError(`${a} needs a value`);
    if (out[name] !== undefined && !repeatable.includes(name)) {
      throw new UsageError(`${a} is given more than once`);
    }
    (out[name] ??= []).push(v);
    i++;
  }
  for (const k of required) {
    if (out[k] === undefined) throw new UsageError(`--${k} is required`);
  }
  return out;
}

function flags(args: readonly string[], allowed: readonly string[]): Record<string, string> {
  const lists = flagLists(args, allowed);
  const out: Record<string, string> = {};
  for (const k of allowed) out[k] = lists[k][0];
  return out;
}

/** The report `reconcile` prints, one line per call of `out`. */
function printReconcile(r: ReconcileReport, submitter: string, channel: string, io: CliIO): void {
  const route = `submitter_id ${JSON.stringify(submitter)} on channel ${JSON.stringify(channel)}`;
  io.out(`book verifies: ${r.bookCount} receipt(s), head ${r.bookHead}; ${r.bookForRoute} booked for ${route}`);
  for (const l of r.logs) {
    io.out(
      `log ${l.path}: ${l.entries} entries, ${l.withReceipt} with a clerk receipt, ` +
        `${l.withoutReceipt} without (not compared)`
    );
  }
  io.out(`booked for ${route}, on no log entry: ${r.bookOnly.length}`);
  for (const b of r.bookOnly) io.out(`  clerk_seq ${b.clerkSeq}  receipt_hash ${b.receiptHash}`);
  const list = (entries: readonly LogOnlyEntry[]): void => {
    for (const e of entries) {
      const seq = e.sequenceNumber === null ? "" : ` (sequenceNumber ${e.sequenceNumber})`;
      const what =
        (e.clerkSeq === null ? "" : `clerk_seq ${e.clerkSeq}, `) +
        (e.receiptHash === null ? "" : `receipt_hash ${e.receiptHash}: `);
      io.out(`  ${e.logPath} entry ${e.index}${seq}: ${what}${e.reason}`);
    }
  };
  io.out(`log entries whose receipt is not among the book's receipts for ${route}: ${r.logOnly.length}`);
  list(r.logOnly);
  io.out(
    `log entries whose receipt fails ILAS's receipt rules for that entry and ${route} ` +
      `(L0 refuses such a log): ${r.refused.length}`
  );
  list(r.refused);
  io.out(
    "note: the logs are read as data; their hash chains are not checked here (L0 checks " +
      "a log's chain when it loads it)"
  );
  if (reconcileFoundNoGaps(r)) {
    io.out("no gaps: the book and the logs hold the same receipts for this submitter and channel");
  } else {
    const entries = (n: number): string => `${n} log entr${n === 1 ? "y" : "ies"}`;
    io.out(
      `gaps: ${r.bookOnly.length} booked receipt(s) on no log entry, ${entries(r.logOnly.length)} ` +
        `whose receipt is not in the book, ${entries(r.refused.length)} whose receipt fails ` +
        `ILAS's receipt rules (docs/S4-WIRE-SPEC.md §7.4 lists the causes)`
    );
  }
}

/** `s` as one POSIX shell word: unchanged when that is safe, single-quoted otherwise. */
function shellWord(s: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}

/**
 * The warning `run` prints when npm or npx started it, or null. npm and npx
 * say so in the environment they give the command: npm_command is "exec"
 * under npx (npm exec), and npm_lifecycle_event is set under an npm script.
 * A program they started can inherit those too; the warning is only a
 * warning, and nothing else depends on it.
 *
 * The command it names uses absolute paths throughout (this node binary,
 * ts-node's bin, this cli.ts, the config file), so it can be run as printed
 * from any directory.
 */
export function launcherWarning(
  env: Readonly<Record<string, string | undefined>>,
  configPath: string
): string | null {
  if (env.npm_command !== "exec" && env.npm_lifecycle_event === undefined) return null;
  let tsNode: string;
  try {
    tsNode = require.resolve("ts-node/dist/bin.js");
  } catch {
    // Not resolvable from here: where the repository's own install puts it.
    tsNode = resolve(__dirname, "..", "..", "..", "node_modules", "ts-node", "dist", "bin.js");
  }
  return (
    `clerkd: warning: started through npm/npx; signals sent to npx (or npm) may not reach ` +
    `clerkd (pid ${process.pid}). Start it directly: ` +
    `${shellWord(process.execPath)} ${shellWord(tsNode)} ${shellWord(__filename)} ` +
    `run --config ${shellWord(resolve(configPath))}`
  );
}

/** A --timeout-ms value: a whole number of milliseconds, more than 0, that setTimeout keeps. */
function timeoutFlag(value: string | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  const n = /^[1-9][0-9]{0,9}$/.test(value) ? Number(value) : NaN;
  if (!(n >= 1 && n <= MAX_TIMER_MS)) {
    throw new UsageError(`--timeout-ms must be a whole number from 1 to ${MAX_TIMER_MS}`);
  }
  return n;
}

async function run(configPath: string, io: CliIO): Promise<number> {
  const config = loadConfigFile(configPath);
  const clerkd = await startClerkd(config, { log: (m) => io.err(`clerkd: ${m}`) });
  const core = clerkd.core;
  const warning = launcherWarning(process.env, configPath);
  if (warning !== null) io.err(warning);
  // The pid is the process to signal: under a wrapper (npx, sh -c) the
  // wrapper's own pid is not this process.
  io.out(
    `clerkd: listening on ${clerkd.socketPath} ` +
      `(pid ${process.pid}, clerk_id ${core.clerkId}, next clerk_seq ${core.nextSeq}, ` +
      `boot ${core.bootId}, principal ${core.principal})`
  );
  const signal = await new Promise<string>((resolve) => {
    const onInt = (): void => done("SIGINT");
    const onTerm = (): void => done("SIGTERM");
    const done = (name: string): void => {
      process.off("SIGINT", onInt);
      process.off("SIGTERM", onTerm);
      resolve(name);
    };
    process.on("SIGINT", onInt);
    process.on("SIGTERM", onTerm);
  });
  io.out(`clerkd: ${signal} received, shutting down`);
  await clerkd.close();
  io.out(`clerkd: stopped (book has ${core.nextSeq} receipts)`);
  return 0;
}

/** Run the CLI. Resolves with the exit code; never calls process.exit itself. */
export async function main(argv: readonly string[], io: CliIO): Promise<number> {
  const [command, ...rest] = argv;
  try {
    switch (command) {
      case "keygen": {
        const f = flags(rest, ["out"]);
        const k = generateClerkKeyFiles(f.out);
        const mode = "0" + k.privateKeyMode.toString(8).padStart(3, "0");
        io.out(`private key: ${k.privateKeyPath} (mode ${mode}; keep it with the clerk's operator)`);
        io.out(`public key:  ${k.publicKeyPath} (give this one to the node: clerkPublicKeyPem)`);
        io.out(`public key fingerprint: ${publicKeyFingerprint(k.publicKeyPem)}`);
        io.out(k.publicKeyPem.trimEnd());
        return 0;
      }
      case "fingerprint": {
        const f = flags(rest, ["pub"]);
        // loadPublicKeyPem refuses a private key, rather than fingerprint its public half.
        io.out(publicKeyFingerprint(loadPublicKeyPem(f.pub)));
        return 0;
      }
      case "reconcile": {
        const f = flagLists(rest, ["book", "log", "pub", "submitter", "channel"], ["log"]);
        const submitter = f.submitter[0];
        const channel = f.channel[0];
        const report = reconcileBookAndLogs({
          bookPath: f.book[0],
          logPaths: f.log,
          publicKey: loadPublicKeyPem(f.pub[0]),
          submitterId: submitter,
          channel,
        });
        printReconcile(report, submitter, channel, io);
        return reconcileFoundNoGaps(report) ? 0 : EXIT_GAPS;
      }
      case "ping": {
        const f = flagLists(rest, ["socket"], [], ["timeout-ms"]);
        const timeoutMs = timeoutFlag(f["timeout-ms"]?.[0], DEFAULT_PING_TIMEOUT_MS);
        const r = await pingClerkd(f.socket[0], timeoutMs);
        if (r.error !== null && r.error.startsWith("clerk stopped:")) {
          io.out(
            `clerkd answered on ${f.socket[0]} in ${r.ms} ms, but it has STOPPED and refuses ` +
              `every request until restarted: ${r.error}`
          );
          return EXIT_STOPPED;
        }
        io.out(
          `clerkd answered on ${f.socket[0]} in ${r.ms} ms` +
            (r.error === null ? "" : ` (the probe was refused, as expected: ${r.error})`)
        );
        return 0;
      }
      case "run": {
        const f = flags(rest, ["config"]);
        return await run(f.config, io);
      }
      case "verify": {
        const f = flags(rest, ["book", "pub"]);
        const pub = loadPublicKeyPem(f.pub);
        const v = verifyBookFile(f.book, pub);
        if (!v.ok) {
          io.err(`book does NOT verify: ${v.reason}`);
          io.err(`${v.count} receipt(s) verified before the break`);
          return 1;
        }
        io.out(`book verifies: ${v.count} receipt(s), head ${v.head}`);
        io.out(
          "note: this shows every receipt is signed by this key and chained; it cannot " +
            "show that no receipts are missing after the last one"
        );
        return 0;
      }
      default:
        throw new UsageError(command === undefined ? "no command" : `unknown command ${command}`);
    }
  } catch (err) {
    if (err instanceof UsageError) {
      io.err(err.message);
      io.err(USAGE);
      return 2;
    }
    io.err(`error: ${(err as Error).message ?? String(err)}`);
    return 1;
  }
}

if (require.main === module) {
  void main(process.argv.slice(2), {
    out: (l) => process.stdout.write(l + "\n"),
    err: (l) => process.stderr.write(l + "\n"),
  }).then((code) => process.exit(code));
}
