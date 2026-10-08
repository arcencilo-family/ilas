// ──────────────────────────────────────────────────────────────────────────────
// Reference clerk — command line.
//   npx ts-node packages/clerk/src/cli.test.ts
//
// keygen / verify / config errors / ping run through main() in this process.
// The signal handling of `run`, its warning when npm or npx started it, and
// anything that would hang the process if it went wrong (a FIFO as a key
// file) are checked on real child processes, which start in a temp directory.
//
// Every path a test gives the CLI is under a temp directory. The last test
// checks that the repository root gained no entry while this file ran.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { spawn, spawnSync } from "child_process";
import type { ChildProcess } from "child_process";
import { createHash, createPublicKey, generateKeyPairSync } from "crypto";
import fs = require("fs"); // the module object itself, so a test can stand in for chmodSync
import { chmodSync, existsSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "fs";
import { createServer } from "net";
import type { Server, Socket } from "net";
import { join } from "path";
import { publicKeyFingerprint } from "../../../src/l0/fingerprint";
import { launcherWarning, main } from "./cli";
import { SocketClerkClient } from "./client";
import { ClerkCore } from "./core";
import { loadClerkPrivateKey } from "./keys";
import {
  checkAsync,
  CLI_PATH,
  makeClerkFixture,
  REPO_ROOT,
  runAll,
  section,
  spawnCli,
  startChildClerkd,
  tempDir,
  trackChild,
} from "./test-support";

/** The repository root's entries before any test ran; the run must add none. */
const REPO_ENTRIES_BEFORE = fs.readdirSync(REPO_ROOT);

async function cli(args: string[]): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await main(args, { out: (l) => out.push(l), err: (l) => err.push(l) });
  return { code, out: out.join("\n"), err: err.join("\n") };
}

/** A book with `n` receipts, made by an in-process core. */
function bookWith(n: number) {
  const f = makeClerkFixture();
  const core = ClerkCore.open({
    clerkId: "cli-test",
    privateKey: loadClerkPrivateKey(f.privateKeyPath),
    bookPath: f.bookPath,
    separation: "IN_PROCESS_NO_SEPARATION",
  });
  for (let i = 0; i < n; i++) core.submit({ submitter_id: "s", channel: "c", payload: { i } });
  core.close();
  return f;
}

section("keygen");

checkAsync("keygen --out writes clerk.key (0600) and clerk.pub.pem, and prints the public key", async () => {
  const dir = join(tempDir(), "keys");
  const r = await cli(["keygen", "--out", dir]);
  assert.equal(r.code, 0, r.err);
  assert.equal(statSync(join(dir, "clerk.key")).mode & 0o777, 0o600);
  assert.match(r.out, /clerk\.key \(mode 0600;/);
  assert.ok(existsSync(join(dir, "clerk.pub.pem")));
  assert.ok(r.out.includes(readFileSync(join(dir, "clerk.pub.pem"), "utf8").trim()));
});

checkAsync("keygen exits 1, says why, and never claims mode 0600, when the key file does not keep that mode", async () => {
  // Stand-in for a mount without POSIX permissions (a Windows drive under WSL).
  const realChmod = fs.chmodSync;
  fs.chmodSync = (p: fs.PathLike, _mode: fs.Mode) => realChmod(p, 0o777);
  const dir = join(tempDir(), "keys");
  let r: { code: number; out: string; err: string };
  try {
    r = await cli(["keygen", "--out", dir]);
  } finally {
    fs.chmodSync = realChmod;
  }
  assert.equal(r.code, 1, r.out);
  assert.match(r.err, /has mode 0777 after it was written/);
  assert.match(r.err, /does not keep POSIX file permissions/);
  assert.doesNotMatch(r.out + r.err, /mode 0600/);
  assert.equal(existsSync(join(dir, "clerk.key")), false);
  assert.equal(existsSync(join(dir, "clerk.pub.pem")), false);
});

checkAsync("keygen exits 1 with the reason, and leaves no key, when chmod itself is refused", async () => {
  // Stand-in for a FAT/exFAT mount owned by another account: chmod throws EPERM.
  const realChmod = fs.chmodSync;
  fs.chmodSync = (p: fs.PathLike, _mode: fs.Mode) => {
    const e = new Error(`EPERM: operation not permitted, chmod '${String(p)}'`) as NodeJS.ErrnoException;
    e.code = "EPERM";
    throw e;
  };
  const dir = join(tempDir(), "keys");
  let r: { code: number; out: string; err: string };
  try {
    r = await cli(["keygen", "--out", dir]);
  } finally {
    fs.chmodSync = realChmod;
  }
  assert.equal(r.code, 1, r.out);
  assert.match(r.err, /setting its mode to 0600 failed \(EPERM/);
  assert.match(r.err, /The key file was removed again/);
  assert.deepEqual(fs.readdirSync(dir), []);
});

checkAsync("keygen refuses to overwrite (exit 1)", async () => {
  const dir = tempDir();
  assert.equal((await cli(["keygen", "--out", dir])).code, 0);
  const r = await cli(["keygen", "--out", dir]);
  assert.equal(r.code, 1);
  assert.match(r.err, /refusing to overwrite/);
});

section("fingerprint");

checkAsync("keygen prints the public key's fingerprint: \"sha256:\" + hex SHA-256 of its SPKI DER, ILAS's format", async () => {
  const dir = join(tempDir(), "keys");
  const r = await cli(["keygen", "--out", dir]);
  assert.equal(r.code, 0, r.err);
  const pem = readFileSync(join(dir, "clerk.pub.pem"), "utf8");
  const der = createPublicKey(pem).export({ type: "spki", format: "der" });
  const expected = "sha256:" + createHash("sha256").update(der).digest("hex");
  assert.equal(publicKeyFingerprint(pem), expected, "not the format ILAS prints");
  assert.ok(r.out.split("\n").includes(`public key fingerprint: ${expected}`), r.out);
});

checkAsync("fingerprint --pub prints, for the node's copy of the key, exactly what keygen printed (exit 0)", async () => {
  const dir = join(tempDir(), "keys");
  const k = await cli(["keygen", "--out", dir]);
  const printed = /^public key fingerprint: (sha256:[0-9a-f]{64})$/m.exec(k.out);
  assert.ok(printed !== null, k.out);
  const copy = join(tempDir(), "node-copy.pub.pem");
  writeFileSync(copy, readFileSync(join(dir, "clerk.pub.pem")));
  const r = await cli(["fingerprint", "--pub", copy]);
  assert.equal(r.code, 0, r.err);
  assert.equal(r.out, printed[1]);
  const other = await cli(["fingerprint", "--pub", makeClerkFixture().publicKeyPath]);
  assert.equal(other.code, 0);
  assert.notEqual(other.out, printed[1], "two keys, one fingerprint");
});

checkAsync("fingerprint refuses a private key, a missing file, a file that is no key and a non-ed25519 key (exit 1, nothing printed)", async () => {
  const f = makeClerkFixture();
  const notKey = join(f.dir, "not-a-key.pem");
  writeFileSync(notKey, "hello\n");
  const rsa = join(f.dir, "rsa.pub.pem");
  writeFileSync(rsa, generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ type: "spki", format: "pem" }));
  for (const [path, re] of [
    [f.privateKeyPath, /holds a private key; give only the public key/],
    [join(f.dir, "absent.pem"), /cannot read public key/],
    [notKey, /is not a readable PEM public key/],
    [rsa, /holds a rsa key, not ed25519/],
  ] as const) {
    const r = await cli(["fingerprint", "--pub", path]);
    assert.equal(r.code, 1, `${path}: ${r.out}`);
    assert.match(r.err, re);
    assert.equal(r.out, "", `${path}: printed ${r.out}`);
  }
});

checkAsync("usage errors exit 2, and write nothing", async () => {
  // Every path is under a temp directory: a flag parser that wrongly let one
  // of these through would write there, never into the working directory.
  const t = tempDir();
  const p = (name: string): string => join(t, name);
  for (const args of [
    [],
    ["nope"],
    ["keygen"],
    ["keygen", "--out"],
    ["keygen", "--out", p("a"), "--out", p("b")],
    ["verify", "--book", p("x")],
    ["run", "--config", p("c"), "--extra", "y"],
    ["fingerprint"],
    ["fingerprint", "--pub", p("a"), "--pub", p("b")],
    ["ping"],
    ["ping", "--socket"],
    ["ping", "--socket", p("s"), "--socket", p("s")],
    ["ping", "--socket", p("s"), "--extra", "y"],
    ["ping", "--timeout-ms", "100"],
    ["ping", "--socket", p("s"), "--timeout-ms", "0"],
    ["ping", "--socket", p("s"), "--timeout-ms", "-5"],
    ["ping", "--socket", p("s"), "--timeout-ms", "1.5"],
    ["ping", "--socket", p("s"), "--timeout-ms", "abc"],
    ["ping", "--socket", p("s"), "--timeout-ms", "2147483648"],
  ]) {
    const r = await cli(args);
    assert.equal(r.code, 2, `${JSON.stringify(args)} exited ${r.code}`);
    assert.match(r.err, /usage:/);
  }
  assert.deepEqual(fs.readdirSync(t), [], "a usage error wrote files");
});

section("Key and config files: anything but a regular file is refused at once");

checkAsync("a directory or a socket as --pub ⇒ exit 1, \"not a regular file\", nothing printed", async () => {
  const f = bookWith(1);
  const dir = join(f.dir, "a-directory");
  mkdirSync(dir);
  const sock = join(f.dir, "s.sock");
  const server = createServer();
  await new Promise<void>((res) => server.listen(sock, () => res()));
  try {
    for (const path of [dir, sock]) {
      for (const args of [
        ["fingerprint", "--pub", path],
        ["verify", "--book", f.bookPath, "--pub", path],
      ]) {
        const r = await cli(args);
        assert.equal(r.code, 1, `${args.join(" ")}: ${r.out}`);
        assert.match(r.err, /cannot read public key .*: .* is not a regular file/);
        assert.equal(r.out, "");
      }
    }
  } finally {
    await new Promise<void>((res) => server.close(() => res()));
  }
});

checkAsync("a FIFO as --pub (fingerprint, verify, reconcile), as the private key or as --config (run) ⇒ exit 1 at once, never a hang", async () => {
  const f = bookWith(1);
  const fifo = join(f.dir, "fifo");
  const mk = spawnSync("mkfifo", ["-m", "0600", fifo]);
  assert.equal(mk.status, 0, `mkfifo failed: ${String(mk.stderr)}`);
  const log = join(f.dir, "log.jsonl");
  writeFileSync(log, "");
  const keyIsFifo = join(f.dir, "key-is-fifo.json");
  writeFileSync(
    keyIsFifo,
    JSON.stringify({ clerk_id: "x", private_key_path: fifo, book_path: "b2/book.jsonl", socket_path: "r2/s.sock" })
  );
  // Each in its own process: a hang would stop this one. Killed if still running at 45 s.
  const runs = [
    ["fingerprint", "--pub", fifo],
    ["verify", "--book", f.bookPath, "--pub", fifo],
    ["reconcile", "--book", f.bookPath, "--log", log, "--pub", fifo, "--submitter", "s", "--channel", "c"],
    ["run", "--config", keyIsFifo],
    ["run", "--config", fifo],
  ].map((args) => ({ args, run: spawnCli(args) }));
  const killers = runs.map(({ run }) => setTimeout(() => run.child.kill("SIGKILL"), 45_000));
  try {
    for (const { args, run } of runs) {
      const { code, signal } = await run.exited;
      assert.equal(signal, null, `${args.join(" ")}: hung on a FIFO and was killed`);
      assert.equal(code, 1, `${args.join(" ")}: exit ${code}; ${run.stderr.join("")}`);
      assert.match(run.stderr.join(""), /is not a regular file/, args.join(" "));
      assert.equal(run.stdout.join(""), "", args.join(" "));
    }
  } finally {
    for (const k of killers) clearTimeout(k);
    for (const { run } of runs) {
      if (run.child.exitCode === null && run.child.signalCode === null) run.child.kill("SIGKILL");
    }
  }
  assert.equal(existsSync(join(f.dir, "b2")), false, "run created a book although its key was refused");
}, 120_000);

section("verify");

checkAsync("verify exits 0 on a good book and says what it cannot show", async () => {
  const f = bookWith(3);
  const r = await cli(["verify", "--book", f.bookPath, "--pub", f.publicKeyPath]);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /book verifies: 3 receipt/);
  assert.match(r.out, /cannot show that no receipts are missing/);
});

checkAsync("verify exits 1 on any break, naming the receipt", async () => {
  const f = bookWith(3);
  const lines = readFileSync(f.bookPath, "utf8").trim().split("\n");
  const r1 = JSON.parse(lines[1]);
  r1.payload_commitment = "0".repeat(64);
  writeFileSync(f.bookPath, [lines[0], JSON.stringify(r1), lines[2]].join("\n") + "\n");
  const r = await cli(["verify", "--book", f.bookPath, "--pub", f.publicKeyPath]);
  assert.equal(r.code, 1);
  assert.match(r.err, /book does NOT verify: receipt 1: receipt_hash does not match/);
  assert.match(r.err, /1 receipt\(s\) verified before the break/);
});

checkAsync("verify exits 1 with the wrong public key, a missing book, or a private key as --pub", async () => {
  const f = bookWith(1);
  const other = makeClerkFixture();
  assert.equal((await cli(["verify", "--book", f.bookPath, "--pub", other.publicKeyPath])).code, 1);
  assert.equal((await cli(["verify", "--book", join(f.dir, "absent.jsonl"), "--pub", f.publicKeyPath])).code, 1);
  const r = await cli(["verify", "--book", f.bookPath, "--pub", f.privateKeyPath]);
  assert.equal(r.code, 1);
  assert.match(r.err, /holds a private key; give only the public key/);
  assert.doesNotMatch(r.out, /book verifies/);
});

section("ping");

checkAsync("ping exits 0 when clerkd answers, run in this process or as its own; a ping books nothing", async () => {
  const f = makeClerkFixture();
  const child = await startChildClerkd(f.configPath);
  try {
    const r = await cli(["ping", "--socket", f.socketPath]);
    assert.equal(r.code, 0, r.err);
    assert.match(
      r.out,
      /^clerkd answered on .*clerk\.sock in \d+ ms \(the probe was refused, as expected: submitter_id must be a non-empty string\)$/
    );
    const p = spawnCli(["ping", "--socket", f.socketPath, "--timeout-ms", "10000"]);
    const done = await p.exited;
    assert.equal(done.code, 0, p.stderr.join(""));
    assert.match(p.stdout.join(""), /clerkd answered on/);
    // Two pings, and the first real submission is still clerk_seq 0.
    const s = await new SocketClerkClient({ socketPath: f.socketPath }).submit({ submitter_id: "s", channel: "c", payload: {} });
    assert.equal(s.clerk_seq, 0);
  } finally {
    await child.stop("SIGTERM");
  }
}, 120_000);

checkAsync("ping exits 1 for a socket file nothing listens on (left by a killed process), a missing path and a regular file", async () => {
  const dir = tempDir();
  const stale = join(dir, "stale.sock");
  const holder = trackChild(
    spawn(
      process.execPath,
      ["-e", `require("net").createServer().listen(${JSON.stringify(stale)}, () => console.log("up"))`],
      { stdio: ["ignore", "pipe", "ignore"] }
    )
  );
  const exited = new Promise((res) => holder.once("exit", res));
  await new Promise<void>((res, rej) => {
    const t = setTimeout(() => rej(new Error("listener did not start")), 15_000);
    holder.stdout!.once("data", () => {
      clearTimeout(t);
      res();
    });
  });
  holder.kill("SIGKILL");
  await exited;
  assert.ok(statSync(stale).isSocket(), "precondition: the killed listener left its socket file");
  const plain = join(dir, "plain");
  writeFileSync(plain, "not a socket\n");
  for (const [path, re] of [
    [stale, /cannot reach the clerk at .*: connect ECONNREFUSED/],
    [join(dir, "absent.sock"), /cannot reach the clerk at .*: connect ENOENT/],
    [plain, /cannot reach the clerk at /],
  ] as const) {
    const r = await cli(["ping", "--socket", path, "--timeout-ms", "5000"]);
    assert.equal(r.code, 1, `${path}: ${r.out}`);
    assert.match(r.err, re);
    assert.equal(r.out, "");
  }
});

checkAsync("ping exits 1 for a listener that does not answer in time, answers something else, or hangs up", async () => {
  const dir = tempDir();
  const peers = new Set<Socket>();
  const listen = async (name: string, onConn: (s: Socket) => void): Promise<{ path: string; server: Server }> => {
    const path = join(dir, name);
    const server = createServer((s) => {
      peers.add(s);
      s.on("error", () => undefined);
      onConn(s);
    });
    await new Promise<void>((res) => server.listen(path, () => res()));
    return { path, server };
  };
  const silent = await listen("silent.sock", () => undefined);
  const garbage = await listen("garbage.sock", (s) => s.end("hello\n"));
  const shape = await listen("shape.sock", (s) => s.end('{"ok":true}\n'));
  const hangup = await listen("hangup.sock", (s) => s.once("data", () => s.destroy())); // reads the probe, then hangs up
  try {
    const t0 = Date.now();
    const r = await cli(["ping", "--socket", silent.path, "--timeout-ms", "300"]);
    assert.equal(r.code, 1, r.out);
    assert.match(r.err, /no answer from the clerk at .* within 300 ms/);
    assert.ok(Date.now() - t0 < 5000, "the timeout was not kept");
    for (const [peer, re] of [
      [garbage, /clerk answer is not JSON/],
      [shape, /clerk answer has an unknown shape/],
      [hangup, /closed the connection without answering/],
    ] as const) {
      const x = await cli(["ping", "--socket", peer.path, "--timeout-ms", "5000"]);
      assert.equal(x.code, 1, `${peer.path}: ${x.out}`);
      assert.match(x.err, re);
    }
  } finally {
    for (const s of peers) s.destroy();
    for (const l of [silent, garbage, shape, hangup]) l.server.close();
  }
});

section("run: refusals before listening");

checkAsync("run refuses a private key others can read (exit 1, reason given, no socket)", async () => {
  const f = makeClerkFixture();
  chmodSync(f.privateKeyPath, 0o644);
  const r = await cli(["run", "--config", f.configPath]);
  assert.equal(r.code, 1);
  assert.match(r.err, /mode 0644/);
  assert.equal(existsSync(f.socketPath), false);
});

checkAsync("run refuses a config with an unknown key or a missing field", async () => {
  const f = makeClerkFixture({ retain_paylod: true });
  const r = await cli(["run", "--config", f.configPath]);
  assert.equal(r.code, 1);
  assert.match(r.err, /unknown config key "retain_paylod"/);
  const g = makeClerkFixture();
  const cfg = JSON.parse(readFileSync(g.configPath, "utf8"));
  delete cfg.book_path;
  writeFileSync(g.configPath, JSON.stringify(cfg));
  const r2 = await cli(["run", "--config", g.configPath]);
  assert.equal(r2.code, 1);
  assert.match(r2.err, /"book_path" is required/);
});

checkAsync("run refuses a book that does not verify (fail closed, exit 1)", async () => {
  const f = bookWith(2);
  writeFileSync(f.bookPath, readFileSync(f.bookPath, "utf8").trim() + "\n{}\n");
  const r = await cli(["run", "--config", f.configPath]);
  assert.equal(r.code, 1);
  assert.match(r.err, /does not verify/);
  assert.equal(existsSync(f.socketPath), false);
});

section("run: as a child process");

checkAsync("SIGINT shuts clerkd down cleanly: exit 0, socket and lock removed", async () => {
  const f = makeClerkFixture({ retain_payload: true });
  const child = await startChildClerkd(f.configPath);
  try {
    const r = await new SocketClerkClient({ socketPath: f.socketPath }).submit({
      submitter_id: "s",
      channel: "c",
      payload: { hello: "world" },
    });
    assert.equal(r.payload_canonical, '{"hello":"world"}');
    const { code } = await child.stop("SIGINT");
    assert.equal(code, 0, child.stderr.join(""));
    assert.match(child.stdout.join(""), /SIGINT received, shutting down/);
    assert.match(child.stdout.join(""), /stopped \(book has 1 receipts\)/);
    assert.equal(existsSync(f.socketPath), false);
    assert.equal(existsSync(`${f.bookPath}.lock`), false);
  } finally {
    await child.stop("SIGKILL", 1000);
  }
}, 90_000);

checkAsync("the listening line names clerkd's own pid, and SIGTERM to that pid stops it cleanly", async () => {
  const f = makeClerkFixture();
  const child = await startChildClerkd(f.configPath);
  try {
    const m = /listening on .* \(pid (\d+), /.exec(child.stdout.join(""));
    assert.ok(m !== null, `no pid in: ${child.stdout.join("")}`);
    assert.equal(Number(m[1]), child.child.pid, "the reported pid is not the clerkd process");
    process.kill(Number(m[1]), "SIGTERM");
    const done = await Promise.race([
      child.exited,
      new Promise<null>((res) => setTimeout(() => res(null), 15_000).unref()),
    ]);
    assert.ok(done !== null, "clerkd still running 15 s after SIGTERM to its reported pid");
    assert.equal(done.code, 0, child.stderr.join(""));
    assert.match(child.stdout.join(""), /SIGTERM received, shutting down/);
    assert.equal(existsSync(f.socketPath), false);
    assert.equal(existsSync(`${f.bookPath}.lock`), false);
  } finally {
    await child.stop("SIGKILL", 1000);
  }
}, 90_000);

checkAsync("`verify` run as its own process exits non-zero on a broken book", async () => {
  const f = bookWith(2);
  writeFileSync(f.bookPath, readFileSync(f.bookPath, "utf8").trim()); // torn final newline
  const run = spawnCli(["verify", "--book", f.bookPath, "--pub", f.publicKeyPath]);
  const { code } = await run.exited;
  assert.equal(code, 1);
  assert.match(run.stderr.join(""), /last line has no newline/);
}, 60_000);

section("run: started through npm or npx");

/**
 * stdout and stderr are separate pipes: the listening line can arrive before
 * stderr written just ahead of it. Wait until `re` shows on stderr, or 1 s.
 */
async function stderrSettled(stderr: string[], re: RegExp): Promise<void> {
  const until = Date.now() + 1000;
  while (!re.test(stderr.join("")) && Date.now() < until) {
    await new Promise((res) => setTimeout(res, 25));
  }
}

/** The direct command the warning names, for a config at `config` (an absolute path without special characters). */
/** A command line with every token that names an existing path replaced by its real path. */
function resolvedTokens(command: string): string {
  return command
    .split(" ")
    .map((t) => (t.startsWith("/") && existsSync(t) ? realpathSync(t) : t))
    .join(" ");
}

function directCommand(config: string): string {
  return `${process.execPath} ${require.resolve("ts-node/dist/bin.js")} ${CLI_PATH} run --config ${config}`;
}

checkAsync("the launcher warning: only under npx (npm_command=exec) or an npm script (npm_lifecycle_event); every path in it absolute", async () => {
  assert.equal(launcherWarning({}, "c.json"), null);
  assert.equal(launcherWarning({ npm_command: "install" }, "c.json"), null);
  for (const env of [{ npm_command: "exec" }, { npm_lifecycle_event: "start" }, { npm_lifecycle_event: "" }]) {
    const w = launcherWarning(env, "my clerk.json");
    assert.ok(w !== null, `no warning for ${JSON.stringify(env)}`);
    assert.doesNotMatch(w, /\n/, "the warning is more than one line");
    assert.match(w, /signals sent to npx \(or npm\) may not reach clerkd/);
    // A relative config path is named as the file it meant here, quoted for the shell.
    const config = join(process.cwd(), "my clerk.json");
    assert.ok(w.endsWith(` run --config '${config}'`), w);
    assert.ok(w.includes(`Start it directly: ${directCommand("")}`.trimEnd()), w);
  }
});

checkAsync("run under npx warns once on stderr, naming the direct command with absolute paths; that command starts clerkd from any directory", async () => {
  const f = makeClerkFixture();
  // Started in the config's own directory with a relative --config.
  const child = await startChildClerkd("clerk.json", 45_000, { npm_command: "exec" }, f.dir);
  let direct: ChildProcess | null = null;
  try {
    await stderrSettled(child.stderr, /warning/);
    const warnings = child.stderr.join("").split("\n").filter((l) => l.includes("warning"));
    assert.equal(warnings.length, 1, child.stderr.join(""));
    const m = /Start it directly: (.*)$/.exec(warnings[0]);
    assert.ok(m !== null, warnings[0]);
    const command = m[1];
    // Compare resolved paths: node_modules may be reached through a symlink, and
    // the child may print the other spelling of the same file.
    assert.equal(resolvedTokens(command), resolvedTokens(directCommand(f.configPath)));
    assert.match(warnings[0], new RegExp(`\\(pid ${child.child.pid}\\)`));
    const r = await new SocketClerkClient({ socketPath: f.socketPath }).submit({ submitter_id: "s", channel: "c", payload: {} });
    assert.equal(r.clerk_seq, 0);
    const { code } = await child.stop("SIGTERM");
    assert.equal(code, 0, child.stderr.join(""));
    assert.match(child.stdout.join(""), /SIGTERM received, shutting down/);

    // The command exactly as printed, from a directory that is neither the
    // repository nor the config's: it starts the same clerk on the same book.
    const env: NodeJS.ProcessEnv = { ...process.env, TS_NODE_TRANSPILE_ONLY: "true" };
    delete env.npm_command;
    delete env.npm_lifecycle_event;
    direct = trackChild(
      spawn("/bin/sh", ["-c", `exec ${command}`], { cwd: tempDir(), env, stdio: ["ignore", "pipe", "pipe"] })
    );
    let out = "";
    let err = "";
    direct.stdout!.setEncoding("utf8").on("data", (s: string) => (out += s));
    direct.stderr!.setEncoding("utf8").on("data", (s: string) => (err += s));
    const directExit = new Promise<number | null>((res) => direct!.once("exit", (c) => res(c)));
    const until = Date.now() + 45_000;
    while (!out.includes("listening on") && direct.exitCode === null && Date.now() < until) {
      await new Promise((res) => setTimeout(res, 50));
    }
    assert.match(out, /listening on/, `the printed command did not start clerkd: ${err}`);
    const again = await new SocketClerkClient({ socketPath: f.socketPath }).submit({ submitter_id: "s", channel: "c", payload: {} });
    assert.equal(again.clerk_seq, 1);
    direct.kill("SIGTERM");
    assert.equal(await directExit, 0, err);
  } finally {
    await child.stop("SIGKILL", 1000);
    if (direct !== null && direct.exitCode === null && direct.signalCode === null) direct.kill("SIGKILL");
  }
}, 150_000);

checkAsync("run started directly with node prints no launcher warning", async () => {
  const f = makeClerkFixture();
  const child = await startChildClerkd(f.configPath);
  try {
    await stderrSettled(child.stderr, /warning/);
    assert.doesNotMatch(child.stderr.join(""), /warning/);
  } finally {
    await child.stop("SIGTERM");
  }
}, 90_000);

section("The working copy");

checkAsync("this test file left no new file or directory in the repository root", async () => {
  const added = fs.readdirSync(REPO_ROOT).filter((name) => !REPO_ENTRIES_BEFORE.includes(name));
  assert.deepEqual(added, [], `new in ${REPO_ROOT}: ${added.join(", ")}`);
});

runAll();
