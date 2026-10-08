# Installing ILAS: instructions for an AI coding agent

This guide is for an AI coding agent (Claude Code, Codex, or similar) installing
ILAS for a human. Follow it in order. Stop at every **HUMAN DECISION** and ask.
Do not choose for the human.

Read first: `docs/S4-WIRE-SPEC.md`, especially §2 (who runs what, and how it is
declared), §5 (the durable log) and §7.4 (known gaps). "S-4" is ILAS's name for
its anchoring layer: the clerk seam, the head commits, the witness receipts and
the continuity check. The spec explains what a witness and a clerk are and why
the status stays at `CANNOT_VERIFY_CONTINUITY` until a witness has retained a
head. That is the correct result in a fresh install, and only then.

## 0. Ground rules

- Do not choose who operates the witness or the clerk, and do not claim either
  is independent. Only the human decides that and declares it (spec §2).
- Do not use sudo or administrator rights, and do not work around a missing
  permission. Steps marked **ADMINISTRATOR** (creating accounts and groups,
  changing a file's owner or group, setgid directories, enabling a user's
  services at boot, system-wide service units) are for the human or their
  administrator: give them the commands and wait.
- Do not use the public test seeds for anything real: 32 bytes of `0x42` (the
  witness test key) and 32 bytes of `0x43` (the clerk test key), in
  `scripts/s4-test-vectors.ts` and `docs/s4-test-vectors.json`.
- Do not edit `docs/s4-test-vectors.json` to make a check pass. If a check
  fails, report it.
- Never edit, truncate or delete an L0 log file, a witness store, an outbox, an
  intake file or a clerk book, to make a check pass or for any other reason.
  Moving a log file aside, unchanged, is a human decision (step 9).
- Do not replace the null witness with a local file or a second directory on the
  same machine and call it a witness. A witness that runs under the node's own
  account is self-certification. It is allowed only when the human has chosen it
  and declares it `self-witnessed`.
- Clerk receipts are verified (gap G1 is closed): L0 commits an entry only if
  its receipt is signed by the configured clerk key, bound to that entry, names
  this node's `submitterId` and `channel`, and has not been used on the log
  before (spec §7.3). Describe them as authenticated only that far: the
  configured key signed them. Not which process held the key or who operates it
  (G1b), and not who submitted (G6).
- Keep private keys on a Linux file system. Both reference packages refuse a
  private key file that its group or other users can access, and they read that
  from the POSIX mode bits. On a drive mounted without POSIX permissions, such
  as `/mnt/c` under WSL with the default mount options, every file reads as mode
  0777 and `chmod 600` does not change it. Both `keygen` commands set the mode
  to 0600, read it back, and on such a drive remove the key again, say why on
  stderr and exit 1. They do the same where setting the mode is refused
  outright (for example a FAT or exFAT mount owned by another account) and
  where writing the key fails: no key file is left behind. Generate keys in a
  directory on a Linux file system.
- Give the node only **public** keys. ILAS refuses a private key where it
  expects the clerk's or the witness's public key, and says so.
- One process writes one log file. ILAS takes a writer lock (`<log path>.lock`)
  when it opens a durable log; a second process on the same log fails at start
  with `L0WriteError: the log <path> is in use by process <pid> …` (or `… in
  use by another thread of this process …`, when one program opens the log
  from two worker threads). If you see that while running the checks below,
  another node (perhaps the human's own application) is running on that log:
  do not remove the lock file, and do not run the checks against that log
  until the human has stopped it. A lock file ILAS cannot read as a lock
  (`L0WriteError: the writer lock <path>.lock names no process: it cannot be
  parsed as a writer lock …`) is refused the same way and never taken over:
  report it, and leave checking (`lsof <log>`, `fuser <log>`) and removing it
  to the human. A file named `.ilas-lock-<32 hex characters>` beside the log is
  a staged lock that a crash left before it was put in place; it is harmless
  (spec §5, One writer per file).
- Start the long-running daemons (`run` for the witness and the clerk) with
  `node node_modules/ts-node/dist/bin.js …`, as shown below, not with `npx`.
  Under `npx` a SIGTERM to the process you started can miss the daemon and
  leave it running (spec §7.5; `packages/witness/README.md`, Command line).
  A `run` started through npm or npx anyway prints one warning line on stderr
  at start, with its pid and the direct command, every path in it absolute
  (`<node> <repo>/node_modules/ts-node/dist/bin.js <repo>/packages/<clerk or
  witness>/src/cli.ts run --config <absolute config path>`), and keeps
  running: it never stops itself over how it was launched. If you see that
  warning, stop the daemon by signalling the pid it names, start it again with
  the command it printed (it works from any directory), and tell the human.
  `keygen`, `verify`, `fingerprint`, `reconcile` and `ping` may use `npx`.
- Name only regular files where a command asks for a key file, a config file
  or the witness's store (in a flag or in a config), or for the book that
  `verify` or `reconcile` reads. Anything else there (a FIFO, a directory, a
  socket) is refused at once, with exit 1 and `… is not a regular file`;
  nothing waits on a FIFO.

## 1. Requirements

- Node.js 18 or later, and npm.
- Git.
- For the reference clerk and witness: Linux (or WSL, working on its Linux file
  system). They need Unix domain sockets and POSIX file modes, and are tested on
  Linux with Node 22, not on Windows.
- The reference clerk and witness have no package of their own. They run from
  a copy of this repository, through `ts-node`, and use ILAS's canonical form
  by relative path; `npm run build` does not compile them. Every machine and
  account that runs one needs its own checkout of the same commit, with the
  `devDependencies` installed (`npm install`, not `npm install --omit=dev`).
  Step 6a covers that.
- The reference clerk works on one host only (a Unix socket): a clerk run by
  someone else runs under a separate account on the node's machine. The
  reference witness works through directories: a witness on another machine
  needs a directory both machines reach (shared or synced), which the deployer
  provides; this repository ships no transport between machines (spec gap
  G10).

Check: `node --version && npm --version && git --version`. Record the output.

## 2. Get the code and install

Ask the human for the repository URL, or for the copy of the repository they
want installed. Do not search for one or pick one yourself. Then:

```
git clone <the repository URL the human gave> ilas
cd ilas
npm install
```

Record the commit: `git rev-parse HEAD`.

ILAS has no runtime dependencies. `package.json` lists only the toolchain
(`typescript`, `ts-node`, `@types/node`) as `devDependencies`, and
`npm install` fetches those and what they depend on. Check:

```
npm ls --omit=dev
```

Expected: the package's own line followed by `└── (empty)`. Anything else
listed there is a finding; stop and report it.

## 3. Verify the build

```
npm run typecheck
echo "typecheck exit $?"
```

`npm run typecheck` type-checks `src/` and both packages. Judge it by its exit
code, which must be 0. npm prints its own `> ilas@… typecheck` header lines
either way; the TypeScript compiler adds nothing when it passes.

Then run every test file. `npm test` runs every `*.test.ts` file under `src/`
and `packages/`, each on its own, and exits non-zero if any fails, but it does
not print which file each summary line belongs to. So run the files one by one,
with their names:

```
rc=0
for f in $(npm run -s test:list); do
  echo "== $f"
  npx ts-node "$f" || rc=1
done
echo "all test files exit $rc"
```

Every file must print a summary line ending in `0 failed`, and the loop must
end with `all test files exit 0`. Record the number of files, and each file's
name with its summary line. Do not compare them with counts written anywhere
else: the suite grows. The whole run takes a few minutes; some files start
child processes and stop them again.

If anything fails, stop and report the output. Do not continue.

## 4. Verify the wire vectors reproduce

```
npx ts-node scripts/s4-test-vectors.ts
git diff --exit-code docs/s4-test-vectors.json
npx ts-node src/vectors.test.ts
npx ts-node packages/witness/src/vectors.test.ts
npx ts-node packages/clerk/src/vectors.test.ts
```

Expected: the second command exits 0 with no diff, and the three vectors tests
report `0 failed`.

If there is a diff, stop and report it. A diff means the code and the spec
disagree.

Note: `git diff` only compares tracked files. On a checkout where
`docs/s4-test-vectors.json` is not yet committed, that command cannot detect a
change. In that case, compare the file's md5 before and after the generator runs
and report the result.

## 5. Start with the null witness (default, always first)

Run the stack with no witness configured. A minimal check:

```
npx ts-node -e '
  import { ILASKillStack } from "./src/index";
  const s = new ILASKillStack();
  const r = s.verifyContinuity();
  console.log(JSON.stringify(s.status().continuity));
  console.log(JSON.stringify({ status: r.status, receiptsChecked: r.receiptsChecked, rejectedReceipts: r.rejectedReceipts }));
  console.log(JSON.stringify(s.status().declarations));
'
```

Expected output:

```
"CANNOT_VERIFY_CONTINUITY"
{"status":"CANNOT_VERIFY_CONTINUITY","receiptsChecked":0,"rejectedReceipts":0}
{"witness":null,"clerk":null,"verified":false,"warnings":[],"keys":{"clerk":null,"witness":null}}
```

That is the correct result. It means no independent witness is configured, not
that something is broken. `declarations` reports who runs the witness and the
clerk as the deployer declared it; nothing is declared yet, and `verified` is
always `false` because a declaration is a claim (spec §2.1). `warnings` lists
contradictions between the declarations and the configuration (none here), and
`keys` the fingerprints of the keys the node was given (none yet). Report it
as-is.

This check runs in memory only (no `logPath`), so it writes nothing.

## 6. HUMAN DECISION: the witness and the clerk

Ask the human all of these questions before you set anything up, and wait for
the answers.

The witness:

1. Will this node have a witness? If so, who operates it? Options:
   - the human themself, possibly under the same account as the node: declare
     **`self-witnessed`**;
   - a superior or a designated department, under a separate account or on a
     separate machine: declare **`independent-operator: <role>`**.
2. On which machine and account will the witness run, and who holds its
   private key?
3. If that is another machine: which directory, reachable from both machines
   (shared or synced), carries this node's intake and outbox, and who provides
   it? This repository ships no transport between machines (spec G10).

The clerk:

4. Will this node use a clerk route? If so, who operates the clerk? The human
   themself: declare **`self-operated`**. A superior or a designated
   department: declare **`independent-operator: <role>`**.
5. Under which account on this machine will the clerk run, and who holds its
   private key? (The reference clerk runs on the node's machine: it speaks over
   a Unix socket.)

The log:

6. Where does the node's durable log live (`logPath`, a file on a disk that
   survives restarts)? Is it a new file, or does a log file already exist
   there? An existing log begun without a clerk cannot be continued with one:
   enabling a clerk then means a new log file, and a witnessed node with a new
   log file needs a new witness submitter id (step 9).

**The safe order.** Set up everything the human chose **before** the node's
first start with a durable log, and start the node once, with everything in
place:

1. step 6a: install on each operator's machine and account;
2. step 6b: the witness side, if a witness is used;
3. step 6c: the clerk side, if a clerk is used, and leave clerkd running;
4. step 6d: hand over the public keys and confirm their fingerprints;
5. step 6e: the node's first start, with the witness and the clerk route the
   human chose, in one program.

Never start the node on its durable log first and add the clerk later on the
same log: that log then loads `CANNOT_VERIFY` (spec §7.3), the clerk books
receipts for entries that live only in memory (G7), and moving to a new log
leaves the witness holding a head the new log cannot reproduce, a `MISMATCH`
under that submitter id for as long as the witness's store exists.

### 6a. Install on each operator's machine and account

The witness and the clerk run from their own copy of this repository (step 1).
On each machine and account that will run one, and only when the human, acting
as that operator, asks you to work there:

```
git clone <the same repository URL> ilas
cd ilas
git checkout <the commit recorded in step 2>
git rev-parse HEAD
npm install
npm run typecheck
echo "typecheck exit $?"
for f in $(npm run -s test:list | grep '^packages/witness/'); do echo "== $f"; npx ts-node "$f"; done
for f in $(npm run -s test:list | grep '^packages/clerk/'); do echo "== $f"; npx ts-node "$f"; done
npx ts-node scripts/s4-test-vectors.ts
git diff --exit-code docs/s4-test-vectors.json
npx ts-node src/vectors.test.ts
```

Run only the loop for the package that operator runs. `git rev-parse HEAD`
must print the commit from step 2. Record the commit, the typecheck exit code
and every summary line. If the operator is someone else and does this
themself, record what they report, as theirs.

**ADMINISTRATOR.** A separate account for an operator, a group shared with the
node's account, and directories owned by one account and readable or writable
by another (the clerk's socket directory with mode 2750, the witness's intakes
and outboxes) need an administrator. `packages/clerk/README.md` §8 and
`packages/witness/README.md` (Deployment) describe the layouts. Give the human
the commands and wait; do not run them.

### 6b. The witness side (only if a witness is used)

**Keys.** Run `keygen` only on the machine and under the account the human
names as the witness operator's, and only when the human, acting as that
operator, asks you to. For an independent operator, the operator generates the
key and hands over only the public key (`witness.pub.pem`). Never ask for, copy
or move the private key.

The reference witness, `packages/witness/README.md`; run from the root of the
operator's copy of the repository, on the witness's machine and account:

```
npx ts-node packages/witness/src/cli.ts keygen --out <key dir>
```

This writes `<key dir>/witness.key` (mode 0600, read back after writing) and
`<key dir>/witness.pub.pem`, prints `public key fingerprint: sha256:<hex>`, and
refuses to overwrite either file. On a file system without POSIX permissions,
or where setting the mode or writing the key fails, it exits 1 and leaves no
key (step 0). The operator keeps that fingerprint line: step 6d compares it.

Config file. Relative paths resolve against the config file's directory. Give
every node its **own intake directory** and its own outbox:

```json
{
  "witnessSetId": "witness-set-a",
  "storePath": "store/witness-store.jsonl",
  "privateKeyPath": "keys/witness.key",
  "submitters": [
    { "id": "node-a", "outboxDir": "outbox/node-a", "intakeDir": "intake/node-a" }
  ],
  "pollIntervalMs": 1000
}
```

The witness creates no directories. Create each intake, each outbox and the
store's directory first, with the permissions the human chose
(`packages/witness/README.md`, Deployment). Never share an outbox, never use an
outbox as an intake (spec §4.1, gap G2), and never share an intake between
nodes: at the witness, a submitter is whoever can write its intake path (gap
G8). The witness refuses a config that shares or nests these directories. A
submitter id must be a plain file name: not empty, not `.` or `..`, no `/` or
`\`, no control character, no lone surrogate, not starting with `.`, and at
most 237 bytes in UTF-8. The witness's config and the node's client refuse
the same ids (spec §4.1). The node needs permission to create and rename files
in its intake directory (it writes a temporary file and renames it into
place), and to read its outbox. Each outbox should sit in a parent directory
no node can write. If the witness runs on another machine, the intake and the
outbox are in the directory the deployer provides (question 3); the paths in
the witness's config and in the node's program then differ, but must name the
same directories.

```
node node_modules/ts-node/dist/bin.js packages/witness/src/cli.ts run --config <config file> --once
node node_modules/ts-node/dist/bin.js packages/witness/src/cli.ts run --config <config file>
npx ts-node packages/witness/src/cli.ts verify --store <store path> --pub <key dir>/witness.pub.pem
npx ts-node packages/witness/src/cli.ts fingerprint --pub <a witness.pub.pem>
```

- `run --once` opens the witness, does one poll, and exits. Run it once now to
  check start-up: it prints `STARTED` (with `"storeCreated":true` the first
  time, and the key's `publicKeyFingerprint`) and exits 0. Without `--once` it
  polls until SIGINT or SIGTERM. Send the signal to the `pid` in its `STARTED`
  line.
- `run` prints one JSON object per line (`STARTED`, `RETAINED`, …). Exit 1 means
  it refused to start or halted. Report its stderr, which carries the reason in
  both cases, and on a halt also the last stdout line (`HALTED`).
- `verify` prints `OK: …` and exits 0, or prints `FAIL: …` and exits non-zero.
  It checks the store against the public key (links, hashes, record signatures,
  receipt signatures, conflict notes), not the outboxes; the outboxes are
  checked against the store each time `run` starts.
- `fingerprint` prints the public key's fingerprint, alone on one line, in the
  format `keygen` printed it, and exits 0; it exits 1 for a private key or a
  file it cannot read.

You do not need the witness running for the node's first start: the node drops
its head commit into the intake, and the witness picks it up at its next poll
(step 7).

### 6c. The clerk side (only if a clerk route is used)

**Keys.** The same rule as for the witness: run `keygen` only on the account
the human names as the clerk operator's, and only when the human, acting as
that operator, asks. For an independent operator, the operator generates the
key and hands over only `clerk.pub.pem`.

The reference clerk, `packages/clerk/README.md`; run from the root of the
operator's copy of the repository, under the clerk's account:

```
npx ts-node packages/clerk/src/cli.ts keygen --out <key dir>
```

This writes `<key dir>/clerk.key` (mode 0600, read back after writing) and
`<key dir>/clerk.pub.pem`, prints `public key fingerprint: sha256:<hex>` and
the public key, and refuses to overwrite either file. On a file system without
POSIX permissions, or where setting the mode or writing either file fails, it
exits 1 and leaves no key (step 0). The operator keeps the fingerprint line:
step 6d compares it.

Config file. Relative paths resolve against the config file's directory:

```json
{
  "clerk_id": "clerk-a",
  "private_key_path": "keys/clerk.key",
  "book_path": "book/receipts.jsonl",
  "socket_path": "run/clerk.sock",
  "socket_mode": "0600",
  "allowed_submitters": ["node-a"],
  "retain_payload": false
}
```

- The book's and the socket's directories are created with mode 0700 if they
  do not exist.
- With `socket_mode` `"0600"` only the clerk's own account can connect, so the
  node must run under that account. A clerk under a separate account needs
  `"0660"` and a socket directory set up as `packages/clerk/README.md` §8
  describes (ADMINISTRATOR).
- The socket path may be at most 107 bytes on Linux, and clerkd refuses to
  start, saying so, when it is longer. Keep the socket's directory short.
- `allowed_submitters` is a name check, not authentication (gap G6). Anyone
  who can connect to the socket can also hold its connections and stop the
  nodes' logs (gap G9); the socket's permissions decide who can.

```
node node_modules/ts-node/dist/bin.js packages/clerk/src/cli.ts run --config <config file>
npx ts-node packages/clerk/src/cli.ts verify --book <book path> --pub <key dir>/clerk.pub.pem
npx ts-node packages/clerk/src/cli.ts fingerprint --pub <a clerk.pub.pem>
npx ts-node packages/clerk/src/cli.ts reconcile --book <book path> --log <durable log path> --pub <key dir>/clerk.pub.pem --submitter <id> --channel <channel>
npx ts-node packages/clerk/src/cli.ts ping --socket <the clerk's socket_path>
```

- `run` prints `clerkd: listening on <socket> (pid <pid>, …)` and runs until
  SIGINT or SIGTERM; send the signal to that pid. It then removes its socket
  and lock and exits 0. It exits 1 without listening if the key, the config or
  the book is refused; report its stderr. On a first run it also says on stderr
  that the book is absent or empty.
- Start `run` now and leave it running while you work (a background job of
  your shell, or a second terminal), and record the pid from its `listening`
  line. Then run `ping`: it must exit 0. A node with a clerk route cannot start
  without a clerkd that answers: its first append fails with `L0ClerkError …
  cannot reach the clerk`. Step 8 decides how it keeps running after the
  install and stops this one.
- `ping` connects to the socket and sends clerkd one probe that clerkd always
  refuses, so nothing is booked. It exits 0 once clerkd answers, and prints
  `clerkd answered on <socket> in <n> ms (the probe was refused, as expected:
  <reason>)`. A clerkd that has stopped after a failed book write still
  answers, but refuses everything: `ping` then exits 4 and prints `… but it
  has STOPPED …` with the reason. Treat exit 4 as a failed check and report
  the reason. It
  exits 1 when nothing answers within `--timeout-ms` (default 5000): no file
  at the path, a socket file left behind by a clerkd that was killed
  (`ECONNREFUSED`), or something on the socket that does not answer as clerkd
  does. It exits 2 for a usage error (a `--timeout-ms` that is not a whole
  number from 1 to 2147483647, or a flag given twice).
- `verify` prints `book verifies: N receipt(s), …` and exits 0, or names the
  first broken receipt and exits 1.
- `fingerprint` prints the public key's fingerprint and exits 0; it exits 1
  for a private key or a file it cannot read.
- `reconcile` compares the book with the node's log (step 7). It reads the log
  as data and never takes the log's writer lock or changes the file. Besides
  the book, it checks every receipt on the log with ILAS's own receipt rules
  for that entry.

### 6d. Hand over the public keys, and confirm them

The node needs `witness.pub.pem` and `clerk.pub.pem`, nothing else. For each
one the node receives:

1. The operator reads out the fingerprint their `keygen` printed (or runs
   `fingerprint --pub` on their own copy of the public key), and tells it to
   the human **out of band**: in person, by phone, or over any channel other
   than the one that carried the file.
2. On the node, you print the fingerprint of the node's copy:

   ```
   npx ts-node packages/witness/src/cli.ts fingerprint --pub <the node's witness.pub.pem>
   npx ts-node packages/clerk/src/cli.ts fingerprint --pub <the node's clerk.pub.pem>
   ```

3. The human compares the two, character by character, and tells you whether
   they match. Record both values and the human's answer.

A mismatch, or a `fingerprint` that exits 1, is a finding: stop and report it.
Do not continue with that key.

### 6e. The node side, and its first start

Save this program as a `.ts` file at the root of the node's copy of the
repository (for example `ilas-node-check.ts`; do not commit it) and fill in
every `<…>`. Set `USE_WITNESS` and `USE_CLERK` to the human's answers. The
project compiles as CommonJS, so the code runs inside an async function. Run
it with `npx ts-node ilas-node-check.ts`. It is the node's start: run it the
first time only when steps 6a–6d are done, and with clerkd running when
`USE_CLERK` is `true`.

```ts
import { readFileSync } from "fs";
import { ILASKillStack } from "./src/index";
import { FileDropWitness } from "./src/s4";
import { SocketClerkClient } from "./packages/clerk/src/client";

// The human's answers from step 6: false for a part this node does not use.
const USE_WITNESS: boolean = true;
const USE_CLERK: boolean = true;

async function main(): Promise<void> {
  const witness = USE_WITNESS
    ? new FileDropWitness({
        id: "witness-set-a",                     // = witnessSetId
        intakeDir: "<this node's intake>",       // = this node's intakeDir in submitters
        outboxDir: "<this node's outbox>",       // = this node's outboxDir
        submitterId: "node-a",                   // = this node's id in submitters
        publicKeyPath: "<path to witness.pub.pem>",
      })
    : undefined;
  const stack = await ILASKillStack.create({
    logPath: "<durable log path>",               // absolute: a file on a disk that survives restarts
    witness,
    clerk: USE_CLERK
      ? {
          client: new SocketClerkClient({ socketPath: "<the clerk's socket_path>" }),
          submitterId: "node-a",                 // = a name in the clerk's allowed_submitters
          channel: "l0",
          clerkPublicKeyPem: readFileSync("<path to clerk.pub.pem>", "utf8"),
        }
      : undefined,
    declarations: {
      witness: USE_WITNESS ? "<the human's witness declaration>" : undefined,
      clerk: USE_CLERK ? "<the human's clerk declaration>" : undefined,
    },
  });
  stack.emitStartupCommit(); // the node's own code then calls stack.emitHeadCommit() on a cadence
  await stack.settleEvidence();

  const s = stack.status();
  const r = stack.verifyContinuity();
  console.log(JSON.stringify({
    loadState: s.logDurability.loadState,
    lastError: s.logDurability.lastError,
    brokenAt: s.logDurability.brokenAt,
    entriesLoaded: s.logDurability.entriesLoaded,
    receiptsUnchecked: s.logDurability.receiptsUnchecked,
    lockTakenOver: s.logDurability.lockTakenOver,
    headCommit: s.lastHeadCommit,
    continuity: r.status,
    receiptsChecked: r.receiptsChecked,
    mismatches: r.mismatches,
    rejectedReceipts: r.rejectedReceipts,
    rejectReasons: r.rejectReasons,
    fetchDiagnostics: witness?.getLastFetchDiagnostics() ?? null,
    submitDiagnostics: witness?.getSubmitDiagnostics() ?? null,
    declarations: s.declarations,
  }, null, 2));
  stack.close(); // stop writing and release the log's writer lock
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
```

**Why `logPath`.** The witness keeps the heads it retained, and the node must
recompute them from its own chain at every later start. Without `logPath`, L0
lives in memory: every start builds a new chain with new timestamps, so every
receipt retained before a restart reads `MISMATCH`. With `logPath` the chain is
reloaded and verified on every start (`loadState` `LOADED_VERIFIED`). Give it
as an absolute path: a relative one is resolved against the directory the
program was started in (once, when the stack is built), so starting the same
program from another directory would open another file.

What to expect on the first start, and to record:

- `loadState` `FIRST_BOOT_OR_ERASED` for a new log file (the file is created
  now), `lastError` `null`.
- `continuity` `CANNOT_VERIFY_CONTINUITY` with `receiptsChecked` 0: the witness
  has not polled yet. `headCommit` is the head this start sent to the witness;
  with a witness, `submitDiagnostics.written` is 1.
- `declarations.witness` and `declarations.clerk` must read exactly as the
  human declared them. An empty or whitespace-only declaration counts as none:
  it is reported as `null`, with a warning.
- `declarations.warnings` must be `[]`. A warning names a contradiction between
  the declarations and the configuration: a finding.
- `declarations.keys.witness` and `declarations.keys.clerk` must equal the
  fingerprints confirmed in step 6d. A `null` there, for a part that is used,
  means the node has no usable key for it: a finding.

Errors you may see:

- `submitterId` must follow the submitter id rule (step 6b, spec §4.1);
  otherwise the `FileDropWitness` constructor throws
  `submitterId <problem>, got <the id as JSON>`.
- `publicKeyPath` must be the witness's **public** key; a file holding a
  private key is refused (no receipt is returned, continuity stays
  `CANNOT_VERIFY_CONTINUITY`, `keys.witness` is `null`, and
  `fetchDiagnostics.dropReasons` says why).
- The clerk route is checked at construction: without a usable Ed25519
  **public** key, or with an empty `submitterId` or `channel`, the constructor
  throws `L0ClerkError` (spec §7.3). A private key is refused with a message
  saying to give the node only `clerk.pub.pem`.
- `L0ClerkError: clerk submission failed … cannot reach the clerk`: clerkd is
  not running, or the socket path differs. Start clerkd and run the program
  again; the file created by the failed start is empty and loads
  `FIRST_BOOT_OR_ERASED` again.
- `L0WriteError: the log <path> is in use by process <pid>`: another process
  runs on this log (step 0).

With a clerk route:

- Every receipt must verify under spec §7.3, name this route's `submitterId`
  and `channel`, and not already be on the log, or nothing commits.
- With `logPath`, every receipt in the log file is checked again at every
  start. **A log file begun without a clerk loads `CANNOT_VERIFY` when the
  clerk route is added**, and so does a log whose receipts were signed by
  another clerk key. Enabling a clerk on such a node, or changing its key,
  means a new log file and, if the node is witnessed, a new witness submitter
  (step 9). Tell the human why.
- After any clerk failure the log refuses every later append until the process
  is restarted (spec §7.6). Report the failure to the human.
- An entry larger than `SocketClerkClient` can deliver (1045414 bytes in
  canonical form, its `maxPayloadBytes`) is refused with `L0PayloadError`
  before it is submitted. That is not a clerk failure: only that entry is
  refused, nothing is booked, and the log goes on (spec §5). Report it.
- The clerk's book can hold receipts the node never committed (gap G7). Step 7
  checks for them with `reconcile`. Never edit the book or the log to make
  them agree.

## 7. Final check: prove the witness and the clerk work

1. **One witness poll** (with a witness). Run the witness once:

   ```
   node node_modules/ts-node/dist/bin.js packages/witness/src/cli.ts run --config <config file> --once
   ```

   If the witness already runs as a service, wait at least two
   `pollIntervalMs` instead, and read its output (`journalctl --user -u
   ilas-witness`, step 8, on the witness's account; for an independent
   operator, ask them). The output must contain a `RETAINED` line, or a
   `DUPLICATE` line, with `"submitterId"` equal to this node's id; for the
   first start, its `seq_no` and `head_hash` equal the `headCommit` the node
   printed. Record that line. No such line is a finding: the node wrote its
   commit somewhere the witness does not read (a wrong `intakeDir`, a different
   `submitterId`, a different witness set `id`), or the witness refused it
   (record its `UNDECLARED`, `NOT_A_FILE`, `REFUSED` or `MALFORMED` line).
   The node creates a missing intake directory itself, so a mistyped
   `intakeDir` shows only here.
2. **Restart the node.** Run the node program from step 6e again. Record the
   printed object.
   - `loadState` must be `LOADED_VERIFIED`, `lastError` `null`. `CANNOT_VERIFY`
     is a finding: record `brokenAt`, `lastError`, `entriesLoaded`, and the log
     file's size and SHA-256 (`ls -l <log>`, `sha256sum <log>`), and go to
     step 9 with the human. A `lastError` that starts `cannot read log file:`
     means the log path exists or may exist but could not be opened as a
     regular file (no permission on a directory above it, a symbolic link at
     the path, a FIFO); a `lastError` `torn final line at index <i>` means the
     file ends inside a line (spec §5). `line <i> is not stored as L0 writes
     it` means that line differs, byte for byte, from what L0 writes for the
     entry it holds (a repeated key, extra whitespace, another escape, a CRLF
     ending); `malformed JSON at line <i>` covers a blank line too. Either way
     someone or something other than L0 wrote that line. Nothing is ever cut
     off the file.
   - `receiptsUnchecked` must be 0. Above 0, with a clerk declared, the clerk
     route is missing from this start: a finding.
   - `lockTakenOver` `true` means an earlier process on this log ended without
     releasing its lock (a crash or a kill). Record it.
3. **Continuity**, from `verifyContinuity()` (`status().continuity` carries
   only the status):
   - **With a witness**, after step 7.1 retained or confirmed this node's head,
     the result must be **`VERIFIED_HISTORICAL` with `receiptsChecked` of at
     least 1** and `rejectedReceipts` 0. `CANNOT_VERIFY_CONTINUITY` at this
     point is **not** a correct result: the setup is broken and must be
     reported as broken. `fetchDiagnostics` usually says why:

     | `fetchDiagnostics` | Likely cause |
     |---|---|
     | `dropReasons` `outbox unreadable: … ENOENT` | `outboxDir` is not this node's outbox |
     | `dropReasons` `outbox unreadable: … EACCES` | the node's account cannot read the outbox |
     | `keyAvailable` `false`, `… holds a PRIVATE key` | `publicKeyPath` names the private key |
     | `keyAvailable` `false`, `cannot read witness public key: …` | `publicKeyPath` is missing, unreadable or not a regular file |
     | `found` 0, no reason | the receipt is not there: no `RETAINED` line in 7.1, or a `RECEIPT_PENDING` at the witness |

   - **Without a witness**, `CANNOT_VERIFY_CONTINUITY` with `receiptsChecked` 0
     is the correct result.
   - `MISMATCH`: record every entry of `mismatches` (`seq_no` and `reason`). A
     finding. After a new log file, a `MISMATCH` under the old submitter id is
     expected: step 9.
   - `REJECTED_RECEIPTS`: the client had a usable key and refused something in
     the outbox (a forged or corrupted receipt, a stray file, a symbolic link
     or special file, a file over 4096 bytes, or a `publicKeyPath` holding a
     different valid public key). Record `rejectedReceipts` and
     `rejectReasons`. A finding.
4. **Declarations.** `warnings` must still be `[]`, and `keys` must still equal
   the fingerprints confirmed in step 6d.
5. **The clerk** (with a clerk route). Run `verify` on the book, then reconcile
   the book with the node's log:

   ```
   npx ts-node packages/clerk/src/cli.ts reconcile --book <book path> --log <durable log path> --pub <clerk.pub.pem> --submitter <the route's submitterId> --channel <the route's channel>
   ```

   Expected: exit 0 and `no gaps: …`, with every log entry counted as carrying
   a clerk receipt. Exit 3 means gaps, in three lists: (a) booked receipts
   that no log entry carries (`clerk_seq`, `receipt_hash`); (b) log entries
   whose receipt passes ILAS's receipt rules but is not in the book; (c) log
   entries whose receipt fails ILAS's receipt rules for that entry and route:
   changed after it was signed, not signed by this key, not bound to that
   entry's content, naming another submitter or channel, or the same receipt
   as an earlier entry of that log. L0 itself refuses to load a log with an
   entry in (c) under this route. A booked receipt whose only entry is in (c)
   is listed under (a) as well. Record the lists; each is a finding that needs
   an explanation (spec §7.4, G7). Exit 1 is an error (a book that does not
   verify, a log with a torn or malformed line); record its message. Run it
   where both files can be read; for a clerk under a separate account, its
   operator runs it with a copy of the node's log file (copying the log is
   safe; never move or change the original). Repeat `--log` for log files
   moved aside earlier (step 9). `reconcile` reads a log more loosely than L0
   loads it (it skips blank lines, and does not require each line to be
   exactly as L0 writes it) and does not check its hash chain, so its exit 0
   does not replace the `loadState` check of step 7.2.
6. **The witness.** Run its `verify` on the store and record the output.

Any finding above goes to the human. Do not explain it away.

## 8. HUMAN DECISION: keep the witness and the clerk running

A daemon started from your shell stops when that shell, the session or the
machine stops. Then:

- **With a clerk route, the node's log stops.** A node whose clerkd is gone
  fails at its next append with `L0ClerkError` and refuses every later append
  until the node itself is restarted after clerkd is back (spec §7.6). A node
  on a new log cannot even start.
- **Without a running witness**, the node's commits are not retained, and
  continuity does not move past the receipts it already has.

Ask the human whether, and how, the witness and the clerk should start at boot.
The examples below are systemd **user** units, run by the operator's own
account. Fill in `<repo>` (the absolute path of that operator's copy of the
repository), `<node>` (the absolute path of `node`, from `command -v node`)
and the absolute config paths.

`~/.config/systemd/user/ilas-clerk.service`:

```ini
[Unit]
Description=ILAS reference clerk (clerkd)

[Service]
Type=simple
WorkingDirectory=<repo>
ExecStart=<node> <repo>/node_modules/ts-node/dist/bin.js <repo>/packages/clerk/src/cli.ts run --config <absolute path of the clerk config>
# Active only once clerkd answers on its socket, so a node ordered after this unit can submit.
# A socket file left behind by a clerkd that was killed does not count. Failed when clerkd exits first, or after 60 s.
ExecStartPost=/usr/bin/timeout 60 /bin/sh -c 'until TS_NODE_TRANSPILE_ONLY=1 <node> <repo>/node_modules/ts-node/dist/bin.js <repo>/packages/clerk/src/cli.ts ping --socket <absolute socket_path> --timeout-ms 2000; do [ -z "$$MAINPID" ] || kill -0 "$$MAINPID" || exit 1; sleep 0.2; done'

[Install]
WantedBy=default.target
```

`~/.config/systemd/user/ilas-witness.service`:

```ini
[Unit]
Description=ILAS reference witness

[Service]
Type=simple
WorkingDirectory=<repo>
ExecStart=<node> <repo>/node_modules/ts-node/dist/bin.js <repo>/packages/witness/src/cli.ts run --config <absolute path of the witness config>

[Install]
WantedBy=default.target
```

- Check each file after filling it in: `systemd-analyze --user verify
  ~/.config/systemd/user/ilas-clerk.service` prints nothing and exits 0 when
  the file is well formed and its program exists. These examples pass that
  check on systemd 255. This repository's tests do not run them as services;
  `src/docs.test.ts` runs the clerk unit's `ExecStartPost` script, as systemd
  would, against a socket file left by a killed clerkd and then a real one.
- The clerk unit counts as started only once clerkd **answers** on its socket:
  `ExecStartPost` runs `clerk ping` (step 6c) until it exits 0. A socket file
  that a killed clerkd left behind (after `SIGKILL`, an out-of-memory kill or
  a power loss) answers nothing, so it does not count; clerkd removes it
  itself when it starts. If clerkd exits before it answers (a refused key,
  config or book), the check stops after at most one more try and the unit
  fails, and `systemctl --user status ilas-clerk` shows clerkd's reason; after
  60 s without an answer it fails too. `$$MAINPID` is how a unit file writes the
  shell's `$MAINPID`, clerkd's pid, which systemd passes to the check.
  `TS_NODE_TRANSPILE_ONLY=1` starts each `ping` in about a second instead of
  several (the code was type-checked in step 6a). Each try that gets no
  answer leaves one `error: …` line in the journal (`error: cannot reach the
  clerk …` while nothing listens on the socket).
- They have no `Restart=` line on purpose: a clerk that refuses its book, or a
  witness that halted, stays stopped, and `systemctl --user status` shows why.
  Restarting it is a decision for its operator.
- `KillMode` stays at its default (`control-group`): `systemctl --user stop`
  signals every process of the unit, and both daemons shut down cleanly on
  SIGTERM.
- **Start the clerk before the node.** If the node's own program runs as a
  unit of the same user, give it `After=ilas-clerk.service` and
  `BindsTo=ilas-clerk.service`: it starts only once clerkd answers on its
  socket, and stops whenever the clerk stops. Otherwise start the node only
  after `systemctl --user is-active ilas-clerk` prints `active` (or `clerk
  ping --socket <socket_path>` exits 0). After any clerk
  outage, restart the node too (spec §7.6). A clerk under another account, or
  a node that runs as a system service, needs system units with `User=`
  (ADMINISTRATOR).
- **Surviving a reboot.** `systemctl --user enable --now ilas-clerk.service
  ilas-witness.service` starts them now and at every start of that user's
  service manager. They start at boot, before anyone logs in, only with
  lingering enabled for the account: `loginctl enable-linger <account>`
  (ADMINISTRATOR on many systems); `loginctl show-user <account> --property=Linger`
  then prints `Linger=yes`. Under WSL, systemd runs only with `[boot]
  systemd=true` in `/etc/wsl.conf` (ADMINISTRATOR), and the distribution
  itself starts only when something opens it.

**Before you enable the units, stop every daemon you started for testing**
(the clerkd from step 6c, any witness `run`): send SIGTERM to the pid from its
`listening` or `STARTED` line, and record how it ended (clerkd prints
`clerkd: stopped (book has N receipts)` and removes its socket; the witness
prints `STOPPED`). A second clerkd on the same book is refused (`book is in use
by process <pid>`). Then the human (or you, on the human's word, for units in
the human's own account) enables them. Record `systemctl --user status
ilas-clerk ilas-witness`, the `listening` / `STARTED` line from
`journalctl --user -u <unit>` and the output of `clerk ping --socket
<socket_path>`, and repeat step 7 once against the running services.

If the human chooses not to keep them running, the report says so plainly,
together with what it means: with a clerk route, the node's L0 refuses appends
whenever clerkd is not running.

## 9. HUMAN DECISION: a new log file (after `CANNOT_VERIFY`, or to enable a clerk)

A log that loads `CANNOT_VERIFY` loads that way on **every** start: a restart
does not clear it, and the node keeps running with its entries in memory only
(with a clerk route the clerk still books receipts for them, G7; and its head
commits describe a chain no later start can reproduce). Do not edit, truncate,
delete or "repair" the file; do not remove a torn last line. Record `brokenAt`,
`lastError`, `entriesLoaded`, and the file's size and SHA-256, and tell the
human. The way back, only on the human's word:

1. Stop every process that runs on that log (the writer lock must be released;
   after a crash the next start takes over the stale lock and reports
   `lockTakenOver`).
2. Keep the old file as evidence: move it aside, unchanged, for example
   `mv <log> <log>.cannot-verify-<date>`, or point `logPath` at a new file.
   Never delete it.
3. **With a witness, start a fresh witness submitter.** Add a submitter with a
   new id, and its own new intake and outbox, to the witness's config (keep the
   old entry, so its records stay declared and checkable with `verify`),
   create the two directories, and restart the witness. Give the node's
   `FileDropWitness` the new `submitterId`, `intakeDir` and `outboxDir`.
   Without this, every receipt the witness holds for the old id reads
   `MISMATCH` against the new log, permanently: the witness's store cannot be
   edited, and at every start it writes any of those receipts missing from
   the old outbox back into it.
4. With a clerk route, the same clerk and key can serve the new log; a new
   clerk key needs a new book as well. `reconcile` then lists the receipts of
   the memory-only entries as booked receipts on no log entry. Pass the old
   file with a second `--log` so that its receipts are matched; left out, they
   are listed there too. A log `reconcile` refuses (exit 1, a torn or
   malformed line) cannot be compared: leave it out, and its receipts show up
   in that list. Record them as the trace of what happened.
5. Run the node program (step 6e) on the new file: `FIRST_BOOT_OR_ERASED`
   once, then step 7 again: `LOADED_VERIFIED` and, with the witness,
   `VERIFIED_HISTORICAL` under the new submitter id.

The same steps apply when a log is replaced for any other reason: enabling a
clerk on a node whose log was begun without one, or changing the clerk key
(spec §7.3).

## 10. Report template

Fill in every field. Write `not run` where a step was skipped, and `none` where
a part is not used.

```
ILAS install report
- commit:               <git rev-parse HEAD>
- node / npm:           <versions>
- runtime deps:         <npm ls --omit=dev: (empty), or what it listed>
- typecheck:            <exit code>
- test files:           <number of files; each file's name and summary line; overall exit>
- vectors reproduce:    <yes / no, with diff or md5 summary>
- vectors tests:        <summary lines of the core, witness and clerk vectors tests>
- witness:              <none / self-witnessed / independent-operator: role>
- witness operator:     <machine, account, private-key holder, as the human stated them>
- witness install:      <commit, typecheck exit, package test and vectors summary lines on the witness's machine and account; or as the operator reported them>
- witness directories:  <intake and outbox paths; the shared or synced directory and who provides it, if the witness is on another machine>
- witness key:          <public key path on the node; fingerprint printed on the node; fingerprint the operator read out; match yes/no; confirmed by>
- clerk:                <none / self-operated / independent-operator: role>
- clerk operator:       <account on this machine, private-key holder, as the human stated them>
- clerk install:        <commit, typecheck exit, package test and vectors summary lines on the clerk's account; or as the operator reported them>
- clerk key:            <public key path on the node; fingerprint printed on the node; fingerprint the operator read out; match yes/no; confirmed by>
- declarations:         <status().declarations from the second run, verbatim, warnings and keys included>
- log file:             <logPath; new or continued>
- log load state:       <loadState on the first and on the second run; brokenAt, lastError, receiptsUnchecked, lockTakenOver where not null, 0 or false>
- witness poll:         <the RETAINED or DUPLICATE line for this node's submitter id, verbatim; or none>
- continuity:           <second run: status, receiptsChecked, mismatches, rejectedReceipts, rejectReasons, fetchDiagnostics>
- verify output:        <witness verify / clerk verify>
- clerk reconcile:      <exit code and its summary lines, with every entry of the three lists>
- clerk ping:           <the `clerkd answered on …` line against the running clerkd; or its exit code and error>
- daemons:              <how the clerk and the witness are kept running (units, enabled, linger) and by whom; systemctl --user status lines; or "not kept running", and what that means>
- test daemons stopped: <each pid started for testing, how it was stopped, its last line>
- new log files:        <old files moved aside (path, size, SHA-256), new submitter ids; or none>
- open items:           <G1b and G2–G10 from spec §7.4, and anything else>
```

Send the report to the human. Do not summarise it into a success message.
