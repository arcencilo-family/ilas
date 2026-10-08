# ILAS reference clerk

A clerk numbers, timestamps and signs every entry before ILAS's evidence log
(L0) commits it. This package is a reference implementation of the clerk side
of `docs/S4-WIRE-SPEC.md` §7, written from that spec. Besides ILAS's own wire
helpers (the canonical form in `src/l0/canonical.ts`, the key fingerprint in
`src/l0/fingerprint.ts`, L0's receipt check `verifyClerkReceipt` in
`src/l0/clerk-verify.ts`, which `reconcile` applies, and L0's types), its code
uses Node built-ins only:
no npm package. ILAS core never imports it (`src/fence.test.ts` enforces
that); your application code wires the two together through ILAS's
`ClerkRoute`.

**It runs from a copy of this repository.** The package has no `package.json`
of its own: it imports those ILAS modules by relative path, its command line
runs through `ts-node`, and `npm run build` compiles only ILAS's `src/`. So
the machine and account that run clerkd need a checkout of the same commit as
the node, with the `devDependencies` installed (`npm install`, not
`npm install --omit=dev`).

**It runs on the node's host.** clerkd speaks only over a Unix domain socket.
An operator other than the node's runs it under a separate account on the
same host (§8); a clerk on another machine needs a transport this package does
not have (spec gap G10).

What is in here:

| Part | File | What it does |
|---|---|---|
| core | `src/core.ts` | validates a request, signs a receipt, appends it to the book, returns it |
| book | `src/book.ts` | append-only JSONL file of receipts; verify-on-start; one writer at a time |
| daemon (clerkd) | `src/server.ts` | the core behind a Unix domain socket; connections served one request per turn, round-robin |
| clients | `src/client.ts` | `SocketClerkClient` and `InProcessClerkClient`, both ILAS `ClerkSubmitClient`s; `pingClerkd()`, behind the `ping` command |
| keys | `src/keys.ts` | Ed25519 key files: generate, load, refuse unsafe permissions and anything that is not a regular file |
| reconcile | `src/reconcile.ts` | compares the book with a node's L0 log files and checks every receipt on them with ILAS's receipt rules (spec gap G7); `reconcileBookAndLogs()` behind the `reconcile` command |
| CLI | `src/cli.ts` | `keygen`, `run`, `verify`, `fingerprint`, `reconcile`, `ping` |

Tested on Linux with Node 22. It needs Unix domain sockets and POSIX file
modes; it has not been tested on Windows.

---

## 1. What a receipt attests, and what it does not

A receipt says:

> "I received these payload bytes from a submitter presenting id X on channel
> C, at my time T, as number N in my book, and signed it."

Precisely:

- **these payload bytes**: the canonical form (`ILAS-CANON-JSON-1`, spec §7.2)
  of the payload as the clerk parsed it. `payload_commitment` is the SHA-256
  of those bytes. The clerk commits to the parsed value, not to the raw
  bytes on the wire: whitespace, key order, escapes and duplicate keys in the
  request line do not survive into the commitment (for a duplicate key, the
  last value wins, as in `JSON.parse`).
- **a submitter presenting id X on channel C**: `submitter_id` and `channel`,
  exactly as the request named them.
- **at my time T**: `clerk_time.wall_ms` (the clerk's wall clock) and
  `clerk_time.monotonic_ns` (`process.hrtime.bigint()`, meaningful only
  within one `clerk_boot_id`).
- **as number N in my book**: `clerk_seq`, counting from 0 and continuing
  across restarts. `prev_receipt_hash` names the receipt before it (64 zeros
  for the first), so the receipts form one chain.
- **and signed it**: Ed25519 over the canonical record, by the clerk's key.

A receipt does **not** show:

- **That the payload is true.** The clerk records what it was sent.
- **Who the submitter really is (spec gap G6).** `submitter_id` is a name the
  peer presents. The optional `allowed_submitters` list compares names; it is
  not authentication. Anyone who can connect to the socket can present any
  name on the list.
- **That the clerk is independent (spec gap G1b).** A valid signature shows
  that the configured key signed the receipt. It does not show which process
  held the key, who operates it, or that the key was not shared. Receipts
  from the daemon say `separation: "SEPARATE_PROCESS"` and `intake: "SOCKET"`.
  That describes how the clerk was started and how the request arrived; the
  daemon cannot see which process is on the other end of its socket.
- **That nothing is missing at the end of the book.** A book cut back to an
  earlier receipt still verifies. Only a party that kept a later receipt (the
  node keeps one in every log entry) can show the cut.
- **That the node committed the entry.** The clerk books a receipt before the
  node checks it. If the node then refuses it (for example because the node
  is configured with a different clerk key), or the answer is lost, or the
  node keeps the entry in memory only, the book holds a receipt the node never
  committed. Along the node's log this shows as a gap in `clerk_seq`, and
  `reconcile` (§6) lists it.
- **That the time is right (spec gap G5).** `clerk_time` is recorded, not
  checked against anything.

## 2. Receipt format

Every field of ILAS's `ClerkSubmissionReceipt`, plus three:

| Field | Value |
|---|---|
| `receipt_form` | `"ILAS-CLERK-RECEIPT-1"` |
| `kind` | `"SUBMISSION"` |
| `clerk_id` | from the config |
| `clerk_boot_id` | 32 random hex characters, new on every start |
| `clerk_principal` | OS user name of the clerk process (`uid:<n>` if it has none) |
| `separation` | `"SEPARATE_PROCESS"` (daemon) or `"IN_PROCESS_NO_SEPARATION"` |
| `separation_warning` | `null` (daemon), or a sentence saying the in-process clerk buys no separation |
| `intake` | `"SOCKET"` (daemon) or `"LOCAL_CALL"` (in-process) |
| `clerk_seq` | 0, 1, 2, ... across restarts |
| `clerk_time` | `{ wall_ms, monotonic_ns }`, `monotonic_ns` a decimal string |
| `prev_receipt_hash` | `receipt_hash` of the previous receipt; 64 zeros for the first |
| `submitter_id`, `channel` | as presented in the request |
| `declared_timestamp` | echoed from the request; `null` if it had none |
| `payload_commitment` | `sha256Hex(canonicalise(payload))` |
| `payload_retained` | `true` only with `retain_payload` in the config |
| `payload_canonical` | the canonical payload when retained, else `null` |
| `signature_alg` | `"ed25519"` |
| `receipt_hash` | `sha256Hex(preimage)` |
| `signature` | base64 Ed25519 over the UTF-8 bytes of `preimage` |

`preimage = canonicalise(receipt without receipt_hash and signature)`, using
ILAS's own `src/l0/canonical.ts`. Every field except `receipt_hash` and
`signature` is signed. ILAS's `verifyClerkReceipt` accepts these receipts
(tested), and this package's signer reproduces the published clerk test
vector byte for byte.

`signature` must be canonical base64: exactly the 88 characters Node writes
for the 64 bytes, `==` padding included. Node's decoder also accepts other
text for the same bytes (padding left off, characters appended, the unused
bits of the last character set); the verifier refuses all of it, so a
receipt's signature text cannot be changed without the key.

Wherever this package takes the clerk's public key (`verifyReceipt`,
`verifyBookFile`, `BookChecker`, `verify --pub`), a private key is refused
with a message to give only the public key. It is not quietly reduced to its
public half: a private key there means the signing key has left the clerk.

## 3. The JSON round trip

ILAS checks `payload_commitment` against the payload object it holds in
memory; the clerk computes it from the payload it parsed off the socket.
They agree only if `canonicalise(x) === canonicalise(JSON.parse(JSON.stringify(x)))`.

That holds for plain JSON data, including `-0` (written as `0` on both
sides), every finite number (JSON text round-trips doubles exactly), any
string including lone surrogates, and a key named `"__proto__"` (an own
property on both sides, or, from an object literal, on neither).

It fails for values JSON rewrites or drops. **`SocketClerkClient` refuses
these before connecting**, with `ClerkPayloadError`, so the clerk never books
a receipt ILAS would reject:

- `undefined` or missing array elements, `NaN`, `Infinity`, `bigint`,
  functions, symbols, a `toJSON` that returns `undefined`, nesting deeper
  than 64 levels (no canonical form);
- boxed primitives such as `new Number(5)`, and a `toJSON` whose result
  depends on its key argument (canonical form differs after JSON).

The check runs the exact request line through `JSON.parse` and compares
canonical forms. It runs when `submit()` is called.

The clerk itself never rebuilds the parsed payload; it canonicalises the
value `JSON.parse` returned, so an own `"__proto__"` key stays data.

## 4. The book

- One receipt per line, JSON, in `clerk_seq` order. Created with mode 0600.
- Appended with `O_APPEND`; `fsync` after every line. A receipt is returned
  only after its line is on disk. When the book file is new, its directory is
  fsynced too where the platform allows.
- Before appending, the clerk checks the line exactly as a later start will.
- If a write or fsync fails, the clerk stops: that request and every later
  one is refused until restart. The next start verifies whatever reached the
  disk.
- A lock file (`<book>.lock`) keeps two clerks off one book. It holds the
  clerk's pid and a random token drawn when the lock was taken. A lock whose
  process no longer exists is taken over. So is a lock naming the starting
  process's own pid that this process did not take: an earlier clerk with
  the same pid left it (a container whose clerk is pid 1 crashed and
  restarted). A lock naming any other live process is refused; if you are
  sure no clerk is running on the book (the pid may have been reused), remove
  the lock file by hand. A lock file that names no process (any other
  content) is refused with the same advice. The lock compares pids within
  one pid namespace, so it does not
  keep apart clerks in different containers or on different hosts that share
  one book file: give every clerk its own book.

`verify` and `reconcile` open the book without blocking and refuse anything
that is not a regular file (a FIFO, a directory): `cannot open book: <path> is
not a regular file`. clerkd's own start does not make that check by name (with
a FIFO at `book_path` it exits 1 with an `ESPIPE` error instead): put nothing
but the book file there. Key files and the config file get the same treatment
everywhere (§6).

**On start the whole book is verified**: every signature against the clerk's
own key, every `prev_receipt_hash` link, `clerk_seq` = line number, a
retained payload against its commitment, `monotonic_ns` never going back
within one boot, and no boot id reappearing after a later one. A torn last
line, an empty line, invalid UTF-8 or JSON, or any failed check, and **the
clerk refuses to run**. It never repairs a book. Use `verify` to see where it
breaks; what to do with a broken book is the operator's decision. Do not edit
it to make it pass.

An absent or empty book starts at `clerk_seq` 0, and the daemon says so on
stderr: that is either a first run or a removed book, and the code cannot
tell which.

The book belongs to one key. A new key needs a new book.

## 5. Config (`run --config <file>`)

```json
{
  "clerk_id": "clerk-a",
  "private_key_path": "keys/clerk.key",
  "book_path": "book/receipts.jsonl",
  "socket_path": "run/clerk.sock",
  "socket_mode": "0600",
  "allowed_submitters": ["ilas-node"],
  "retain_payload": false
}
```

| Key | Required | Meaning |
|---|---|---|
| `clerk_id` | yes | name signed into every receipt (at most 256 characters) |
| `private_key_path` | yes | the clerk's Ed25519 key (PKCS#8 PEM); refused unless only its owner can access it |
| `book_path` | yes | the receipt book; created with its directory (0700) if absent |
| `socket_path` | yes | the Unix socket; its directory is created with mode 0700 if absent |
| `socket_mode` | no | `"0600"` (default): only the clerk's account can connect. `"0660"`: the socket's group can too |
| `allowed_submitters` | no | list of accepted `submitter_id` names. A name check, not authentication (G6) |
| `retain_payload` | no | `true` keeps the canonical payload in every receipt and in the book. Default `false` |

Relative paths resolve against the config file's directory. Unknown keys are
refused.

The socket directory is checked on start. With `socket_mode` `"0600"` it must
give group and other users no access (for example 0700). With `"0660"` it
must give other users no access (for example 0750, with a group you chose).
A regular file at `socket_path` is never removed; a socket another process is
listening on is never taken over; a socket left by a dead process is removed.
clerkd binds a temporary name (a dot and 8 hex characters) in the socket's
directory and then links it to `socket_path`, so that stopping it removes
`socket_path` only while that is still its own socket, never one another
clerkd has put there since. The directory path therefore needs room for
that 9-byte name within the platform's socket path limit (107 bytes on
Linux); start is refused, with the reason, if it has none.

Limits: a request line is at most 1 MiB (1048576 bytes, without the
newline). A longer line is refused and the connection closed. A payload of
up to 1045414 bytes in canonical form always fits on one line, whatever
`submitter_id`, `channel` and `declared_timestamp` come with it: the rest
of a line is at most 3162 bytes (the arithmetic is at `MAX_PAYLOAD_BYTES`
in `src/wire.ts`, and in spec §7.5). A request line must also be complete
within 10 s of its first byte; a line still incomplete then is refused and
the connection closed (a peer that sends one byte at a time would otherwise
never count as idle). `submitter_id` and `channel` are
at most 256 characters. Idle connections close after 30 s. At most 64
connections are open at once.

Fairness: connections take turns. clerkd serves one request per turn,
round-robin over the connections that hold a complete request line, each turn
in its own pass of the event loop, so new data and new connections are read
between any two requests; a connection with more lines waiting goes to the
back of the queue after its turn. A peer that pipelines requests, even one
that reads every answer at once, gets one request served per round like
everyone else, and cannot keep clerkd from serving other submitters or from
accepting new connections.

Backpressure: each connection has at most one answer in flight. Once it has
sent a complete line, clerkd reads nothing more from that connection until
the line has had its turn and the answer has left the process, so a client
may pipeline requests but must read its answers to be served further. A peer
that never reads stops being served once the socket's buffers are full (about
300 receipts with Linux defaults) and is closed when idle for 30 s; a
connection whose unsent output passes `MAX_UNSENT_BYTES` (8 MiB, exported by
`src/server.ts`) is closed at once. A client that writes a large batch and
reads only after the whole write has completed can stall until the idle
timeout. `SocketClerkClient` sends one line and then reads, and is unaffected.

Half-close: a peer that ends its side of the connection right after its last
request still gets an answer to every complete line it sent before it ended,
in order; clerkd ends its own side only then. A last line without its newline
gets no answer.

What these limits do not stop: anyone who can connect can hold all 64
connections by sending a complete line (even an empty one) more often than
every 30 s. Submissions then fail to connect, and every ILAS node that
submits meanwhile stops its L0 until restarted (spec §7.6). The daemon
cannot tell who is connected, so it cannot limit connections per peer. With
`socket_mode` `"0600"` only the clerk's own account can do this; with
`"0660"`, every member of the socket's group can. A peer that reads slowly
can still hold its connection, but it can no longer make clerkd queue
answers in memory, and no peer, however fast it pipelines, can keep clerkd
busy for other submitters.

## 6. CLI

Run from the repository root (the TypeScript toolchain is in its
`node_modules`):

```
npx ts-node packages/clerk/src/cli.ts keygen --out <dir>
node node_modules/ts-node/dist/bin.js packages/clerk/src/cli.ts run --config <file>
npx ts-node packages/clerk/src/cli.ts verify --book <path> --pub <pem>
npx ts-node packages/clerk/src/cli.ts fingerprint --pub <pem>
npx ts-node packages/clerk/src/cli.ts reconcile --book <path> --log <l0.jsonl> [--log <l0.jsonl> ...] --pub <pem> --submitter <id> --channel <ch>
npx ts-node packages/clerk/src/cli.ts ping --socket <path> [--timeout-ms N]
```

Every key file (`--pub`, the config's `private_key_path`) and the config file
(`run --config`) is opened without blocking and refused at once, exit 1,
unless it is a regular file. A FIFO is never waited on; a FIFO, a directory
or a socket is reported on stderr as `error: cannot read public key <p>: <p>
is not a regular file`, `error: clerk private key <p> is not a regular file`
or `error: cannot read config <p>: <p> is not a regular file`. The private
key's type and mode are checked on the descriptor that is then read.

- `keygen` writes `clerk.key` (mode 0600) and `clerk.pub.pem` into `<dir>`
  (created 0700 if needed), and prints the private key's path, the public
  key's path, `public key fingerprint: sha256:<hex>` and the public key in
  PEM. It refuses to overwrite an existing key. It reads
  the key file's mode back after writing: on a filesystem that does not keep
  POSIX permissions (for example a Windows drive mounted in WSL, `/mnt/c`)
  the mode does not stay 0600, or setting it is refused (for example a FAT
  or exFAT mount owned by another account), and keygen removes the key
  again and exits 1 with the reason. Generate the key on a filesystem that
  keeps permissions. If writing either file fails, keygen removes what it
  wrote, so neither new file is left behind; it never removes a file it did
  not create.
- `run` starts clerkd and prints one `clerkd: listening on ...` line with
  clerkd's pid, the next `clerk_seq`, the boot id and the principal. SIGINT
  or SIGTERM closes it cleanly: it stops listening, removes its socket and
  lock, and exits 0. It exits 1 without listening if the key, config or book
  is refused.
- `verify` checks a book against a public key. Exit 0 if every receipt
  verifies; exit 1 on any break, naming the first broken receipt. `--pub`
  must be the public key; a private key file is refused (exit 1). A book path
  that is not a regular file (a FIFO, a directory) is refused (exit 1).
- `fingerprint` prints the fingerprint of a public key file, alone on one
  line: `sha256:` followed by the hex SHA-256 of the key's SPKI DER bytes, the
  format `keygen` printed and ILAS reports as `status().declarations.keys.clerk`
  (spec §2.1). Exit 0. Exit 1 for a private key (`holds a private key; give
  only the public key`), an unreadable file, a file that is not a regular
  file, a file that is not a PEM public key, or a key that is not Ed25519. The
  operator and the node's owner use it to confirm, out of band, that the node
  holds the operator's key.
- `reconcile` compares the book with one or more of a node's L0 log files, for
  one submitter and channel (spec gap G7). It verifies the book first: a book
  that does not verify is exit 1, and nothing is compared. It reads each log
  as plain JSON lines: it takes no writer lock, writes nothing, and does not
  check the log's hash chain (L0 does that when it loads the log), so it can
  run beside a live node. It reads lines more loosely than L0 loads them: it
  skips blank lines and does not require each line to be exactly as L0 writes
  it, so it can read a log that L0 refuses to load (spec §5). Every receipt on
  a log is checked with ILAS's own receipt rules for its entry:
  `verifyClerkReceipt` from ILAS core, with this key and the entry's six
  payload fields; a `submitter_id` and `channel` that name the reconciled
  route; and each receipt on at most one entry of a log (within one log file,
  as L0 checks; the same receipt in two `--log` files is not flagged). It
  prints three lists:
  - (a) `booked for submitter_id "X" on channel "Y", on no log entry: N`:
    receipts booked for that route that no log entry carries, as `clerk_seq N
    receipt_hash H`. An entry whose receipt is in (c) does not count as
    carrying it, so such a booking is listed here too.
  - (b) `log entries whose receipt is not among the book's receipts for …: N`:
    entries whose receipt passes ILAS's rules but is not in the book, as
    `<log> entry i (sequenceNumber n): clerk_seq c, receipt_hash H: not in
    the book`.
  - (c) `log entries whose receipt fails ILAS's receipt rules for that entry
    and … (L0 refuses such a log): N`, in the same form, with the reason:
    `submitter_id "…" does not name the reconciled submitter`; `channel "…"
    does not name the reconciled channel`; `the same receipt as entry <n> of
    this log; a receipt binds one entry`; `fails ILAS's receipt check:
    <reason>` (for example `payload_commitment does not match the submitted
    payload`, or `signature does not verify against the configured clerk
    key`); or `clerkReceipt is not a JSON object`.

  Entries without a receipt are counted (`N without (not compared)`), not
  compared. It does not apply L0's key-less shape checks (a
  `declared_timestamp` equal to the entry's `timestamp`; known `kind`,
  `separation` and `intake`); a receipt this clerk signed can fail those only
  when it was requested by something other than L0. Exit 0: no gaps (`no
  gaps: …`); 3: any of the three lists is not empty (`gaps: A booked
  receipt(s) on no log entry, B log entries whose receipt is not in the book,
  C log entries whose receipt fails ILAS's receipt rules …`); 1: an error (a
  book that does not verify, a log with a torn final line or a malformed
  line, a path that is not a regular file); 2: usage. `--log` may be given
  more than once, for a node whose earlier log files were moved aside: the
  receipts of a log passed that way are matched, and those of a log left out
  are listed under (a). Every listed receipt needs an explanation; spec §7.4
  (G7) lists the usual causes.
- `ping` tells whether clerkd is answering on a socket. It opens one
  connection and sends one probe line, `{}`, which clerkd always refuses, so
  nothing is booked. Exit 0 once a well-formed clerkd answer arrives within
  `--timeout-ms` (default 5000), printing `clerkd answered on <path> in N ms
  (the probe was refused, as expected: <reason>)`. A clerkd that has stopped
  after a failed book write answers too, refusing everything, and its reason
  shows there: `ping` then prints `… but it has STOPPED and refuses every
  request until restarted: clerk stopped: <reason>` and exits 4. Exit 1 when
  nothing listens on the path (a missing path; a
  socket file left by a clerkd that was killed: `ECONNREFUSED`), when no
  answer arrives in time, when the peer hangs up, or when the answer is not a
  clerkd response line: `error: cannot reach the clerk at <path>: …`, `error:
  no answer from the clerk at <path> within N ms`, and so on. Exit 2 when
  `--timeout-ms` is not a whole number from 1 to 2147483647. The example
  systemd unit in `docs/INSTALL-FOR-AGENTS.md` (step 8) runs it until it
  exits 0.

Each flag may be given once, except `reconcile`'s `--log`; a repeated flag
(`--pub is given more than once`), an unknown one, a missing required one, a
flag without its value, or an unknown command is a usage error: the reason
and the usage text on stderr, exit 2.

**Start `run` with `node`, not `npx`**, as shown above (or from a script
that `exec`s that command). `npx` runs its command under `sh -c`; where
`/bin/sh` is dash (Debian, Ubuntu), a SIGTERM sent to the npx process stops
npx and the shell but never reaches clerkd. clerkd then keeps running,
holding its socket and book lock and issuing receipts, and the next start is
refused with `book is in use by process <pid>`. Ctrl-C at a terminal still
works, because it signals the whole process group. If clerkd was started
some other way, signal the pid its `listening` line reports. Under systemd
with the default `KillMode=control-group`, stopping the unit signals every
process in it. `docs/INSTALL-FOR-AGENTS.md` (step 8) has an example systemd
user unit that keeps clerkd running across a reboot and counts it as started
only once `ping` gets an answer from it: a socket file left behind by a
clerkd that was killed does not count. Start clerkd before any node that uses
it: a node whose clerk is unreachable fails at its next append and stops its
L0 until the node itself is restarted (spec §7.6).

Started through npm or npx anyway (`npm_command` is `exec`, or
`npm_lifecycle_event` is set, as npm sets them for the command it runs),
`run` prints one warning line on stderr at start: signals sent to npx (or
npm) may not reach clerkd, its pid, and the direct command with every path in
it absolute, so it works as printed from any directory:

```
clerkd: warning: started through npm/npx; signals sent to npx (or npm) may not reach clerkd (pid 4242). Start it directly: /usr/bin/node /srv/ilas/node_modules/ts-node/dist/bin.js /srv/ilas/packages/clerk/src/cli.ts run --config /srv/clerk/clerk.json
```

The node binary is the one running clerkd (`process.execPath`), ts-node's
`bin.js` is the one `require.resolve` finds from `cli.ts` (or, failing that,
`<repo>/node_modules/ts-node/dist/bin.js`), and the config path is resolved
against the directory `run` was started in. Paths are quoted for the shell
where needed. clerkd then runs as usual: it does not stop itself over how it
was launched. A program started under npx passes those variables on to what
it starts, so a clerkd it starts directly warns too.

Exit codes: 0 success; 1 failure (a refused key, config or book, a book that
does not verify, a `ping` that gets no clerkd answer); 2 usage error; 3
`reconcile` found gaps; 4 `ping` reached a clerkd that has stopped. Setting `TS_NODE_TRANSPILE_ONLY=true` shortens
start-up; the tests start clerkd that way, with the same
`node .../ts-node/dist/bin.js` command.

Protocol, for other clients: newline-delimited JSON over the socket, one
response line per request line, in order.

```
request:  {"submitter_id": "...", "channel": "...", "declared_timestamp": 1700000000007, "payload": {...}}
response: {"ok": true, "receipt": {...}}   or   {"ok": false, "error": "..."}
```

## 7. Wiring it into ILAS

The node needs only the clerk's **public** key.

```ts
import { readFileSync } from "fs";
import { ILASKillStack } from "./src/index";
import { SocketClerkClient } from "./packages/clerk/src/client";

async function main(): Promise<void> {
  const stack = new ILASKillStack({
    logPath: "/var/lib/ilas/l0.jsonl",
    clerk: {
      client: new SocketClerkClient({ socketPath: "/run/ilas-clerk/clerk.sock" }),
      submitterId: "ilas-node",
      channel: "l0",
      clerkPublicKeyPem: readFileSync("/etc/ilas/clerk.pub.pem", "utf8"),
    },
    declarations: { clerk: "self-operated" }, // or "independent-operator: <role>"
  });
  await stack.ready(); // waits for the clerk receipts of the start-up entries
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
```

The project compiles as CommonJS, so `await` needs an enclosing `async`
function, as here. `ILASKillStack.create(options)` does the same in one
call. Every L0 append then goes through the clerk; nothing commits unless
the receipt verifies against `clerkPublicKeyPem` (spec §7.3), names the
route's `submitterId` and `channel`, and binds to the entry. If the clerk is
down or a receipt is refused, appends fail with `L0ClerkError` and L0 stops
(spec §7.6; ILAS's behaviour, not this package's).

`SocketClerkClient` sends one request per connection and keeps one request
in flight at a time, so a client's requests reach the clerk in the order
`submit()` was called. ILAS submits in append order; `clerk_seq` then rises
along the ILAS log. It waits 10 s by default for the connection and the
answer; `timeoutMs` must be more than 0 and at most 2147483647 (about 24.8
days, the longest delay a Node timer keeps), or the constructor throws.

`pingClerkd(socketPath, timeoutMs = DEFAULT_PING_TIMEOUT_MS)` (5000) is the
`ping` command as a function: it sends `PING_PROBE` (`{}`), which clerkd
refuses, and resolves with `{ ms, ok, error }` once a well-formed clerkd
answer arrives (`error` is the refusal's reason). It rejects with
`ClerkTransportError` when nothing answers, or answers something else, within
`timeoutMs` (more than 0 and at most 2147483647). A program can use it to
wait for clerkd before it builds a stack with a clerk route.

ILAS reports the fingerprint of the route's key as
`status().declarations.keys.clerk`; it must equal what `keygen` printed for
the clerk's key (or what `fingerprint --pub` prints for it). With a clerk
route but no clerk declaration, or a clerk declaration but no route,
`status().declarations.warnings` says so (spec §2.1).

`SocketClerkClient` declares `maxPayloadBytes` = 1045414, the largest
canonical payload that always fits on one request line (§5). ILAS reads it
when the log is built and refuses a larger entry with `L0PayloadError`
before submitting it: nothing is booked or committed, and L0 goes on. Without
it, the client would refuse the line after ILAS had submitted, and L0 would
stop. `InProcessClerkClient` declares no limit.

For development, or a single process that wants a book, `InProcessClerkClient`
runs the core inside the caller:

```ts
import { InProcessClerkClient, loadClerkPrivateKey } from "./packages/clerk/src";

const client = InProcessClerkClient.open({
  clerkId: "dev-clerk",
  privateKey: loadClerkPrivateKey("keys/clerk.key"),
  bookPath: "book/receipts.jsonl",
});
```

Its receipts say `IN_PROCESS_NO_SEPARATION`, `LOCAL_CALL`, and carry a
`separation_warning`: the caller shares memory with the signing key, so it
can sign anything the clerk can. It buys no separation.

## 8. Deployment

**Independence is the deployer's decision.** This code cannot check who runs
the clerk, on which machine, under which account, or who holds its key. ILAS
reports what you declare as a claim (`declarations` in `status()`, always
`verified: false`).

**Private, single-person deployment.** Running the clerk under the same
account as the node is allowed. Declare it: `declarations: { clerk:
"self-operated" }`. Be clear about what that gives you: the receipts record
what was submitted, in what order and when, and an edit of the book that is
not re-signed with the clerk's key is caught by the next start or `verify`.
But mode 0600 does not keep out the same account: the node's account can
read the clerk's key, re-sign, and rewrite the book. Such receipts cannot
stand against the operator.

**Enterprise deployment.** A superior or a designated department runs the
clerk under a separate account and holds the private key. The node's operator
receives only `clerk.pub.pem`, and confirms with the clerk's operator, out of
band, that its fingerprint matches (`fingerprint`, §6). Declare it, for
example `declarations: { clerk: "independent-operator: <role>" }`.

- Separate account, same host: run clerkd as the clerk's account, with the
  key and book owned by that account and mode 0600. Set `socket_mode` to
  `"0660"` and put the socket in a directory owned by the clerk's account
  whose group contains the node's account and nobody else who should submit.
  On Linux, give that directory mode 2750: the setgid bit makes the socket
  inherit the directory's group; without it the socket gets the clerk's own
  primary group. Creating the account and the group, and setting up that
  directory, needs an administrator. The tests here run under one account and
  do not exercise this setup.
- Separate host: not supported. This package only speaks over a Unix domain
  socket. A clerk on another host needs a transport you provide and secure
  (for example an SSH-forwarded Unix socket); none is included or tested
  (spec gap G10).
- The clerk's account runs clerkd from its own checkout of this repository,
  at the node's commit, with `npm install` done there (see the top of this
  README).

Generate the key where the clerk runs, as the clerk's operator. Never use
the public test seeds from `docs/s4-test-vectors.json` or
`scripts/s4-test-vectors.ts` for anything real.

**Installing with an AI coding agent.** An AI coding agent (Claude Code,
Codex, or similar) can help non-experts install ILAS and this clerk by
following `docs/INSTALL-FOR-AGENTS.md`. The agent must not choose the
operator for the human: who runs the clerk, and where its key is held, is the
human's decision, and the agent asks.

## 9. Tests

From the repository root:

```
npx tsc -p packages/clerk
npx ts-node packages/clerk/src/core.test.ts         # core, book, lock, keys, tamper, refusals
npx ts-node packages/clerk/src/wire.test.ts         # JSON round trip, payload size limit, socket protocol, line deadline, socket placement,
                                                    #   round-robin turns, a pipelining peer beside a normal one, half-close
npx ts-node packages/clerk/src/interop.test.ts      # ILAS L0 + ILASKillStack against clerkd as a child process
npx ts-node packages/clerk/src/l0-clerk-e2e.test.ts # L0 through clerkd end to end: reordered receipts, reload, refusals, payload size limit
npx ts-node packages/clerk/src/vectors.test.ts      # the clerk vectors in docs/s4-test-vectors.json
npx ts-node packages/clerk/src/cli.test.ts          # keygen, fingerprint, verify, ping, run, usage errors, FIFOs and other non-regular
                                                    #   files refused at once, signal handling, the npm/npx warning
npx ts-node packages/clerk/src/reconcile.test.ts    # reconcile against logs written by ILAS's L0: gaps, ILAS's receipt rules,
                                                    #   refusals, read-only beside a live node
npx ts-node packages/clerk/src/harness-signal.test.ts # a test stopped by a signal still kills its clerkd and removes its files
```

Keys are generated per run; files go to temporary directories that are
removed at the end, and child processes start in a temporary working
directory, never in the repository (`cli.test.ts` ends by checking that the
repository root gained no entry); child processes are killed when a test file exits, also
when the test process is stopped by SIGINT, SIGTERM or SIGHUP (it then exits
with 128 plus the signal's number; SIGKILL cannot be cleaned up after).
`src/harness-child.fixture.ts` is a fixture for that test, not a test. The
child clerkd in the tests runs under the same account as the test, which
shows the wire works across a process boundary and nothing about
independence.
