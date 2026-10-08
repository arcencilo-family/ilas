# ILAS reference witness

A standalone process that implements the **witness** side of the ILAS
wire (`docs/S4-WIRE-SPEC.md` §3–§4). It:

1. reads HEAD_COMMIT files that ILAS nodes drop into an intake directory (one
   shared by all nodes, or one per node);
2. keeps every commit it accepts in its **own** append-only, hash-chained store,
   each record signed with its Ed25519 key;
3. signs a WITNESS_RECEIPT for each retained commit with that key;
4. writes that receipt into the submitting node's **own** outbox directory.

On the node, ILAS core's `FileDropWitness` client reads the outbox, checks each
receipt's signature against the witness public key it was configured with, and
hands the verified receipts to `ContinuityVerifier`.

The package is written from the spec, not from the ILAS client: it has its own
receipt preimage and verifier (`src/receipt.ts`), and the tests check that the
two implementations agree, including against `docs/s4-test-vectors.json`. Its
runtime code uses Node built-ins only, no npm package, and imports two modules
from ILAS core: `src/l0/canonical.ts` (the canonical JSON form used to hash its
store records) and `src/l0/fingerprint.ts` (the key fingerprint it prints).
The tests use more of ILAS core, to check interoperation, and `readme.test.ts`
also uses the TypeScript compiler. ILAS core never imports this package;
`src/fence.test.ts` enforces that.

**It runs from a copy of this repository.** The package has no `package.json`
of its own: it imports those ILAS modules by relative path, its command line
runs through `ts-node`, and `npm run build` compiles only ILAS's `src/`. The
machine and account that run the witness need a checkout of the same commit
as the node, with the `devDependencies` installed (`npm install`, not
`npm install --omit=dev`).

## What a receipt says, and what it does not

A receipt from this witness says:

> **"I retained head H at sequence S at my time T for submitter X."**

Precisely: whoever holds this witness's private key appended a record with that
`seq_no` (S) and `head_hash` (H) to its store, at witness clock time
`witness_ts` (T), for the submitter whose outbox the receipt was written to (X).
X is not inside the signature (gap G2, below); it is given by *which outbox the
receipt is in*, which is why every submitter has its own.

"For submitter X" means: the commit was read from X's intake path,
`<intake directory>/X`. **At the witness, a submitter's identity is the intake
path it writes to. Nothing authenticates it.**

A receipt does **not** say:

- **that X sent the commit.** Whoever can write X's intake path can submit as
  X. With one shared intake, that is every node that can write the directory:
  another node can drop a commit under X's name, the witness retains and signs
  it for X, and X's own chain, untouched, then reads `MISMATCH` (a false alarm
  that stays as long as the witness's store does). Give each node **its own
  intake directory** that only that node's account can write (see
  Configuration and Deployment); the file permissions are what stop one node
  from writing as another.
- **that the node is honest.** The witness checks the *shape* of a commit, not
  the chain behind it. It retains whatever head it is sent.
- **that the witness is independent of the node.** That depends on who runs the
  witness, on which host and account, and who holds its key. Neither this code
  nor ILAS can see or check that. ILAS records it only as a declaration.
- **that the history is complete.** A node only witnesses the heads it submits.
  The ILAS client overwrites a single intake file per node, so a commit that is
  replaced before the witness reads it is never seen (the later head covers a
  longer prefix of the chain). And a witness operator can delete the store (G3).
- **anything about time** beyond the witness's own clock (spec gap G5).

## How a poll works

Each poll lists every intake directory (the shared one, if configured, and each
submitter's own) and handles every entry. Rows are matched top to bottom; the
first that fits applies.

| Situation | What the witness does | Event |
|---|---|---|
| Name starts with `.` | Ignores it without a word: the ILAS client's temporary files | none |
| Name is not a submitter declared for this directory (in the shared intake, the name of a submitter that has its own intake counts as not declared) | Leaves it alone (never reads, moves or deletes it) | `UNDECLARED` |
| Declared name, but a directory, symlink, FIFO, … | Does not follow or read it | `NOT_A_FILE` |
| Declared file larger than 4096 bytes | Does not read it | `REFUSED` |
| Not valid JSON | Leaves it; reads it again next poll (it may be half-written) | `DEFERRED` |
| Still not valid JSON, byte-identical to the last poll | Leaves it | `MALFORMED` |
| Valid JSON, but not an acceptable HEAD_COMMIT | Does not retain or sign it; leaves it | `REFUSED` |
| This submitter's head (`seq_no`, `head_hash`) already retained, at any earlier point | No new record, no new receipt; consumes the file | `DUPLICATE` |
| Anything else | Retains, signs, writes the receipt, consumes the file | `RETAINED` |

`UNDECLARED`, `NOT_A_FILE`, `MALFORMED` and `REFUSED` describe a file that is
left sitting there; each is reported once, and again only if the file changes,
not on every poll. A `DUPLICATE` file is consumed.

**Acceptable HEAD_COMMIT.** Exactly the four keys `seq_no`, `head_hash`, `ts`,
`witness_set_id`; `seq_no` a safe integer ≥ −1; `head_hash` 64 lowercase hex
characters; `ts` a finite number; `witness_set_id` equal to this witness's
configured `witnessSetId`. A commit addressed to another witness set is not
signed. One consistency rule from spec §3: `seq_no` −1 (empty chain) must carry
the genesis hash (64 zeros), and the genesis hash is valid only at −1.

**Temporary files and half-written files.** The ILAS client writes each commit
to `.<submitterId>.<12 random hex>.tmp` in the intake (created exclusively,
synced), then renames it onto `<submitterId>`. The witness skips dot names, so
it never sees a commit from that client half-written. Another writer may write
in place; a file that does not parse is never signed, and is reported
`MALFORMED` only if the same bytes are still there on the next poll.

**What counts as a duplicate.** Same submitter, same `seq_no`, same
`head_hash`, retained at any earlier point. The node's own `ts` is not part of
what a receipt attests, so a cadence re-emit of an unchanged head produces no
second receipt.

**Rewrites, and rollbacks to a new head, are retained, never dropped.**

- Same submitter, same `seq_no`, **different** `head_hash`: retained and signed.
  The record carries a `SAME_SEQ_DIFFERENT_HEAD` note pointing at the earlier
  record. The node now holds receipts for two different heads at one sequence,
  so ILAS's continuity check reports `MISMATCH` for whichever one its live
  chain does not reproduce.
- A `seq_no` **lower** than one already retained for that submitter, with a
  head **not retained before**: retained and signed, with a
  `SEQ_LOWER_THAN_RETAINED` note.
- A rollback to a head the witness **already retained** (the node goes back
  to exactly an earlier `seq_no` and `head_hash`) is a `DUPLICATE`: the store
  never holds one head twice for a submitter, so no new record and no note are
  written, and the witness's store does not show when the node went back. The
  rollback is still evidenced: the node holds the receipts for the higher
  heads the witness retained after that one, and its rolled-back chain cannot
  reproduce them, so ILAS's continuity check reports `MISMATCH`.

**Order of operations for a retained commit.**

1. Sign the receipt fields.
2. Hash the record and sign it whole (`record_sig`, see Store format), then
   append it to the store (`O_APPEND`, `fsync`). Before writing, the witness
   checks that the store is still exactly the size it last left it; afterwards,
   that it grew by exactly one line.
3. Only then write the receipt: into a new file
   `<outbox>/.staging/<receipt name>.<12 random hex>.tmp` (created exclusively,
   never through a symlink), `fsync`, rename into the outbox, `fsync` the
   outbox directory where the platform allows it. The ILAS client skips
   directories, so it never sees a partial receipt. `.staging` is created with
   mode 0700 and used only if it is a real directory: a symlink or anything
   else in its place is not followed, and the receipt stays pending
   (`RECEIPT_PENDING`) until it is removed.
4. Re-read the intake file and delete it **only if its bytes are unchanged**.
   If the node has written a newer commit meanwhile, that file is left for the
   next poll (`INTAKE_LEFT`).

**The remaining race.** Between the re-read in step 4 and the delete there is a
short window. A commit the node writes in exactly that window is deleted
unprocessed. The node emits again on its cadence, so the next commit replaces
it; the loss is a gap in the evidence, not a wrong receipt.

**Receipt names.** `receipt-<store index, 12 digits>.json`. They sort in the
order the store retained them. The index counts across all submitters, so one
submitter's outbox has gaps in the numbering; the order is still the store's.

**When writing fails.**

- Receipt write fails after the record was retained: `RECEIPT_PENDING`; the
  write is retried on every poll (`RECEIPT_WRITTEN` when it succeeds). The
  intake file is consumed, because the commit is already retained. Something
  already standing at the receipt's name is never overwritten: other bytes, or
  anything that is not a regular file (a symlink, even to the right bytes, a
  FIFO, a directory). It is never followed or blocked on either: every outbox
  and intake entry is opened once, `O_NOFOLLOW|O_NONBLOCK`, and judged on that
  descriptor.
- Store append fails, the clock returns something other than a non-negative
  integer, or something else changed the store: the witness **halts**. `run`
  writes `HALTED` (with the reason in `detail`) to stdout, writes the same
  reason to stderr, and exits 1. The commit stays in the intake. A halted
  witness stays halted: every further poll is refused, even once the cause has
  gone. On the next start the store is verified again before anything else
  happens.

## Start-up checks (fail closed)

`run` refuses to start, exits 1 and explains why on stderr, if:

- the config is invalid (see below), or its file is not a regular file;
- the private key file is missing, unreadable, not a regular file (a FIFO
  there is refused at once, never waited on), not Ed25519, or **accessible to
  its group or to others** (the message gives the mode and the `chmod 600` fix);
- an intake directory (the shared one, or a submitter's own), an outbox
  directory, or the store's directory does not exist. The witness creates no
  directories of its own: who may read and write them is a deployment decision;
- **the store does not verify**: a line that is not the exact serialisation of
  its record, a broken link, a wrong hash, a record without its `record_sig` or
  with one not made by the configured key over that record, a receipt signature
  not made by that key, a head repeated for one submitter, a conflict note that
  differs from what the earlier records imply, a commit for another witness
  set, or a last line without its newline (an interrupted append). Use `verify`
  to inspect it;
- **an outbox disagrees with the store**: it holds a receipt for a record the
  store does not have (the store was truncated, replaced or removed — a store
  truncated to a clean prefix still verifies on its own, so this is where that
  shows), a receipt that differs from the store, or one that belongs to another
  submitter;
- **an outbox entry with a receipt's name cannot be read as a receipt**
  (`OUTBOX_UNREADABLE`): a symlink (even one pointing at the right bytes), a
  FIFO, a directory, or a file larger than any receipt. It is not followed, not
  blocked on, and not replaced;
- a receipt missing from an outbox cannot be restored (`OUTBOX_UNWRITABLE`),
  for example because `.staging` is a symlink.

On a successful start, receipts missing from an outbox are rebuilt from the
store (Ed25519 signatures are deterministic, so they are the same bytes). The
outbox is a copy of the store's receipts: receipts removed from it come back on
the next start. Files in an outbox that are not this witness's receipts are
reported (`FOREIGN_OUTBOX_FILE`) and left alone; so is a `.staging` that is not
a real directory. Leftover staging files (`receipt-<12 digits>.json.<hex>.tmp`)
are removed from a real `.staging` directory. If no store exists, an empty one
is created and `STARTED` reports `"storeCreated": true`.

**One store, one key, one witness set.** To change the key or the set id, start
a new store with new outboxes. The old store stays checkable with `verify` and
the old public key.

## Store format

JSON Lines, one record per retained commit, keys in this order (the example was
made with the public test seed from the vectors; never use that key for real):

```json
{"index":0,"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","submitter_id":"node-a","commit":{"seq_no":3,"head_hash":"9da9efa8574d56d89680217063fc4732374b9a5a6032caeaa7367a62a3b49cc8","ts":1700000000007,"witness_set_id":"witness-set-a"},"witness_ts":1700000000123,"witness_sig":"/ZxFjBXZZNtnRXCDCjIbXaiYBPXDC9STDS7SBXEXfwJ7wg90NoNWbr9InAzPd/LCzPPie4V1ckyX88jhNU/KDg==","conflicts":[],"hash":"dd52d9bbe5beb0e5c1a09d6a601b8967b8d2f3ccdedf400d0841dcb11cf840fc","record_sig":"wbUE8KbMf2CgH2Ck2SE7ugbZMtC6dzxRH6EhclvlEpKszDDfD2tAJBv1Mm+pKj4XPjObcy6DPI5sHqxcTsSNCQ=="}
```

| Field | Meaning |
|---|---|
| `index` | Position in the store, from 0 |
| `prev_hash` | `hash` of the previous record; 64 zeros for index 0 |
| `submitter_id` | The submitter the commit was attributed to: the declared name of the intake path it was read from. Not authenticated (see "What a receipt says") |
| `commit` | The HEAD_COMMIT exactly as accepted |
| `witness_ts` | Witness clock when the commit was retained, ms |
| `witness_sig` | The receipt signature (base64 Ed25519 over `"<seq_no> <head_hash> <witness_ts>"`) |
| `conflicts` | `SAME_SEQ_DIFFERENT_HEAD` / `SEQ_LOWER_THAN_RETAINED` notes, each naming an earlier record |
| `hash` | SHA-256 (hex) of the canonical JSON (`ILAS-CANON-JSON-1`, spec §7.2) of all the fields above |
| `record_sig` | base64 Ed25519 signature by the witness key over `"ILAS-WITNESS-STORE-RECORD-1\n<hash>"` |

**What `record_sig` protects.** `witness_sig` covers only the three receipt
fields. `record_sig` covers the record's `hash`, which covers every other field,
including `prev_hash`; so each signature vouches for its record whole and for
the store up to it. Without the key, nobody can change a field, re-attribute a
record to another submitter, renumber, reorder, remove a record from the middle
or replay one, even with every hash recomputed: start-up and `verify` refuse
such a store. A store **cut back to a clean prefix** still verifies, because
each remaining record is genuine; the outbox check at start-up notices that while
an outbox still holds the later receipts (G3). The record preimage starts with
a letter and a receipt preimage with a number, so neither signature can pass for
the other. Anyone holding the key can, of course, write any store.

The receipt written for that record is:

```json
{"seq_no":3,"head_hash":"9da9efa8574d56d89680217063fc4732374b9a5a6032caeaa7367a62a3b49cc8","witness_ts":1700000000123,"witness_sig":"/ZxFjBXZZNtnRXCDCjIbXaiYBPXDC9STDS7SBXEXfwJ7wg90NoNWbr9InAzPd/LCzPPie4V1ckyX88jhNU/KDg=="}
```

which is `receipt_valid` from `docs/s4-test-vectors.json`, byte for byte.

## Configuration

```json
{
  "witnessSetId": "witness-set-a",
  "storePath": "/srv/witness/store/witness-store.jsonl",
  "privateKeyPath": "/srv/witness/keys/witness.key",
  "submitters": [
    { "id": "node-a", "outboxDir": "/srv/witness/outbox/node-a", "intakeDir": "/srv/witness/intake/node-a" },
    { "id": "node-b", "outboxDir": "/srv/witness/outbox/node-b", "intakeDir": "/srv/witness/intake/node-b" }
  ],
  "pollIntervalMs": 1000
}
```

That is the layout to use when more than one node submits: every node has its
own intake directory. The older shape, one shared `intakeDir` at the top level
and no `intakeDir` per submitter, still works, and is fine for a single node;
with several nodes it lets any of them submit as any other (see "What a receipt
says"). The two can be mixed.

| Key | Required | Meaning |
|---|---|---|
| `witnessSetId` | yes | The set id this witness serves. Commits with any other `witness_set_id` are refused. Must equal the node's `FileDropWitness` `id`. |
| `intakeDir` | unless every submitter has its own | The shared intake, for submitters without an `intakeDir` of their own. Each node writes one file named by its submitter id. If set while every submitter has its own, it is still watched, and anything dropped there is reported `UNDECLARED`. |
| `storePath` | yes | The store file. Its directory must exist; the file is created on first start. |
| `privateKeyPath` | yes | Ed25519 private key (PEM, as `keygen` writes it), mode 0600 or stricter. There is no default. |
| `submitters` | yes | Non-empty list of `{ "id", "outboxDir" }`, plus optionally `"intakeDir"`: that submitter's own intake. Its commit is then read only from `<its intakeDir>/<id>`, never from the shared intake. No other keys. |
| `pollIntervalMs` | no | 10 to 3 600 000; default 1000. |

Relative paths are resolved against the directory of the config file.

The config is refused if:

- it has an unknown key, a required key is missing, or a submitter without its
  own `intakeDir` has no shared `intakeDir` to use;
- a submitter id is one the node's client would refuse: empty, `.`, `..`,
  containing `/`, `\` or a control character (U+0000–U+001F, U+007F–U+009F,
  NUL among them), not well-formed Unicode (a lone surrogate), starting with
  `.` (dot names in an intake are temporary files the witness ignores), or
  longer than 237 bytes in UTF-8 (the client first writes
  `.<id>.<12 hex>.tmp`, which must fit a 255-byte file name); or an id is
  declared twice. The rule is `submitterIdProblem()`. Store records keep the
  older, looser rule (`bareNameProblem()`), so a store written before still
  verifies; its records for ids no longer declarable count as records for
  undeclared submitters;
- **two submitters share an outbox, an outbox is an intake directory, two
  submitters' own intakes are one directory, or a submitter's own intake is
  the shared one**, or any two of these directories are nested inside each
  other (compared after resolving symlinks);
- the store or the private key lies inside an intake or an outbox (the node can
  reach those directories), or the store and the key are the same file;
- `pollIntervalMs` is out of range.

## Command line

Run from the repository root:

```sh
npx ts-node packages/witness/src/cli.ts keygen --out <dir>
node node_modules/ts-node/dist/bin.js packages/witness/src/cli.ts run --config <file> [--once]
npx ts-node packages/witness/src/cli.ts verify --store <path> --pub <pem>
npx ts-node packages/witness/src/cli.ts fingerprint --pub <pem>
```

- **`keygen --out <dir>`** writes `<dir>/witness.key` (private) and
  `<dir>/witness.pub.pem` (public), and prints the public key's fingerprint as
  `public key fingerprint: sha256:<hex>`: `sha256:` followed by the hex SHA-256
  of the key's SPKI DER bytes, the same line the clerk's `keygen` prints and
  the format ILAS reports as `status().declarations.keys.witness` (the package
  exports it as `publicKeyFingerprint(key)`). It refuses
  to overwrite either file. It sets the
  private key's mode to 0600 and reads it back: on a file system that does not
  keep POSIX permissions (a Windows drive under WSL mounted without metadata,
  for example) the mode is something else, and on one that refuses the chmod
  (a FAT or exFAT mount owned by another account, some FUSE mounts) setting it
  fails. Either way, and if writing the key fails, `keygen` removes the key
  again, says why on stderr and exits 1. The mode it prints is the one it read
  back.
- **`run --config <file>`** opens the witness (all start-up checks above), then
  polls every `pollIntervalMs` until SIGINT or SIGTERM. A signal is handled
  between polls, never in the middle of an append. `--once` does a single poll
  and exits.
- **`verify --store <path> --pub <pem>`** walks the whole store and re-checks
  every link, hash, record signature, receipt signature and conflict note
  against the given public key. It prints `OK: …` with the key's
  `public key fingerprint: sha256:<hex>`, a per-submitter count, every conflict
  note and the last record's hash, or `FAIL: …` naming the first
  bad line, and exits non-zero on any break or if the store does not exist. `OK`
  means every record is as the key's holder signed it. It cannot show that the
  store was not cut back to a clean prefix: compare the last record hash with
  one you noted earlier. `--pub` must be the **public** key file; a file holding
  a private key is refused.
- **`fingerprint --pub <pem>`** prints only the public key's fingerprint
  (`sha256:<hex>`, one line), exactly what `keygen` printed for it and what the
  clerk's `fingerprint --pub` prints for the same file, and exits 0. It exits 1
  for a private key, a missing or unreadable file, a file with no key, or a
  key that is not Ed25519, and 2 for a usage error. The witness's operator and
  the node's owner use it to confirm, out of band, that the node holds the
  operator's public key.

**Files given to a command must be regular files.** `--pub`, `--store`,
`--config` and the config's `privateKeyPath` and `storePath` are opened
without blocking and checked on that descriptor before anything is read.
Anything else (a FIFO, a directory, a socket, a device) is refused at once,
with exit 1; a FIFO is never waited on. The messages, on stderr: `error:
cannot read public key file <p>: <p> is not a regular file (it is a FIFO)`;
`error: private key path <p> is not a regular file (it is a FIFO)`; `error:
cannot read config file <p>: <p> is not a regular file (it is a FIFO)`; and,
with such a `storePath`, `error: the witness store <p> does not verify: cannot
read store <p>: …`, after which `run` refuses to start. `verify --store`
prints its usual `FAIL: <p> does not verify: cannot read store <p>: <p> is not
a regular file (it is a FIFO)` on stdout. A missing store is still reported as
absent.

Exit codes: `0` success or clean shutdown; `1` refused to start, halted, or
verification failed; `2` usage error: an unknown command or option, a flag
given twice (`error: --pub given twice`), a missing required flag or a flag
without its value, with the usage text on stderr. `help` (or `--help`) prints
the usage and exits 0; no command at all prints it and exits 2.

**Starting `run` so that it can be stopped.** Start it so that the process you
signal is the witness's own node process: the command above, with `node`, or
the same command exec'd by a supervisor (for a systemd unit,
`ExecStart=/usr/bin/node <repo>/node_modules/ts-node/dist/bin.js <repo>/packages/witness/src/cli.ts run --config <file>`,
with `WorkingDirectory=<repo>`; `docs/INSTALL-FOR-AGENTS.md`, step 8, has a
whole user unit that keeps the witness running across a reboot). The `pid` in the `STARTED` line is the process
to send SIGTERM to. Under `npx ts-node … run` the process tree is npm → `sh -c`
→ node, and a SIGTERM sent to npx may stop npx and the shell without reaching
the witness; a `kill` of the npx process (`kill $!`, `kill %1`) can then leave
the witness running. `run` never stops itself because of how it was launched
(a witness that keeps running after whatever started it exits, `nohup` or a
service, is doing what it was told). Instead, when npm or npx started it
(`npm_command=exec`, or `npm_lifecycle_event` set), `run` writes one warning
line to stderr at start, naming its pid and the direct command, with every
path in it absolute, for example:

```
warning: this witness (pid 4242) was started through npm/npx; a signal sent to npx may not reach it, so stopping npx can leave it running. Signal pid 4242, or start it directly: /usr/bin/node /srv/ilas/node_modules/ts-node/dist/bin.js /srv/ilas/packages/witness/src/cli.ts run --config /srv/witness/witness.json
```

The node binary is the one running the witness (`process.execPath`);
ts-node's `bin.js` is the copy actually running this file (npx may have
fetched one outside the repository), else the one `require.resolve` finds,
else `<repo>/node_modules/ts-node/dist/bin.js`; `cli.ts` is the file in use
(a compiled `cli.js` is named without ts-node); and the config is resolved
against the directory `run` was started in. Paths are quoted for the shell
where needed. The command therefore works as printed from any directory.

`run --once` is not a daemon and writes no such warning. Ctrl-C in a terminal
reaches every process of the group and works either way.

`run` writes one JSON object per line to stdout, for example:

```
{"t":"…","event":"STARTED","pid":4242,"witnessSetId":"witness-set-a","submitters":["node-a"],"records":0,"storeCreated":true,"publicKeyFingerprint":"sha256:…","pollIntervalMs":1000}
{"t":"…","event":"RETAINED","submitterId":"node-a","index":0,"seq_no":9,"head_hash":"…","witness_ts":1791230000000,"conflicts":[],"receiptFile":"/srv/witness/outbox/node-a/receipt-000000000000.json"}
{"t":"…","event":"STOPPED","signal":"SIGTERM"}
```

Event names: `STARTED`, `RECEIPT_RESTORED`, `FOREIGN_OUTBOX_FILE`,
`RECORDS_FOR_UNDECLARED_SUBMITTERS`, the poll events in the table above,
`INTAKE_LEFT`, `INTAKE_UNREADABLE`, `UNREADABLE`, `RECEIPT_PENDING`,
`RECEIPT_WRITTEN`, `HALTED`, `STOPPED`. `UNDECLARED` and `INTAKE_UNREADABLE`
carry the `intakeDir` they are about.

If `run` exits 1, the reason is on **stderr** in both cases: a refusal to start
(`error: …`), or a halt (`error: the witness halted: …`, also in the `detail`
of the last stdout line, `HALTED`).

## Deployment

**Independence is the deployer's decision.** Nothing in this package can make
the witness independent of the node, or tell whether it is. Decide who operates
it, then declare that choice to ILAS so it is reported for what it is: a claim.

- **Private, single-person deployment.** Running the witness under the same
  account as the node is allowed. Declare it **`self-witnessed`** through
  `ILASKillStack`'s `declarations` option (and, if a clerk also runs under that
  account, declare the clerk **`self-operated`**). Such a witness still catches
  accidents and a chain that is rebuilt later by mistake, but the account that
  could rewrite the chain can also rewrite the witness.
- **Enterprise deployment.** A superior or a designated department runs the
  witness, on a **separate host or a separate account**, and **holds the private
  key**. The node's operator receives only `witness.pub.pem`, and confirms with
  the witness's operator, out of band, that its fingerprint matches
  (`fingerprint`, Command line). Declare it as
  `independent-operator: <role>`.
  - A separate account on the node's host works with the layout below.
    Creating that account, its groups and the directories' owners and modes
    needs an administrator.
  - On a separate host, the node and the witness must both reach this node's
    intake and outbox: a directory that is shared or synced between the two
    machines, which the deployer provides. Who can write each intake and each
    outbox on it must be worked out for that file system as below. This
    package ships no transport between machines and has not been tested
    across one (spec gap G10).

**A submitter is who can write its intake path.** The witness takes the intake
path a commit is read from as the submitter's identity; it cannot check who
wrote the file. So with more than one node, give each node **its own intake
directory** (`submitters[].intakeDir`) that only that node's account can write,
inside a parent directory no node can write (otherwise a node could rename
another's intake directory and put its own in place). With one shared intake,
every node that can write it can submit under every declared name.

For a separate-account setup on one host, a workable layout is: each node's
intake is writable by that node's account only (the ILAS client never reads it
back) and readable and writable by the witness account (it deletes what it
consumes); each outbox is writable only by the witness account and readable by
that node's account, inside a parent directory no node can write (so that no
node can put a directory of its own in an outbox's place); the store directory
and the key directory are accessible only to the witness account. The witness
still treats every intake and outbox entry as untrusted (see "When writing
fails"), so a node that can write an outbox anyway can withhold receipts there
or plant false ones, which the next start reports, but cannot make the witness
follow a link at a receipt's name, block on a FIFO, or overwrite a file. The
witness creates receipt files with mode 0644 filtered by its umask, so run it
with a umask that leaves them readable to the node (for example 022, or 027
with a shared group on the outbox).

**Getting help installing.** An AI coding agent (for example Claude Code or
Codex) can help a non-expert install ILAS and this witness by following
`docs/INSTALL-FOR-AGENTS.md`. The agent must **not** choose the operator for the
human: who runs the witness, on which machine or account, and who holds its key
are questions the agent asks and the human answers.

## Known gaps, in plain words

- **G2 — a receipt does not name its submitter or witness set.** The signature
  covers only `seq_no`, `head_hash` and `witness_ts`. A receipt signed for one
  node would verify for any node that trusts the same key. This package keeps
  receipts apart by **layout**, not by cryptography: one outbox per submitter
  (enforced in the config and checked against the store at every start) and one
  witness set per store. The real fix is a versioned preimage that names the set
  and the submitter; that is a spec change and changes the vectors.
- **G3 — the evidence lives only with the witness.** ILAS keeps no copy of what
  the witness retained. If the witness's store and outboxes are deleted, the
  anchor is gone. Without the key, a record cannot be changed, re-attributed,
  reordered or removed from the middle, even with the hashes recomputed (each
  record is signed whole). But a store cut back to a clean prefix still
  verifies; this witness notices that only while an outbox still holds the
  later receipts. Backups or write-once storage for the store are the
  deployer's job.
- **G4 — shared directories are not a witness.** The file-drop wire is just
  directories. A witness that runs as the node's own account, in directories
  the node can write, is the node witnessing itself. That is acceptable only if
  it is declared `self-witnessed`.
- **Submitters are not authenticated.** The intake path is the submitter's
  identity (see "What a receipt says"). Per-submitter intake directories and
  their file permissions are what keep one node from submitting as another;
  nothing in the wire does.

Other limits worth knowing:

- **Empty-chain commits.** A node with an empty chain emits `seq_no` −1 with the
  genesis hash (64 zeros). That is a valid HEAD_COMMIT; this witness retains and
  signs it. ILAS core's `ContinuityVerifier` treats such a receipt as reproduced
  on any chain, empty or not: every chain has the empty prefix, whose head is
  the genesis hash. −1 with any other hash, or anything below −1, is a
  `MISMATCH` (spec §3, §6). The receipt says nothing about any entry; it shows
  only that the witness was reachable before the first append.
- **One process per store.** If two witness processes append to one store,
  the one whose view is out of date notices on its next append (the size no
  longer matches) and halts. It is a check, not a lock.
- **POSIX permissions.** The private-key checks read POSIX mode bits. Where
  those are not real (Windows file systems, or a WSL `/mnt/c` mount without
  metadata) `keygen` will not leave a key there and `run` refuses one; keep the
  key on a POSIX file system.
- **Case-insensitive file systems.** The directory-separation check compares
  paths after resolving symlinks, but does not fold case.

## Wiring it into ILAS

On the node, configure ILAS core's `FileDropWitness` client to match this
witness's config, give ILAS a **durable log** (`logPath`), and declare who
operates the witness. The project compiles as CommonJS, so the code runs inside
an async function:

```ts
import { ILASKillStack } from "./src/index";
import { FileDropWitness } from "./src/s4";

async function main(): Promise<void> {
  const witness = new FileDropWitness({
    id: "witness-set-a",                           // = witnessSetId
    intakeDir: "/srv/witness/intake/node-a",       // = this node's intakeDir (or the shared intakeDir)
    outboxDir: "/srv/witness/outbox/node-a",       // = this node's outboxDir
    submitterId: "node-a",                         // = this node's submitter id
    publicKeyPath: "/etc/ilas/witness.pub.pem",    // the witness's PUBLIC key, from its operator
  });

  const stack = await ILASKillStack.create({
    logPath: "/var/lib/ilas/l0.jsonl",             // durable L0: required for witnessing to mean anything
    witness,
    declarations: { witness: "self-witnessed" },   // or "independent-operator: <role>"
  });

  stack.emitStartupCommit();   // then stack.emitHeadCommit() on a cadence
  const status = stack.status();
  console.log(status.logDurability.loadState);   // LOADED_VERIFIED on every start after the first
  console.log(status.continuity);   // VERIFIED_HISTORICAL, MISMATCH, REJECTED_RECEIPTS, or CANNOT_VERIFY_CONTINUITY
  console.log(witness.getLastFetchDiagnostics()); // what the last read of the outbox found, and why it dropped anything
  console.log(status.declarations); // { witness: "self-witnessed", clerk: null, verified: false,
                                    //   warnings: [], keys: { clerk: null, witness: "sha256:…" } }
  stack.close();               // at shutdown: release the log's writer lock
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
```

**Why `logPath`.** The witness keeps the heads it retained; the node must be
able to recompute them from its own chain at every later start. Without
`logPath`, L0 lives in memory: every start builds a new chain with new
timestamps, so every receipt retained before a restart reads `MISMATCH`. That
`MISMATCH` is honest (the earlier chain is gone), but it is not a finding about
tampering, and it makes witnessing useless across restarts. With `logPath` the
chain is reloaded and verified (`LOADED_VERIFIED`), and the earlier receipts
reproduce.

| ILAS `FileDropWitness` | Witness config |
|---|---|
| `id` | `witnessSetId` |
| `intakeDir` | the `intakeDir` of this node's entry in `submitters`; the top-level `intakeDir` if the entry has none |
| `outboxDir` | the `outboxDir` of this node's entry in `submitters` |
| `submitterId` | the `id` of that entry |
| `publicKeyPath` | the `witness.pub.pem` made next to `privateKeyPath` (never the private key: a file holding one is refused) |

Until the witness has retained a head for this node, continuity reads
`CANNOT_VERIFY_CONTINUITY`. That is the correct answer, not a fault. Once `run`
has printed `RETAINED` (or `DUPLICATE`) for this node's submitter id, the
node's next reading must be `VERIFIED_HISTORICAL`; `CANNOT_VERIFY_CONTINUITY`
then means the node cannot read or check the receipt, and
`getLastFetchDiagnostics()` says why: `outbox unreadable: …` for a wrong or
unreadable `outboxDir`, `keyAvailable: false` with a reason for a
`publicKeyPath` that is missing, not a regular file, or holds the private key.
`REJECTED_RECEIPTS` means the client had a usable key and found something in
the outbox that does not verify against it (a `publicKeyPath` holding a
different valid public key shows up this way, as every receipt refused). Like
`MISMATCH`, it is a finding. The client re-reads the key file at every fetch,
opening it without blocking: anything but a regular file of at most 64 KiB is
no key, so a FIFO at `publicKeyPath` cannot stop the node's `status()`.
`publicKeyFingerprint()` on the client gives the fingerprint of the key it
would use now, which ILAS reports as `status().declarations.keys.witness`; it
must equal what this witness's `keygen` printed.

**A new log file needs a new submitter id.** The witness keeps every head it
retained for a submitter, for as long as its store exists. If the node starts a
new L0 log file (after a log that loads `CANNOT_VERIFY`, or to enable a clerk
route), its new chain cannot reproduce those heads, and every receipt under the
old id reads `MISMATCH`. Give the node a new submitter id with its own new
intake and outbox for the new file (keep the old entry in `submitters`, so its
records stay declared), and move the old log aside rather than deleting it
(spec §5).

## Tests

```sh
npx ts-node packages/witness/src/witness.test.ts   # core, config, keys, store, refusals
npx ts-node packages/witness/src/interop.test.ts   # with ILAS core: emitter, client, continuity
npx ts-node packages/witness/src/cli.test.ts       # the CLI as child processes (also through npx): FIFOs and other
                                                   #   non-regular files refused at once, the absolute direct command
npx ts-node packages/witness/src/vectors.test.ts   # docs/s4-test-vectors.json, own code
npx ts-node packages/witness/src/readme.test.ts    # this README: snippets compile, examples verify
npx ts-node packages/witness/src/harness-signal.test.ts # a test stopped by a signal still stops its children and removes its files
npx tsc -p packages/witness                        # typecheck
```

`cli.test.ts` and `interop.test.ts` kill their child processes and remove
their temporary directories when the test process is stopped by SIGINT,
SIGTERM or SIGHUP, and then exit with 128 plus the signal's number (130, 143,
129); a signal that arrives during a synchronous test is handled when that
test ends. SIGKILL cannot be cleaned up after. `src/harness-child.fixture.ts`
is a fixture for `harness-signal.test.ts`, not a test.
