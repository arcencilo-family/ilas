// ──────────────────────────────────────────────────────────────────────────────
// ILAS — child-process helper for file-drop-witness.test.ts (not a test itself)
//
// One FileDropWitness.retrieveReceipts() against the outbox named on the
// command line, with a writer of the outbox winning the race on purpose: the
// first time the client opens <outboxDir>/<name> (or reads it by name), the FIFO
// at <fifoPath> is renamed onto that name a moment before. Whatever by-name
// check the client made before that point saw a regular file. Then one
// publicKeyFingerprint(). Prints the fetch diagnostics, whether the swap
// happened, and the fingerprint as one JSON line on stdout. The test runs this
// in a child so that a client which blocks opening a FIFO (in the outbox, or at
// <publicKeyPath>) is killed by the parent's timeout instead of hanging the
// whole run. A <name> that no fetch opens leaves the FIFO where it is.
//   node -r ts-node/register src/s4/fetch-child.fixture.ts \
//     <outboxDir> <publicKeyPath> <name> <fifoPath>
//
// The hook replaces fs.openSync and fs.readFileSync on the fs module object
// itself (an import-equals binding is that object): the client's compiled
// CommonJS looks both up on it at call time.
// ──────────────────────────────────────────────────────────────────────────────

import fs = require("fs");
import { join } from "path";
import { FileDropWitness } from "./file-drop-witness";

const [outboxDir, publicKeyPath, name, fifoPath] = process.argv.slice(2);
const target = join(outboxDir, name);
let swapped = false;

type AnyFn = (...args: unknown[]) => unknown;
const mutableFs = fs as unknown as Record<string, AnyFn>;
for (const method of ["openSync", "readFileSync"]) {
  const original = mutableFs[method];
  mutableFs[method] = (...args: unknown[]) => {
    if (!swapped && args[0] === target) {
      swapped = true;
      fs.renameSync(fifoPath, target);
    }
    return original(...args);
  };
}

const client = new FileDropWitness({
  id: "witness-set-a",
  intakeDir: join(outboxDir, "unused-intake"),
  outboxDir,
  submitterId: "ilas-node-a",
  publicKeyPath,
});
client.retrieveReceipts();
const keyFingerprint = client.publicKeyFingerprint();
process.stdout.write(
  JSON.stringify({ swapped, ...client.getLastFetchDiagnostics(), keyFingerprint }) + "\n"
);
