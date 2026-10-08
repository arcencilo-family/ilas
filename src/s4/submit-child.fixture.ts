// ──────────────────────────────────────────────────────────────────────────────
// ILAS — child-process helper for file-drop-witness.test.ts (not a test itself)
//
// One FileDropWitness.submit() against the intake named on the command line,
// then the submit diagnostics as one JSON line on stdout. The test runs this in
// a child process so that a submit() that blocks — a FIFO planted at the drop
// name, with no reader — is killed by the parent's timeout instead of hanging
// the whole run.
//   node -r ts-node/register src/s4/submit-child.fixture.ts \
//     <intakeDir> <outboxDir> <submitterId> <commit JSON>
// ──────────────────────────────────────────────────────────────────────────────

import { FileDropWitness } from "./file-drop-witness";

const [intakeDir, outboxDir, submitterId, commitJson] = process.argv.slice(2);
const client = new FileDropWitness({ id: "witness-set-a", intakeDir, outboxDir, submitterId });
client.submit(JSON.parse(commitJson));
process.stdout.write(JSON.stringify(client.getSubmitDiagnostics()) + "\n");
