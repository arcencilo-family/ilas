// ──────────────────────────────────────────────────────────────────────────────
// Reference witness — this package's README, checked against the code.
//   npx ts-node packages/witness/src/readme.test.ts
//
// Every ```ts snippet must compile as a file at the repository root, under the
// project's own compiler options (CommonJS, strict). The check runs in memory:
// nothing is written into the repository. The store-format example must be a
// record this package verifies under the published test key, and its receipt
// the published vector. A few statements that once were wrong are fenced.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { createPublicKey } from "crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join, resolve } from "path";
import ts from "typescript";

import { receiptBytes } from "./receipt";
import { readStore, receiptOf } from "./store";

let passed = 0;
let failed = 0;
function check(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${(err as Error).message}`);
    failed++;
  }
}

const REPO = resolve(__dirname, "..", "..", "..");
const README = readFileSync(join(__dirname, "..", "README.md"), "utf8");
const VECTORS = JSON.parse(readFileSync(join(REPO, "docs", "s4-test-vectors.json"), "utf8")) as {
  witness_public_key_spki_pem: string;
  receipt_valid: { receipt: Record<string, unknown> };
};

/** The bodies of the fenced blocks with this language tag, in order. */
function fences(lang: string): string[] {
  const out: string[] = [];
  const re = /```([a-z]*)\n([\s\S]*?)```/g;
  for (let m = re.exec(README); m !== null; m = re.exec(README)) {
    if (m[1] === lang) out.push(m[2]);
  }
  return out;
}

/** Type-check `code` as if it were <repo>/<name>.ts; returns the diagnostics for that file. */
function typecheck(code: string, name: string): string[] {
  const read = ts.readConfigFile(join(REPO, "tsconfig.json"), ts.sys.readFile);
  const parsed = ts.parseJsonConfigFileContent(read.config, ts.sys, REPO);
  const options: ts.CompilerOptions = {
    ...parsed.options,
    noEmit: true,
    rootDir: undefined,
    outDir: undefined,
    declaration: false,
    declarationMap: false,
    sourceMap: false,
  };
  const virtual = join(REPO, `${name}.ts`);
  const host = ts.createCompilerHost(options);
  const getSourceFile = host.getSourceFile.bind(host);
  const fileExists = host.fileExists.bind(host);
  const readFile = host.readFile.bind(host);
  host.getSourceFile = (fileName, languageVersion, onError, shouldCreate) =>
    fileName === virtual
      ? ts.createSourceFile(fileName, code, languageVersion, true)
      : getSourceFile(fileName, languageVersion, onError, shouldCreate);
  host.fileExists = (fileName) => fileName === virtual || fileExists(fileName);
  host.readFile = (fileName) => (fileName === virtual ? code : readFile(fileName));
  const program = ts.createProgram([virtual], options, host);
  const source = program.getSourceFile(virtual);
  assert.ok(source !== undefined, "the snippet was not loaded");
  return [...program.getSyntacticDiagnostics(source), ...program.getSemanticDiagnostics(source)].map(
    (d) => `TS${d.code}: ${ts.flattenDiagnosticMessageText(d.messageText, " ")}`
  );
}

console.log("── the README, against the code ──");

check("every ts snippet compiles at the repository root (CommonJS, strict): no top-level await", () => {
  const snippets = fences("ts");
  assert.ok(snippets.length >= 1, "the README has a ts snippet");
  snippets.forEach((code, i) => {
    const diagnostics = typecheck(code, `__witness_readme_snippet_${i}`);
    assert.deepEqual(diagnostics, [], `snippet ${i + 1}: ${diagnostics.join(" | ")}`);
  });
});

check("the wiring snippet gives ILAS a durable log (logPath)", () => {
  const wiring = fences("ts").find((code) => code.includes("ILASKillStack.create"));
  assert.ok(wiring !== undefined, "the wiring snippet is there");
  assert.match(wiring!, /^\s*logPath: "/m);
});

check("the store-format example verifies under the vector key, record_sig included, and its receipt is receipt_valid", () => {
  const json = fences("json");
  const line = json.find((block) => block.startsWith('{"index":0'));
  const receipt = json.find((block) => block.startsWith('{"seq_no":'));
  assert.ok(line !== undefined && receipt !== undefined, "both examples are there");
  const dir = mkdtempSync(join(tmpdir(), "ilas-witness-readme-"));
  try {
    const path = join(dir, "store.jsonl");
    writeFileSync(path, line!.trim() + "\n");
    const store = readStore(path, {
      publicKey: createPublicKey(VECTORS.witness_public_key_spki_pem),
      witnessSetId: "witness-set-a",
    });
    assert.equal(store.records.length, 1);
    const bytes = receiptBytes(receiptOf(store.records[0]));
    assert.equal(bytes, receipt!.trim() + "\n", "the receipt example is that record's receipt");
    assert.equal(bytes, JSON.stringify(VECTORS.receipt_valid.receipt) + "\n", "and it is receipt_valid");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

check("statements that were once wrong stay corrected", () => {
  // The empty chain: ILAS core reproduces a -1 receipt that carries the genesis hash.
  assert.doesNotMatch(README, /cannot recompute a head below/);
  assert.match(README, /treats such a receipt as reproduced\s+on any chain/);
  // A rollback to an already-retained head is a duplicate, not a new record.
  assert.doesNotMatch(README, /Rewrites and rollbacks are retained, never dropped\./);
  assert.match(README, /rollback to a head the witness \*\*already retained\*\*[\s\S]*?is a `DUPLICATE`/);
  // The intake path is the identity, and it is not authenticated.
  assert.doesNotMatch(README, /Who sent the commit/);
  assert.match(README, /a submitter's identity is the intake\s+path it writes to\. Nothing authenticates it\./);
  // The long-running command is started so that SIGTERM reaches it.
  assert.match(README, /^node node_modules\/ts-node\/dist\/bin\.js packages\/witness\/src\/cli\.ts run /m);
  assert.doesNotMatch(README, /^npx ts-node packages\/witness\/src\/cli\.ts run /m);
  // A halt explains itself on stderr.
  assert.match(README, /error: the witness halted:/);
  // `run` does not stop itself because of how it was launched; under npm/npx it warns.
  assert.doesNotMatch(README, /watches the\s+process that launched it/);
  assert.match(README, /`run` never stops itself because of how it was launched/);
  // The direct command it names works from any directory: every path in it is
  // absolute (in the example, absolute or a <placeholder> for one).
  assert.match(
    README,
    /^warning: .*started through npm\/npx; a signal sent to npx may not reach it.*start it directly: [/<]\S* [/<]\S*\/ts-node\/dist\/bin\.js [/<]\S*\/packages\/witness\/src\/cli\.ts run --config [/<]\S+$/m,
    "the README's example npm/npx warning names node, ts-node's bin.js, cli.ts and the config by absolute paths, as `run` prints them"
  );
  assert.doesNotMatch(
    README,
    /start it directly: node node_modules\/ts-node\/dist\/bin\.js /,
    "the README's example npm/npx warning still shows the old relative direct command"
  );
  // Staging files are created new, under a random name, not "<name>.<pid>.tmp".
  assert.doesNotMatch(README, /\.<pid>\.tmp/);
  assert.match(README, /<receipt name>\.<12 random hex>\.tmp/);
});

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
