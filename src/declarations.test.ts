// ──────────────────────────────────────────────────────────────────────────────
// ILAS — deployer declarations in status(): who runs the witness and the clerk.
// These are claims ILAS cannot check, and status() must say so.
//   npx ts-node src/declarations.test.ts
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { createHash, createPublicKey, generateKeyPairSync } from "crypto";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { ILASKillStack, NullWitness } from "./index";
import type { ClerkRoute, DeploymentDeclarations, HeadCommit, Witness, WitnessReceipt } from "./index";
import { FileDropWitness } from "./s4";

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

console.log("── Declarations are reported as claims ──");

check("no declarations ⇒ both null, verified false, no warnings, no keys", () => {
  const d = new ILASKillStack().status().declarations;
  assert.deepEqual(d, {
    witness: null,
    clerk: null,
    verified: false,
    warnings: [],
    keys: { clerk: null, witness: null },
  });
});

check("a self-witnessed deployment is reported as declared", () => {
  const d = new ILASKillStack({
    declarations: { witness: "self-witnessed", clerk: "self-operated" },
  }).status().declarations;
  assert.equal(d.witness, "self-witnessed");
  assert.equal(d.clerk, "self-operated");
});

check("verified is false even for an independent-operator declaration", () => {
  const d = new ILASKillStack({
    declarations: { witness: "independent-operator: security department" },
  }).status().declarations;
  assert.equal(d.witness, "independent-operator: security department");
  assert.equal(d.verified, false, "a declaration must never read as verified");
});

check("declarations do not change the continuity reading", () => {
  const s = new ILASKillStack({ declarations: { witness: "self-witnessed" } });
  assert.equal(s.status().continuity, "CANNOT_VERIFY_CONTINUITY");
});

check("status reports a copy: mutating the options later changes nothing", () => {
  const decl: DeploymentDeclarations = { witness: "self-witnessed" };
  const s = new ILASKillStack({ declarations: decl });
  decl.witness = "independent-operator: someone else";
  assert.equal(s.status().declarations.witness, "self-witnessed");
});

// ── what ILAS can see beside the claims ──────────────────────────────────────

const root = mkdtempSync(join(tmpdir(), "ilas-declarations-"));

/** "sha256:" + hex SHA-256 of the key's SPKI DER, computed here, independently. */
function expectedFingerprint(pem: string): string {
  const der = createPublicKey(pem).export({ type: "spki", format: "der" });
  return "sha256:" + createHash("sha256").update(der).digest("hex");
}

function newPublicKeyPem(): string {
  return generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }) as string;
}

/** A clerk route whose client never answers: the bootstrap appends stay pending. */
function quietRoute(pem: string): ClerkRoute {
  return {
    client: { submit: () => new Promise(() => undefined) },
    submitterId: "node-a",
    channel: "l0",
    clerkPublicKeyPem: pem,
  };
}

/**
 * A witness other than NullWitness, with an optional fingerprint method that
 * may misbehave (return a non-string, throw): ILAS must cope with any of it.
 */
function witnessWith(fingerprint?: () => unknown): Witness {
  const w: Record<string, unknown> = {
    id: "custom",
    submit(_c: HeadCommit): void {},
    retrieveReceipts: (): WitnessReceipt[] => [],
  };
  if (fingerprint !== undefined) w.publicKeyFingerprint = fingerprint;
  return w as unknown as Witness;
}

console.log("── Contradictions ILAS can see are reported as warnings; verified stays false ──");

check("a witness declared with the NullWitness configured ⇒ one warning", () => {
  for (const witness of [undefined, new NullWitness()]) {
    const d = new ILASKillStack({
      witness,
      declarations: { witness: "independent-operator: audit" },
    }).status().declarations;
    assert.equal(d.warnings.length, 1, JSON.stringify(d.warnings));
    assert.match(d.warnings[0], /witness is declared.*NullWitness/);
    assert.equal(d.verified, false);
    assert.equal(d.witness, "independent-operator: audit", "the claim is still reported as made");
  }
});

check("a witness configured but none declared ⇒ one warning; an explicit NullWitness undeclared ⇒ none", () => {
  const d = new ILASKillStack({ witness: witnessWith() }).status().declarations;
  assert.equal(d.warnings.length, 1, JSON.stringify(d.warnings));
  assert.match(d.warnings[0], /witness is configured.*no witness declaration/);
  assert.deepEqual(new ILASKillStack({ witness: new NullWitness() }).status().declarations.warnings, []);
});

check("a clerk declared without a clerk route ⇒ one warning", () => {
  const d = new ILASKillStack({ declarations: { clerk: "independent-operator: security" } }).status().declarations;
  assert.equal(d.warnings.length, 1, JSON.stringify(d.warnings));
  assert.match(d.warnings[0], /clerk is declared.*no clerk route/);
  assert.equal(d.verified, false);
});

check("a clerk route without a clerk declaration ⇒ one warning, and keys.clerk is the route key's fingerprint", () => {
  const pem = newPublicKeyPem();
  const d = new ILASKillStack({ clerk: quietRoute(pem) }).status().declarations;
  assert.equal(d.warnings.length, 1, JSON.stringify(d.warnings));
  assert.match(d.warnings[0], /clerk route is configured.*no clerk declaration/);
  assert.equal(d.keys.clerk, expectedFingerprint(pem));
  assert.match(d.keys.clerk ?? "", /^sha256:[0-9a-f]{64}$/);
});

check("everything declared and configured ⇒ no warnings, both keys, verified still false", () => {
  const clerkPem = newPublicKeyPem();
  const witnessFp = expectedFingerprint(newPublicKeyPem());
  const d = new ILASKillStack({
    clerk: quietRoute(clerkPem),
    witness: witnessWith(() => witnessFp),
    declarations: { witness: "self-witnessed", clerk: "self-operated" },
  }).status().declarations;
  assert.deepEqual(d.warnings, []);
  assert.deepEqual(d.keys, { clerk: expectedFingerprint(clerkPem), witness: witnessFp });
  assert.equal(d.verified, false);
});

check("a blank declaration (empty or whitespace only) states nothing: reported as null, and warned about as not given", () => {
  for (const blank of ["", "   ", "\n", "\t \r\n"]) {
    const label = JSON.stringify(blank);
    const w = new ILASKillStack({ witness: witnessWith(), declarations: { witness: blank } }).status().declarations;
    assert.equal(w.witness, null, `${label}: a blank witness declaration was reported as given`);
    assert.equal(w.warnings.length, 1, `${label}: ${JSON.stringify(w.warnings)}`);
    assert.match(w.warnings[0], /witness is configured.*no witness declaration/);
    const c = new ILASKillStack({ clerk: quietRoute(newPublicKeyPem()), declarations: { clerk: blank } }).status().declarations;
    assert.equal(c.clerk, null, `${label}: a blank clerk declaration was reported as given`);
    assert.equal(c.warnings.length, 1, `${label}: ${JSON.stringify(c.warnings)}`);
    assert.match(c.warnings[0], /clerk route is configured.*no clerk declaration/);
    const none = new ILASKillStack({ declarations: { witness: blank, clerk: blank } }).status().declarations;
    assert.deepEqual(
      { witness: none.witness, clerk: none.clerk, warnings: none.warnings },
      { witness: null, clerk: null, warnings: [] },
      `${label}: nothing configured, nothing stated`
    );
  }
  // From JavaScript: a value that is not a string states nothing either.
  const odd = new ILASKillStack({ declarations: { witness: { who: "x" } as unknown as string } }).status().declarations;
  assert.equal(odd.witness, null);
  assert.deepEqual(odd.warnings, []);
  // Text around a declaration is kept as given.
  assert.equal(new ILASKillStack({ declarations: { witness: " self-witnessed " } }).status().declarations.witness, " self-witnessed ");
});

console.log("── The witness key is read through its OPTIONAL publicKeyFingerprint() ──");

check("read at every status(): a key the witness changes is seen; no method, a throw, or a non-string ⇒ null", () => {
  let current: unknown = "sha256:" + "1".repeat(64);
  const s = new ILASKillStack({ witness: witnessWith(() => current), declarations: { witness: "self-witnessed" } });
  assert.equal(s.status().declarations.keys.witness, current);
  current = "sha256:" + "2".repeat(64);
  assert.equal(s.status().declarations.keys.witness, current, "a cached fingerprint was reported");
  current = null;
  assert.equal(s.status().declarations.keys.witness, null);
  current = 42;
  assert.equal(s.status().declarations.keys.witness, null, "a non-string was reported as a fingerprint");
  const throwing = new ILASKillStack({
    witness: witnessWith(() => {
      throw new Error("no key");
    }),
  });
  assert.equal(throwing.status().declarations.keys.witness, null, "a throwing method broke status()");
  assert.equal(new ILASKillStack({ witness: witnessWith() }).status().declarations.keys.witness, null);
});

check("FileDropWitness: keys.witness is the fingerprint of the configured public key file; none without one", () => {
  const pem = newPublicKeyPem();
  const keyPath = join(root, "witness.pub.pem");
  writeFileSync(keyPath, pem);
  const config = { id: "w", intakeDir: join(root, "intake"), outboxDir: join(root, "outbox"), submitterId: "node-a" };
  const withKey = new ILASKillStack({
    witness: new FileDropWitness({ ...config, publicKeyPath: keyPath }),
    declarations: { witness: "self-witnessed" },
  }).status().declarations;
  assert.equal(withKey.keys.witness, expectedFingerprint(pem));
  assert.deepEqual(withKey.warnings, []);
  const without = new ILASKillStack({ witness: new FileDropWitness(config) }).status().declarations;
  assert.equal(without.keys.witness, null);
});

check("the reported warnings are a copy: editing them changes nothing later", () => {
  const s = new ILASKillStack({ declarations: { clerk: "self-operated" } });
  const first = s.status().declarations;
  first.warnings.push("planted");
  first.warnings.length = 0;
  assert.equal(s.status().declarations.warnings.length, 1);
});

rmSync(root, { recursive: true, force: true });

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
