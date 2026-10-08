// ──────────────────────────────────────────────────────────────────────────────
// ILAS — canonical JSON rules ("ILAS-CANON-JSON-1") acceptance tests.
//   npx ts-node src/l0/canonical.test.ts
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { canonicalise, CanonicalisationError, sha256Hex } from "./canonical";

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

console.log("── canonical form ──");

check("keys are sorted by code unit; insertion order does not matter", () => {
  assert.equal(canonicalise({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalise({ a: 2, b: 1 }), '{"a":2,"b":1}');
});

check("no whitespace; nested objects and arrays", () => {
  assert.equal(canonicalise({ x: [1, { y: "z" }], n: null }), '{"n":null,"x":[1,{"y":"z"}]}');
});

check("strings use JSON escaping", () => {
  assert.equal(canonicalise('a"b\n'), '"a\\"b\\n"');
});

check("undefined object properties are omitted (JSON semantics)", () => {
  assert.equal(canonicalise({ a: 1, b: undefined }), '{"a":1}');
});

check("undefined array elements are REFUSED, not coerced to null", () => {
  assert.throws(() => canonicalise([1, undefined]), CanonicalisationError);
});

check("non-finite numbers are REFUSED", () => {
  assert.throws(() => canonicalise({ n: NaN }), CanonicalisationError);
  assert.throws(() => canonicalise({ n: Infinity }), CanonicalisationError);
});

check("bigint, function, symbol are REFUSED", () => {
  assert.throws(() => canonicalise({ n: BigInt(1) }), CanonicalisationError);
  assert.throws(() => canonicalise({ f: () => 1 }), CanonicalisationError);
  assert.throws(() => canonicalise({ s: Symbol("x") }), CanonicalisationError);
});

check("cycles are REFUSED", () => {
  const a: Record<string, unknown> = {};
  a.self = a;
  assert.throws(() => canonicalise(a), CanonicalisationError);
});

check("toJSON gets exactly one call and its result is what is encoded", () => {
  let calls = 0;
  const v = { toJSON: () => { calls++; return { k: "v" }; } };
  assert.equal(canonicalise(v), '{"k":"v"}');
  assert.equal(calls, 1);
});

check("the hash is over the exact canonical bytes", () => {
  assert.equal(sha256Hex(canonicalise({ a: 1 })), sha256Hex('{"a":1}'));
});

check("object KEYS use JSON string escaping too", () => {
  assert.equal(canonicalise({ 'a"b': 1 }), '{"a\\"b":1}');
  assert.equal(canonicalise({ "a\\b": 1 }), '{"a\\\\b":1}');
  assert.equal(canonicalise({ "a\nb": 1 }), '{"a\\nb":1}');
  assert.equal(canonicalise({ "\u0001": 1 }), '{"\\u0001":1}');
  // Without key escaping these two different payloads would share their bytes.
  assert.notEqual(canonicalise({ 'a":1,"b': 2 }), canonicalise({ a: 1, b: 2 }));
});

check("keys sort by UTF-16 code unit: case, accents, astral vs BMP (not locale, not code point)", () => {
  assert.equal(canonicalise({ B: 1, a: 2 }), '{"B":1,"a":2}');
  assert.equal(canonicalise({ "é": 1, z: 2, "😀": 3, "～": 4 }), '{"z":2,"é":1,"😀":3,"～":4}');
  assert.equal(canonicalise({ "～": 1, "😀": 2 }), '{"😀":2,"～":1}');
});

check("every property is read exactly once; the first value read is what is encoded", () => {
  let reads = 0;
  const v = {} as Record<string, unknown>;
  Object.defineProperty(v, "k", {
    enumerable: true,
    get: () => (++reads === 1 ? "first" : "second"),
  });
  assert.equal(canonicalise(v), '{"k":"first"}');
  assert.equal(reads, 1);
});

check("depth: a value inside 64 nested containers is accepted, inside 65 it is refused", () => {
  const nest = (levels: number): unknown => {
    let x: unknown = 1;
    for (let i = 0; i < levels; i++) x = [x];
    return x;
  };
  assert.doesNotThrow(() => canonicalise(nest(64)));
  assert.throws(() => canonicalise(nest(65)), CanonicalisationError);
  const nestObj = (levels: number): unknown => {
    let x: unknown = 1;
    for (let i = 0; i < levels; i++) x = { k: x };
    return x;
  };
  assert.doesNotThrow(() => canonicalise(nestObj(64)));
  assert.throws(() => canonicalise(nestObj(65)), CanonicalisationError);
});

check("a SHARED reference that is not a cycle is encoded; a real cycle is still refused", () => {
  const s = { x: 1 };
  assert.equal(canonicalise({ a: s, b: s }), '{"a":{"x":1},"b":{"x":1}}');
  assert.equal(canonicalise([s, s]), '[{"x":1},{"x":1}]');
  const c: Record<string, unknown> = { s };
  c.again = c;
  assert.throws(() => canonicalise(c), CanonicalisationError);
});

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
