// ──────────────────────────────────────────────────────────────────────────────
// Reference clerk — the wire: JSON round-trip of payloads, socket framing,
// socket permissions, and client failure modes.
//   npx ts-node packages/clerk/src/wire.test.ts
//
// clerkd runs INSIDE this test process here (startClerkd), reached through a
// real Unix socket. Its receipts therefore say SEPARATE_PROCESS although the
// client is in the same process: SEPARATE_PROCESS describes how the clerk was
// started, not who connected. interop.test.ts runs clerkd as a child process,
// and so does the one test here in which another process floods clerkd (in
// this process, clerkd's own event loop would also be the client's).
//
// The question this file answers: for every value ILAS can submit, does the
// commitment the clerk computes after JSON.parse equal the one ILAS computes
// on its in-memory object? Where the answer is no, the client must refuse
// before sending, and the clerk's book must not grow.
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { spawn } from "child_process";
import { chmodSync, existsSync, mkdirSync, readdirSync, statSync, unlinkSync, writeFileSync } from "fs";
import { createConnection, createServer } from "net";
import type { Server, Socket } from "net";
import { dirname, join } from "path";
import { canonicalise, sha256Hex } from "../../../src/l0/canonical";
import { verifyClerkReceipt } from "../../../src/l0/clerk-verify";
import { ClerkRefusedError, ClerkTransportError, InProcessClerkClient, SocketClerkClient } from "./client";
import { ClerkConfigError, loadConfigFile, parseConfig } from "./config";
import type { ClerkConfig } from "./config";
import { startClerkd, ClerkdStartError, MAX_CONNECTIONS } from "./server";
import type { RunningClerkd } from "./server";
import {
  ClerkPayloadError,
  ClerkRequestError,
  encodeRequest,
  MAX_LINE_BYTES,
  MAX_NAME_LENGTH,
  MAX_PAYLOAD_BYTES,
  MAX_REQUEST_OVERHEAD_BYTES,
  MAX_RESPONSE_BYTES,
} from "./wire";
import {
  checkAsync,
  makeClerkFixture,
  rejects,
  runAll,
  section,
  startChildClerkd,
  tempDir,
  throws,
} from "./test-support";
import type { ClerkFixture } from "./test-support";

// One daemon for the round-trip cases; separate ones where a test needs its own.
let fx: ClerkFixture;
let clerkd: RunningClerkd;
let client: SocketClerkClient;

async function boot(extra: Record<string, unknown> = {}) {
  const f = makeClerkFixture(extra);
  const d = await startClerkd(loadConfigFile(f.configPath));
  return { f, d, c: new SocketClerkClient({ socketPath: f.socketPath, timeoutMs: 5000 }) };
}

function submitPayload(payload: unknown) {
  return client.submit({ submitter_id: "ilas-node", channel: "l0", declared_timestamp: null, payload });
}

/** Send raw bytes on one connection; collect `expect` response lines. */
function raw(socketPath: string, bytes: Buffer, expect: number, timeoutMs = 5000): Promise<{ lines: unknown[]; closed: boolean }> {
  return new Promise((resolve, reject) => {
    const s = createConnection(socketPath);
    let buf = "";
    let closed = false;
    const lines: unknown[] = [];
    const timer = setTimeout(() => {
      s.destroy();
      reject(new Error(`raw: got ${lines.length}/${expect} lines before timeout`));
    }, timeoutMs);
    const done = () => {
      clearTimeout(timer);
      s.destroy();
      resolve({ lines, closed });
    };
    s.setEncoding("utf8");
    s.on("connect", () => s.write(bytes));
    s.on("data", (d: string) => {
      buf += d;
      let nl: number;
      while ((nl = buf.indexOf("\n")) !== -1) {
        lines.push(JSON.parse(buf.slice(0, nl)));
        buf = buf.slice(nl + 1);
        if (lines.length === expect) {
          // Give the server a moment to close, so `closed` can be observed.
          setTimeout(done, 100);
        }
      }
    });
    s.on("error", () => undefined);
    s.on("close", () => {
      closed = true;
      if (lines.length >= expect) done();
    });
  });
}

function line(obj: unknown): Buffer {
  return Buffer.from(JSON.stringify(obj) + "\n", "utf8");
}

function sleep(ms: number): Promise<void> {
  return new Promise((res) => setTimeout(res, ms));
}

/** `p`, or null if it has not settled within `ms`. Leaves no timer behind. */
async function within<T>(p: Promise<T>, ms: number): Promise<T | null> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([p, new Promise<null>((res) => (timer = setTimeout(() => res(null), ms)))]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * An open connection that records what the server sends and when it closes.
 * `lines()` resolves with the response lines once `n` have arrived.
 */
async function openConnection(socketPath: string) {
  const s: Socket = await new Promise((res, rej) => {
    const c = createConnection(socketPath);
    c.once("connect", () => {
      c.off("error", rej);
      res(c);
    });
    c.once("error", rej);
  });
  s.on("error", () => undefined);
  s.setEncoding("utf8");
  let text = "";
  const waiters: Array<() => void> = [];
  s.on("data", (t: string) => {
    text += t;
    for (const w of waiters.splice(0)) w();
  });
  const closed = new Promise<string>((res) => s.once("close", () => res(text)));
  const lines = (n: number): Promise<unknown[]> =>
    new Promise((res) => {
      const tryNow = (): void => {
        const parts = text.split("\n").slice(0, -1);
        if (parts.length >= n) res(parts.slice(0, n).map((l) => JSON.parse(l)));
        else waiters.push(tryNow);
      };
      tryNow();
    });
  return { s, closed, lines };
}

section("Setup");

checkAsync("clerkd starts on a socket with mode 0600 in a 0700 directory", async () => {
  ({ f: fx, d: clerkd, c: client } = await boot());
  assert.equal(statSync(fx.socketPath).mode & 0o777, 0o600);
  assert.equal(statSync(join(fx.dir, "run")).mode & 0o777, 0o700);
  assert.ok(statSync(fx.socketPath).isSocket());
});

// ── round trip: values whose commitment survives ─────────────────────────────

section("Round trip: payloads whose canonical form survives JSON transport");

const lone = "\ud800";
const viaParse = JSON.parse('{"__proto__":{"x":1},"a":2}') as Record<string, unknown>;
const viaDefine: Record<string, unknown> = { b: 1 };
Object.defineProperty(viaDefine, "__proto__", { value: { y: 2 }, enumerable: true, writable: true, configurable: true });
const nullProto = Object.create(null) as Record<string, unknown>;
nullProto.k = "v";

const survivors: Array<[string, unknown]> = [
  ["a plain L0 entry", { timestamp: 1, moduleId: "m", eventType: "e", provenanceTag: "LaneA", parameters: { n: 1 }, outcome: "ok" }],
  ["-0 at top level, nested and in arrays", { z: -0, a: [-0, 0], o: { z: -0 } }],
  ["very large and very small numbers", { a: 1e21, b: 1e-7, c: 5e-324, d: Number.MAX_VALUE, e: -Number.MAX_VALUE, f: Number.MAX_SAFE_INTEGER + 2, g: 0.1 + 0.2, h: 123456789012345680000 }],
  ["unicode: accents, CJK, emoji with modifier, combining marks", { s: "héllo 日本語 👍🏽 é" }],
  ["control characters, U+2028/U+2029 and quotes", { s: "\u0000\u0001\u001f  \"\\/\n\t" }],
  ["lone surrogates in values and keys", { s: lone + "x\udfff", [lone]: 1, ["a\ud83d"]: 2 }],
  ["keys sorted by code unit: empty, case, accents, astral", { "": 0, Z: 1, a: 2, "é": 3, "￿": 4, "𝟘": 5 }],
  ["an own __proto__ key (as JSON.parse makes it)", viaParse],
  ["an own __proto__ key (defined with defineProperty)", viaDefine],
  ["an object literal __proto__ (sets the prototype; not data on either side)", { __proto__: { inherited: 1 }, own: 2 }],
  ["keys named like Object.prototype members", { constructor: 1, toString: "x", hasOwnProperty: null, valueOf: [] }],
  ["undefined object properties (omitted on both sides)", { a: 1, b: undefined, c: { d: undefined } }],
  ["a Date (toJSON called once on each side)", { when: new Date(1_700_000_000_000) }],
  ["an object with a null prototype", nullProto],
  ["a typed array and a Map (plain-object form on both sides)", { u8: new Uint8Array([1, 2]), m: new Map([["k", 1]]) }],
  ["empty containers, null, booleans, nesting", { a: [], o: {}, n: null, t: true, f: false, deep: [[[{ x: [1] }]]] }],
  ["a payload that is not an object", [1, "two", null]],
  ["63 levels of nesting (inside the canonical depth bound)", (() => { let v: unknown = 1; for (let i = 0; i < 63; i++) v = { v }; return v; })()],
];

for (const [name, payload] of survivors) {
  checkAsync(name, async () => {
    // Sanity: these really do round-trip.
    assert.equal(canonicalise(JSON.parse(JSON.stringify(payload))), canonicalise(payload));
    const r = await submitPayload(payload);
    assert.equal(r.payload_commitment, sha256Hex(canonicalise(payload)));
    const v = verifyClerkReceipt(r as unknown as Record<string, unknown>, fx.publicKeyPem, payload);
    assert.ok(v.ok, `ILAS refused: ${v.reason}`);
  });
}

// ── round trip: values whose commitment would NOT survive ────────────────────

section("Round trip: payloads that would not survive are refused before sending");

const keyDependent = { v: { toJSON: (key?: string) => (key === undefined ? "direct" : "via-json") } };
const deep70 = (() => { let v: unknown = 1; for (let i = 0; i < 70; i++) v = { v }; return v; })();
// eslint-disable-next-line no-sparse-arrays
const sparse = [1, , 3];

const casualties: Array<[string, unknown, RegExp]> = [
  ["an undefined array element (JSON would write null)", [1, undefined], /no canonical form/],
  ["a sparse array (JSON would write null)", sparse, /no canonical form/],
  ["NaN (JSON would write null)", { n: NaN }, /no canonical form/],
  ["Infinity and -Infinity", { a: Infinity, b: -Infinity }, /no canonical form/],
  ["a bigint", { n: BigInt(7) }, /no canonical form/],
  ["a function-valued property (JSON would drop it)", { f: () => 1 }, /no canonical form/],
  ["a symbol-valued property (JSON would drop it)", { s: Symbol("x") }, /no canonical form/],
  ["a nested toJSON returning undefined (JSON would drop the key)", { a: { toJSON: () => undefined } }, /no canonical form/],
  ["a boxed number (canonical {} but JSON 5)", { n: new Number(5) }, /changes when written as JSON/],
  ["a boxed string (canonical {\"0\":..} but JSON a string)", { s: new String("ab") }, /changes when written as JSON/],
  ["a boxed boolean", { b: new Boolean(false) }, /changes when written as JSON/],
  ["a toJSON whose result depends on its key argument", keyDependent, /changes when written as JSON/],
  ["more than 64 levels of nesting", deep70, /no canonical form/],
];

for (const [name, payload, expect] of casualties) {
  checkAsync(name, async () => {
    const before = clerkd.core.nextSeq;
    const err = await rejects(submitPayload(payload));
    assert.ok(err instanceof ClerkPayloadError, `got ${err.name}: ${err.message}`);
    assert.match(err.message, expect);
    assert.equal(clerkd.core.nextSeq, before, "the clerk booked a receipt for a refused payload");
  });
}

checkAsync("why refuse: for such payloads ILAS rejects a receipt the clerk signs over the JSON form", async () => {
  for (const payload of [{ n: new Number(5) }, keyDependent, { a: [1, undefined] }, { n: NaN }, { f: () => 1, k: 1 }]) {
    const arrived = JSON.parse(JSON.stringify(payload));
    const r = await submitPayload(arrived); // what a naive client would have caused
    const v = verifyClerkReceipt(r as unknown as Record<string, unknown>, fx.publicKeyPem, payload);
    assert.equal(v.ok, false, `ILAS accepted a receipt for ${JSON.stringify(arrived)}`);
  }
});

checkAsync("an undefined payload is refused as missing", async () => {
  const err = await rejects(submitPayload(undefined));
  assert.ok(err instanceof ClerkRequestError);
  assert.match(err.message, /payload is missing/);
});

checkAsync("a request over the line limit is refused by the client before connecting", async () => {
  const before = clerkd.core.nextSeq;
  const err = await rejects(submitPayload({ pad: "x".repeat(MAX_LINE_BYTES) }));
  assert.ok(err instanceof ClerkRequestError);
  assert.match(err.message, /at most 1048576 bytes/);
  assert.equal(clerkd.core.nextSeq, before);
});

// ── the payload size limit the socket client declares ───────────────────────

section("maxPayloadBytes: a payload within it always fits on one request line");

/** The longest names JSON can make of MAX_NAME_LENGTH code units: 6 bytes each. */
const WORST_SUBMITTER = "\u0001".repeat(MAX_NAME_LENGTH); // control characters: \u0001
const WORST_CHANNEL = "\ud800".repeat(MAX_NAME_LENGTH); // lone surrogates: \ud800
/** The longest number JSON writes: 25 bytes. */
const WORST_TIMESTAMP = -0.0000012345678901234567;

/** A payload whose canonical form is exactly `bytes` bytes. */
function payloadOfSize(bytes: number): { pad: string } {
  const base = Buffer.byteLength(canonicalise({ pad: "" }), "utf8");
  const p = { pad: "x".repeat(bytes - base) };
  assert.equal(Buffer.byteLength(canonicalise(p), "utf8"), bytes);
  return p;
}

checkAsync("SocketClerkClient declares maxPayloadBytes = MAX_LINE_BYTES − 3162; InProcessClerkClient declares none", async () => {
  assert.equal(MAX_REQUEST_OVERHEAD_BYTES, 3162);
  assert.equal(MAX_PAYLOAD_BYTES, 1_048_576 - 3162);
  assert.equal(client.maxPayloadBytes, MAX_PAYLOAD_BYTES);
  assert.ok(Number.isSafeInteger(client.maxPayloadBytes) && client.maxPayloadBytes > 0);
  assert.equal("maxPayloadBytes" in InProcessClerkClient.prototype, false);
  // The parts of the sum, measured rather than counted.
  const skeleton = JSON.stringify({ submitter_id: "", channel: "", declared_timestamp: 0, payload: 0 });
  assert.equal(Buffer.byteLength(skeleton) - 4 - 1 - 1, 61, "fixed text");
  assert.equal(Buffer.byteLength(JSON.stringify(WORST_SUBMITTER)), 2 + 6 * MAX_NAME_LENGTH);
  assert.equal(Buffer.byteLength(JSON.stringify(WORST_CHANNEL)), 2 + 6 * MAX_NAME_LENGTH);
  assert.equal(JSON.stringify(WORST_TIMESTAMP).length, 25);
  for (const t of [-Number.MAX_VALUE, -Number.MIN_VALUE, -1.2345678901234567e-308, -123456789012345680000, -0.000009999999999999999, -1.2345678901234566e-7]) {
    assert.ok(JSON.stringify(t).length <= 25, `${t} is longer than 25 bytes in JSON`);
  }
});

checkAsync("with the longest names and timestamp, a payload of exactly maxPayloadBytes makes a line of exactly MAX_LINE_BYTES, and the clerk books it", async () => {
  const before = clerkd.core.nextSeq;
  const req = { submitter_id: WORST_SUBMITTER, channel: WORST_CHANNEL, declared_timestamp: WORST_TIMESTAMP, payload: payloadOfSize(MAX_PAYLOAD_BYTES) };
  assert.equal(Buffer.byteLength(encodeRequest(req), "utf8"), MAX_LINE_BYTES);
  const r = await client.submit(req);
  assert.equal(r.payload_commitment, sha256Hex(canonicalise(req.payload)));
  assert.equal(clerkd.core.nextSeq, before + 1);
  // One byte more would not fit with these names: the limit is tight, not generous.
  const err = throws(() => encodeRequest({ ...req, payload: payloadOfSize(MAX_PAYLOAD_BYTES + 1) }));
  assert.ok(err instanceof ClerkRequestError, `got ${err.name}: ${err.message}`);
  assert.match(err.message, /request is 1048577 bytes/);
});

checkAsync("a payload takes as many bytes on the line as its canonical form, for every payload the client sends", async () => {
  const at = (payload: unknown) =>
    Buffer.byteLength(encodeRequest({ submitter_id: "s", channel: "c", declared_timestamp: null, payload }), "utf8");
  const empty = at(null) - 4;
  for (const [name, payload] of survivors) {
    assert.equal(at(payload) - empty, Buffer.byteLength(canonicalise(payload), "utf8"), name);
  }
});

// ── raw protocol ─────────────────────────────────────────────────────────────

section("Socket protocol: one response line per request line, in order");

checkAsync("two requests on one connection get two responses, in order", async () => {
  const before = clerkd.core.nextSeq;
  const req = (n: number) => ({ submitter_id: "s", channel: "c", declared_timestamp: n, payload: { n } });
  const { lines } = await raw(fx.socketPath, Buffer.concat([line(req(1)), line(req(2))]), 2);
  const [a, b] = lines as Array<{ ok: boolean; receipt: { clerk_seq: number; declared_timestamp: number } }>;
  assert.ok(a.ok && b.ok);
  assert.equal(a.receipt.clerk_seq, before);
  assert.equal(b.receipt.clerk_seq, before + 1);
  assert.equal(a.receipt.declared_timestamp, 1);
  assert.equal(b.receipt.declared_timestamp, 2);
});

checkAsync("bad lines get an error response each, and the connection stays usable", async () => {
  const before = clerkd.core.nextSeq;
  const bytes = Buffer.concat([
    Buffer.from("{not json\n"),
    Buffer.from("\n"),
    Buffer.from([0xff, 0xfe, 0x0a]),
    line({ submitter_id: "s", channel: "c", payload: {}, extra: true }),
    line({ submitter_id: "s", channel: "c", payload: { ok: 1 } }),
  ]);
  const { lines } = await raw(fx.socketPath, bytes, 5);
  const rs = lines as Array<{ ok: boolean; error?: string }>;
  assert.match(rs[0].error!, /not valid JSON/);
  assert.match(rs[1].error!, /not valid JSON/);
  assert.match(rs[2].error!, /not valid UTF-8/);
  assert.match(rs[3].error!, /unknown request field "extra"/);
  assert.equal(rs[4].ok, true);
  assert.equal(clerkd.core.nextSeq, before + 1);
});

checkAsync("a raw payload with an own __proto__ key commits to it, as ILAS would for the same parsed object", async () => {
  const text = '{"submitter_id":"s","channel":"c","payload":{"__proto__":{"x":1},"a":2}}\n';
  const { lines } = await raw(fx.socketPath, Buffer.from(text), 1);
  const r = (lines[0] as { ok: boolean; receipt: Record<string, unknown> }).receipt;
  const sameObject = (JSON.parse(text) as { payload: unknown }).payload;
  assert.equal(canonicalise(sameObject), '{"__proto__":{"x":1},"a":2}');
  assert.equal(r.payload_commitment, sha256Hex(canonicalise(sameObject)));
  assert.ok(verifyClerkReceipt(r, fx.publicKeyPem, sameObject).ok);
});

checkAsync("duplicate keys in a raw line: the clerk commits to the parsed value (the last one wins)", async () => {
  const text = '{"submitter_id":"s","channel":"c","payload":{"a":1,"a":2}}\n';
  const { lines } = await raw(fx.socketPath, Buffer.from(text), 1);
  const r = (lines[0] as { receipt: Record<string, unknown> }).receipt;
  assert.equal(r.payload_commitment, sha256Hex('{"a":2}'));
});

checkAsync("a raw payload nested deeper than 64 levels is refused by the clerk itself", async () => {
  const before = clerkd.core.nextSeq;
  const text = `{"submitter_id":"s","channel":"c","payload":${"[".repeat(70)}${"]".repeat(70)}}\n`;
  const { lines } = await raw(fx.socketPath, Buffer.from(text), 1);
  const r = lines[0] as { ok: boolean; error: string };
  assert.equal(r.ok, false);
  assert.match(r.error, /no canonical form/);
  assert.equal(clerkd.core.nextSeq, before);
});

checkAsync("a line of exactly MAX_LINE_BYTES is accepted", async () => {
  const shell = { submitter_id: "s", channel: "c", declared_timestamp: null, payload: { pad: "" } };
  const pad = MAX_LINE_BYTES - Buffer.byteLength(JSON.stringify(shell));
  const exact = JSON.stringify({ ...shell, payload: { pad: "x".repeat(pad) } });
  assert.equal(Buffer.byteLength(exact), MAX_LINE_BYTES);
  const { lines } = await raw(fx.socketPath, Buffer.from(exact + "\n"), 1, 15_000);
  assert.equal((lines[0] as { ok: boolean }).ok, true);
});

checkAsync("a longer line is refused, nothing is booked, and the connection is closed", async () => {
  const before = clerkd.core.nextSeq;
  const big = Buffer.alloc(MAX_LINE_BYTES + 10, 0x20); // no newline at all
  const { lines, closed } = await raw(fx.socketPath, big, 1, 15_000);
  const r = lines[0] as { ok: boolean; error: string };
  assert.equal(r.ok, false);
  assert.match(r.error, /longer than 1048576 bytes; connection closed/);
  assert.ok(closed, "connection left open after an oversize line");
  assert.equal(clerkd.core.nextSeq, before);
});

checkAsync("a line that passes the limit only when its newline arrives is refused too, and not booked", async () => {
  const before = clerkd.core.nextSeq;
  const shell = { submitter_id: "s", channel: "c", declared_timestamp: null, payload: { pad: "" } };
  const pad = MAX_LINE_BYTES + 20 - Buffer.byteLength(JSON.stringify(shell));
  const bytes = Buffer.from(JSON.stringify({ ...shell, payload: { pad: "x".repeat(pad) } }) + "\n");
  assert.equal(bytes.length, MAX_LINE_BYTES + 21);
  const c = await openConnection(fx.socketPath);
  try {
    // Everything but the last few bytes stays under the limit while it waits.
    c.s.write(bytes.subarray(0, MAX_LINE_BYTES - 5));
    await sleep(300);
    c.s.write(bytes.subarray(MAX_LINE_BYTES - 5));
    const got = await within(c.lines(1), 10_000);
    assert.ok(got !== null, "no answer to an oversize line");
    const r = got[0] as { ok: boolean; error: string };
    assert.equal(r.ok, false, "an oversize line was booked");
    assert.match(r.error, /longer than 1048576 bytes; connection closed/);
    assert.ok((await within(c.closed, 5000)) !== null, "connection left open after an oversize line");
    assert.equal(clerkd.core.nextSeq, before);
  } finally {
    c.s.destroy();
  }
});

// ── backpressure ─────────────────────────────────────────────────────────────

section("Backpressure: one request per connection at a time");

/** Wait until `value()` has not changed for `quietMs`; return its last value. */
async function settled(value: () => number, quietMs: number, maxMs = 120_000): Promise<number> {
  let last = value();
  let since = Date.now();
  const end = Date.now() + maxMs;
  while (Date.now() - since < quietMs && Date.now() < end) {
    await sleep(100);
    const v = value();
    if (v !== last) {
      last = v;
      since = Date.now();
    }
  }
  return last;
}

checkAsync("a peer that writes requests and never reads the answers stops being served; the answers are not queued in clerkd", async () => {
  const { f, d } = await boot();
  const N = 3000;
  const s: Socket = await new Promise((res, rej) => {
    const c = createConnection(f.socketPath);
    c.once("connect", () => {
      c.off("error", rej);
      res(c);
    });
    c.once("error", rej);
  });
  s.on("error", () => undefined);
  try {
    s.pause(); // reads nothing until told to
    const req = line({ submitter_id: "peer", channel: "c", declared_timestamp: 1, payload: { pad: "x".repeat(64) } });
    s.write(Buffer.concat(new Array<Buffer>(N).fill(req)));
    const booked = await settled(() => d.core.nextSeq, 1500);
    assert.ok(
      booked < N / 2,
      `clerkd booked and answered ${booked} of ${N} requests although the peer read none of the answers`
    );
    // Another submitter is served meanwhile.
    const honest = await new SocketClerkClient({ socketPath: f.socketPath, timeoutMs: 5000 }).submit({
      submitter_id: "honest",
      channel: "c",
      payload: {},
    });
    assert.equal(honest.submitter_id, "honest");
    // Once the peer reads, every request is answered, in order: nothing was dropped.
    s.setEncoding("utf8");
    let text = "";
    const all = new Promise<string[]>((res) => {
      s.on("data", (t: string) => {
        text += t;
        const lines = text.split("\n").slice(0, -1);
        if (lines.length >= N) res(lines);
      });
    });
    s.resume();
    const got = await within(all, 60_000);
    assert.ok(got !== null, `the peer got ${text.split("\n").length - 1} of ${N} answers once it read`);
    const seqs = got.map((l) => {
      const r = JSON.parse(l) as { ok: boolean; receipt: { clerk_seq: number; submitter_id: string } };
      assert.ok(r.ok, l);
      assert.equal(r.receipt.submitter_id, "peer");
      return r.receipt.clerk_seq;
    });
    for (let i = 1; i < seqs.length; i++) assert.ok(seqs[i] > seqs[i - 1], `answer ${i} is out of order`);
    assert.equal(d.core.nextSeq, N + 1);
  } finally {
    s.destroy();
    await d.close();
  }
}, 180_000);

checkAsync("a peer that pipelines requests and reads its answers gets every answer, in order", async () => {
  const { f, d } = await boot();
  const N = 2000;
  try {
    const reqs = Array.from({ length: N }, (_, i) =>
      line({ submitter_id: "s", channel: "c", declared_timestamp: i, payload: { i } })
    );
    const { lines } = await raw(f.socketPath, Buffer.concat(reqs), N, 120_000);
    const rs = lines as Array<{ ok: boolean; receipt: { clerk_seq: number; declared_timestamp: number } }>;
    rs.forEach((r, i) => {
      assert.ok(r.ok);
      assert.equal(r.receipt.clerk_seq, i);
      assert.equal(r.receipt.declared_timestamp, i);
    });
    assert.equal(d.core.nextSeq, N);
  } finally {
    await d.close();
  }
}, 180_000);

checkAsync("a peer that pipelines requests and then ends its side of the connection gets every answer", async () => {
  const { f, d } = await boot();
  const N = 50;
  try {
    const reqs = Array.from({ length: N }, (_, i) =>
      line({ submitter_id: "s", channel: "c", declared_timestamp: i, payload: { i } })
    );
    const text = await new Promise<string>((res, rej) => {
      const s = createConnection(f.socketPath);
      let got = "";
      const timer = setTimeout(() => {
        s.destroy();
        rej(new Error(`connection still open after 30 s; ${got.split("\n").length - 1} answers`));
      }, 30_000);
      s.setEncoding("utf8");
      s.on("connect", () => s.end(Buffer.concat(reqs)));
      s.on("data", (t: string) => (got += t));
      s.on("error", () => undefined);
      s.on("close", () => {
        clearTimeout(timer);
        res(got);
      });
    });
    const answers = text.split("\n").slice(0, -1);
    assert.equal(answers.length, N, `${answers.length} of ${N} answers before the connection closed`);
    answers.forEach((l, i) => {
      const r = JSON.parse(l) as { ok: boolean; receipt: { clerk_seq: number } };
      assert.ok(r.ok, l);
      assert.equal(r.receipt.clerk_seq, i);
    });
    assert.equal(d.core.nextSeq, N);
  } finally {
    await d.close();
  }
}, 60_000);

checkAsync("a peer that pipelines, ends its side and reads only later still gets every answer; nothing is booked unanswered", async () => {
  const { f, d } = await boot();
  const N = 400;
  try {
    const reqs = Array.from({ length: N }, (_, i) =>
      line({ submitter_id: "s", channel: "c", declared_timestamp: i, payload: { pad: "x".repeat(200), i } })
    );
    const s: Socket = await new Promise((res, rej) => {
      const c = createConnection(f.socketPath);
      c.once("connect", () => {
        c.off("error", rej);
        res(c);
      });
      c.once("error", rej);
    });
    s.on("error", () => undefined);
    s.pause(); // read nothing for now
    s.end(Buffer.concat(reqs));
    await sleep(3000);
    let text = "";
    s.setEncoding("utf8");
    const closed = new Promise<void>((res) => s.once("close", () => res()));
    s.on("data", (t: string) => (text += t));
    s.resume();
    assert.ok((await within(closed, 60_000)) !== null, "connection still open 60 s after the peer began to read");
    const answers = text.split("\n").slice(0, -1);
    assert.equal(answers.length, N, `${answers.length} answers, ${d.core.nextSeq} booked`);
    assert.equal(d.core.nextSeq, N, "receipts booked whose answers never left");
    answers.forEach((l, i) => assert.equal((JSON.parse(l) as { receipt: { clerk_seq: number } }).receipt.clerk_seq, i));
  } finally {
    await d.close();
  }
}, 120_000);

section("Fairness: connections take turns, one request each");

checkAsync("two connections that pipeline at once are served round-robin, not one after the other", async () => {
  const { f, d } = await boot();
  const N = 20;
  const a = await openConnection(f.socketPath);
  const b = await openConnection(f.socketPath);
  try {
    await sleep(200); // both accepted by clerkd
    const batch = (who: string) =>
      Buffer.concat(Array.from({ length: N }, (_, i) => line({ submitter_id: who, channel: "c", declared_timestamp: i, payload: { i } })));
    a.s.write(batch("a"));
    b.s.write(batch("b"));
    const got = await within(Promise.all([a.lines(N), b.lines(N)]), 30_000);
    assert.ok(got !== null, "not every request was answered");
    const owner: string[] = [];
    for (const [who, rs] of [["a", got[0]], ["b", got[1]]] as const) {
      (rs as Array<{ ok: boolean; receipt: { clerk_seq: number; declared_timestamp: number } }>).forEach((r, i) => {
        assert.ok(r.ok);
        assert.equal(r.receipt.declared_timestamp, i, `${who}: answer ${i} out of order`);
        owner[r.receipt.clerk_seq] = who;
      });
    }
    let longest = 1;
    for (let i = 1, run = 1; i < owner.length; i++) {
      run = owner[i] === owner[i - 1] ? run + 1 : 1;
      longest = Math.max(longest, run);
    }
    assert.ok(longest <= 3, `one connection was served ${longest} times in a row: ${owner.join("")}`);
  } finally {
    a.s.destroy();
    b.s.destroy();
    await d.close();
  }
}, 60_000);

/**
 * A peer that pipelines as fast as clerkd takes requests and reads every
 * answer: one connection, 200-line batches written while the socket takes
 * them. Prints "served" on its first answer; exits when the connection
 * closes, when its stdin ends, or after 60 s.
 */
const FLOODER = `
const s = require("net").connect(process.argv[1]);
const batch = (JSON.stringify({ submitter_id: "flood", channel: "c", declared_timestamp: null, payload: { n: 1 } }) + "\\n").repeat(200);
const pump = () => { while (s.write(batch)); s.once("drain", pump); };
let first = true;
s.on("connect", pump);
s.on("data", () => { if (first) { first = false; process.stdout.write("served\\n"); } });
s.on("error", () => process.exit(0));
s.on("close", () => process.exit(0));
process.stdin.on("end", () => process.exit(0));
process.stdin.resume();
setTimeout(() => process.exit(0), 60000);
`;

checkAsync("a peer that pipelines requests and reads every answer does not keep clerkd from serving another submitter", async () => {
  const f = makeClerkFixture();
  const child = await startChildClerkd(f.configPath);
  const flooder = spawn(process.execPath, ["-e", FLOODER, f.socketPath], { stdio: ["pipe", "pipe", "ignore"] });
  try {
    const served = new Promise<void>((res) => flooder.stdout!.once("data", () => res()));
    assert.ok((await within(served, 30_000)) !== null, "the flooding peer was never served");
    await sleep(500);
    const honest = new SocketClerkClient({ socketPath: f.socketPath, timeoutMs: 5000 });
    for (let i = 0; i < 3; i++) {
      const r = await honest.submit({ submitter_id: "honest", channel: "c", payload: { i } });
      assert.equal(r.submitter_id, "honest");
    }
    assert.equal(flooder.exitCode, null, "the flooding peer stopped early; nothing was tested");
  } finally {
    flooder.kill("SIGKILL");
    await child.stop("SIGTERM");
  }
}, 120_000);

// ── connection limits ────────────────────────────────────────────────────────

section("Connection limits: a request line must arrive within its deadline");

checkAsync("trickled bytes of an unfinished line hold no slot: all MAX_CONNECTIONS such connections close at the deadline", async () => {
  const f = makeClerkFixture();
  const d = await startClerkd(loadConfigFile(f.configPath), { lineDeadlineMs: 500 });
  const holders: Array<Awaited<ReturnType<typeof openConnection>>> = [];
  let ticker: NodeJS.Timeout | undefined;
  try {
    for (let i = 0; i < MAX_CONNECTIONS; i++) {
      const c = await openConnection(f.socketPath);
      c.s.write("{");
      holders.push(c);
    }
    // One byte every 100 ms: never idle, never a complete line.
    ticker = setInterval(() => {
      for (const c of holders) if (!c.s.destroyed) c.s.write(" ");
    }, 100);
    const texts = await within(Promise.all(holders.map((c) => c.closed)), 5000);
    assert.ok(texts !== null, "trickling connections still open 5 s after a 500 ms line deadline");
    for (const t of texts) {
      assert.match(t, /"ok":false.*request line not complete within 500 ms of its first byte; connection closed/);
    }
    // The slots are free again: a real submission gets through.
    const r = await new SocketClerkClient({ socketPath: f.socketPath, timeoutMs: 5000 }).submit({
      submitter_id: "s",
      channel: "c",
      payload: {},
    });
    assert.equal(r.clerk_seq, 0);
    assert.equal(d.core.nextSeq, 1, "a trickled line was booked");
  } finally {
    if (ticker !== undefined) clearInterval(ticker);
    for (const c of holders) c.s.destroy();
    await d.close();
  }
});

checkAsync("the deadline runs per line: lines that each arrive in time are answered on a longer-lived connection", async () => {
  const f = makeClerkFixture();
  const d = await startClerkd(loadConfigFile(f.configPath), { lineDeadlineMs: 1000 });
  const c = await openConnection(f.socketPath);
  try {
    const req = (n: number) => line({ submitter_id: "s", channel: "c", declared_timestamp: n, payload: { n } });
    const [a, b, e] = [req(1), req(2), req(3)];
    // Each line spans 400 ms; together they take 1200 ms, longer than the deadline.
    c.s.write(a.subarray(0, 10));
    await sleep(400);
    c.s.write(Buffer.concat([a.subarray(10), b.subarray(0, 10)]));
    await sleep(400);
    c.s.write(Buffer.concat([b.subarray(10), e.subarray(0, 10)]));
    await sleep(400);
    c.s.write(e.subarray(10));
    const got = await within(c.lines(3), 5000);
    assert.ok(got !== null, "lines that each arrived within the deadline were not all answered");
    const rs = got as Array<{ ok: boolean; receipt: { clerk_seq: number; declared_timestamp: number } }>;
    assert.deepEqual(rs.map((r) => r.ok), [true, true, true]);
    assert.deepEqual(rs.map((r) => r.receipt.declared_timestamp), [1, 2, 3]);
    assert.equal(c.s.destroyed, false, "the connection was closed although every line was on time");
  } finally {
    c.s.destroy();
    await d.close();
  }
});

checkAsync("startClerkd refuses a line deadline that is not a positive number", async () => {
  const f = makeClerkFixture();
  for (const bad of [0, -1, NaN, Infinity]) {
    const err = await rejects(startClerkd(loadConfigFile(f.configPath), { lineDeadlineMs: bad }));
    assert.ok(err instanceof ClerkdStartError, `${bad}: got ${err.name}`);
  }
  assert.equal(existsSync(`${f.bookPath}.lock`), false);
});

checkAsync("startClerkd refuses a line deadline longer than setTimeout keeps (2147483647 ms), saying so", async () => {
  const f = makeClerkFixture();
  for (const tooLong of [2_147_483_648, 3_000_000_000, Number.MAX_SAFE_INTEGER]) {
    let started: RunningClerkd | undefined;
    let err: Error;
    try {
      err = await rejects(
        startClerkd(loadConfigFile(f.configPath), { lineDeadlineMs: tooLong }).then((d) => (started = d))
      );
    } finally {
      if (started !== undefined) await started.close();
    }
    assert.ok(err instanceof ClerkdStartError, `${tooLong}: got ${err.name}: ${err.message}`);
    assert.match(err.message, new RegExp(`lineDeadlineMs is ${tooLong}; a timer runs for at most 2147483647 ms`));
  }
  assert.equal(existsSync(`${f.bookPath}.lock`), false);
});

checkAsync("the longest line deadline accepted (2147483647 ms) really waits: a line sent in two pieces is answered", async () => {
  const f = makeClerkFixture();
  const d = await startClerkd(loadConfigFile(f.configPath), { lineDeadlineMs: 2_147_483_647 });
  const c = await openConnection(f.socketPath);
  try {
    const l = line({ submitter_id: "s", channel: "c", declared_timestamp: 7, payload: { n: 7 } });
    c.s.write(l.subarray(0, 10));
    await sleep(200);
    c.s.write(l.subarray(10));
    const got = await within(c.lines(1), 5000);
    assert.ok(got !== null, "no answer to a line sent in two pieces");
    assert.equal((got[0] as { ok: boolean }).ok, true, JSON.stringify(got[0]));
  } finally {
    c.s.destroy();
    await d.close();
  }
});

// ── client failure modes ─────────────────────────────────────────────────────

section("SocketClerkClient: every failure rejects, none hangs");

checkAsync("a refused submission rejects with ClerkRefusedError carrying the clerk's reason", async () => {
  const err = await rejects(client.submit({ submitter_id: "s".repeat(300), channel: "c", payload: {} }));
  // Long ids are caught client-side by the same validation.
  assert.ok(err instanceof ClerkRequestError);
  const { f, d, c } = await boot({ allowed_submitters: ["only-me"] });
  try {
    const refused = await rejects(c.submit({ submitter_id: "not-me", channel: "c", payload: {} }));
    assert.ok(refused instanceof ClerkRefusedError, `got ${refused.name}`);
    assert.match(refused.message, /not on this clerk's list/);
    assert.equal(d.core.nextSeq, 0);
    void f;
  } finally {
    await d.close();
  }
});

checkAsync("concurrent submits from one client reach the clerk in call order", async () => {
  const before = clerkd.core.nextSeq;
  // Large first payloads make the early requests slower to send than the late ones.
  const sizes = [200_000, 150_000, 100_000, 50_000, 10, 10, 10, 10, 10, 10, 10, 10];
  const receipts = await Promise.all(sizes.map((n, i) => submitPayload({ i, pad: "x".repeat(n) })));
  receipts.forEach((r, i) => {
    assert.equal(r.clerk_seq, before + i, `request ${i} was booked as ${r.clerk_seq - before}`);
    assert.equal(r.payload_commitment, sha256Hex(canonicalise({ i, pad: "x".repeat(sizes[i]) })));
  });
});

checkAsync("one request in flight at a time: a slow first answer cannot be overtaken", async () => {
  // A stand-in clerk that "books" a request when it answers it, holds request 0
  // for 200 ms and answers the rest at once. Were requests sent concurrently,
  // 1..3 would be booked before 0.
  const booked: number[] = [];
  const { path, server } = await fakeServer((s) => {
    let buf = "";
    s.setEncoding("utf8");
    s.on("data", (d: string) => {
      buf += d;
      const nl = buf.indexOf("\n");
      if (nl === -1) return;
      const i = (JSON.parse(buf.slice(0, nl)) as { payload: { i: number } }).payload.i;
      const answer = () => {
        booked.push(i);
        s.end(JSON.stringify({ ok: true, receipt: { i } }) + "\n");
      };
      if (i === 0) setTimeout(answer, 200);
      else answer();
    });
  });
  try {
    const c = new SocketClerkClient({ socketPath: path, timeoutMs: 5000 });
    await Promise.all([0, 1, 2, 3].map((i) => c.submit({ submitter_id: "s", channel: "c", payload: { i } })));
    assert.deepEqual(booked, [0, 1, 2, 3]);
  } finally {
    server.close();
  }
});

checkAsync("a failed request does not block the ones queued behind it", async () => {
  const c = new SocketClerkClient({ socketPath: fx.socketPath, timeoutMs: 5000 });
  const results = await Promise.allSettled([
    c.submit({ submitter_id: "s", channel: "c", payload: { a: 1 } }),
    c.submit({ submitter_id: "s", channel: "c", payload: { n: new Number(1) } }), // refused locally
    c.submit({ submitter_id: "s", channel: "c", payload: { a: 3 } }),
  ]);
  assert.deepEqual(results.map((r) => r.status), ["fulfilled", "rejected", "fulfilled"]);
});

checkAsync("timeoutMs above 2147483647 (the longest delay setTimeout keeps) is refused, saying so; 2147483647 works", async () => {
  for (const t of [2_147_483_648, 3_000_000_000, Number.MAX_SAFE_INTEGER]) {
    const err = throws(() => new SocketClerkClient({ socketPath: fx.socketPath, timeoutMs: t }));
    assert.match(err.message, new RegExp(`^timeoutMs is ${t}; a timer runs for at most 2147483647 ms`));
  }
  const c = new SocketClerkClient({ socketPath: fx.socketPath, timeoutMs: 2_147_483_647 });
  const before = clerkd.core.nextSeq;
  const r = await c.submit({ submitter_id: "s", channel: "c", payload: { longest: true } });
  assert.equal(r.clerk_seq, before);
});

checkAsync("no clerk at the path ⇒ ClerkTransportError", async () => {
  const c = new SocketClerkClient({ socketPath: join(tempDir(), "nobody.sock"), timeoutMs: 2000 });
  const err = await rejects(c.submit({ submitter_id: "s", channel: "c", payload: {} }));
  assert.ok(err instanceof ClerkTransportError);
  assert.match(err.message, /cannot reach the clerk/);
});

async function fakeServer(onConn: (s: import("net").Socket) => void): Promise<{ path: string; server: Server }> {
  const path = join(tempDir(), "fake.sock");
  const server = createServer(onConn);
  await new Promise<void>((res) => server.listen(path, () => res()));
  return { path, server };
}

checkAsync("a clerk that accepts but never answers ⇒ timeout rejection", async () => {
  const { path, server } = await fakeServer(() => undefined);
  try {
    const c = new SocketClerkClient({ socketPath: path, timeoutMs: 300 });
    const t0 = Date.now();
    const err = await rejects(c.submit({ submitter_id: "s", channel: "c", payload: {} }));
    assert.ok(err instanceof ClerkTransportError);
    assert.match(err.message, /within 300 ms/);
    assert.ok(Date.now() - t0 < 3000);
  } finally {
    server.close();
  }
});

checkAsync("an answer larger than MAX_RESPONSE_BYTES ⇒ ClerkTransportError at once, not at the timeout", async () => {
  const { path, server } = await fakeServer((s) => {
    s.on("error", () => undefined);
    s.write(Buffer.alloc(MAX_RESPONSE_BYTES + 64 * 1024, 0x20)); // no newline, ever
  });
  try {
    const c = new SocketClerkClient({ socketPath: path, timeoutMs: 8000 });
    const t0 = Date.now();
    const err = await rejects(c.submit({ submitter_id: "s", channel: "c", payload: {} }));
    assert.ok(err instanceof ClerkTransportError, `got ${err.name}`);
    assert.match(err.message, /exceeds 8388608 bytes/);
    assert.ok(Date.now() - t0 < 8000, "the client buffered until its timeout");
  } finally {
    server.close();
  }
});

checkAsync("a clerk that answers garbage or hangs up ⇒ ClerkTransportError", async () => {
  const a = await fakeServer((s) => s.end("this is not json\n"));
  const b = await fakeServer((s) => s.destroy());
  const cc = await fakeServer((s) => s.end('{"ok":true,"receipt":"nope"}\n'));
  try {
    for (const [srv, expect] of [
      [a, /not JSON/],
      [b, /closed the connection|cannot reach/],
      [cc, /unknown shape/],
    ] as const) {
      const c = new SocketClerkClient({ socketPath: srv.path, timeoutMs: 2000 });
      const err = await rejects(c.submit({ submitter_id: "s", channel: "c", payload: {} }));
      assert.ok(err instanceof ClerkTransportError, `got ${err.name}`);
      assert.match(err.message, expect);
    }
  } finally {
    a.server.close();
    b.server.close();
    cc.server.close();
  }
});

// ── socket placement ─────────────────────────────────────────────────────────

section("Socket placement: other users cannot reach it; nothing is clobbered");

async function startWith(mutate: (cfg: ClerkConfig, f: ClerkFixture) => void) {
  const f = makeClerkFixture();
  const cfg = loadConfigFile(f.configPath);
  mutate(cfg, f);
  return { f, cfg, start: () => startClerkd(cfg) };
}

checkAsync("start refuses a socket directory other users can enter", async () => {
  const { f, start } = await startWith(() => undefined);
  mkdirSync(join(f.dir, "run"), { mode: 0o755 });
  chmodSync(join(f.dir, "run"), 0o755);
  const err = await rejects(start());
  assert.ok(err instanceof ClerkdStartError, `got ${err.name}: ${err.message}`);
  assert.match(err.message, /mode 0755/);
});

checkAsync("with socket_mode 0600, a directory its group can enter is refused as well", async () => {
  const { f, start } = await startWith(() => undefined);
  mkdirSync(join(f.dir, "run"), { mode: 0o750 });
  chmodSync(join(f.dir, "run"), 0o750);
  const err = await rejects(start());
  assert.ok(err instanceof ClerkdStartError, `got ${err.name}: ${err.message}`);
  assert.match(err.message, /mode 0750, which lets other accounts reach the socket path/);
  assert.equal(existsSync(f.socketPath), false);
});

checkAsync("socket_mode is \"0600\" or \"0660\"; anything else is a config error, not a quiet 0660", async () => {
  const base = { clerk_id: "c", private_key_path: "k", book_path: "b", socket_path: "s" };
  for (const mode of ["0666", "0777", "0644", "0700", "600", "660", 0o600, 0o660, null]) {
    const err = throws(() => parseConfig({ ...base, socket_mode: mode }, "/x"));
    assert.ok(err instanceof ClerkConfigError, `${JSON.stringify(mode)}: got ${err.name}`);
    assert.match(err.message, /"socket_mode" must be "0600" or "0660"/);
  }
  assert.equal(parseConfig({ ...base, socket_mode: "0660" }, "/x").socketMode, 0o660);
  assert.equal(parseConfig({ ...base, socket_mode: "0600" }, "/x").socketMode, 0o600);
  assert.equal(parseConfig(base, "/x").socketMode, 0o600);
});

checkAsync("socket_mode 0660 allows a group-only directory and sets the socket to 0660", async () => {
  const { f, start } = await startWith((cfg) => {
    cfg.socketMode = 0o660;
  });
  mkdirSync(join(f.dir, "run"), { mode: 0o750 });
  chmodSync(join(f.dir, "run"), 0o750);
  const d = await start();
  try {
    assert.equal(statSync(f.socketPath).mode & 0o777, 0o660);
  } finally {
    await d.close();
  }
  chmodSync(join(f.dir, "run"), 0o755);
  const { start: again } = await startWith((cfg) => {
    cfg.socketMode = 0o660;
    cfg.socketPath = f.socketPath;
  });
  const err = await rejects(again());
  assert.match(err.message, /users outside its group/);
});

checkAsync("start refuses to remove a regular file at the socket path", async () => {
  const { f, start } = await startWith(() => undefined);
  mkdirSync(join(f.dir, "run"), { mode: 0o700 });
  writeFileSync(f.socketPath, "precious");
  const err = await rejects(start());
  assert.match(err.message, /not a socket; refusing to remove it/);
  assert.ok(existsSync(f.socketPath));
});

checkAsync("start refuses when another process is listening on the socket path", async () => {
  const { f, start } = await startWith(() => undefined);
  mkdirSync(join(f.dir, "run"), { mode: 0o700 });
  const squatter = createServer(() => undefined);
  await new Promise<void>((res) => squatter.listen(f.socketPath, () => res()));
  try {
    const err = await rejects(start());
    assert.match(err.message, /already listening/);
  } finally {
    squatter.close();
  }
});

checkAsync("a stale socket left by a killed process is cleared, and close() removes the socket", async () => {
  const { f, start } = await startWith(() => undefined);
  mkdirSync(join(f.dir, "run"), { mode: 0o700 });
  const holder = spawn(
    process.execPath,
    ["-e", `require("net").createServer().listen(${JSON.stringify(f.socketPath)}, () => console.log("up"))`],
    { stdio: ["ignore", "pipe", "ignore"] }
  );
  try {
    await new Promise<void>((res, rej) => {
      const t = setTimeout(() => rej(new Error("holder did not start")), 10_000);
      holder.stdout!.once("data", () => {
        clearTimeout(t);
        res();
      });
    });
    holder.kill("SIGKILL");
    await new Promise((res) => holder.once("exit", res));
  } finally {
    if (holder.exitCode === null && holder.signalCode === null) holder.kill("SIGKILL");
  }
  assert.ok(statSync(f.socketPath).isSocket(), "the killed process left no socket file");
  const d = await start();
  try {
    const r = await new SocketClerkClient({ socketPath: f.socketPath }).submit({ submitter_id: "s", channel: "c", payload: {} });
    assert.equal(r.clerk_seq, 0);
  } finally {
    await d.close();
  }
  assert.equal(existsSync(f.socketPath), false, "close() left the socket behind");
});

checkAsync("stopping a clerkd leaves alone a socket another clerkd has since put at its path", async () => {
  const a = makeClerkFixture();
  const da = await startClerkd(loadConfigFile(a.configPath));
  // Only the socket itself is in the directory: the name clerkd bound first is gone.
  assert.deepEqual(readdirSync(dirname(a.socketPath)), ["clerk.sock"]);
  const b = makeClerkFixture();
  const cfgB = loadConfigFile(b.configPath);
  cfgB.socketPath = a.socketPath;
  let db: RunningClerkd | undefined;
  try {
    unlinkSync(a.socketPath); // someone removes A's socket while A runs...
    db = await startClerkd(cfgB); // ...and B, on its own book, takes the path
    await da.close();
    assert.ok(existsSync(a.socketPath), "stopping A removed B's socket");
    const r = await new SocketClerkClient({ socketPath: a.socketPath, timeoutMs: 5000 }).submit({
      submitter_id: "s",
      channel: "c",
      payload: {},
    });
    assert.equal(r.clerk_boot_id, db.core.bootId, "the submission did not reach B");
  } finally {
    await da.close();
    if (db !== undefined) await db.close();
  }
  assert.equal(existsSync(a.socketPath), false, "B's close() left its socket behind");
  assert.deepEqual(readdirSync(dirname(a.socketPath)), []);
});

checkAsync("a socket directory too long for the temporary bind name is refused with the reason", async () => {
  const { f, cfg, start } = await startWith(() => undefined);
  // dir + "/s" fits the platform limit; dir + "/" + 9-byte temporary name does not.
  const limit = process.platform === "linux" ? 107 : 103;
  const dir = join(f.dir, "d".repeat(limit - 4 - Buffer.byteLength(f.dir) - 1));
  mkdirSync(dir, { mode: 0o700 });
  cfg.socketPath = join(dir, "s");
  assert.ok(Buffer.byteLength(cfg.socketPath) <= limit);
  const err = await rejects(start());
  assert.ok(err instanceof ClerkdStartError, `got ${err.name}: ${err.message}`);
  assert.match(err.message, /binds a 9-byte temporary name/);
  assert.equal(existsSync(`${f.bookPath}.lock`), false);
});

section("Teardown");

checkAsync("the shared clerkd closes cleanly", async () => {
  await clerkd.close();
  assert.equal(existsSync(fx.socketPath), false);
});

runAll();
