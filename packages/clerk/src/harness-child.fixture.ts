// ──────────────────────────────────────────────────────────────────────────────
// Fixture for harness-signal.test.ts (not a test file itself).
//
// A stand-in for a clerk test file in the middle of its run: it makes a clerk
// fixture (a temp directory), starts clerkd as a child process the way the
// tests do, prints {"clerkd": <pid>, "dir": <path>} as one JSON line, and then
// waits until it is stopped. harness-signal.test.ts stops it with a signal and
// checks that clerkd and the directory went with it.
// ──────────────────────────────────────────────────────────────────────────────

import { makeClerkFixture, startChildClerkd } from "./test-support";

void (async () => {
  const f = makeClerkFixture();
  const clerkd = await startChildClerkd(f.configPath);
  process.stdout.write(JSON.stringify({ clerkd: clerkd.child.pid, dir: f.dir }) + "\n");
  setInterval(() => undefined, 60_000);
})().catch((err: unknown) => {
  process.stderr.write(`fixture failed: ${(err as Error).stack ?? String(err)}\n`);
  process.exit(1);
});
