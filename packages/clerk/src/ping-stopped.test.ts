// ──────────────────────────────────────────────────────────────────────────────
// Reference clerk — `ping` against a clerkd that has STOPPED after a failed
// book write must say so and fail, not pass as "answering".
//   npx ts-node packages/clerk/src/ping-stopped.test.ts
// ──────────────────────────────────────────────────────────────────────────────

import assert from "assert";
import { main, EXIT_STOPPED } from "./cli";
import { pingClerkd, SocketClerkClient } from "./client";
import { loadConfigFile } from "./config";
import { startClerkd } from "./server";
import { checkAsync, makeClerkFixture, rejects, runAll, section } from "./test-support";

section("ping reports a stopped clerkd");

checkAsync("a healthy clerkd: ping exits 0; after a failed book write: ping says STOPPED and exits 4", async () => {
  const fx = makeClerkFixture();
  const running = await startClerkd(loadConfigFile(fx.configPath));
  const book = (running.core as unknown as { book: { fd: number } }).book;
  const realFd = book.fd;
  const lines: string[] = [];
  const io = { out: (l: string) => lines.push(l), err: (l: string) => lines.push(l) };
  try {
    assert.equal(await main(["ping", "--socket", fx.socketPath], io), 0, lines.join("\n"));
    assert.doesNotMatch(lines.join("\n"), /STOPPED/);

    const client = new SocketClerkClient({ socketPath: fx.socketPath });
    await client.submit({ submitter_id: "s", channel: "c", payload: { n: 0 } });
    // Fault injection: the next book write fails, which stops the clerk.
    book.fd = -1;
    await rejects(client.submit({ submitter_id: "s", channel: "c", payload: { n: 1 } }));
    book.fd = realFd;
    assert.ok(running.core.failure !== null, "the clerk did not stop");

    const r = await pingClerkd(fx.socketPath, 5_000);
    assert.ok(r.error !== null && r.error.startsWith("clerk stopped:"), `ping saw: ${String(r.error)}`);

    lines.length = 0;
    const code = await main(["ping", "--socket", fx.socketPath], io);
    assert.equal(code, EXIT_STOPPED, lines.join("\n"));
    assert.match(lines.join("\n"), /STOPPED and refuses every request until restarted: clerk stopped:/);
  } finally {
    book.fd = realFd;
    await running.close();
  }
});

runAll();
