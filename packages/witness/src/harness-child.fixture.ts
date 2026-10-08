// ──────────────────────────────────────────────────────────────────────────────
// Reference witness — fixture for harness-signal.test.ts. Not a test itself.
//
// A stand-in for a test file that uses test-support: it makes a temp dir,
// starts a child it tracks, and starts a detached process it tracks by pid (as
// cli.test.ts does with a witness behind npx), then prints
// {"child":…,"stray":…,"dir":…} on one line.
//
//   (no argument)  idles until it is signalled
//   busy           runs 40 synchronous "tests" of 250 ms, printing "step <n>"
//                  after each and calling betweenTests() between them, as
//                  cli.test.ts and interop.test.ts do; then prints "done" and
//                  exits 0 (the exit handler cleans up)
// ──────────────────────────────────────────────────────────────────────────────

import { spawn } from "child_process";
import { writeFileSync } from "fs";
import { join } from "path";

import { betweenTests, tempDir, trackChild, trackPid } from "./test-support";

const IDLE = ["-e", "setInterval(() => {}, 1000)"];

const dir = tempDir("ilas-witness-harness-");
writeFileSync(join(dir, "witness.key"), "a test key\n");
const child = trackChild(spawn(process.execPath, IDLE, { stdio: "ignore" }));
const stray = spawn(process.execPath, IDLE, { stdio: "ignore", detached: true });
stray.unref();
if (stray.pid !== undefined) trackPid(stray.pid);
process.stdout.write(JSON.stringify({ child: child.pid, stray: stray.pid, dir }) + "\n");

if (process.argv[2] === "busy") {
  void (async () => {
    for (let step = 0; step < 40; step++) {
      const end = Date.now() + 250;
      while (Date.now() < end) {
        // a synchronous test: no turn of the event loop
      }
      process.stdout.write(`step ${step}\n`);
      await betweenTests();
    }
    process.stdout.write("done\n");
    process.exit(0);
  })();
} else {
  setInterval(() => undefined, 1000);
}
