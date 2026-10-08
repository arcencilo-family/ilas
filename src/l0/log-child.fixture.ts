// ──────────────────────────────────────────────────────────────────────────────
// ILAS — child-process helper for l0.file.test.ts and l0.lock.test.ts (not a
// test itself). Each mode does one thing with a durable LockedEvidenceLog and
// prints one JSON line on stdout. The tests run it in a child process so that a
// log that blocks (a FIFO at the log path) is killed by the parent's timeout
// instead of hanging the run, so that a second process can hold a log's writer
// lock, and so that a file-size limit (ulimit -f) applies to one process only.
//   node -r ts-node/register src/l0/log-child.fixture.ts <mode> <path> [arg]
//
//   load <path>               construct, print the durability info
//   swap-fifo <path>          construct, append, replace the file with a FIFO,
//                             append again, print what the second append did
//   hold <path>               construct, print { pid }, then keep the log open
//                             until stdin closes, and exit normally
//   append-big <path> <bytes> construct, append an entry whose parameters hold
//                             <bytes> characters, then a small one; print both
// ──────────────────────────────────────────────────────────────────────────────

import { spawnSync } from "child_process";
import { unlinkSync } from "fs";
import { LockedEvidenceLog } from "./index";

const [mode, path, arg] = process.argv.slice(2);

function entry(n: number, parameters: Record<string, unknown> = { n }) {
  return {
    timestamp: 1_700_000_000_000 + n,
    moduleId: "child",
    eventType: "unit",
    provenanceTag: "LaneA" as const,
    parameters,
    outcome: "ok",
  };
}

function outcome(fn: () => void): { ok: true } | { ok: false; name: string; message: string } {
  try {
    fn();
    return { ok: true };
  } catch (err) {
    return { ok: false, name: (err as Error).name, message: (err as Error).message };
  }
}

function print(value: unknown): void {
  process.stdout.write(JSON.stringify(value) + "\n");
}

switch (mode) {
  case "load": {
    const log = new LockedEvidenceLog({ path, fsync: false });
    print({ info: log.getDurabilityInfo(), length: log.length });
    break;
  }
  case "swap-fifo": {
    const log = new LockedEvidenceLog({ path, fsync: false });
    void log.append(entry(0));
    unlinkSync(path);
    const mk = spawnSync("mkfifo", [path], { encoding: "utf8" });
    if (mk.status !== 0) {
      print({ setupFailed: `mkfifo: ${mk.stderr ?? String(mk.error)}` });
      break;
    }
    const second = outcome(() => void log.append(entry(1)));
    print({ second, length: log.length, info: log.getDurabilityInfo() });
    break;
  }
  case "hold": {
    const log = new LockedEvidenceLog({ path, fsync: false });
    print({ pid: process.pid, info: log.getDurabilityInfo() });
    process.stdin.resume();
    process.stdin.on("end", () => process.exit(0));
    break;
  }
  case "append-big": {
    const log = new LockedEvidenceLog({ path, fsync: false });
    const big = outcome(() => void log.append(entry(100, { pad: "x".repeat(Number(arg)) })));
    const afterBig = { length: log.length, info: log.getDurabilityInfo() };
    const small = outcome(() => void log.append(entry(101)));
    print({
      loadState: afterBig.info.loadState,
      big,
      afterBig,
      small,
      length: log.length,
      hashes: log.getAll().map((e) => e.hash),
    });
    break;
  }
  default:
    print({ setupFailed: `unknown mode ${mode}` });
}
