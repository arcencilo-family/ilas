// ──────────────────────────────────────────────────────────────────────────────
// ILAS — S-4 local receipt store
//
// A convenience cache of witness receipts for an operator inspecting the node.
// IMPORTANT: this local copy is NOT the anchor. The evidential fact is the
// witness's own retention of a receipt in its independent WORM store; this file
// just lets an operator SEE what the node believes it has been given. The
// continuity predicate deliberately reads receipts from the Witness, not from
// here, so that anyone who tampers with (or a bug that corrupts) this cache
// cannot influence the verdict.
// ──────────────────────────────────────────────────────────────────────────────

import { appendFileSync, existsSync, mkdirSync, readFileSync } from "fs";
import { dirname } from "path";
import type { WitnessReceipt } from "./types";

export class ReceiptStore {
  private readonly receipts: WitnessReceipt[] = [];
  private readonly path: string | null;

  constructor(options?: { path?: string }) {
    this.path = options?.path ?? null;
    if (this.path && existsSync(this.path)) {
      const raw = readFileSync(this.path, "utf8");
      for (const line of raw.split("\n")) {
        if (line.trim().length === 0) continue;
        this.receipts.push(JSON.parse(line) as WitnessReceipt);
      }
    }
  }

  add(receipt: WitnessReceipt): void {
    this.receipts.push(receipt);
    if (this.path) {
      mkdirSync(dirname(this.path), { recursive: true });
      appendFileSync(this.path, JSON.stringify(receipt) + "\n");
    }
  }

  getAll(): readonly WitnessReceipt[] {
    return this.receipts;
  }
}
