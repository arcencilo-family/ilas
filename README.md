# ILAS — Integrity Layer for Agentic Systems

Detect when your AI agent has been compromised, is leaking data, or is having its permissions silently eroded.

---

## What it is

ILAS is a middleware integrity layer written in TypeScript. It sits between your agent runtime and the external interfaces it touches — tool calls, outbound content, configuration — and maintains a cryptographically verifiable record of what happened. It is framework-agnostic: no assumptions about your orchestration stack, model provider, or deployment environment.

## What it is NOT

- Not an endpoint security product. It does not scan for malware or monitor syscalls.
- Not a replacement for patching your agent runtime. Vulnerabilities in the underlying model or framework are out of scope.
- Not tied to any specific agent platform. No LangChain, no AutoGen, no vendor lock-in.

---

## The Kill Stack

Four components that ship today:

### L0 — Locked Evidence Log
Append-only Merkle chain. Every event across all modules lands here. Each entry carries a SHA-256 hash over its full payload plus the previous entry's hash. `verify()` walks the chain and returns the exact sequence number where tampering occurred. Nothing is ever modified or deleted.

### M3 — Canary Tripwire Injection
Plant cryptographically random 32-byte tokens at three depths (`shallow`, `medium`, `deep`). Run `checkOutbound(content)` on anything leaving the agent boundary. First hit returns `alarm`; three or more hits in a rolling 7-day window returns `quarantine`. Canaries can be rotated without losing planted identity.

### M5 — Configuration Drift Limits
Register parameters with baseline values. `recordChange()` returns a verdict on every mutation: `ok`, `flagged`, or `material`. Three triggers — single-parameter rolling change exceeds 5% of baseline in 30 days; cumulative change across all parameters exceeds 10% in 30 days; any parameter suppressed to near-zero (≤ 0.001). Catches slow permission erosion that looks like normal noise in isolation.

### V0 — Verdict Engine
Aggregates `ModuleSignal` inputs from L0, M3, and M5 into a single `IntegrityState`. Four states: `UNVERIFIED → DEGRADED → VERIFIED`, with `QUARANTINED` as a one-way trap. Transition rules are deterministic and conservative: any `hard_alarm` goes to `QUARANTINED` immediately from any state; upgrades require explicit verification cycles, not just the absence of alarms; recovery from `QUARANTINED` requires an `independentReviewComplete` flag — clean signals alone are not sufficient. Optional staleness timeout degrades state if no verification cycle runs within a configured window.

---

## State machine

```
UNVERIFIED ──[clean cycle]──▶ DEGRADED ──[clean cycle]──▶ VERIFIED
     │                            │                               │
     │                     [soft_alarm]                    [soft_alarm]
     │                            │                               │
     │                            ▼                               │
     └──[soft_alarm]──────▶ DEGRADED ◀─────────────────────────--┘
     │                            │
     │                            │
  [hard_alarm]              [hard_alarm]                   [hard_alarm]
     │                            │                               │
     └────────────────────────────┼───────────────────────────────┘
                                  ▼
                            QUARANTINED
                                  │
               [clean cycle + independentReviewComplete=true]
                                  │
                                  ▼
                             DEGRADED
```

---

## Install

```bash
npm install
npm run build
```

Requires Node 18+. No runtime dependencies beyond Node's built-in `crypto`.

---

## Quick start

```typescript
import { ILASKillStack } from "./src";
import type { ModuleSignal } from "./src";

const ilas = new ILASKillStack();

// Plant canaries before any agent output is processed
const token = ilas.canary.plantCanary("deep");

// Register parameters you want drift-monitored
ilas.drift.registerParameter("max_tool_calls", 50);
ilas.drift.registerParameter("output_token_limit", 4096, true); // structural

// In your agent's output pipeline:
const check = ilas.canary.checkOutbound(agentOutput);
if (check.hit) {
  const signal: ModuleSignal = {
    moduleId: "m3",
    severity: check.severity === "quarantine" ? "hard_alarm" : "soft_alarm",
    message: `canary hit: ${check.tokens?.map(t => t.id).join(", ")}`,
    timestamp: Date.now(),
  };
  ilas.verdict.processSignal(signal);
}

// Run a verification cycle after each agent turn:
const allClear = ilas.verdict.runVerificationCycle([
  { moduleId: "m3", severity: "clean", message: "no hits", timestamp: Date.now() },
  { moduleId: "m5", severity: "clean", message: "within bounds", timestamp: Date.now() },
]);

console.log(ilas.status());
// { state: 'DEGRADED', logSize: 4, activeCanaries: 1, cumulativeDrift: 0 }
```

---

## Tests

```bash
# Unit tests for the Verdict Engine
npx ts-node src/v0/v0.test.ts

# Full integration smoke test
npx ts-node src/integration.test.ts
```

---

## Project layout

```
src/
├── types.ts          # Shared interfaces and enums
├── index.ts          # ILASKillStack entry point
├── l0/               # Locked Evidence Log (Merkle chain)
├── m3/               # Canary Tripwire Injection
├── m5/               # Configuration Drift Limits
└── v0/               # Verdict Engine
```

---

## Threat model

ILAS is designed for a specific attacker position: an agent that has been manipulated — via prompt injection, poisoned tool output, or indirect instruction — into behaving outside its intended authorization envelope. The signals it watches for:

- **Exfiltration**: canary tokens appearing in outbound content that should never have accessed them
- **Injection persistence**: repeated canary hits suggesting ongoing context contamination
- **Permission erosion**: configuration parameters drifting toward values that expand agent authority
- **Suppression**: parameters pushed to near-zero to disable safety limits

ILAS does not protect against a compromised host, a malicious model provider, or an attacker with direct access to the process. The `LockedEvidenceLog` provides tamper *detection*, not tamper *prevention* — if an attacker can write to process memory, the chain can be rebuilt. The value is in making silent manipulation expensive and leaving a verifiable audit trail when it isn't.

---

## License

MIT

---

Created by the Arcencilo Family. Contributions welcome.

*"The integrity of an autonomous agent is not a feature. It is a prerequisite."*
