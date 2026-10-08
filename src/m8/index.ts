// ──────────────────────────────────────────────────────────────────────────────
// ILAS / M8 Conservation Auditor
// 2026-06-13 (CEST), Frank Böhm + AI colleagues
//
// First shipped invariant: TOOL-CALL <-> RESULT PAIRING.
// Every tool_call has exactly one matching tool_result and vice versa.
//
// Bounds, stated UP FRONT not as footnote:
//
//   1. M8 audits the BOOK, not the WORLD. It cannot catch a runtime that
//      fabricates a matched call+result pair it never executed: both halves
//      land in the stream and read clean. The pairing invariant proves the
//      ledger balances, not that the entries describe reality. Tests assert
//      this as correct behaviour, not as a miss.
//
//   2. M8's real-time verdict is EPHEMERAL; the evidence is PERMANENT.
//      The in-memory session map dies on M8 restart, so dangling sessions
//      that never closed disappear from the live view. The underlying
//      tool_event entries in L0 are durable and integrity-verifiable via
//      the Merkle chain, so any session's pairing is reconstructable
//      post-hoc by replaying L0 offline. Crash case = real-time miss,
//      forensic replay catches.
//
// Severities, deterministic — each alarm is decided by a fact in the stream,
// never by a probability:
//   - RESULT with NO matching CALL                -> hard_alarm
//       orphan; fabrication threat; strict (decided when the result arrives);
//       real-time; ungameable in the pairing axis (an attacker cannot fake a
//       matched pair without a real result existing in the stream).
//   - SESSION_CLOSE with unmatched CALL(s)        -> soft_alarm
//       dangling-at-close; decided at a deterministic boundary (the close).
//   - dangling mid-session past danglingThresholdMs -> informational
//       liveness hint; NOT graded as a security signal. The threshold absorbs
//       upstream flush latency; it is NOT a probability cut.
//
// V0 mapping (unchanged contract):
//   hard_alarm -> QUARANTINED
//   soft_alarm -> DEGRADED
//   informational -> no signal; surface to ops dashboards only.
// ──────────────────────────────────────────────────────────────────────────────

import type { LockedEvidenceLog } from "../l0";
import type { ModuleSignal } from "../types";

export type IngestStatus = "ok" | "matched" | "orphan_alarm";
export type CloseStatus = "clean" | "dangling_alarm";

export interface IngestResult {
  status: IngestStatus;
  signal?: ModuleSignal;
}

export interface CloseResult {
  status: CloseStatus;
  danglingCallIds: string[];
  signal?: ModuleSignal;
}

export interface PendingEntry {
  callId: string;
  sessionId: string;
  agentId: string;
  callTs: number;
  ageMs: number;
}

export interface LivenessReport {
  pending: PendingEntry[];
}

interface CallRecord {
  sessionId: string;
  agentId: string;
  toolName: string | null;
  callTs: number;
  matched: boolean;
}

const DEFAULT_DANGLING_THRESHOLD_MS = 30_000;
const NO_SESSION_SENTINEL = "__no_session__";

export class ConservationAuditor {
  private readonly calls = new Map<string, CallRecord>();
  private readonly sessions = new Map<string, Set<string>>();
  private danglingThresholdMs = DEFAULT_DANGLING_THRESHOLD_MS;

  constructor(
    private readonly log?: LockedEvidenceLog,
    private readonly clock: () => number = Date.now,
  ) {}

  setDanglingThresholdMs(ms: number): void {
    if (!(ms > 0)) throw new Error("danglingThresholdMs must be > 0");
    this.danglingThresholdMs = ms;
  }

  ingestCall(
    callId: string,
    sessionId: string | null | undefined,
    agentId: string,
    toolName: string | null = null,
    timestamp?: number,
  ): IngestResult {
    const ts = timestamp ?? this.clock();
    const sid = sessionId && sessionId.length > 0 ? sessionId : NO_SESSION_SENTINEL;

    if (!this.calls.has(callId)) {
      this.calls.set(callId, {
        sessionId: sid,
        agentId,
        toolName,
        callTs: ts,
        matched: false,
      });
      let set = this.sessions.get(sid);
      if (!set) {
        set = new Set();
        this.sessions.set(sid, set);
      }
      set.add(callId);
    }
    this.log?.enqueue({
      timestamp: ts,
      moduleId: "m8",
      eventType: "call_recorded",
      provenanceTag: "LaneA",
      parameters: { callId, sessionId: sid, agentId, toolName },
      outcome: "ok",
    });
    return { status: "ok" };
  }

  ingestResult(
    callId: string,
    sessionId: string | null | undefined,
    agentId: string,
    toolName: string | null = null,
    timestamp?: number,
  ): IngestResult {
    const ts = timestamp ?? this.clock();
    const sid = sessionId && sessionId.length > 0 ? sessionId : NO_SESSION_SENTINEL;
    const record = this.calls.get(callId);

    if (!record) {
      this.log?.enqueue({
        timestamp: ts,
        moduleId: "m8",
        eventType: "orphan_result",
        provenanceTag: "LaneA",
        parameters: { callId, sessionId: sid, agentId, toolName },
        outcome: "orphan_alarm",
      });
      const signal: ModuleSignal = {
        moduleId: "m8",
        severity: "hard_alarm",
        message: `tool_result with no matching tool_call (callId=${callId})`,
        timestamp: ts,
      };
      return { status: "orphan_alarm", signal };
    }

    record.matched = true;
    this.log?.enqueue({
      timestamp: ts,
      moduleId: "m8",
      eventType: "pair_matched",
      provenanceTag: "LaneA",
      parameters: { callId, sessionId: sid, agentId, toolName },
      outcome: "matched",
    });
    return { status: "matched" };
  }

  closeSession(sessionId: string, agentId: string, timestamp?: number): CloseResult {
    const ts = timestamp ?? this.clock();
    const callIds = this.sessions.get(sessionId);
    const dangling: string[] = [];

    if (callIds) {
      for (const cid of callIds) {
        const r = this.calls.get(cid);
        if (r && !r.matched) dangling.push(cid);
        this.calls.delete(cid);
      }
      this.sessions.delete(sessionId);
    }

    if (dangling.length === 0) {
      this.log?.enqueue({
        timestamp: ts,
        moduleId: "m8",
        eventType: "session_closed",
        provenanceTag: "LaneA",
        parameters: { sessionId, agentId, dangling: [] },
        outcome: "clean",
      });
      return { status: "clean", danglingCallIds: [] };
    }

    this.log?.enqueue({
      timestamp: ts,
      moduleId: "m8",
      eventType: "session_closed",
      provenanceTag: "LaneA",
      parameters: { sessionId, agentId, dangling },
      outcome: "dangling_alarm",
    });
    const signal: ModuleSignal = {
      moduleId: "m8",
      severity: "soft_alarm",
      message: `session ${sessionId} closed with ${dangling.length} unmatched tool_call(s)`,
      timestamp: ts,
    };
    return { status: "dangling_alarm", danglingCallIds: dangling, signal };
  }

  /**
   * Pull-based liveness scan. Returns calls older than danglingThresholdMs
   * with no matching result yet. PURE INFORMATION, not a security signal.
   * Surface to ops dashboards; do not feed into VerdictEngine.
   */
  evaluateLiveness(timestamp?: number): LivenessReport {
    const now = timestamp ?? this.clock();
    const cutoff = now - this.danglingThresholdMs;
    const pending: PendingEntry[] = [];
    for (const [callId, r] of this.calls.entries()) {
      if (!r.matched && r.callTs <= cutoff) {
        pending.push({
          callId,
          sessionId: r.sessionId,
          agentId: r.agentId,
          callTs: r.callTs,
          ageMs: now - r.callTs,
        });
      }
    }
    return { pending };
  }

  getOpenSessions(): number {
    return this.sessions.size;
  }

  getPendingCount(): number {
    let n = 0;
    for (const r of this.calls.values()) if (!r.matched) n++;
    return n;
  }
}
