export { IntegrityState } from "./types";
export type {
  LogEntry,
  CanaryToken,
  DriftSnapshot,
  ModuleSignal,
  ProvenanceTag,
  CanaryDepth,
  SignalSeverity,
  ActionType,
  PermissionResult,
  EscalationLevel,
  EscalationRecord,
  EscalateStatus,
  EscalateResult,
  ScanCommitment,
  ScanStatus,
  RotationResult,
  PassCondition,
  ExpectedBehavior,
  ProbeCategory,
  DivergenceLevel,
  Probe,
  ProbeResult,
} from "./types";

export {
  LockedEvidenceLog,
  L0WriteError,
  L0ClerkError,
  L0PayloadError,
  recomputeHeadHashAt,
} from "./l0";
export type {
  VerifyResult,
  L0LoadState,
  DurabilityInfo,
  ClerkSubmitClient,
  ClerkRoute,
  ClerkClockStamp,
  LockedEvidenceLogOptions,
} from "./l0";
export { publicKeyFingerprint } from "./l0/fingerprint";

// ── S-4 anchor preparation: head commits and continuity (docs/S4-WIRE-SPEC.md
// §3–§6). S-4-READY, not complete — the anchor needs a witness the deployer runs.
export {
  NullWitness,
  HeadCommitEmitter,
  ContinuityVerifier,
  ReceiptStore,
  GENESIS_HEAD_HASH,
} from "./s4";
export type {
  Witness,
  HeadCommit,
  WitnessReceipt,
  ContinuityStatus,
  ContinuityReport,
  ContinuityMismatch,
} from "./s4";

export { CanaryManager } from "./m3";
export type { CheckOutboundResult, CheckSeverity } from "./m3";

export { DriftMonitor } from "./m5";
export type { ChangeResult, ChangeStatus } from "./m5";

export { VerdictEngine } from "./v0";
export type { HistoryEntry } from "./v0";

export { ProvenanceTracker } from "./m7";
export { PrivilegeManager } from "./m6";
export { ScanScheduler } from "./m1";
export { DetectionRotator } from "./m2";
export { ProbeManager, STARTER_PROBES } from "./m4";
export { ConservationAuditor } from "./m8";
export type {
  IngestStatus as M8IngestStatus,
  CloseStatus as M8CloseStatus,
  IngestResult as M8IngestResult,
  CloseResult as M8CloseResult,
  PendingEntry as M8PendingEntry,
  LivenessReport as M8LivenessReport,
} from "./m8";

// ── ILASKillStack ─────────────────────────────────────────────────────────────

import { IntegrityState } from "./types";
import { LockedEvidenceLog } from "./l0";
import type { ClerkRoute, DurabilityInfo } from "./l0";
import {
  NullWitness,
  HeadCommitEmitter,
  ContinuityVerifier,
} from "./s4";
import type { Witness, HeadCommit, ContinuityReport } from "./s4";
import { CanaryManager } from "./m3";
import { DriftMonitor } from "./m5";
import { VerdictEngine } from "./v0";
import { ProvenanceTracker } from "./m7";
import { PrivilegeManager } from "./m6";
import { ScanScheduler } from "./m1";
import { DetectionRotator } from "./m2";
import { ProbeManager } from "./m4";
import { ConservationAuditor } from "./m8";

export interface ILASKillStackOptions {
  /** Enable durable L0 by pointing at a JSONL file. Omit for in-memory. */
  logPath?: string;
  /**
   * With logPath: fsync the L0 file after every entry. Default true; false only
   * for tests and benchmarks that ask for it (LockedEvidenceLogOptions.fsync).
   */
  fsync?: boolean;
  /** Route every L0 append through a clerk's client. */
  clerk?: ClerkRoute;
  /**
   * The continuity witness. Defaults to NullWitness — which means continuity can
   * only ever report CANNOT_VERIFY_CONTINUITY until a real, independent witness
   * is supplied. Choosing that witness is the deployer's decision, not the code's
   * (docs/S4-WIRE-SPEC.md §2).
   */
  witness?: Witness;
  /**
   * Who operates the witness and the clerk, as the deployer declares it. ILAS
   * cannot check this; it is carried into status() as a claim, never as a fact.
   */
  declarations?: DeploymentDeclarations;
}

/**
 * Deployer declarations. Recommended wording (docs/S4-WIRE-SPEC.md §2):
 * "self-witnessed" when the node's own operator runs the witness, or
 * "independent-operator: <role>" when someone else does.
 */
export interface DeploymentDeclarations {
  witness?: string;
  clerk?: string;
}

/**
 * The declarations as reported. `verified` is always false: they are claims.
 * ILAS does not parse the declaration strings; one that is blank (empty or
 * whitespace only) states nothing and is reported as null, like one that was
 * not given. Beside them it reports what it
 * can see for itself: whether a witness and a clerk route are configured at
 * all (`warnings`, when that contradicts what is declared or left undeclared),
 * and the fingerprints of the keys it was given (`keys`), for each operator to
 * compare out of band with the key they hold. Neither field verifies a claim.
 */
export interface DeclarationReport {
  witness: string | null;
  clerk: string | null;
  verified: false;
  /** Plain sentences, one per contradiction between the declarations and the configuration. */
  warnings: string[];
  keys: {
    /** publicKeyFingerprint of the clerk route's public key; null without a route. */
    clerk: string | null;
    /**
     * publicKeyFingerprint of the witness's public key, read through the
     * witness's optional publicKeyFingerprint() method; null when the witness
     * has no such method, or no usable key.
     */
    witness: string | null;
  };
}

export interface KillStackStatus {
  state: IntegrityState;
  logSize: number;
  activeCanaries: number;
  cumulativeDrift: number;
  provenanceMismatches: number;
  activeEscalations: number;
  nextScanIn: number;
  rotationCycles: number;
  probeLibrarySize: number;
  openSessions: number;
  pendingPairs: number;

  // ── S-4 additive fields (do NOT feed back into `state`; v0 is untouched) ──
  // `state` above is the v0 IntegrityState, unchanged. Durability and continuity
  // are reported SEPARATELY so a cannot-verify load or a continuity mismatch is
  // visible on the endpoint without silently reconciling into v0.
  logDurability: DurabilityInfo;
  continuity: ContinuityReport["status"];
  lastHeadCommit: HeadCommit | null;
  declarations: DeclarationReport;
}

export class ILASKillStack {
  readonly log:        LockedEvidenceLog;
  readonly canary:     CanaryManager;
  readonly drift:      DriftMonitor;
  readonly verdict:    VerdictEngine;
  readonly provenance: ProvenanceTracker;
  readonly privilege:  PrivilegeManager;
  readonly scanner:    ScanScheduler;
  readonly rotation:   DetectionRotator;
  readonly probes:     ProbeManager;
  readonly auditor:    ConservationAuditor;

  // ── S-4 ──
  readonly witness:    Witness;
  readonly headCommit: HeadCommitEmitter;
  readonly continuity: ContinuityVerifier;

  private readonly declared: { readonly witness: string | null; readonly clerk: string | null };
  private readonly declarationWarnings: readonly string[];

  constructor(options?: ILASKillStackOptions) {
    this.log = new LockedEvidenceLog({
      ...(options?.logPath ? { path: options.logPath } : {}),
      ...(options?.clerk ? { clerk: options.clerk } : {}),
      ...(options?.fsync !== undefined ? { fsync: options.fsync } : {}),
    });

    // If a verified chain was loaded, suppress the bootstrap re-seed that
    // module constructors (ProbeManager's 10 appends) would otherwise emit, for
    // each entry already on the chain. A bootstrap entry the chain lacks (an
    // earlier start was interrupted part-way) is appended now. The guard is
    // toggled HERE, at the assembly, so no mechanism module is touched.
    const loadedExisting = this.log.loadedExisting();
    if (loadedExisting) this.log.beginReplayGuard();

    this.canary     = new CanaryManager(this.log);
    this.drift      = new DriftMonitor(this.log);
    this.verdict    = new VerdictEngine(this.log);
    this.provenance = new ProvenanceTracker(this.log);
    this.privilege  = new PrivilegeManager(this.log);
    this.scanner    = new ScanScheduler(this.log);
    this.rotation   = new DetectionRotator(this.log);
    this.probes     = new ProbeManager(this.log);
    this.auditor    = new ConservationAuditor(this.log);

    if (loadedExisting) this.log.endReplayGuard();

    // S-4 wiring. NullWitness by default: continuity is CANNOT_VERIFY_CONTINUITY
    // until a real independent witness is supplied (docs/S4-WIRE-SPEC.md §2).
    this.witness    = options?.witness ?? new NullWitness();
    this.headCommit = new HeadCommitEmitter(this.log, this.witness);
    this.continuity = new ContinuityVerifier(this.log, this.witness);

    // Copied, not referenced: a caller mutating its options object later must not
    // change what status() reports. A blank declaration states nothing: it is
    // reported as not given (null), and warned about as such.
    this.declared = Object.freeze({
      witness: statedDeclaration(options?.declarations?.witness),
      clerk: statedDeclaration(options?.declarations?.clerk),
    });
    this.declarationWarnings = Object.freeze(
      declarationWarnings(
        this.declared,
        !(this.witness instanceof NullWitness),
        this.log.getClerkKeyFingerprint() !== null
      )
    );
  }

  /**
   * Stop the verdict engine's staleness timer, then close the L0 log: stop
   * writing and release its writer lock. Await settleEvidence() first. Later
   * appends throw L0WriteError.
   */
  close(): void {
    this.verdict.clearStalenessTimeout();
    this.log.close();
  }

  /**
   * The constructor cannot await the ten bootstrap receipts. Operational code
   * must await this (or use create) before treating the stack as initialized.
   */
  async ready(): Promise<void> {
    await this.log.settle();
  }

  /** Await every queued clerk receipt before any result is disposed or trusted. */
  settleEvidence(): Promise<void> {
    return this.log.settle();
  }

  static async create(options?: ILASKillStackOptions): Promise<ILASKillStack> {
    const stack = new ILASKillStack(options);
    await stack.ready();
    return stack;
  }

  // ── S-4 operations ──────────────────────────────────────────────────────────

  /** Emit the startup HEAD_COMMIT (docs/S4-WIRE-SPEC.md §3). Call once, after construction. */
  emitStartupCommit(): HeadCommit {
    return this.headCommit.emitStartupCommit();
  }

  /** Emit a cadence HEAD_COMMIT. Decorative; evidential of nothing (docs/S4-WIRE-SPEC.md §3). */
  emitHeadCommit(): HeadCommit {
    return this.headCommit.emit();
  }

  /**
   * Run the all-retained-receipts continuity predicate (docs/S4-WIRE-SPEC.md
   * §6). Read-only. A clean result upgrades nothing; a missing witness yields
   * CANNOT_VERIFY_CONTINUITY.
   */
  verifyContinuity(): ContinuityReport {
    return this.continuity.verify();
  }

  status(): KillStackStatus {
    return {
      state:               this.verdict.getState(),
      logSize:             this.log.length,
      activeCanaries:      this.canary.getActiveCanaries().length,
      cumulativeDrift:     this.drift.getCumulativeDrift(),
      provenanceMismatches:this.provenance.getMismatchCount(),
      activeEscalations:   this.privilege.getActiveEscalations().length,
      nextScanIn:          this.scanner.getNextScanIn(),
      rotationCycles:      this.rotation.getRotationCount(),
      probeLibrarySize:    this.probes.getProbeCount(),
      openSessions:        this.auditor.getOpenSessions(),
      pendingPairs:        this.auditor.getPendingCount(),

      logDurability:       this.log.getDurabilityInfo(),
      continuity:          this.continuity.verify().status,
      lastHeadCommit:      this.headCommit.getLastCommit(),
      declarations: {
        witness: this.declared.witness,
        clerk: this.declared.clerk,
        verified: false,
        warnings: [...this.declarationWarnings],
        keys: {
          clerk: this.log.getClerkKeyFingerprint(),
          witness: witnessKeyFingerprint(this.witness),
        },
      },
    };
  }
}

/**
 * A declaration as given, or null when none was stated: absent, not a string,
 * or blank (empty or whitespace only). The text is otherwise kept as given.
 */
function statedDeclaration(text: unknown): string | null {
  return typeof text === "string" && text.trim().length > 0 ? text : null;
}

/**
 * What ILAS can see that contradicts the declarations: a declared witness or
 * clerk that is not configured, or a configured one nobody declared. Built
 * from the configuration only; the declaration strings are not parsed.
 */
function declarationWarnings(
  declared: { witness: string | null; clerk: string | null },
  witnessConfigured: boolean,
  clerkRouteConfigured: boolean
): string[] {
  const warnings: string[] = [];
  if (declared.witness !== null && !witnessConfigured) {
    warnings.push(
      "A witness is declared, but no witness is configured (NullWitness): nothing outside this node holds its heads."
    );
  }
  if (declared.witness === null && witnessConfigured) {
    warnings.push(
      "A witness is configured, but no witness declaration was given: who operates it is not stated."
    );
  }
  if (declared.clerk !== null && !clerkRouteConfigured) {
    warnings.push(
      "A clerk is declared, but this node has no clerk route: no entry is stamped by a clerk."
    );
  }
  if (declared.clerk === null && clerkRouteConfigured) {
    warnings.push(
      "A clerk route is configured, but no clerk declaration was given: who operates the clerk is not stated."
    );
  }
  return warnings;
}

/**
 * The witness's key fingerprint, through its OPTIONAL publicKeyFingerprint()
 * method. null when the witness has no such method, has no usable key, or the
 * method throws or returns anything but a string. Never throws.
 */
function witnessKeyFingerprint(witness: Witness): string | null {
  try {
    const method = (witness as { publicKeyFingerprint?: unknown }).publicKeyFingerprint;
    if (typeof method !== "function") return null;
    const value: unknown = method.call(witness);
    return typeof value === "string" ? value : null;
  } catch {
    return null;
  }
}
