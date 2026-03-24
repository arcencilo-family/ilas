import type { ProvenanceTag } from "../types";
import type { LockedEvidenceLog } from "../l0";

export type ActionType =
  | "memory_read"
  | "memory_write"
  | "external_call"
  | "canary_plant"
  | "canary_check"
  | "integrity_scan"
  | "config_change"
  | "file_op"
  | "parameter_register";

export interface PermissionResult {
  permitted: boolean;
  actionType: ActionType;
  provenanceTag: ProvenanceTag;
  expectedLanes: ProvenanceTag[];
}

// Trust matrix: permitted lanes per action type
const TRUST_RULES: Record<ActionType, ProvenanceTag[]> = {
  memory_read:        ["LaneA", "LaneB"],
  memory_write:       ["LaneA"],
  external_call:      ["LaneA"],
  canary_plant:       ["LaneB"],
  canary_check:       ["LaneB"],
  integrity_scan:     ["LaneB"],
  config_change:      ["LaneC"],
  file_op:            ["LaneC"],
  parameter_register: ["LaneC"],
};

const MISMATCH_WINDOW_MS = 90 * 24 * 60 * 60 * 1000; // 90 days
const SOFT_ALARM_THRESHOLD = 2;

interface MismatchRecord {
  actionType: ActionType;
  provenanceTag: ProvenanceTag;
  timestamp: number;
}

export class ProvenanceTracker {
  private readonly mismatches: MismatchRecord[] = [];

  constructor(private readonly log?: LockedEvidenceLog) {}

  checkPermission(actionType: ActionType, provenanceTag: ProvenanceTag): PermissionResult {
    const expectedLanes = TRUST_RULES[actionType];
    const permitted = expectedLanes.includes(provenanceTag);
    return { permitted, actionType, provenanceTag, expectedLanes };
  }

  tagAction(actionType: ActionType, provenanceTag: ProvenanceTag): PermissionResult {
    const result = this.checkPermission(actionType, provenanceTag);
    const now = Date.now();

    if (!result.permitted) {
      this.mismatches.push({ actionType, provenanceTag, timestamp: now });
    }

    this.log?.append({
      timestamp: now,
      moduleId: "m7",
      eventType: "action_tagged",
      provenanceTag,
      parameters: {
        actionType,
        permitted: result.permitted,
        expectedLanes: result.expectedLanes,
      },
      outcome: result.permitted ? "permitted" : "mismatch",
    });

    return result;
  }

  getMismatchCount(): number {
    const windowStart = Date.now() - MISMATCH_WINDOW_MS;
    return this.mismatches.filter((m) => m.timestamp >= windowStart).length;
  }

  shouldAlarm(): boolean {
    return this.getMismatchCount() >= SOFT_ALARM_THRESHOLD;
  }
}
