// The rules: which action kinds an agent may take freely and which wait for a person's seal.
// Revived from OP-CHORE's TOOL_RISK_ALLOWLIST (Opera_final/lib/kernel/permissions.ts): unknown kinds are refused.

export type Risk = 'read' | 'safe' | 'sealed';

export const KINDS = {
  read: 'read', search: 'read', fetch: 'read',
  draft: 'safe', write_local: 'safe', test: 'safe', preview_deploy: 'safe', note: 'safe',
  send_email: 'sealed', send_message: 'sealed', deploy_production: 'sealed', push_main: 'sealed', publish: 'sealed',
  charge_payment: 'sealed', delete_data: 'sealed', sign_agreement: 'sealed',
} as const satisfies Record<string, Risk>;

export type Kind = keyof typeof KINDS;

export const LIMITS = {
  maxActions: 8,
  maxIntentChars: 500,
  maxSummaryChars: 300,
  maxPlanSteps: 20,
  maxPlanStepChars: 300,
  maxStopConditions: 10,
  maxInputBytes: 16 * 1024,
  maxEvidenceBytes: 8 * 1024,
  maxNoteChars: 500,
  maxAgentChars: 80,
  maxOpenRunsPerAgent: 3,
  maxOpenRunsTotal: 20,
  maxWaitingSeals: 10,
  sealRequestTtlSeconds: 24 * 3600,
  receiptTtlSeconds: 15 * 60,
} as const;

export const isKind = (k: unknown): k is Kind => typeof k === 'string' && Object.hasOwn(KINDS, k);
export const riskOf = (k: Kind): Risk => KINDS[k];

export function describePolicy() {
  const byRisk: Record<Risk, string[]> = { read: [], safe: [], sealed: [] };
  for (const [k, r] of Object.entries(KINDS)) byRisk[r].push(k);
  return {
    kinds: byRisk,
    meaning: {
      read: 'next answers go; report the outcome.',
      safe: 'next answers go; report the outcome.',
      sealed: 'next opens a seal request and answers wait until a person seals or refuses; after the seal, next answers go with a single-use receipt; report the outcome with evidence.',
    },
    limits: LIMITS,
  };
}
