/**
 * M3 tests-first markers for the web suite (docs/control-plane/M3_PLAN.md).
 *
 * vitest's strict xfail is ``it.fails`` (already used in
 * ``script-preview.test.ts``): the test passes only while its body fails and
 * turns red the moment the feature lands, so the build must then replace
 * ``it.fails`` with ``it``.  This module exports the reason strings only, so a
 * marked test can name the task it waits on:
 *
 *   it.fails(`${M3_PENDING.T2} renders /approve/:id`, () => { ... })
 *
 * Python mirrors: tests/m3_pending.py and ee/tests/m3_pending.py.
 */

export const M3_PENDING = {
  T1: "M3T1Pending: admin reads (devices, codes status, bundles, alerts, verify, JSONL export)",
  T2: "M3T2Pending: web app router, Approve page with context, Devices and enrollment, Policy proposals",
  T3: "M3T3Pending: enrollment-code flow, proposals, approvals and publish routes, CSRF catalog",
  T4: "M3T4Pending: server verification at publish, migration labels, direct-publish demo-only flag",
  T5: "M3T5Pending: pilot.sh, ACME, Keycloak pilot realm, docs/PILOT.md",
  T6: "M3T6Pending: m3_pilot.py (Playwright), scenario static checks, ee-web-e2e CI job",
  T7: "M3T7Pending: evidence pack signed by a dedicated evidence_signer_key; --expect-root",
  T8: "M3T8Pending: Alerts with ack, device badge, Evidence download and JSONL export, history, Settings",
  T9: "M3T9Pending: D5 security follow-ups (T9a and T9b)",
  T10: "M3T10Pending: pilot hardening: backup and restore drill, upgrade, Trivy and ZAP",
  T11: "M3T11Pending: option: device quarantine and signed stop (agg/stop/v1)",
  T12: "M3T12Pending: hostile review (reserved)",
  T13: "M3T13Pending: gate run and M3_DEMO.md (reserved)",
  T14: "M3T14Pending: docs (reserved)",
} as const;

export type M3Task = keyof typeof M3_PENDING;

/** The reason string for task ``n`` (1..14); throws on an unknown task. */
export function m3Reason(n: number): string {
  const key = `T${n}` as M3Task;
  const reason = M3_PENDING[key];
  if (reason === undefined) throw new Error(`Unknown M3 task number: ${n}`);
  return reason;
}
