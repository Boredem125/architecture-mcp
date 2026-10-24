/**
 * Escalation display rules (D5.5, N9).
 *
 * - Absent environment = prod (D2.4).
 * - In M2 no key kind may make a remote approval on prod.
 * - Deny is always allowed on pending escalations (prod or non-prod).
 */

/**
 * Return ``true`` when the environment string means "production".
 * An absent, null, or empty environment is treated as prod (D2.4).
 */
export function isProdEnvironment(
  env: string | null | undefined,
): boolean {
  if (env === undefined || env === null || env === "") return true;
  return env === "prod";
}

/** Escalation state needed for the approve/deny decision. */
interface EscalationContext {
  environment?: string | null;
  status: string;
}

/**
 * Whether the UI may offer "Approve" for this escalation.
 *
 * Returns ``false`` for prod (D5.5 / N9) and for already-decided
 * escalations.  Returns ``true`` only for pending non-prod escalations.
 */
export function canApprove(escalation: EscalationContext): boolean {
  if (isProdEnvironment(escalation.environment)) return false;
  if (escalation.status !== "pending") return false;
  return true;
}

/**
 * Whether the UI may offer "Deny" for this escalation.
 *
 * Deny is allowed on prod and non-prod pending escalations.
 */
export function canDeny(escalation: EscalationContext): boolean {
  if (escalation.status !== "pending") return false;
  return true;
}
