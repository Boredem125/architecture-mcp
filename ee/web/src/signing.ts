/**
 * Canonical byte signing for the agg/remote-approval/v1 protocol.
 *
 * Produces bytes identical to Python's
 * ``json.dumps(payload, sort_keys=True, separators=(",", ":"))``
 * prefixed by ``tag || 0x00``.
 *
 * D5.6 field set (agg/remote-approval/v1):
 *   request_id, command, fingerprint, reviewer_id, decision, approved_at,
 *   org_id, project_id, device_id, registry_version, policy_sequence,
 *   user_id, key_id, nonce, not_after
 */

/** Tag used for remote approval envelopes. */
export const REMOTE_APPROVAL_TAG = "agg/remote-approval/v1";

/**
 * Fields that Python treats as float (timestamps).  Python's json.dumps
 * serialises ``1700000000.0`` as ``"1700000000.0"`` while JavaScript's
 * JSON.stringify produces ``"1700000000"``.  We match Python's output by
 * appending ``.0`` to integer-valued numbers in these fields.
 */
const FLOAT_FIELDS: ReadonlySet<string> = new Set([
  "approved_at",
  "not_after",
]);

/**
 * Serialise a single JSON value to a string that matches Python's
 * ``json.dumps`` output for the given *key*.
 */
function serialiseValue(key: string, value: unknown): string {
  if (
    typeof value === "number" &&
    FLOAT_FIELDS.has(key) &&
    Number.isFinite(value) &&
    Number.isInteger(value)
  ) {
    // Python float with no fractional part: 1700000000.0
    return value.toFixed(1);
  }
  return JSON.stringify(value);
}

/**
 * Produce canonical JSON bytes matching Python's
 * ``json.dumps(payload, sort_keys=True, separators=(",",":")).encode("utf-8")``.
 *
 * Keys are sorted lexicographically, separators are ``(",", ":")``, and
 * known timestamp fields use the Python float representation.
 */
export function canonicalJson(
  payload: Record<string, unknown>,
): Uint8Array {
  const keys = Object.keys(payload).sort();
  const parts: string[] = [];
  for (const key of keys) {
    parts.push(`${JSON.stringify(key)}:${serialiseValue(key, payload[key])}`);
  }
  // Match Python json.dumps(ensure_ascii=True): every UTF-16 code unit
  // above 0x7f becomes a lowercase \uXXXX escape; astral characters
  // become surrogate pairs, as in Python.
  const json = `{${parts.join(",")}}`.replace(
    /[\u0080-￿]/g,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
  return new TextEncoder().encode(json);
}

/**
 * Produce the signed byte sequence: ``tag || 0x00 || canonicalJson(payload)``.
 */
export function canonicalBytes(
  tag: string,
  payload: Record<string, unknown>,
): Uint8Array {
  const tagBytes = new TextEncoder().encode(tag);
  const jsonBytes = canonicalJson(payload);
  const result = new Uint8Array(tagBytes.length + 1 + jsonBytes.length);
  result.set(tagBytes, 0);
  result[tagBytes.length] = 0x00;
  result.set(jsonBytes, tagBytes.length + 1);
  return result;
}
