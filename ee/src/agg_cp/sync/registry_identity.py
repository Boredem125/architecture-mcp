"""Server-side identity binding for registry v2+ (ADR 0011 A1.1).

``check_registry_identity`` runs only SELECTs against the DB.
It compares added and carried keys against enrollments, user rows
and role bindings.  Returns either a *Refusal* (reason class + key_id)
or a *Plan* listing added keys, promotions and removed key_ids.

Spec reference: ``T12D_D5_SPEC.md`` section 5.2 (matching rules).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Refusal:
    reason: str
    key_id: str


@dataclass
class AddedKey:
    key_id: str
    user_id: str
    roles: list[str]
    kind: str


@dataclass
class Promotion:
    key_id: str
    user_id: str


@dataclass
class Plan:
    added: list[AddedKey] = field(default_factory=list)
    promoted: list[Promotion] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)


def check_registry_identity(
    conn: Any,
    org_id: str,
    prev: dict[str, Any],
    cur: dict[str, Any],
) -> Refusal | Plan:
    """Check identity binding rules for a registry version.

    *prev* is ``chain[-1].payload``; *cur* is the new envelope's payload.
    The connection must already have ``app.org_id`` set and be inside a
    transaction (``autocommit=False``).

    Returns a :class:`Refusal` on the first rule violation, or a
    :class:`Plan` describing what the caller should persist.
    """
    prev_keys_by_id: dict[str, dict] = {}
    for k in prev.get("keys", []):
        prev_keys_by_id[k["key_id"]] = k

    prev_admins = set(prev.get("admins", []))
    cur_admins = set(cur.get("admins", []))

    plan = Plan()

    cur_key_ids = {k["key_id"] for k in cur.get("keys", [])}
    prev_key_ids = set(prev_keys_by_id.keys())
    plan.removed = sorted(prev_key_ids - cur_key_ids)

    for entry in cur.get("keys", []):
        kid = entry["key_id"]
        is_added = kid not in prev_keys_by_id
        has_admin = kid in cur_admins or "admin" in entry.get("roles", [])

        if is_added:
            # --- Rules 1-8 for added keys ---

            # Rule 1: cross-org check
            cross = conn.execute(
                "SELECT check_key_id_cross_org(%s, %s::uuid)",
                [kid, org_id],
            ).fetchone()
            if cross and cross[0]:
                return Refusal("other_org", kid)

            # Rule 2: must have a pending enrollment
            link_rows = conn.execute(
                "SELECT DISTINCT user_id::text, public_key, kind "
                "FROM signer_links "
                "WHERE org_id = %s::uuid AND key_id = %s "
                "AND public_key IS NOT NULL "
                "AND used_at IS NOT NULL "
                "AND status = 'pending'",
                [org_id, kid],
            ).fetchall()
            if not link_rows:
                return Refusal("unknown_key", kid)

            # Rule 3: more than one distinct user_id (R-5)
            distinct_users = {r[0] for r in link_rows}
            if len(distinct_users) > 1:
                return Refusal("unknown_key", kid)

            # Rule 4: must match public_key and kind
            matched = False
            for r in link_rows:
                if r[1] == entry.get("public_key") and r[2] == entry.get("kind"):
                    matched = True
                    break
            if not matched:
                return Refusal("unknown_key", kid)

            # Rule 5: user_id must match
            link_user_id = link_rows[0][0]
            if entry.get("user_id") != link_user_id:
                return Refusal("user_mismatch", kid)

            # Rule 6: user row must exist, active, same org
            # S3: the ::uuid cast is safe only because rule 5 already
            # matched link_user_id, a DB uuid.
            user_row = conn.execute(
                "SELECT oidc_issuer, oidc_subject, status "
                "FROM users "
                "WHERE id = %s::uuid AND org_id = %s::uuid",
                [entry["user_id"], org_id],
            ).fetchone()
            if user_row is None or user_row[2] != "active":
                return Refusal("user_mismatch", kid)

            # Rule 7: iss and sub must match
            if entry.get("iss") != user_row[0] or entry.get("sub") != user_row[1]:
                return Refusal("identity_mismatch", kid)

            # Rule 8: admin keys need org-scope admin role binding
            if has_admin:
                admin_bind = conn.execute(
                    "SELECT 1 FROM role_bindings "
                    "WHERE org_id = %s::uuid AND user_id = %s::uuid "
                    "AND role = 'admin' "
                    "AND scope_type = 'org' AND scope_id = %s::uuid "
                    "LIMIT 1",
                    [org_id, entry.get("user_id", ""), org_id],
                ).fetchone()
                if admin_bind is None:
                    return Refusal("not_admin", kid)

            plan.added.append(AddedKey(
                key_id=kid,
                user_id=entry.get("user_id", ""),
                roles=entry.get("roles", []),
                kind=entry.get("kind", "cli"),
            ))

        else:
            # --- Rules 9-10 for carried keys ---
            prev_entry = prev_keys_by_id[kid]

            # Rule 9: identity fields must not change
            for field_name in ("user_id", "iss", "sub", "public_key", "kind"):
                if entry.get(field_name) != prev_entry.get(field_name):
                    return Refusal("identity_changed", kid)

            # Rule 10: promotion check
            had_admin_prev = (
                kid in prev_admins
                or "admin" in prev_entry.get("roles", [])
            )
            if not had_admin_prev and has_admin:
                # Promotion: needs org-scope admin role binding
                admin_bind = conn.execute(
                    "SELECT 1 FROM role_bindings "
                    "WHERE org_id = %s::uuid AND user_id = %s::uuid "
                    "AND role = 'admin' "
                    "AND scope_type = 'org' AND scope_id = %s::uuid "
                    "LIMIT 1",
                    [org_id, entry.get("user_id", ""), org_id],
                ).fetchone()
                if admin_bind is None:
                    return Refusal("not_admin", kid)
                plan.promoted.append(Promotion(
                    key_id=kid,
                    user_id=entry.get("user_id", ""),
                ))

    return plan
