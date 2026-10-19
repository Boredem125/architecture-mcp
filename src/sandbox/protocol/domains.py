"""Domain tags for signing context separation (ADR 0007 section 3).

Each signing context (record, approval, grant, policy-change, evidence) gets
its own tag.  Signed bytes are ``tag || 0x00 || canonical JSON``, so a
signature made under one tag cannot verify under another, even when the
canonical bytes happen to match.

Tags are UTF-8 strings.  Reserved tags are defined but not yet used in
signing; they exist so the namespace is claimed and no future collision can
occur.
"""

# --- Active tags (in use) ---------------------------------------------------

APPROVAL = "agg/approval/v1"
RECORD = "agg/record/v1"
GRANT = "agg/grant/v1"
POLICY_CHANGE = "agg/policy-change/v1"
EVIDENCE = "agg/evidence/v1"

# --- Reserved tags (not yet in use) -----------------------------------------

REGISTRY = "agg/registry/v1"
BUNDLE = "agg/bundle/v1"
DEVICE_ASSERT = "agg/device-assert/v1"
AUDIT_HEAD = "agg/audit-head/v1"
