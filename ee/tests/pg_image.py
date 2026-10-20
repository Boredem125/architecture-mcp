"""Single source of truth for the pinned Postgres image used in ee/ tests and CI.

The digest is obtained via ``docker pull postgres:16`` + ``docker inspect``.
CI's ``ee`` job postgres service must use this exact value (tested in
``test_t6_pg_harness.py::test_ci_workflow_pg_image_matches``).
"""

PG_IMAGE: str = "postgres:16@sha256:ca0bd484cb98bf4b24eb1010e73fb3fcbd6714d240fbc1a10eea5b7dbecb641d"
