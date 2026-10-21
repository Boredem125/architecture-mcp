# M1 done: control-plane foundation (21 Oct 2026)

**Next action (founder):** start M2 (sync) planning in a fresh session. Make `tests`, `security` and `image` required checks on `main` (repo settings), and delete the 15 stale `claude/cool-mayer-3l0bi1*` branches.

1. **Founder approval:** the founder approved M1 on 21 Oct 2026 ("approve M1, carry step 5 gap to M2").
2. **Gate, all 5 items measured** (`M1_BASELINE.md`, sections "M1 gate readings", "Gate item 4 reading", "Gate items 3 (second clause) and 5"):
   - Item 1: connector suite green on CI Windows and Linux. Read per founder ruling A: 3 named Windows environment skips (SEC-27/28 need a dependency-free Python); the Linux skip list matches CI (31 ids).
   - Item 2: `ee/` suite in CI 412 passed, 0 skipped, branch coverage 87% (gate 85%).
   - Item 3: with `ee/` removed the C-class count holds (the 24-test gap is the four Class B files, ruling A). Fresh venv `pip install .`: M0 E2E 16/16 checks; step 5 dual control not exercised (carried to M2, below).
   - Item 4: on a fresh clone, Semgrep 0 ERROR, Gitleaks 0, Trivy fs 0; ZAP 0 High, 0 Medium; `api` image 0 fixable HIGH/CRITICAL (founder ruling), 44 unfixed Debian base-image HIGH published as a limit.
   - Item 5: `demo.py` on a fresh clone at `2f71036`: 27 PASS, 0 FAIL (`M1_DEMO.md`). T13 security sign-off: APPROVE WITH CONDITIONS, F1/F2 fixed and re-reviewed.
3. **Built:** Phase A connector hardening (T0-T4c: money floor, hook bounds, lexer, runners, `--root` allowlist, key home, pinned approver keys, domain-tagged signatures, legacy evidence). Phase B `ee/` control plane (T5-T15): Postgres with forced RLS and a DB-computed admin audit chain, OIDC ID-token verification, login/sessions/CSRF/setup code, orgs/projects/RBAC with IDOR 404s, 4-worker uvicorn on one Postgres, compose stack (Caddy, Keycloak demo), one-page web app, docs.
4. **First real Docker run (laptop, 21 Oct)** found and fixed, each signed off by security-engineer: Caddy file capability vs `cap_drop: ALL`; secrets unreadable by their consumers (now per-consumer owner, 0400/0440); `migrate` ignored `AGG_DATABASE_URL_FILE`; Keycloak `start-dev` on a read-only FS (now built at image-build time, `USER 1000`); `demo.py` added bob with the username instead of his Keycloak `sub` and reported a failed login as PASS.
5. **Audit of the cloud session's range** (`29ed27d..e5d6665`, lead-architect): OK WITH ISSUES, no Critical/High; named exceptions recorded in `M1_BASELINE.md`.
6. **Carried to M2:**
   - E2E step 5 dual control: the money preset escalates (`GOVERNANCE_UNEVALUATED`) and one reviewer approves, but `requires_dual` is false (Stripe allowlisted, semantic service absent). Make a live two-reviewer path part of the M2 demo.
   - Slimmer `api` base image (distroless or Chainguard) to clear the 44 unfixed HIGH.
   - A dependency-free Python in CI so the 3 SEC-27/28 tests run.
   - `ee/` tests on Windows (`os.setsid` in `test_t10_multiworker.py`, symlink privilege in `test_m1_t13_review.py`).
   - Lows: CSRF tests compare code with itself; Semgrep warnings at `keyhome.py:198,200`; SEC-33 and `root_exposure` domain groups; ca-bundle `DAC_READ_SEARCH` can read Caddy's private keys (stated limit); a DB connection pool before load.
7. **Limits (honest):** no compliance claims. Windows needs `127.0.0.1 idp.localhost` in hosts and `demo.py --ca` (README). The demo Keycloak uses `admin/admin` (demo profile only, T13 F3). Per-task security sign-offs for T8-T11 are recorded in commit messages and `M1_BASELINE.md` only; no review transcripts are in the repo.
