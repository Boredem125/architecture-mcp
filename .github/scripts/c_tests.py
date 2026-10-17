"""Print the connector (Class C) test files, one per line, for the standalone job.

    python .github/scripts/c_tests.py

C = every tracked tests/**/test_*.py except the Class A and B files listed in
docs/control-plane/REVIEW_QA.md section 2 / M0_INVENTORY.md section 2. A files
test legacy code deleted in M0; B files test legacy API routes and are being
rewritten. When QA's docs/control-plane/M0_C_MANIFEST.sha256 exists, the job
also runs `sha256sum -c` on it (gate check 1), so C files stay byte-identical.
"""
from __future__ import annotations

import subprocess

CLASS_A = {
    "tests/integration/test_pipeline.py",
    "tests/unit/test_message_models.py",
    "tests/unit/test_request_evaluator.py",
    "tests/unit/test_policy_engine.py",
}
CLASS_B = {
    "tests/security/test_api_robustness.py",
    "tests/security/test_api_auth.py",
    "tests/integration/test_api_connector.py",
    "tests/unit/test_recorder_scan.py",
}


def main() -> None:
    tracked = subprocess.run(
        ["git", "ls-files", "tests"], capture_output=True, text=True, check=True
    ).stdout.split()
    for path in sorted(tracked):
        name = path.rsplit("/", 1)[-1]
        if name.startswith("test_") and name.endswith(".py") and path not in CLASS_A | CLASS_B:
            print(path)


if __name__ == "__main__":
    main()
