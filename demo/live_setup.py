"""Set up a fresh project for a *live* demo with the real Claude Code.

Creates the same small project as demo/call_demo.py (a fake .env, a config
file with a fake key, a README with a hidden instruction), connects Claude
Code's hooks and the sandbox MCP server, turns on the injection scan and the
example governance policy, and signs the baseline policy.

Usage:
    python demo/live_setup.py [--dir PARENT]

Then, in that project folder: `sandbox watch` in one terminal and `claude`
in another. Use demo/try.py to send any tool call someone names straight
through the gateway.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from call_demo import FAKE_CONFIG, FAKE_ENV, GOV_POLICY, POISONED_README, SANDBOX  # noqa: E402

from sandbox.connector.install import init  # noqa: E402
from sandbox.connector.layout import FolderLayout  # noqa: E402
from sandbox.connector.policy import load_policy, save_policy  # noqa: E402


def setup(parent: Path) -> Path:
    shutil.rmtree(parent, ignore_errors=True)
    root = parent / "invoice-service"
    root.mkdir(parents=True)
    (root / "app.py").write_text('print("ok")\n')
    (root / ".env").write_text(FAKE_ENV + "\n")
    (root / "config.txt").write_text(FAKE_CONFIG)
    (root / "README.md").write_text(POISONED_README)
    subprocess.run(["git", "init", "-q"], cwd=root, check=False)
    init(root, claude=True, mcp=True)
    layout = FolderLayout(root)
    policy = load_policy(layout.policy_file)
    policy.semantic.enabled = True
    policy.network.allow_mcp_servers = ["stripe"]
    save_policy(policy, layout.policy_file)
    for args in (["governance", "use", str(GOV_POLICY)],
                 ["policy", "baseline", "--reason", "live demo baseline"]):
        subprocess.run([SANDBOX, *args], cwd=root, check=True, capture_output=True)
    return root


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dir", default="", help="Parent folder (default: temp).")
    args = ap.parse_args()
    root = setup(Path(args.dir or tempfile.gettempdir()) / "gateway-live-demo")
    print(f"Live demo project ready: {root}")
    print("Next, each in its own terminal, inside that folder:")
    print("  sandbox watch --reviewer alice")
    print("  claude")


if __name__ == "__main__":
    main()
