"""Detect a data-exfiltration shape in a shell command: a sensitive source AND a
network egress in the same command.

Deterministic on purpose. Exfiltration in a command is structural, not a matter
of prose, so this is regex, not the jev-os model. The pattern (sensitive file +
network sink) follows the industry approach, e.g. Elastic's published
"Potential Data Exfiltration Through Wget/Curl" detection rules (Elastic License
v2); only the general pattern is reused here, not their rule code.

It is not a full parser and can be evaded (obfuscation, staging to a temp file
first, unusual tools). It raises scrutiny — the gateway already escalates shell
commands — by turning an exfil-shaped command into a dual-control/critical one
and giving the human approver an explicit reason. It never lowers a verdict.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# A sensitive *source* of data. Kept close to risk.py's sensitive set.
_SENSITIVE = re.compile(
    r"""(?ix)
    (?:^|[\s'"=@/\\])              # a boundary so 'environment' doesn't match '.env'
    (?:
        \.env\b
      | \.ssh\b | id_rsa | id_ed25519 | \.pem\b | \.ppk\b
      | \.aws\b | credentials\b | service-account
      | \.kube\b | kubeconfig
      | secret s? \b | password s? \b | api[_-]?key s? \b | token s? \b
      | /etc/(?:passwd|shadow)\b
    )
    """,
)

# A network *egress*: sending data out, not just any network use.
_EGRESS = (
    ("curl_upload", re.compile(r"(?ix)\bcurl\b[^|;&]*?(--data(?:-binary|-raw|-urlencode)?|(?<!\w)-d\b|--form|(?<!\w)-F\b|--upload-file|(?<!\w)-T\b)")),
    ("wget_post", re.compile(r"(?ix)\bwget\b[^|;&]*?(--post-file|--post-data|--body-file|--body-data)")),
    ("netcat", re.compile(r"(?ix)(?:^|\|\s*)(?:nc|ncat|netcat)\b[^|;&]*\d")),
    ("scp_remote", re.compile(r"(?ix)\b(?:scp|sftp|rsync)\b[^|;&]*\s[\w.-]+@[\w.-]+:")),
    ("pipe_to_net", re.compile(r"(?ix)\|\s*(?:curl|nc|ncat|netcat|wget)\b")),
    ("cloud_upload", re.compile(r"(?ix)\b(?:aws\s+s3\s+(?:cp|sync|mv)|gh\s+gist\s+create|gh\s+release\s+upload|rclone\s+copy)\b")),
    ("ps_upload", re.compile(r"(?ix)(Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^|;&]*(-InFile|-Body|-Method\s+Post)")),
)


@dataclass
class ExfilFinding:
    sensitive: str      # the matched sensitive token
    egress: str         # the egress technique name
    detail: str

    def factor_detail(self) -> str:
        return f"command reads {self.sensitive!r} and sends it out ({self.egress})"


def detect(command: str) -> ExfilFinding | None:
    if not command:
        return None
    sens = _SENSITIVE.search(command)
    if not sens:
        return None
    for name, pattern in _EGRESS:
        if pattern.search(command):
            token = sens.group(0).strip(" '\"=@/\\")
            return ExfilFinding(sensitive=token, egress=name,
                                detail=f"sensitive source ({token}) + egress ({name})")
    return None
