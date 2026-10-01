"""Convert a ZAP JSON report (zap-api-scan.py -J) to SARIF 2.1.0.

    python .github/scripts/zap_to_sarif.py zap.json zap.sarif

ZAP risk -> SARIF level: High -> error, Medium -> warning, Low -> note,
Informational -> none. DAST findings are about URLs, not files, so each
result is anchored to the API's app factory (where middleware and routes are
wired) and the method + URL go in the message.
"""
from __future__ import annotations

import json
import re
import sys

LEVEL = {"3": "error", "2": "warning", "1": "note", "0": "none"}
ANCHOR = "src/sandbox/api/app.py"


def convert(report: dict) -> dict:
    rules, results = {}, []
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            # One plugin can raise differently named alerts (100000 reports both
            # "A Client Error ..." and "A Server Error ..."), so the rule id
            # includes the name; keying on the plugin alone labelled every 4xx
            # as a server error.
            name = alert.get("alert") or alert.get("name") or ""
            rule_id = f"zap-{alert.get('pluginid')}-{re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')[:48]}"
            level = LEVEL.get(str(alert.get("riskcode")), "warning")
            rules.setdefault(rule_id, {
                "id": rule_id,
                "name": alert.get("alert") or alert.get("name"),
                "shortDescription": {"text": alert.get("alert") or alert.get("name") or rule_id},
                "fullDescription": {"text": _strip(alert.get("desc", ""))},
                "help": {"text": _strip(alert.get("solution", ""))},
                "defaultConfiguration": {"level": level},
                "properties": {"riskdesc": alert.get("riskdesc"), "cweid": alert.get("cweid")},
            })
            for inst in alert.get("instances", []) or [{}]:
                where = f"{inst.get('method', '')} {inst.get('uri', site.get('@name', ''))}".strip()
                param = f" (parameter {inst['param']})" if inst.get("param") else ""
                results.append({
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": f"{alert.get('alert')}: {where}{param}"},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": ANCHOR},
                        "region": {"startLine": 1},
                    }}],
                    "partialFingerprints": {"zapInstance": f"{rule_id}|{where}|{inst.get('param', '')}"},
                })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "OWASP ZAP", "informationUri": "https://www.zaproxy.org/",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }


def _strip(html: str) -> str:
    import re

    return re.sub(r"<[^>]+>", "", html or "").strip()


def main() -> None:
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, encoding="utf-8") as f:
        sarif = convert(json.load(f))
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
    print(f"{dst}: {len(sarif['runs'][0]['results'])} results")


if __name__ == "__main__":
    main()
