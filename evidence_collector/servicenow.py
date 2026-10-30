"""Push control evidence and exceptions into ServiceNow GRC (Policy and Compliance).

For every control in the run:

* the control's evidence file is attached to its GRC control record
  (``sn_compliance_control``), so each control carries its own dated evidence
  for every collection run across the audit period;
* if the control failed, a GRC issue (``sn_grc_issue``) is opened listing the
  exceptions, unless one is already open for that control.

Map controls to ServiceNow records with ``servicenow_control_sys_id`` in
``controls.yaml`` or the ``SN_CONTROL_MAP`` environment variable (JSON).

Modes: ``dry-run`` records the exact requests and sends nothing; ``live`` calls
the REST Attachment and Table APIs. Table and field names follow ServiceNow's
standard GRC model but vary by instance and version, so they are configurable.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ServiceNowConfig:
    instance_url: str
    user: str = ""
    password: str = ""
    control_map: dict = field(default_factory=dict)
    control_table: str = "sn_compliance_control"
    issue_table: str = "sn_grc_issue"
    issue_fields: dict = field(default_factory=dict)

    @classmethod
    def from_env(cls, require: bool) -> "ServiceNowConfig":
        url = os.environ.get("SN_INSTANCE_URL")
        if not url:
            if require:
                raise RuntimeError("SN_INSTANCE_URL is not set")
            url = "https://your-instance.service-now.com"
        return cls(
            instance_url=url.rstrip("/"),
            user=os.environ.get("SN_USER", ""),
            password=os.environ.get("SN_PASSWORD", ""),
            control_map=json.loads(os.environ.get("SN_CONTROL_MAP", "{}")),
            control_table=os.environ.get("SN_CONTROL_TABLE", "sn_compliance_control"),
            issue_table=os.environ.get("SN_ISSUE_TABLE", "sn_grc_issue"),
            issue_fields=json.loads(os.environ.get("SN_ISSUE_FIELDS", "{}")),
        )


def issue_payload(row: dict, run_id: str, period: dict, cfg: ServiceNowConfig) -> dict:
    exc_lines = [f"- {e['item']}: {e['reason']}" for e in row["exceptions"]]
    maps = "; ".join(f"{k}: {', '.join(v)}" for k, v in row["mappings"].items() if v)
    return {
        "short_description": f"[Evidence] {row['id']} control exceptions: {row['name']}",
        "description": "\n".join([
            f"Automated evidence collection found {len(row['exceptions'])} exception(s) "
            f"out of a population of {row['population']} for control {row['id']}.",
            f"Audit period: {period['start']} to {period['end']}. Collection run: {run_id}.",
            f"Framework mappings: {maps}",
            "Exceptions:", *exc_lines,
            f"Evidence file: {row['evidence_file']} (SHA-256 {row['evidence_sha256']})",
        ]),
        **cfg.issue_fields,
    }


class ServiceNowGRC:
    def __init__(self, cfg: ServiceNowConfig, mode: str = "dry-run", session=None) -> None:
        if mode not in ("dry-run", "live"):
            raise ValueError("mode must be 'dry-run' or 'live'")
        self.cfg, self.mode, self.session = cfg, mode, session
        self.requests_log: list[dict] = []
        if mode == "live" and session is None:
            import requests

            self.session = requests.Session()
            self.session.auth = (cfg.user, cfg.password)
            self.session.headers.update({"Accept": "application/json"})

    def _call(self, method: str, path: str, **kwargs) -> dict:
        url = f"{self.cfg.instance_url}{path}"
        entry = {"method": method, "url": url, "params": kwargs.get("params")}
        if "json" in kwargs:
            entry["json"] = kwargs["json"]
        if "data" in kwargs:
            entry["body"] = f"<{len(kwargs['data'])} bytes>"
        self.requests_log.append(entry)
        if self.mode == "dry-run":
            return {"result": []} if method == "GET" else {"result": {"sys_id": "DRY-RUN"}}
        resp = self.session.request(method, url, timeout=30, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def control_sys_id(self, row: dict) -> str | None:
        sys_id = row.get("servicenow_control_sys_id") or self.cfg.control_map.get(row["id"])
        if not sys_id and self.mode == "dry-run":
            return f"<sys_id for {row['id']}>"
        return sys_id or None

    def attach(self, sys_id: str, path: Path, name: str) -> str:
        res = self._call("POST", "/api/now/attachment/file",
                         params={"table_name": self.cfg.control_table, "table_sys_id": sys_id, "file_name": name},
                         headers={"Content-Type": "application/json"}, data=path.read_bytes())
        return res["result"]["sys_id"]

    def find_open_issue(self, control_id: str) -> str | None:
        res = self._call("GET", f"/api/now/table/{self.cfg.issue_table}",
                         params={"sysparm_query": f"short_descriptionSTARTSWITH[Evidence] {control_id} ^active=true",
                                 "sysparm_fields": "sys_id", "sysparm_limit": 1})
        rows = res.get("result") or []
        return rows[0]["sys_id"] if rows else None

    def publish(self, package_dir: Path, manifest: dict, results: list[dict]) -> dict:
        out = {"mode": self.mode, "attached": [], "skipped_unmapped": [], "issues_created": [], "issues_already_open": []}
        for row in results:
            sys_id = self.control_sys_id(row)
            if not sys_id:
                out["skipped_unmapped"].append(row["id"])
                continue
            name = f"{row['id']}-evidence-{manifest['run_id']}.json"
            self.attach(sys_id, package_dir / row["evidence_file"], name)
            out["attached"].append(row["id"])

            if row["result"] == "FAIL":
                existing = self.find_open_issue(row["id"])
                if existing:
                    out["issues_already_open"].append(row["id"])
                    continue
                res = self._call("POST", f"/api/now/table/{self.cfg.issue_table}",
                                 json=issue_payload(row, manifest["run_id"], manifest["audit_period"], self.cfg))
                out["issues_created"].append({"control": row["id"], "sys_id": res["result"]["sys_id"]})

        if self.mode == "dry-run":
            (package_dir / "servicenow_requests.json").write_text(json.dumps(self.requests_log, indent=2) + "\n")
        return out
