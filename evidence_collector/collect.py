"""Run every control test, package the evidence, and optionally push it to ServiceNow GRC."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import date
from pathlib import Path

import yaml

from .checks import REGISTRY, Period
from .evidence import EvidencePackage, verify_package
from .servicenow import ServiceNowConfig, ServiceNowGRC
from .sources import FixtureSource, LiveSource

ROOT = Path(__file__).resolve().parent.parent


def load_controls(path: str | Path) -> tuple[Period, list[dict]]:
    cfg = yaml.safe_load(Path(path).read_text())
    p = cfg["audit_period"]
    period = Period(_date(p["start"]), _date(p["end"]))
    controls = cfg["controls"]
    for c in controls:  # YAML reads clauses like 7.2 as numbers; keep them as strings
        c["mappings"] = {k: [str(x) for x in (v or [])] for k, v in c.get("mappings", {}).items()}
    missing = [c["id"] for c in controls if c["test"] not in REGISTRY]
    if missing:
        raise ValueError(f"controls reference tests that don't exist: {missing}")
    ids = [c["id"] for c in controls]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate control IDs in controls.yaml")
    return period, controls


def _date(v) -> date:
    return v if isinstance(v, date) else date.fromisoformat(str(v))


def run(controls_path, out_dir, source_mode="fixture", servicenow="off", fixtures_dir=None,
        period_override: tuple[str, str] | None = None, source=None) -> dict:
    period, controls = load_controls(controls_path)
    if period_override:
        period = Period(date.fromisoformat(period_override[0]), date.fromisoformat(period_override[1]))

    fixtures = FixtureSource(fixtures_dir or ROOT / "fixtures")
    src = source or (LiveSource(fixtures) if source_mode == "live" else fixtures)

    pkg = EvidencePackage(out_dir, period, {
        "source_mode": source_mode,
        "code_version": os.environ.get("GITHUB_SHA", "local"),
        "triggered_by": os.environ.get("GITHUB_EVENT_NAME", "manual"),
    })

    for ctrl in controls:
        try:
            result = REGISTRY[ctrl["test"]](src, period, ctrl)
        except Exception as e:  # one broken source must not stop the other controls
            from .checks import TestResult
            result = TestResult([], [{"item": "collection", "reason": f"evidence collection failed: {e}"}])
        row = pkg.add(ctrl, result)
        flag = "PASS" if row["result"] == "PASS" else f"FAIL ({len(row['exceptions'])} exception(s))"
        print(f"{row['id']:<6} {row['name'][:58]:<58} pop={row['population']:<3} {flag}")

    manifest = pkg.finish()
    s = manifest["summary"]
    print(f"\n{s['passed']}/{s['controls']} controls passed. Evidence package: {pkg.dir}")
    print(f"Manifest SHA-256: {manifest['manifest_sha256']}")

    if servicenow != "off":
        grc = ServiceNowGRC(ServiceNowConfig.from_env(require=servicenow == "live"), servicenow)
        sn = grc.publish(pkg.dir, manifest, pkg.results)
        manifest["servicenow"] = sn
        print(f"ServiceNow GRC ({servicenow}): evidence attached to {len(sn['attached'])} controls, "
              f"{len(sn['issues_created'])} issues created, {len(sn['issues_already_open'])} already open"
              + (f", unmapped: {', '.join(sn['skipped_unmapped'])}" if sn["skipped_unmapped"] else ""))
        if servicenow == "dry-run":
            print(f"Requests that would be sent: {pkg.dir / 'servicenow_requests.json'}")

    manifest["package_dir"] = str(pkg.dir)
    manifest["results"] = pkg.results
    return manifest


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Collect SOC 2 / ISO 27001 / ISO 9001 control evidence.")
    p.add_argument("--controls", default=str(ROOT / "config" / "controls.yaml"))
    p.add_argument("--out", default="evidence")
    p.add_argument("--source", default="fixture", choices=["fixture", "live"])
    p.add_argument("--servicenow", default="off", choices=["off", "dry-run", "live"])
    p.add_argument("--period", nargs=2, metavar=("START", "END"), help="override audit period (YYYY-MM-DD)")
    p.add_argument("--fail-on-exceptions", action="store_true", help="exit 1 if any control fails")
    p.add_argument("--verify", metavar="PACKAGE_DIR", help="check an evidence package against its manifest")
    a = p.parse_args(argv)
    if a.verify:
        problems = verify_package(a.verify)
        print("\n".join(problems) if problems else f"Evidence package intact: {a.verify}")
        return 1 if problems else 0
    m = run(a.controls, a.out, a.source, a.servicenow, period_override=a.period)
    return 1 if a.fail_on_exceptions and m["summary"]["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
