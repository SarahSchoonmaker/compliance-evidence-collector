"""Package control results as audit evidence.

For each run this writes:

* ``sources/<dataset>.json``   raw snapshot of every dataset used, so a test can be re-performed
* ``controls/<ID>.json``       one evidence file per control: population, exceptions, sample, provenance
* ``control_matrix.csv``       the unified control framework with results
* ``report.md``                human-readable summary by control and by framework
* ``manifest.json``            SHA-256 of every file, so any later change is detectable
"""

from __future__ import annotations

import csv
import hashlib
import json
import random
from datetime import datetime, timezone
from pathlib import Path

from .checks import Period, TestResult

# Typical auditor sample sizes by control frequency. Firms vary; these are illustrative.
SAMPLE_SIZES = {"annual": 1, "quarterly": 2, "monthly": 2, "weekly": 5, "daily": 25,
                "per_event": 25, "continuous": 1}

FRAMEWORKS = {"soc2": "SOC 2 (TSC 2017)", "iso27001": "ISO/IEC 27001:2022", "iso9001": "ISO 9001:2015"}


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def select_sample(population: list[str], frequency: str, run_id: str, control_id: str) -> dict:
    """Reproducible random sample for auditor re-performance. The seed is recorded."""
    size = min(SAMPLE_SIZES.get(frequency, 25), len(population))
    seed = int(sha256_bytes(f"{run_id}:{control_id}".encode())[:8], 16)
    items = sorted(random.Random(seed).sample(population, size)) if size else []
    return {"method": f"random, seeded, size by frequency ({frequency})", "seed": seed, "size": size, "items": items}


class EvidencePackage:
    def __init__(self, out_dir: str | Path, period: Period, meta: dict) -> None:
        self.collected_at = datetime.now(timezone.utc)
        self.run_id = self.collected_at.strftime("%Y%m%dT%H%M%SZ")
        self.dir = Path(out_dir) / self.run_id
        (self.dir / "sources").mkdir(parents=True, exist_ok=True)
        (self.dir / "controls").mkdir(exist_ok=True)
        self.period = period
        self.meta = meta
        self.source_hashes: dict[str, str] = {}
        self.results: list[dict] = []

    def _write(self, rel: str, obj) -> str:
        data = (json.dumps(obj, indent=2, default=str) + "\n").encode()
        (self.dir / rel).write_bytes(data)
        return sha256_bytes(data)

    def add(self, ctrl: dict, result: TestResult) -> dict:
        sources = []
        for ds in result.datasets:
            if ds.name not in self.source_hashes:
                self.source_hashes[ds.name] = self._write(
                    f"sources/{ds.name}.json",
                    {"system": ds.system, "query": ds.query, "collected_at": self.collected_at.isoformat(),
                     "record_count": len(ds.records), "records": ds.records})
            sources.append({"dataset": ds.name, "system": ds.system, "query": ds.query,
                            "record_count": len(ds.records), "snapshot": f"sources/{ds.name}.json",
                            "snapshot_sha256": self.source_hashes[ds.name]})

        evidence = {
            "control": {k: ctrl[k] for k in ("id", "name", "owner", "frequency", "test", "mappings")},
            "run_id": self.run_id,
            "collected_at": self.collected_at.isoformat(),
            "audit_period": {"start": str(self.period.start), "end": str(self.period.end)},
            "result": "PASS" if result.passed else "FAIL",
            "population": {"count": len(result.population), "items": result.population},
            "exceptions": {"count": len(result.exceptions), "items": result.exceptions},
            "auditor_sample": select_sample(result.population, ctrl["frequency"], self.run_id, ctrl["id"]),
            "test_approach": "Automated test of the full population; sample provided for auditor re-performance.",
            "sources": sources,
            "notes": result.notes,
            **self.meta,
        }
        path = f"controls/{ctrl['id']}.json"
        sha = self._write(path, evidence)
        row = {"id": ctrl["id"], "name": ctrl["name"], "owner": ctrl["owner"], "result": evidence["result"],
               "population": len(result.population), "exceptions": result.exceptions,
               "mappings": ctrl["mappings"], "evidence_file": path, "evidence_sha256": sha,
               "servicenow_control_sys_id": ctrl.get("servicenow_control_sys_id", "")}
        self.results.append(row)
        return row

    def finish(self) -> dict:
        self._write_matrix()
        (self.dir / "report.md").write_text(self._report())
        files = sorted(p for p in self.dir.rglob("*") if p.is_file() and p.name != "manifest.json")
        manifest = {
            "run_id": self.run_id,
            "collected_at": self.collected_at.isoformat(),
            "audit_period": {"start": str(self.period.start), "end": str(self.period.end)},
            **self.meta,
            "summary": {"controls": len(self.results),
                        "passed": sum(r["result"] == "PASS" for r in self.results),
                        "failed": sum(r["result"] == "FAIL" for r in self.results)},
            "files": {str(p.relative_to(self.dir)): sha256_bytes(p.read_bytes()) for p in files},
        }
        self._write("manifest.json", manifest)
        manifest["manifest_sha256"] = sha256_bytes((self.dir / "manifest.json").read_bytes())
        return manifest

    def _write_matrix(self) -> None:
        with (self.dir / "control_matrix.csv").open("w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["control_id", "control", "owner", "soc2", "iso27001", "iso9001",
                        "result", "population", "exceptions", "evidence_file"])
            for r in self.results:
                m = r["mappings"]
                w.writerow([r["id"], r["name"], r["owner"], " ".join(m.get("soc2", [])),
                            " ".join(m.get("iso27001", [])), " ".join(m.get("iso9001", [])),
                            r["result"], r["population"], len(r["exceptions"]), r["evidence_file"]])

    def _report(self) -> str:
        lines = [f"# Control evidence report: run {self.run_id}", "",
                 f"Audit period {self.period.start} to {self.period.end}. "
                 f"Collected {self.collected_at:%Y-%m-%d %H:%M} UTC. "
                 f"Source mode: {self.meta.get('source_mode')}. Code version: {self.meta.get('code_version')}.", "",
                 "## Results by control", "",
                 "| Control | Name | Result | Population | Exceptions |", "|---|---|---|---|---|"]
        for r in self.results:
            lines.append(f"| {r['id']} | {r['name']} | {r['result']} | {r['population']} | {len(r['exceptions'])} |")
        failing = [r for r in self.results if r["exceptions"]]
        if failing:
            lines += ["", "## Exceptions", ""]
            for r in failing:
                for e in r["exceptions"]:
                    lines.append(f"- **{r['id']}** `{e['item']}`: {e['reason']}")
        lines += ["", "## Coverage by framework", ""]
        for key, label in FRAMEWORKS.items():
            covered = [r for r in self.results if r["mappings"].get(key)]
            reqs = sorted({x for r in covered for x in r["mappings"][key]})
            failed = [r["id"] for r in covered if r["result"] == "FAIL"]
            lines.append(f"- **{label}**: {len(covered)} controls covering {', '.join(reqs)}"
                         + (f". Failing: {', '.join(failed)}" if failed else ". All passing"))
        lines += ["", "Every control is tested once and its evidence is reused for each framework it maps to."]
        return "\n".join(lines) + "\n"


def verify_package(package_dir: str | Path) -> list[str]:
    """Re-hash every file against the manifest. Returns a list of problems (empty means intact)."""
    d = Path(package_dir)
    manifest = json.loads((d / "manifest.json").read_text())
    problems = []
    for rel, expected in manifest["files"].items():
        p = d / rel
        if not p.exists():
            problems.append(f"missing: {rel}")
        elif sha256_bytes(p.read_bytes()) != expected:
            problems.append(f"modified: {rel}")
    listed = set(manifest["files"]) | {"manifest.json", "servicenow_requests.json"}
    for p in d.rglob("*"):
        if p.is_file() and str(p.relative_to(d)) not in listed:
            problems.append(f"unexpected file: {p.relative_to(d)}")
    return problems
