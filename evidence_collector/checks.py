"""Automated control tests (one function per control test in controls.yaml).

Each test receives the evidence source and the audit period, tests the *full
population* (not a sample), and returns the population, every exception with a
reason, and the datasets it used. Point-in-time checks (configuration) are
evaluated as of collection; event-based checks are filtered to the audit period.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta

from .sources import Dataset


@dataclass
class Period:
    start: date
    end: date

    def contains(self, ts: str | None) -> bool:
        return ts is not None and self.start <= _d(ts) <= self.end

    def quarters(self) -> list[str]:
        out, y, q = [], self.start.year, (self.start.month - 1) // 3 + 1
        while True:
            q_end = date(y, q * 3, 1) + timedelta(days=32)
            q_end = q_end.replace(day=1) - timedelta(days=1)
            if q_end > self.end:
                break
            if q_end >= self.start:
                out.append(f"{y}-Q{q}")
            y, q = (y + 1, 1) if q == 4 else (y, q + 1)
        return out


@dataclass
class TestResult:
    population: list[str]
    exceptions: list[dict] = field(default_factory=list)
    datasets: list[Dataset] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.exceptions


def _d(ts: str) -> date:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).date() if "T" in ts else date.fromisoformat(ts)


def _dt(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


REGISTRY = {}


def control_test(name):
    def wrap(fn):
        REGISTRY[name] = fn
        return fn
    return wrap


@control_test("mfa_enforced")
def mfa_enforced(src, period, ctrl):
    users = src.fetch("identity_users")
    pop = [u for u in users.records if u["console_access"] and u["status"] == "active"]
    exc = [{"item": u["username"], "reason": "console access without MFA"} for u in pop if not u["mfa_enabled"]]
    return TestResult([u["username"] for u in pop], exc, [users],
                      ["Population: active users with console access. Programmatic-only accounts excluded."])


@control_test("terminated_access_removed")
def terminated_access_removed(src, period, ctrl):
    hris, idp = src.fetch("hris_employees"), src.fetch("identity_users")
    accounts = {u["username"]: u for u in idp.records}
    terms = [e for e in hris.records if e["status"] == "terminated" and period.contains(e["termination_at"])]
    exc = []
    for e in terms:
        acct = accounts.get(e["username"])
        if acct is None:
            continue
        if acct["status"] == "active":
            exc.append({"item": e["employee_id"], "reason": f"account '{e['username']}' still active after "
                        f"termination on {e['termination_at'][:10]}"})
        elif _dt(acct["disabled_at"]) - _dt(e["termination_at"]) > timedelta(hours=24):
            hours = (_dt(acct["disabled_at"]) - _dt(e["termination_at"])).total_seconds() / 3600
            exc.append({"item": e["employee_id"], "reason": f"disabled {hours:.0f}h after termination (SLA 24h)"})
    return TestResult([e["employee_id"] for e in terms], exc, [hris, idp],
                      ["Population: HRIS terminations in the audit period, matched to identity accounts."])


@control_test("access_review_completed")
def access_review_completed(src, period, ctrl):
    reviews = src.fetch("access_reviews")
    by_q = {r["quarter"]: r for r in reviews.records}
    quarters = period.quarters()
    exc = []
    for q in quarters:
        r = by_q.get(q)
        if r is None or r["status"] != "completed":
            exc.append({"item": q, "reason": "no completed access review"})
        elif not r.get("signed_off_by"):
            exc.append({"item": q, "reason": "review completed without management sign-off"})
    return TestResult(quarters, exc, [reviews], ["Population: quarters ending within the audit period."])


@control_test("branch_protection")
def branch_protection(src, period, ctrl):
    bp = src.fetch("branch_protection")
    exc = []
    for r in bp.records:
        if r["required_approving_review_count"] < 1:
            exc.append({"item": r["repo"], "reason": "no required reviewers on main"})
        elif not r["enforce_admins"]:
            exc.append({"item": r["repo"], "reason": "admins can bypass branch protection"})
    return TestResult([r["repo"] for r in bp.records], exc, [bp])


@control_test("pr_independent_approval")
def pr_independent_approval(src, period, ctrl):
    pulls = src.fetch("merged_pulls")
    pop = [p for p in pulls.records if period.contains(p["merged_at"])]
    exc = []
    for p in pop:
        independent = [a for a in p["approvals"] if a != p["author"]]
        if not independent:
            exc.append({"item": f"{p['repo']}#{p['number']}",
                        "reason": f"merged {p['merged_at'][:10]} by {p['merged_by']} without independent approval"})
    return TestResult([f"{p['repo']}#{p['number']}" for p in pop], exc, [pulls],
                      ["Population: pull requests merged to main within the audit period."])


@control_test("storage_encrypted")
def storage_encrypted(src, period, ctrl):
    b = src.fetch("storage_buckets")
    exc = [{"item": x["name"], "reason": "default encryption not enabled"} for x in b.records if not x["encryption"]]
    return TestResult([x["name"] for x in b.records], exc, [b])


@control_test("no_public_storage")
def no_public_storage(src, period, ctrl):
    b = src.fetch("storage_buckets")
    exc = [{"item": x["name"], "reason": "public access block not fully enabled"}
           for x in b.records if not x["public_access_block"]]
    return TestResult([x["name"] for x in b.records], exc, [b])


@control_test("audit_logging")
def audit_logging(src, period, ctrl):
    t = src.fetch("audit_trails")
    good = [x for x in t.records if x["is_multi_region"] and x["is_logging"] and x["log_file_validation"]]
    exc = [] if good else [{"item": "account", "reason": "no logging multi-region trail with log file validation"}]
    notes = [f"Compliant trail(s): {', '.join(x['name'] for x in good)}"] if good else []
    notes += [f"Informational: trail '{x['name']}' is not logging" for x in t.records if not x["is_logging"]]
    return TestResult([x["name"] for x in t.records], exc, [t], notes)


@control_test("vulnerability_sla")
def vulnerability_sla(src, period, ctrl):
    f = src.fetch("vulnerability_findings")
    sla = ctrl.get("sla_days", {"critical": 7, "high": 30})
    pop = [x for x in f.records if x["severity"] in sla and period.contains(x["found_at"])]
    exc = []
    for x in pop:
        due = _d(x["found_at"]) + timedelta(days=sla[x["severity"]])
        if x["remediated_at"]:
            if _d(x["remediated_at"]) > due:
                days = (_d(x["remediated_at"]) - _d(x["found_at"])).days
                exc.append({"item": x["id"], "reason": f"{x['severity']} fixed in {days} days (SLA {sla[x['severity']]})"})
        elif period.end > due:
            exc.append({"item": x["id"], "reason": f"{x['severity']} still open past SLA due date {due}"})
    return TestResult([x["id"] for x in pop], exc, [f],
                      [f"SLA days: {sla}. Open findings not yet past due at period end are not exceptions."])


@control_test("training_completion")
def training_completion(src, period, ctrl):
    hris, lms = src.fetch("hris_employees"), src.fetch("training_records")
    latest: dict[str, date] = {}
    for r in lms.records:
        d = _d(r["completed_at"])
        latest[r["username"]] = max(d, latest.get(r["username"], d))
    active = [e for e in hris.records if e["status"] == "active"]
    cutoff = period.end - timedelta(days=365)
    exc = [{"item": e["employee_id"], "reason": "no security training in the 12 months before period end"}
           for e in active if latest.get(e["username"], date.min) < cutoff]
    return TestResult([e["employee_id"] for e in active], exc, [hris, lms],
                      ["Population: employees active at period end."])


@control_test("corrective_actions")
def corrective_actions(src, period, ctrl):
    capa = src.fetch("corrective_actions")
    pop = [c for c in capa.records if period.contains(c["due_date"])]
    exc = []
    for c in pop:
        if not c.get("root_cause") or c["root_cause"].lower().startswith("under analysis"):
            exc.append({"item": c["id"], "reason": "no documented root cause"})
        if not c["closed_at"]:
            exc.append({"item": c["id"], "reason": f"open past due date {c['due_date']}"})
        elif _d(c["closed_at"]) > _d(c["due_date"]):
            exc.append({"item": c["id"], "reason": f"closed {c['closed_at']} after due date {c['due_date']}"})
    return TestResult([c["id"] for c in pop], exc, [capa],
                      ["Population: corrective actions due within the audit period."])
