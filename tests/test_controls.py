from datetime import date
from pathlib import Path

import pytest

from evidence_collector.checks import REGISTRY, Period
from evidence_collector.collect import load_controls
from evidence_collector.sources import Dataset, FixtureSource

ROOT = Path(__file__).parent.parent
PERIOD, CONTROLS = load_controls(ROOT / "config" / "controls.yaml")
CTRL = {c["id"]: c for c in CONTROLS}
FIXTURES = FixtureSource(ROOT / "fixtures")


def run_control(cid, src=FIXTURES, period=PERIOD):
    return REGISTRY[CTRL[cid]["test"]](src, period, CTRL[cid])


class OverrideSource:
    """Fixtures, with chosen datasets replaced, to test edge cases."""

    def __init__(self, **overrides):
        self.overrides = overrides

    def fetch(self, name):
        if name in self.overrides:
            return Dataset(name, "test", "test", self.overrides[name])
        return FIXTURES.fetch(name)


EXPECTED_EXCEPTIONS = {
    "AC-01": [], "AC-02": ["E104"], "AC-03": [], "CM-01": [], "CM-02": ["acme/data-pipeline#211"],
    "DP-01": ["acme-legacy-exports"], "DP-02": [], "LM-01": [], "VM-01": ["VULN-302"],
    "HR-01": [], "QM-01": [],
}


@pytest.mark.parametrize("cid", sorted(EXPECTED_EXCEPTIONS))
def test_each_control_finds_exactly_the_expected_exceptions(cid):
    result = run_control(cid)
    assert [e["item"] for e in result.exceptions] == EXPECTED_EXCEPTIONS[cid]


def test_every_control_maps_to_soc2_and_iso27001():
    for c in CONTROLS:
        assert c["mappings"]["soc2"] and c["mappings"]["iso27001"], c["id"]


def test_period_quarters():
    assert PERIOD.quarters() == ["2026-Q2", "2026-Q3"]
    assert Period(date(2026, 1, 1), date(2026, 12, 31)).quarters() == ["2026-Q1", "2026-Q2", "2026-Q3", "2026-Q4"]


def test_events_outside_period_are_excluded():
    pop = run_control("CM-02").population
    assert "acme/payments-api#150" not in pop  # merged in March, before the window
    assert "E108" not in run_control("AC-02").population  # terminated in January


def test_programmatic_accounts_excluded_from_mfa_population():
    assert "svc-deploy" not in run_control("AC-01").population


def test_mfa_missing_is_an_exception():
    users = FIXTURES.fetch("identity_users").records
    users = [dict(u, mfa_enabled=False) if u["username"] == "carol" else u for u in users]
    assert [e["item"] for e in run_control("AC-01", OverrideSource(identity_users=users)).exceptions] == ["carol"]


def test_late_deprovisioning_is_an_exception():
    users = [dict(u, disabled_at="2026-06-13T09:00:00Z") if u["username"] == "dave" else u
             for u in FIXTURES.fetch("identity_users").records]
    exc = run_control("AC-02", OverrideSource(identity_users=users)).exceptions
    assert any(e["item"] == "E103" and "SLA 24h" in e["reason"] for e in exc)


def test_missing_access_review_signoff_is_an_exception():
    reviews = [dict(r, signed_off_by=None) if r["quarter"] == "2026-Q3" else r
               for r in FIXTURES.fetch("access_reviews").records]
    exc = run_control("AC-03", OverrideSource(access_reviews=reviews)).exceptions
    assert exc == [{"item": "2026-Q3", "reason": "review completed without management sign-off"}]


def test_open_vulnerability_past_due_is_an_exception():
    findings = [dict(f, found_at="2026-08-01") if f["id"] == "VULN-305" else f
                for f in FIXTURES.fetch("vulnerability_findings").records]
    exc = run_control("VM-01", OverrideSource(vulnerability_findings=findings)).exceptions
    assert "VULN-305" in [e["item"] for e in exc]


def test_no_logging_trail_fails():
    trails = [{"name": "t", "is_multi_region": True, "is_logging": False, "log_file_validation": True}]
    assert not run_control("LM-01", OverrideSource(audit_trails=trails)).passed
