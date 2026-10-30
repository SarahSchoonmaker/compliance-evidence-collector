import json
from pathlib import Path

from evidence_collector.collect import run
from evidence_collector.evidence import select_sample, verify_package
from evidence_collector.servicenow import ServiceNowConfig, ServiceNowGRC
from evidence_collector.sources import FixtureSource, LiveSource

ROOT = Path(__file__).parent.parent
CONTROLS = ROOT / "config" / "controls.yaml"


def collect(tmp_path, **kw):
    return run(CONTROLS, tmp_path, **kw)


def test_package_contains_evidence_for_every_control(tmp_path):
    m = collect(tmp_path)
    d = Path(m["package_dir"])
    assert m["summary"] == {"controls": 11, "passed": 7, "failed": 4}
    for cid in ["AC-01", "CM-02", "QM-01"]:
        ev = json.loads((d / "controls" / f"{cid}.json").read_text())
        assert ev["population"]["count"] == len(ev["population"]["items"])
        assert ev["sources"] and all((d / s["snapshot"]).exists() for s in ev["sources"])
    assert (d / "control_matrix.csv").read_text().count("\n") == 12
    assert "Coverage by framework" in (d / "report.md").read_text()


def test_manifest_detects_tampering(tmp_path):
    d = Path(collect(tmp_path)["package_dir"])
    assert verify_package(d) == []
    f = d / "controls" / "CM-02.json"
    f.write_text(f.read_text().replace('"FAIL"', '"PASS"'))
    assert verify_package(d) == ["modified: controls/CM-02.json"]


def test_sample_is_reproducible_and_sized_by_frequency():
    pop = [f"x{i}" for i in range(100)]
    a = select_sample(pop, "per_event", "run1", "CM-02")
    assert a == select_sample(pop, "per_event", "run1", "CM-02")
    assert a["size"] == 25 and set(a["items"]) <= set(pop)
    assert select_sample(pop, "quarterly", "run1", "AC-03")["size"] == 2
    assert select_sample([], "daily", "run1", "X")["items"] == []


def test_broken_source_fails_one_control_not_the_run(tmp_path):
    class Broken(FixtureSource):
        def fetch(self, name):
            if name == "storage_buckets":
                raise ConnectionError("S3 unreachable")
            return super().fetch(name)

    m = collect(tmp_path, source=Broken(ROOT / "fixtures"))
    assert m["summary"]["controls"] == 11
    ev = json.loads((Path(m["package_dir"]) / "controls" / "DP-01.json").read_text())
    assert ev["result"] == "FAIL" and "S3 unreachable" in ev["exceptions"]["items"][0]["reason"]


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self.body


class FakeSession:
    def __init__(self, open_for=()):
        self.calls, self.open_for = [], set(open_for)

    def request(self, method, url, timeout=None, **kw):
        self.calls.append((method, url, kw))
        if method == "GET":
            hit = any(c in kw["params"]["sysparm_query"] for c in self.open_for)
            return FakeResponse({"result": [{"sys_id": "OPEN"}] if hit else []})
        return FakeResponse({"result": {"sys_id": f"S{len(self.calls)}"}})


def _publish(tmp_path, session, control_map):
    m = collect(tmp_path)
    cfg = ServiceNowConfig("https://t.service-now.com", "u", "p", control_map=control_map)
    return ServiceNowGRC(cfg, "live", session=session).publish(Path(m["package_dir"]), m, m["results"])


ALL = {c: f"SYS_{c}" for c in ["AC-01", "AC-02", "AC-03", "CM-01", "CM-02", "DP-01", "DP-02",
                               "LM-01", "VM-01", "HR-01", "QM-01"]}


def test_evidence_attached_to_each_control_and_issues_for_failures(tmp_path):
    s = FakeSession()
    out = _publish(tmp_path, s, ALL)
    attach = [c for c in s.calls if c[1].endswith("/api/now/attachment/file")]
    assert len(attach) == 11
    assert {c[2]["params"]["table_sys_id"] for c in attach} == set(ALL.values())
    assert sorted(i["control"] for i in out["issues_created"]) == ["AC-02", "CM-02", "DP-01", "VM-01"]
    issue = next(c[2]["json"] for c in s.calls if c[0] == "POST" and "json" in c[2])
    assert issue["short_description"].startswith("[Evidence] ")


def test_open_issues_are_not_duplicated(tmp_path):
    out = _publish(tmp_path, FakeSession(open_for={"CM-02"}), ALL)
    assert out["issues_already_open"] == ["CM-02"]
    assert len(out["issues_created"]) == 3


def test_unmapped_controls_are_skipped_in_live_mode(tmp_path):
    out = _publish(tmp_path, FakeSession(), {"AC-01": "SYS_AC-01"})
    assert out["attached"] == ["AC-01"] and len(out["skipped_unmapped"]) == 10


def test_dry_run_writes_requests_and_sends_nothing(tmp_path):
    m = collect(tmp_path, servicenow="dry-run")
    log = json.loads((Path(m["package_dir"]) / "servicenow_requests.json").read_text())
    assert len(log) == 11 + 4 * 2  # attachments + (lookup + create) per failed control
    assert verify_package(m["package_dir"]) == []


class FakeIAM:
    class exceptions:
        class NoSuchEntityException(Exception):
            pass

    def get_paginator(self, _):
        class P:
            def paginate(self_inner):
                return [{"Users": [{"UserName": "alice"}, {"UserName": "svc"}]}]
        return P()

    def get_login_profile(self, UserName):
        if UserName == "svc":
            raise self.exceptions.NoSuchEntityException()
        return {}

    def list_mfa_devices(self, UserName):
        return {"MFADevices": [{"SerialNumber": "x"}] if UserName == "alice" else []}


def test_live_iam_collector_normalizes_records():
    class Session:
        def client(self, name):
            return FakeIAM()

    ds = LiveSource(FixtureSource(ROOT / "fixtures"), aws_session=Session()).fetch("identity_users")
    assert ds.system == "AWS IAM" and "list_mfa_devices" in ds.query
    assert ds.records[0] == {"username": "alice", "console_access": True, "mfa_enabled": True,
                             "status": "active", "disabled_at": None}
    assert ds.records[1]["console_access"] is False
