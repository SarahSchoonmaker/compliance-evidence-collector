"""Evidence sources.

Every source returns a ``Dataset``: the records plus *how* they were obtained
(system and query). Recording the query is what lets an auditor rely on the
output as complete and accurate "information produced by the entity" (IPE).

* ``FixtureSource`` reads the synthetic JSON in ``fixtures/`` so the demo runs anywhere.
* ``LiveSource`` pulls identity, storage and logging data from AWS (boto3) and
  change-management data from GitHub, and falls back to fixtures for systems
  this demo doesn't connect to (HRIS, LMS, scanner, CAPA register).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Dataset:
    name: str
    system: str
    query: str
    records: list[dict]


class FixtureSource:
    def __init__(self, directory: str | Path) -> None:
        self.dir = Path(directory)

    def fetch(self, name: str) -> Dataset:
        data = json.loads((self.dir / f"{name}.json").read_text())
        return Dataset(name, data["system"], f"read fixtures/{name}.json", data["records"])


class LiveSource:
    """Live collectors for AWS and GitHub. Everything else falls back to fixtures."""

    def __init__(self, fallback: FixtureSource, aws_session=None, github=None) -> None:
        self.fallback = fallback
        self._aws = aws_session
        self._github = github
        self.handlers = {
            "identity_users": self._iam_users,
            "storage_buckets": self._s3_buckets,
            "audit_trails": self._cloudtrail,
            "branch_protection": self._branch_protection,
            "merged_pulls": self._merged_pulls,
        }

    def fetch(self, name: str) -> Dataset:
        handler = self.handlers.get(name)
        return handler() if handler else self.fallback.fetch(name)

    # --- AWS --------------------------------------------------------------

    @property
    def aws(self):
        if self._aws is None:
            import boto3

            self._aws = boto3.Session()
        return self._aws

    def _iam_users(self) -> Dataset:
        iam = self.aws.client("iam")
        records = []
        for page in iam.get_paginator("list_users").paginate():
            for u in page["Users"]:
                name = u["UserName"]
                try:
                    iam.get_login_profile(UserName=name)
                    console = True
                except iam.exceptions.NoSuchEntityException:
                    console = False
                mfa = bool(iam.list_mfa_devices(UserName=name)["MFADevices"])
                records.append({"username": name, "console_access": console, "mfa_enabled": mfa,
                                "status": "active", "disabled_at": None})
        return Dataset("identity_users", "AWS IAM",
                       "iam.list_users + iam.get_login_profile + iam.list_mfa_devices (all users)", records)

    def _s3_buckets(self) -> Dataset:
        s3 = self.aws.client("s3")
        records = []
        for b in s3.list_buckets()["Buckets"]:
            name = b["Name"]
            try:
                rules = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"]
                enc = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
            except s3.exceptions.ClientError:
                enc = None
            try:
                cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                blocked = all(cfg.values())
            except s3.exceptions.ClientError:
                blocked = False
            records.append({"name": name, "encryption": enc, "public_access_block": blocked})
        return Dataset("storage_buckets", "AWS S3",
                       "s3.list_buckets + s3.get_bucket_encryption + s3.get_public_access_block", records)

    def _cloudtrail(self) -> Dataset:
        ct = self.aws.client("cloudtrail")
        records = []
        for t in ct.describe_trails()["trailList"]:
            status = ct.get_trail_status(Name=t["TrailARN"])
            records.append({"name": t["Name"], "is_multi_region": t.get("IsMultiRegionTrail", False),
                            "is_logging": status.get("IsLogging", False),
                            "log_file_validation": t.get("LogFileValidationEnabled", False)})
        return Dataset("audit_trails", "AWS CloudTrail",
                       "cloudtrail.describe_trails + cloudtrail.get_trail_status", records)

    # --- GitHub -----------------------------------------------------------

    @property
    def github(self):
        if self._github is None:
            import requests

            s = requests.Session()
            s.headers.update({"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
                              "Accept": "application/vnd.github+json"})
            self._github = s
        return self._github

    def _repos(self) -> list[str]:
        return [r.strip() for r in os.environ.get("GITHUB_REPOS", "").split(",") if r.strip()]

    def _gh(self, path: str, **params):
        resp = self.github.get(f"https://api.github.com{path}", params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _branch_protection(self) -> Dataset:
        records = []
        for repo in self._repos():
            try:
                p = self._gh(f"/repos/{repo}/branches/main/protection")
                reviews = p.get("required_pull_request_reviews") or {}
                records.append({"repo": repo, "branch": "main",
                                "required_approving_review_count": reviews.get("required_approving_review_count", 0),
                                "enforce_admins": (p.get("enforce_admins") or {}).get("enabled", False),
                                "dismiss_stale_reviews": reviews.get("dismiss_stale_reviews", False)})
            except Exception:
                records.append({"repo": repo, "branch": "main", "required_approving_review_count": 0,
                                "enforce_admins": False, "dismiss_stale_reviews": False})
        return Dataset("branch_protection", "GitHub",
                       f"GET /repos/{{repo}}/branches/main/protection for {self._repos()}", records)

    def _merged_pulls(self) -> Dataset:
        records = []
        for repo in self._repos():
            page = 1
            while True:
                pulls = self._gh(f"/repos/{repo}/pulls", state="closed", base="main", per_page=100, page=page)
                if not pulls:
                    break
                for pr in pulls:
                    if not pr.get("merged_at"):
                        continue
                    reviews = self._gh(f"/repos/{repo}/pulls/{pr['number']}/reviews", per_page=100)
                    approvers = sorted({r["user"]["login"] for r in reviews if r["state"] == "APPROVED"})
                    records.append({"repo": repo, "number": pr["number"], "author": pr["user"]["login"],
                                    "merged_at": pr["merged_at"], "approvals": approvers,
                                    "merged_by": (pr.get("merged_by") or {}).get("login")})
                page += 1
        return Dataset("merged_pulls", "GitHub",
                       "GET /repos/{repo}/pulls?state=closed&base=main + /reviews per merged PR", records)
