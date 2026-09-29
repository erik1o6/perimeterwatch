from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from perimeterwatch.config import Settings
from perimeterwatch.core import engine
from perimeterwatch.core.models import AssetType, ModuleResult, ScanMode, Sensitivity
from perimeterwatch.web import mail
from perimeterwatch.web.app import create_app
from perimeterwatch.worker.runner import Worker
from tests.conftest import CANARY, POSTGRES_URL, ROOT, fresh_database
from tests.unit.test_engine_and_storage import make_module


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        database_url=POSTGRES_URL,
        per_host_rps=1000,
        min_scan_interval_minutes=0,
        # Most tests exercise scanning itself. The rule that scanning needs a
        # verified domain has tests of its own in test_flows.py.
        scan_requires_verification=False,
        base_url="http://testserver",
        max_targets_per_tenant=3,
    )


@pytest.fixture
def database(settings: Settings) -> Any:
    db = fresh_database(settings)
    yield db
    db.engine.dispose()


@pytest.fixture
def outbox(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, str]]:
    sent: list[dict[str, str]] = []

    def fake_send(settings: Settings, to: str, subject: str, body: str) -> None:
        sent.append({"to": to, "subject": subject, "body": body})

    monkeypatch.setattr(mail, "send", fake_send)
    return sent


@pytest.fixture
def app(settings: Settings, database: Any, outbox: list[dict[str, str]]) -> Any:
    return create_app(settings, database)


def csrf_of(html: str) -> str:
    match = re.search(r'name="csrf" value="([^"]+)"', html)
    assert match, "page has no CSRF field"
    return match.group(1)


class Browser:
    """One person's browser: keeps cookies and fills in the CSRF field."""

    def __init__(self, app: Any, outbox: list[dict[str, str]], email: str) -> None:
        self.client = TestClient(app, follow_redirects=False)
        self.outbox = outbox
        self.email = email
        self.csrf = ""

    def get(self, path: str, **kw: Any) -> Any:
        response = self.client.get(path, **kw)
        if 'name="csrf"' in response.text:
            self.csrf = csrf_of(response.text)
        return response

    def post(
        self, path: str, data: dict[str, str] | None = None, *, csrf: str | None = None
    ) -> Any:
        form = dict(data or {})
        form["csrf"] = self.csrf if csrf is None else csrf
        return self.client.post(path, data=form)

    def follow(self, response: Any) -> Any:
        assert response.status_code == 303, (response.status_code, response.text[:300])
        return self.get(response.headers["location"])

    def request_link(self, email: str | None = None) -> str | None:
        before = len(self.outbox)
        self.get("/login")
        response = self.post("/login", {"email": email or self.email})
        assert response.status_code == 200
        if len(self.outbox) == before:
            return None
        match = re.search(r"/auth/(\S+)", self.outbox[-1]["body"])
        assert match
        return match.group(1)

    def sign_in(self) -> Browser:
        token = self.request_link()
        assert token
        assert self.get(f"/auth/{token}").status_code == 200
        response = self.post(f"/auth/{token}")
        assert response.status_code == 303, response.text[:300]
        self.get("/targets")
        return self

    def add_target(self, domain: str = ROOT) -> str:
        response = self.post("/targets", {"domain": domain})
        assert response.status_code == 303
        location = response.headers["location"]
        assert location.startswith("/targets/") and "error" not in location, location
        self.get(location)
        return location.removeprefix("/targets/")


@pytest.fixture
def browser(app: Any, outbox: list[dict[str, str]]) -> Any:
    def make(email: str = f"ana@{ROOT}") -> Browser:
        return Browser(app, outbox, email)

    return make


@pytest.fixture
def alice(browser: Any) -> Browser:
    return browser(f"alice@{ROOT}").sign_in()


@pytest.fixture
def mallory(browser: Any) -> Browser:
    return browser("mallory@rival-protocol.xyz").sign_in()


@pytest.fixture(autouse=True)
def modules(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Stand-in scan modules, so no test reaches the network."""
    state = {"dmarc_missing": True}

    async def passive(self: Any, target: Any, ctx: Any) -> ModuleResult:
        findings = []
        if state["dmarc_missing"]:
            findings.append(
                self.finding(
                    "email.dmarc.missing", AssetType.DOMAIN, target.root_domain,
                    f"{target.root_domain} has no DMARC record",
                )
            )  # fmt: skip
        if ctx.verified:
            findings.append(
                self.finding(
                    "breach.account", AssetType.EMAIL_ADDRESS, f"ana.lopez@{target.root_domain}",
                    f"ana.lopez@{target.root_domain} appears in the ExampleCo breach",
                    sensitivity=Sensitivity.PERSONAL, evidence={"breach": "ExampleCo"},
                )
            )  # fmt: skip
            findings.append(
                self.finding(
                    "secrets.exposed", AssetType.REPOSITORY, "acme-protocol/deploy",
                    "Github credential in acme-protocol/deploy",
                    sensitivity=Sensitivity.SECRET, evidence={"starts_with": "ghp_********"},
                )
            )  # fmt: skip
        return self.result(findings=findings)

    registry = {
        "email_posture": make_module("email_posture", behaviour=passive),
        "ports": make_module("ports", mode=ScanMode.ACTIVE),
    }
    for target in (
        "perimeterwatch.core.module.all_modules",
        "perimeterwatch.report.build.all_modules",
    ):
        monkeypatch.setattr(target, lambda: dict(registry))
    monkeypatch.setattr(engine, "all_modules", lambda: dict(registry))
    return {"registry": registry, "state": state}


@pytest.fixture
def worker(settings: Settings, database: Any) -> Worker:
    return Worker(settings, database)


@pytest.fixture
def verify_dns(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Decide what the DNS verification check will find."""
    from perimeterwatch.safety import authorisation as auth

    def set_result(verified: bool) -> None:
        async def check(domain: str, token: str, **kw: Any) -> auth.VerificationResult:
            detail = "Found." if verified else "No matching TXT record."
            return auth.VerificationResult(verified, "authoritative", detail)

        monkeypatch.setattr(auth, "check_dns", check)
        monkeypatch.setattr("perimeterwatch.web.routes.check_dns", check)

    return set_result


__all__ = ["CANARY", "Browser", "csrf_of"]
