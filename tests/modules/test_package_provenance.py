"""Provenance records of published packages. Nothing here touches the network: the
registries are stood in for by a table of answers.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest

from perimeterwatch.core.fingerprint import finding_fingerprint, finding_state_hash
from perimeterwatch.core.models import Finding, ModuleResult, ModuleStatus, Severity, Target
from perimeterwatch.modules import packages
from perimeterwatch.modules.packages import (
    PROVENANCE_NOTE,
    Packages,
    environment_text,
    file_text,
    repository_text,
    source_repository,
    version_before,
    workflow_text,
)
from tests.conftest import ROOT, fixture_text
from tests.modules.test_supply_chain import Registries, no_personal_data

NPM = "registry.npmjs.org"
PYPI = "pypi.org"
ORG = "acme-protocol"
KINDS = (
    "package.provenance.publisher",
    "package.provenance.lost",
    "package.provenance.absent",
)
SLSA = "https://slsa.dev/provenance/v1"


class Provenance(Registries):
    """npm and PyPI only. A request to any other host fails the test."""

    HOSTS = (NPM, PYPI)

    def attestation(self, name: str, version: str, answer: Any) -> Provenance:
        package = name.replace("/", "%2f")
        self.routes[(NPM, f"/-/npm/v1/attestations/{package}@{version}")] = answer
        return self

    def integrity(self, name: str, version: str, file: str, answer: Any) -> Provenance:
        self.routes[(PYPI, f"/integrity/{name}/{version}/{file}/provenance")] = answer
        return self

    def paths(self, host: str, prefix: str) -> list[str]:
        return [p for p in self.made("GET", host) if p.startswith(prefix)]


@pytest.fixture
def registries() -> Provenance:
    return Provenance()


def npm_document() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(fixture_text("packages", "npm_provenance.json"))
    return document


def pypi_document() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(fixture_text("packages", "pypi_acme-sdk.json"))
    return document


def unattested(document: dict[str, Any], *versions: str) -> dict[str, Any]:
    """The same package, with these versions published the old way, by a person."""
    for version in versions:
        entry = document["versions"][version]
        del entry["dist"]["attestations"]
        entry["_npmUser"] = {"name": "alice-acme", "email": "alice.private@mail.example"}
    return document


def encoded(statement: Any) -> str:
    return base64.b64encode(json.dumps(statement).encode()).decode()


def attestation(
    repository: Any = f"https://github.com/{ORG}/acme-sdk",
    workflow: Any = ".github/workflows/release.yml",
) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(fixture_text("packages", "npm_attestation.json"))
    envelope = document["attestations"][1]["bundle"]["dsseEnvelope"]
    statement = json.loads(base64.b64decode(envelope["payload"]))
    parameters = statement["predicate"]["buildDefinition"]["externalParameters"]
    parameters["workflow"].update(repository=repository, path=workflow)
    envelope["payload"] = encoded(statement)
    return document


def old_attestation(uri: str, entry_point: str) -> dict[str, Any]:
    """The layout used by provenance version 0.2."""
    document = attestation()
    row = document["attestations"][1]
    row["predicateType"] = "https://slsa.dev/provenance/v0.2"
    row["bundle"]["dsseEnvelope"]["payload"] = encoded(
        {
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {
                "invocation": {"configSource": {"uri": uri, "entryPoint": entry_point}},
            },
        }
    )
    return document


def pypi_provenance(**publisher: Any) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(fixture_text("packages", "pypi_provenance.json"))
    document["attestation_bundles"][0]["publisher"].update(publisher)
    return document


def npm_target(org: str | None = None) -> Target:
    return Target(root_domain=ROOT, npm_packages=["acme-sdk"], github_org=org)


def pypi_target(org: str | None = None) -> Target:
    return Target(root_domain=ROOT, pypi_packages=["acme-sdk"], github_org=org)


def provenance_findings(result: ModuleResult) -> list[Finding]:
    return [f for f in result.findings if f.kind in KINDS]


def one(result: ModuleResult, kind: str) -> Finding:
    [finding] = provenance_findings(result)
    assert finding.kind == kind
    return finding


def not_read(result: ModuleResult) -> None:
    """The lookup is reported as failed, and nothing is claimed about provenance."""
    assert provenance_findings(result) == []
    assert result.status is ModuleStatus.PARTIAL
    assert any("provenance" in n and "could not be read" in n for n in result.notes)
    assert "Traceback" not in result.model_dump_json()


async def scan(make_ctx: Any, registries: Provenance, target: Target) -> ModuleResult:
    return await Packages().run(target, make_ctx(handler=registries))


class TestPresent:
    async def test_npm(self, make_ctx: Any, registries: Provenance) -> None:
        registries.npm("acme-sdk", npm_document())
        registries.attestation("acme-sdk", "1.3.0", attestation())
        result = await scan(make_ctx, registries, npm_target())
        assert result.status is ModuleStatus.OK
        finding = one(result, "package.provenance.publisher")
        assert finding.asset_key == "npm:acme-sdk"
        assert finding.identity == {"registry": "npm"}
        assert finding.state == {
            "kind": "github",
            "repository": "acme-protocol/acme-sdk",
            "workflow": ".github/workflows/release.yml",
        }
        assert finding.evidence == {
            "registry": "npm",
            "name": "acme-sdk",
            "page": "https://www.npmjs.com/package/acme-sdk",
            "latest_version": "1.3.0",
            "environment": "",
            "trusted_publisher": "github",
            "note": PROVENANCE_NOTE,
        }
        assert finding.severity is Severity.INFO
        assert finding.severity_note is None

    async def test_npm_asks_for_one_record_only(
        self, make_ctx: Any, registries: Provenance
    ) -> None:
        registries.npm("acme-sdk", npm_document())
        registries.attestation("acme-sdk", "1.3.0", attestation())
        await scan(make_ctx, registries, npm_target())
        assert registries.paths(NPM, "/-/") == ["/-/npm/v1/attestations/acme-sdk@1.3.0"]
        assert registries.made("GET", NPM)[0] == "/acme-sdk"
        assert len(registries.made("GET", NPM)) == 2

    async def test_npm_scoped_name(self, make_ctx: Any, registries: Provenance) -> None:
        document = npm_document()
        document["name"] = "@acme/sdk"
        registries.npm("@acme/sdk", document)
        registries.attestation("@acme/sdk", "1.3.0", attestation())
        target = Target(root_domain=ROOT, npm_packages=["@acme/sdk"])
        result = await scan(make_ctx, registries, target)
        assert one(result, "package.provenance.publisher").asset_key == "npm:@acme/sdk"
        assert registries.paths(NPM, "/-/") == ["/-/npm/v1/attestations/@acme%2fsdk@1.3.0"]

    async def test_npm_older_layout(self, make_ctx: Any, registries: Provenance) -> None:
        registries.npm("acme-sdk", npm_document())
        registries.attestation(
            "acme-sdk",
            "1.3.0",
            old_attestation(
                f"git+https://github.com/{ORG}/acme-sdk@refs/heads/main",
                ".github/workflows/release.yml",
            ),
        )
        result = await scan(make_ctx, registries, npm_target())
        assert one(result, "package.provenance.publisher").state == {
            "kind": "github",
            "repository": "acme-protocol/acme-sdk",
            "workflow": ".github/workflows/release.yml",
        }

    async def test_npm_without_a_trusted_publisher(
        self, make_ctx: Any, registries: Provenance
    ) -> None:
        document = npm_document()
        del document["versions"]["1.3.0"]["_npmUser"]["trustedPublisher"]
        registries.npm("acme-sdk", document)
        registries.attestation("acme-sdk", "1.3.0", attestation())
        result = await scan(make_ctx, registries, npm_target())
        finding = one(result, "package.provenance.publisher")
        assert "trusted_publisher" not in finding.evidence
        assert finding.state["repository"] == "acme-protocol/acme-sdk"

    async def test_pypi(self, make_ctx: Any, registries: Provenance) -> None:
        registries.pypi("acme-sdk", pypi_document())
        registries.integrity("acme-sdk", "2.4.1", "acme_sdk.tar.gz", pypi_provenance())
        registries.integrity("acme-sdk", "1.0.0", "acme_sdk.tar.gz", pypi_provenance())
        result = await scan(make_ctx, registries, pypi_target())
        assert result.status is ModuleStatus.OK
        finding = one(result, "package.provenance.publisher")
        assert finding.asset_key == "pypi:acme-sdk"
        assert finding.state == {
            "kind": "github",
            "repository": "acme-protocol/acme-sdk",
            "workflow": "release.yml",
        }
        assert finding.evidence["latest_version"] == "2.4.1"
        assert finding.evidence["environment"] == "release"
        assert finding.evidence["note"] == PROVENANCE_NOTE
        assert finding.severity is Severity.INFO
        # The latest version has a record, so the one before it need not be asked about.
        assert registries.paths(PYPI, "/integrity/") == [
            "/integrity/acme-sdk/2.4.1/acme_sdk.tar.gz/provenance"
        ]

    async def test_pypi_without_an_environment(self, make_ctx: Any, registries: Provenance) -> None:
        registries.pypi("acme-sdk", pypi_document())
        registries.integrity(
            "acme-sdk", "2.4.1", "acme_sdk.tar.gz", pypi_provenance(environment=None)
        )
        result = await scan(make_ctx, registries, pypi_target())
        assert one(result, "package.provenance.publisher").evidence["environment"] == ""

    async def test_an_answer_is_remembered(self, make_ctx: Any, registries: Provenance) -> None:
        registries.npm("acme-sdk", npm_document())
        registries.attestation("acme-sdk", "1.3.0", attestation())
        ctx = make_ctx(handler=registries)
        first = await Packages().run(npm_target(), ctx)
        second = await Packages().run(npm_target(), ctx)
        assert len(registries.paths(NPM, "/-/")) == 1
        assert one(first, KINDS[0]).state == one(second, KINDS[0]).state

    async def test_a_failed_lookup_is_not_remembered(
        self, make_ctx: Any, registries: Provenance
    ) -> None:
        registries.npm("acme-sdk", npm_document())
        registries.attestation("acme-sdk", "1.3.0", httpx.Response(503))
        ctx = make_ctx(handler=registries)
        not_read(await Packages().run(npm_target(), ctx))
        registries.attestation("acme-sdk", "1.3.0", attestation())
        result = await Packages().run(npm_target(), ctx)
        assert result.status is ModuleStatus.OK
        one(result, "package.provenance.publisher")

    async def test_what_is_remembered_is_checked_again(
        self, make_ctx: Any, registries: Provenance
    ) -> None:
        registries.npm("acme-sdk", npm_document())
        registries.attestation("acme-sdk", "1.3.0", attestation())
        ctx = make_ctx(handler=registries)
        ctx.cache_set(
            packages.PROVENANCE_NAMESPACE,
            "npm:acme-sdk@1.3.0",
            json.dumps({"kind": "github", "repository": "../../x", "workflow": "<script>"}),
            packages.PROVENANCE_TTL,
        )
        result = await Packages().run(npm_target(), ctx)
        finding = one(result, "package.provenance.publisher")
        assert finding.state["repository"] == "acme-protocol/acme-sdk"


class TestLost:
    async def test_npm(self, make_ctx: Any, registries: Provenance) -> None:
        registries.npm("acme-sdk", unattested(npm_document(), "1.3.0"))
        result = await scan(make_ctx, registries, npm_target())
        assert result.status is ModuleStatus.OK
        finding = one(result, "package.provenance.lost")
        assert finding.severity is Severity.MEDIUM
        assert finding.asset_key == "npm:acme-sdk"
        assert finding.evidence["latest_version"] == "1.3.0"
        assert finding.evidence["previous_version"] == "1.2.0"
        assert finding.evidence["note"] == PROVENANCE_NOTE
        assert "1.3.0" in finding.title and "1.2.0" in finding.title
        assert registries.paths(NPM, "/-/") == []

    async def test_pypi(self, make_ctx: Any, registries: Provenance) -> None:
        registries.pypi("acme-sdk", pypi_document())
        registries.integrity("acme-sdk", "1.0.0", "acme_sdk.tar.gz", pypi_provenance())
        result = await scan(make_ctx, registries, pypi_target())
        assert result.status is ModuleStatus.OK
        finding = one(result, "package.provenance.lost")
        assert finding.severity is Severity.MEDIUM
        assert finding.evidence["latest_version"] == "2.4.1"
        assert finding.evidence["previous_version"] == "1.0.0"
        assert finding.evidence["note"] == PROVENANCE_NOTE
        assert len(registries.paths(PYPI, "/integrity/")) == 2

    async def test_the_version_before_is_the_one_published_before(
        self, make_ctx: Any, registries: Provenance
    ) -> None:
        # 1.2.1 is a later fix to the older line, published after the latest version.
        document = unattested(npm_document(), "1.3.0")
        document["versions"]["1.2.1"] = unattested(npm_document(), "1.2.0")["versions"]["1.2.0"]
        document["time"]["1.2.1"] = "2026-09-01T00:00:00.000Z"
        registries.npm("acme-sdk", document)
        result = await scan(make_ctx, registries, npm_target())
        finding = one(result, "package.provenance.lost")
        assert finding.evidence["previous_version"] == "1.2.0"

    async def test_regaining_a_record_gives_a_publisher(
        self, make_ctx: Any, registries: Provenance
    ) -> None:
        registries.npm("acme-sdk", unattested(npm_document(), "1.2.0"))
        registries.attestation("acme-sdk", "1.3.0", attestation())
        result = await scan(make_ctx, registries, npm_target())
        one(result, "package.provenance.publisher")


class TestAbsent:
    async def test_npm(self, make_ctx: Any, registries: Provenance) -> None:
        registries.npm("acme-sdk", unattested(npm_document(), "1.2.0", "1.3.0"))
        result = await scan(make_ctx, registries, npm_target())
        assert result.status is ModuleStatus.OK
        finding = one(result, "package.provenance.absent")
        assert finding.severity is Severity.INFO
        assert finding.state == {}
        assert finding.evidence["latest_version"] == "1.3.0"
        assert finding.evidence["previous_version"] == "1.2.0"
        assert finding.evidence["note"] == PROVENANCE_NOTE
        assert PROVENANCE_NOTE in result.notes
        assert "signature" in PROVENANCE_NOTE and "does not verify" in PROVENANCE_NOTE

    async def test_pypi(self, make_ctx: Any, registries: Provenance) -> None:
        registries.pypi("acme-sdk", pypi_document())
        result = await scan(make_ctx, registries, pypi_target())
        assert result.status is ModuleStatus.OK
        finding = one(result, "package.provenance.absent")
        assert finding.asset_key == "pypi:acme-sdk"
        assert finding.evidence["note"] == PROVENANCE_NOTE
        assert registries.paths(PYPI, "/integrity/") == [
            "/integrity/acme-sdk/2.4.1/acme_sdk.tar.gz/provenance",
            "/integrity/acme-sdk/1.0.0/acme_sdk.tar.gz/provenance",
        ]

    async def test_a_package_that_does_not_exist(
        self, make_ctx: Any, registries: Provenance
    ) -> None:
        result = await scan(make_ctx, registries, npm_target())
        assert [f.kind for f in result.findings] == ["package.missing"]

    async def test_lookalikes_are_not_asked_about(
        self, make_ctx: Any, registries: Provenance
    ) -> None:
        registries.npm("acme-sdk", npm_document())
        registries.npm("acme_sdk", npm_document())
        registries.attestation("acme-sdk", "1.3.0", attestation())
        registries.HOSTS = (*registries.HOSTS, "api.npmjs.org")
        result = await scan(make_ctx, registries, npm_target())
        assert [f.asset_key for f in provenance_findings(result)] == ["npm:acme-sdk"]
        assert len(registries.paths(NPM, "/-/")) == 1


class TestOneVersion:
    def only_latest(self) -> dict[str, Any]:
        document = npm_document()
        del document["versions"]["1.2.0"]
        del document["time"]["1.2.0"]
        return document

    async def test_npm_with_a_record(self, make_ctx: Any, registries: Provenance) -> None:
        registries.npm("acme-sdk", self.only_latest())
        registries.attestation("acme-sdk", "1.3.0", attestation())
        result = await scan(make_ctx, registries, npm_target())
        assert result.status is ModuleStatus.OK
        one(result, "package.provenance.publisher")

    async def test_npm_without_a_record(self, make_ctx: Any, registries: Provenance) -> None:
        registries.npm("acme-sdk", unattested(self.only_latest(), "1.3.0"))
        result = await scan(make_ctx, registries, npm_target())
        assert result.status is ModuleStatus.OK
        finding = one(result, "package.provenance.absent")
        assert "previous_version" not in finding.evidence

    async def test_pypi_without_a_record(self, make_ctx: Any, registries: Provenance) -> None:
        document = pypi_document()
        del document["releases"]["1.0.0"]
        registries.pypi("acme-sdk", document)
        result = await scan(make_ctx, registries, pypi_target())
        assert result.status is ModuleStatus.OK
        finding = one(result, "package.provenance.absent")
        assert "previous_version" not in finding.evidence
        assert len(registries.paths(PYPI, "/integrity/")) == 1

    async def test_pypi_with_a_record(self, make_ctx: Any, registries: Provenance) -> None:
        document = pypi_document()
        del document["releases"]["1.0.0"]
        registries.pypi("acme-sdk", document)
        registries.integrity("acme-sdk", "2.4.1", "acme_sdk.tar.gz", pypi_provenance())
        result = await scan(make_ctx, registries, pypi_target())
        one(result, "package.provenance.publisher")


class TestPublisherChange:
    async def test_npm_repository_change(self, make_ctx: Any, registries: Provenance) -> None:
        registries.npm("acme-sdk", npm_document())
        registries.attestation("acme-sdk", "1.3.0", attestation())
        first = one(await scan(make_ctx, registries, npm_target()), KINDS[0])
        same = one(await scan(make_ctx, registries, npm_target()), KINDS[0])

        document = npm_document()
        document["versions"]["1.4.0"] = json.loads(
            json.dumps(document["versions"]["1.3.0"]).replace("1.3.0", "1.4.0")
        )
        document["time"]["1.4.0"] = "2026-09-20T00:00:00.000Z"
        document["dist-tags"]["latest"] = "1.4.0"
        registries.npm("acme-sdk", document)
        registries.attestation(
            "acme-sdk", "1.4.0", attestation(repository="https://github.com/mallory/acme-sdk")
        )
        second = one(await scan(make_ctx, registries, npm_target()), KINDS[0])

        assert second.state["repository"] == "mallory/acme-sdk"
        key = b"k" * 32
        prints = {finding_fingerprint(ROOT, f, key) for f in (first, same, second)}
        assert len(prints) == 1
        assert finding_state_hash(first) == finding_state_hash(same)
        assert finding_state_hash(first) != finding_state_hash(second)

    async def test_a_new_version_alone_changes_nothing(
        self, make_ctx: Any, registries: Provenance
    ) -> None:
        registries.pypi("acme-sdk", pypi_document())
        registries.integrity(
            "acme-sdk", "2.4.1", "acme_sdk.tar.gz", pypi_provenance(environment="release")
        )
        first = one(await scan(make_ctx, registries, pypi_target()), KINDS[0])
        document = pypi_document()
        document["info"]["version"] = "2.5.0"
        document["releases"]["2.5.0"] = [
            {"filename": "acme_sdk.tar.gz", "upload_time_iso_8601": "2026-09-20T10:00:00Z"}
        ]
        registries.pypi("acme-sdk", document)
        registries.integrity(
            "acme-sdk", "2.5.0", "acme_sdk.tar.gz", pypi_provenance(environment="production")
        )
        second = one(await scan(make_ctx, registries, pypi_target()), KINDS[0])
        assert second.evidence["latest_version"] == "2.5.0"
        assert second.evidence["environment"] == "production"
        assert finding_state_hash(first) == finding_state_hash(second)

    @pytest.mark.parametrize("field", ["workflow", "repository"])
    async def test_pypi_change(self, make_ctx: Any, registries: Provenance, field: str) -> None:
        registries.pypi("acme-sdk", pypi_document())
        registries.integrity("acme-sdk", "2.4.1", "acme_sdk.tar.gz", pypi_provenance())
        first = one(await scan(make_ctx, registries, pypi_target()), KINDS[0])
        changed = {"workflow": "other.yml", "repository": "mallory/acme-sdk"}[field]
        registries.integrity(
            "acme-sdk", "2.4.1", "acme_sdk.tar.gz", pypi_provenance(**{field: changed})
        )
        second = one(await scan(make_ctx, registries, pypi_target()), KINDS[0])
        key = b"k" * 32
        assert finding_fingerprint(ROOT, first, key) == finding_fingerprint(ROOT, second, key)
        assert finding_state_hash(first) != finding_state_hash(second)


class TestOrganisation:
    async def test_inside(self, make_ctx: Any, registries: Provenance) -> None:
        registries.npm("acme-sdk", npm_document())
        registries.attestation("acme-sdk", "1.3.0", attestation())
        finding = one(await scan(make_ctx, registries, npm_target("Acme-Protocol")), KINDS[0])
        assert finding.severity is Severity.INFO
        assert finding.severity_note is None

    async def test_outside_npm(self, make_ctx: Any, registries: Provenance) -> None:
        registries.npm("acme-sdk", npm_document())
        registries.attestation(
            "acme-sdk", "1.3.0", attestation(repository="https://github.com/mallory/acme-sdk")
        )
        finding = one(await scan(make_ctx, registries, npm_target(ORG)), KINDS[0])
        assert finding.severity is Severity.LOW
        assert "outside your GitHub organisation acme-protocol" in (finding.severity_note or "")

    async def test_outside_pypi(self, make_ctx: Any, registries: Provenance) -> None:
        registries.pypi("acme-sdk", pypi_document())
        registries.integrity(
            "acme-sdk",
            "2.4.1",
            "acme_sdk.tar.gz",
            pypi_provenance(repository="acme-protocol-x/acme-sdk"),
        )
        finding = one(await scan(make_ctx, registries, pypi_target(ORG)), KINDS[0])
        assert finding.severity is Severity.LOW
        assert finding.severity_note

    async def test_another_service_is_outside(self, make_ctx: Any, registries: Provenance) -> None:
        registries.pypi("acme-sdk", pypi_document())
        registries.integrity(
            "acme-sdk",
            "2.4.1",
            "acme_sdk.tar.gz",
            pypi_provenance(
                kind="GitLab",
                repository=f"{ORG}/tools/acme-sdk",
                workflow_filepath=".gitlab-ci.yml",
            ),
        )
        finding = one(await scan(make_ctx, registries, pypi_target(ORG)), KINDS[0])
        assert finding.state == {
            "kind": "gitlab",
            "repository": "acme-protocol/tools/acme-sdk",
            "workflow": ".gitlab-ci.yml",
        }
        assert finding.severity is Severity.LOW

    async def test_no_organisation_configured(self, make_ctx: Any, registries: Provenance) -> None:
        registries.npm("acme-sdk", npm_document())
        registries.attestation(
            "acme-sdk", "1.3.0", attestation(repository="https://github.com/mallory/acme-sdk")
        )
        finding = one(await scan(make_ctx, registries, npm_target()), KINDS[0])
        assert finding.severity is Severity.INFO


def unreachable(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectTimeout("slow")


BAD_ANSWERS = [
    httpx.Response(301, headers={"location": "https://evil.example/"}),
    httpx.Response(403),
    httpx.Response(404, json={"error": "Not found"}),
    httpx.Response(404, content=b"<html>Page Not Found</html>"),
    httpx.Response(404, json={"message": "Something else"}),
    httpx.Response(404, json=["No provenance available"]),
    httpx.Response(429),
    httpx.Response(500),
    httpx.Response(503, json={"message": "No provenance available for acme_sdk.tar.gz"}),
    "<html>gateway error</html>",
    '{"attestations": [',
    "",
    "[" * 100_000,
    "null",
    "[1, 2, 3]",
    '"text"',
    {},
    {"attestations": "none", "attestation_bundles": "none"},
    {"attestations": [], "attestation_bundles": []},
    {"attestations": [1, None, {}], "attestation_bundles": [1, None, {}]},
    {
        "attestations": [{"predicateType": SLSA, "bundle": "x"}],
        "attestation_bundles": [{"publisher": "x"}],
    },
    {
        "attestations": [
            {"predicateType": SLSA, "bundle": {"dsseEnvelope": {"payload": "not base64 !"}}}
        ],
        "attestation_bundles": [{"publisher": {"kind": 7}}],
    },
    {
        "attestations": [
            {"predicateType": SLSA, "bundle": {"dsseEnvelope": {"payload": encoded([1])}}}
        ],
        "attestation_bundles": [{"publisher": {"kind": "GitHub"}}],
    },
    {
        "attestations": [
            {
                "predicateType": SLSA,
                "bundle": {"dsseEnvelope": {"payload": encoded({"predicate": {"x": 1}})}},
            }
        ],
        "attestation_bundles": [{"publisher": {"kind": "Unheard-of", "repository": "a/b"}}],
    },
    unreachable,
]

BAD_VERSION_RECORDS: list[Any] = [
    None,
    "text",
    {},
    {"dist": "text"},
    {"dist": {"attestations": "yes"}},
    {"dist": {"attestations": []}},
    {"dist": {"attestations": {}}},
    {"dist": {"attestations": {"url": "https://registry.npmjs.org/x"}}},
    {"dist": {"attestations": {"provenance": "text"}}},
    {"dist": {"attestations": {"provenance": {"predicateType": 5}}}},
    {"dist": {"attestations": {"provenance": {"predicateType": "https://evil.example/"}}}},
    {"dist": {"attestations": {"provenance": {"predicateType": SLSA + "x" * 500}}}},
]


class TestFailedLookups:
    """A lookup that fails is "could not be read". It is never "lost" or "absent"."""

    @pytest.mark.parametrize("answer", BAD_ANSWERS)
    async def test_npm_record_of_the_latest(
        self, make_ctx: Any, registries: Provenance, answer: Any
    ) -> None:
        registries.npm("acme-sdk", npm_document())
        registries.attestation("acme-sdk", "1.3.0", answer)
        not_read(await scan(make_ctx, registries, npm_target()))

    @pytest.mark.parametrize("answer", BAD_ANSWERS)
    async def test_pypi_latest(self, make_ctx: Any, registries: Provenance, answer: Any) -> None:
        registries.pypi("acme-sdk", pypi_document())
        registries.integrity("acme-sdk", "2.4.1", "acme_sdk.tar.gz", answer)
        registries.integrity("acme-sdk", "1.0.0", "acme_sdk.tar.gz", pypi_provenance())
        not_read(await scan(make_ctx, registries, pypi_target()))

    @pytest.mark.parametrize("answer", BAD_ANSWERS)
    async def test_pypi_version_before(
        self, make_ctx: Any, registries: Provenance, answer: Any
    ) -> None:
        registries.pypi("acme-sdk", pypi_document())
        registries.integrity("acme-sdk", "1.0.0", "acme_sdk.tar.gz", answer)
        not_read(await scan(make_ctx, registries, pypi_target()))

    @pytest.mark.parametrize("entry", BAD_VERSION_RECORDS)
    async def test_npm_latest_version_not_understood(
        self, make_ctx: Any, registries: Provenance, entry: Any
    ) -> None:
        document = npm_document()
        document["versions"]["1.3.0"] = entry
        registries.npm("acme-sdk", document)
        not_read(await scan(make_ctx, registries, npm_target()))
        assert registries.paths(NPM, "/-/") == []

    @pytest.mark.parametrize("entry", BAD_VERSION_RECORDS)
    async def test_npm_version_before_not_understood(
        self, make_ctx: Any, registries: Provenance, entry: Any
    ) -> None:
        document = unattested(npm_document(), "1.3.0")
        document["versions"]["1.2.0"] = entry
        registries.npm("acme-sdk", document)
        not_read(await scan(make_ctx, registries, npm_target()))

    @pytest.mark.parametrize(
        "change",
        [
            {"time": None},
            {"time": "text"},
            {"time": {"1.2.0": "2025-01-02T10:00:00.000Z"}},
            {"time": {"1.2.0": "2025-01-02T10:00:00.000Z", "1.3.0": "last week"}},
            {"time": {"1.2.0": 5, "1.3.0": ["x"]}},
        ],
    )
    async def test_npm_order_of_versions_unknown(
        self, make_ctx: Any, registries: Provenance, change: dict[str, Any]
    ) -> None:
        document = unattested(npm_document(), "1.3.0")
        document.update(change)
        registries.npm("acme-sdk", document)
        not_read(await scan(make_ctx, registries, npm_target()))

    @pytest.mark.parametrize(
        "change",
        [
            {"dist-tags": {"latest": "1.9.9"}},
            {"dist-tags": {"latest": "1.3.0/../1.2.0"}},
            {"dist-tags": {"latest": "<script>alert(1)</script>"}},
            {"dist-tags": {"latest": "1" * 500}},
            {"dist-tags": {"latest": None}},
            {"versions": []},
        ],
    )
    async def test_npm_latest_version_unknown(
        self, make_ctx: Any, registries: Provenance, change: dict[str, Any]
    ) -> None:
        document = npm_document()
        document.update(change)
        registries.npm("acme-sdk", document)
        result = await scan(make_ctx, registries, npm_target())
        not_read(result)
        assert "<script>" not in result.model_dump_json()

    @pytest.mark.parametrize(
        "files",
        [
            [],
            "text",
            [None, 5, {}],
            [{"filename": 5, "upload_time_iso_8601": "2026-07-01T10:00:00Z"}],
            [{"filename": "../../etc/passwd", "upload_time_iso_8601": "2026-07-01T10:00:00Z"}],
            [{"filename": "a/b.tar.gz", "upload_time_iso_8601": "2026-07-01T10:00:00Z"}],
            [{"filename": "a..b.tar.gz", "upload_time_iso_8601": "2026-07-01T10:00:00Z"}],
            [{"filename": "a?x=1#y.tar.gz", "upload_time_iso_8601": "2026-07-01T10:00:00Z"}],
            [{"filename": "<script>.whl", "upload_time_iso_8601": "2026-07-01T10:00:00Z"}],
            [{"filename": "a" * 500 + ".whl", "upload_time_iso_8601": "2026-07-01T10:00:00Z"}],
            [{"filename": "acme_sdk.tar.gz", "upload_time_iso_8601": "last week"}],
        ],
    )
    async def test_pypi_files_of_the_latest_unusable(
        self, make_ctx: Any, registries: Provenance, files: Any
    ) -> None:
        document = pypi_document()
        document["releases"]["2.4.1"] = files
        registries.pypi("acme-sdk", document)
        registries.integrity("acme-sdk", "1.0.0", "acme_sdk.tar.gz", pypi_provenance())
        result = await scan(make_ctx, registries, pypi_target())
        not_read(result)
        text = result.model_dump_json()
        assert "passwd" not in text and "<script>" not in text
        for path in registries.paths(PYPI, "/integrity/"):
            assert ".." not in path and "?" not in path and "<" not in path

    async def test_pypi_files_of_the_version_before_unusable(
        self, make_ctx: Any, registries: Provenance
    ) -> None:
        document = pypi_document()
        document["releases"]["1.0.0"][0]["filename"] = "../x.tar.gz"
        registries.pypi("acme-sdk", document)
        not_read(await scan(make_ctx, registries, pypi_target()))

    async def test_very_long_history_without_a_record(
        self, make_ctx: Any, registries: Provenance, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Only the latest version's own record is read, so the version before is unknown.
        monkeypatch.setattr(packages, "MAX_DOCUMENT_BYTES", 50_000)
        document = unattested(npm_document(), "1.3.0")
        latest = dict(document["versions"]["1.3.0"])
        document["readme"] = "x" * 100_000
        registries.npm("acme-sdk", document)
        registries.routes[(NPM, "/acme-sdk/latest")] = latest
        not_read(await scan(make_ctx, registries, npm_target()))

    async def test_very_long_history_with_a_record(
        self, make_ctx: Any, registries: Provenance, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(packages, "MAX_DOCUMENT_BYTES", 50_000)
        document = npm_document()
        latest = dict(document["versions"]["1.3.0"])
        document["readme"] = "x" * 100_000
        registries.npm("acme-sdk", document)
        registries.routes[(NPM, "/acme-sdk/latest")] = latest
        registries.attestation("acme-sdk", "1.3.0", attestation())
        result = await scan(make_ctx, registries, npm_target())
        no_personal_data(result)
        one(result, "package.provenance.publisher")

    async def test_other_findings_survive(self, make_ctx: Any, registries: Provenance) -> None:
        registries.npm("acme-sdk", npm_document())
        registries.attestation("acme-sdk", "1.3.0", httpx.Response(500))
        result = await scan(make_ctx, registries, npm_target())
        assert [f.kind for f in result.findings] == ["package.maintainers"]
        assert result.status is ModuleStatus.PARTIAL


class TestOversized:
    async def test_npm(
        self, make_ctx: Any, registries: Provenance, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(packages, "MAX_PROVENANCE_BYTES", 5_000)
        document = attestation()
        document["pad"] = "x" * 50_000
        registries.npm("acme-sdk", npm_document())
        registries.attestation("acme-sdk", "1.3.0", document)
        result = await scan(make_ctx, registries, npm_target())
        not_read(result)
        assert any("sent more than 5 kB" in n for n in result.notes)

    async def test_pypi(
        self, make_ctx: Any, registries: Provenance, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(packages, "MAX_PROVENANCE_BYTES", 5_000)
        registries.pypi("acme-sdk", pypi_document())
        registries.integrity(
            "acme-sdk", "2.4.1", "acme_sdk.tar.gz", pypi_provenance(pad="x" * 50_000)
        )
        registries.integrity("acme-sdk", "1.0.0", "acme_sdk.tar.gz", pypi_provenance())
        not_read(await scan(make_ctx, registries, pypi_target()))

    async def test_pypi_refusal(
        self, make_ctx: Any, registries: Provenance, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(packages, "MAX_PROVENANCE_BYTES", 5_000)
        registries.pypi("acme-sdk", pypi_document())
        registries.integrity(
            "acme-sdk",
            "2.4.1",
            "acme_sdk.tar.gz",
            httpx.Response(404, json={"message": "No provenance available", "pad": "x" * 50_000}),
        )
        registries.integrity("acme-sdk", "1.0.0", "acme_sdk.tar.gz", pypi_provenance())
        not_read(await scan(make_ctx, registries, pypi_target()))

    async def test_payload_inside_the_answer(
        self, make_ctx: Any, registries: Provenance, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        document = attestation(workflow=".github/workflows/" + "a" * 3_000 + ".yml")
        monkeypatch.setattr(
            packages,
            "MAX_PROVENANCE_BYTES",
            len(document["attestations"][1]["bundle"]["dsseEnvelope"]["payload"]) - 1,
        )
        assert packages.npm_publisher(attestation()).repository == "acme-protocol/acme-sdk"
        with pytest.raises(packages.RegistryError):
            packages.npm_publisher(document)

    async def test_many_records(self, make_ctx: Any, registries: Provenance) -> None:
        document = attestation()
        filler = {"predicateType": "https://example.invalid/other", "bundle": {}}
        document["attestations"] = [filler] * 5_000 + document["attestations"]
        registries.npm("acme-sdk", npm_document())
        registries.attestation("acme-sdk", "1.3.0", document)
        not_read(await scan(make_ctx, registries, npm_target()))


HOSTILE = [
    "<script>alert(1)</script>",
    "acme-protocol/<script>alert(1)</script>",
    "../../etc/passwd",
    "acme-protocol/..",
    "../acme-sdk",
    "acme-protocol/acme-sdk/../../x",
    "acme-protocol/acme sdk",
    "acme-protocol/acme-sdk?x=1",
    "acme-protocol/acme-sdk#x",
    "acme-protocol\\acme-sdk",
    "acme-protocol/acme-sdk\n",
    "acme-protocol/acme-sdk\x00",
    "acme-protocol/" + "a" * 5_000,
    "a" * 100_000,
    "'; DROP TABLE findings; --",
    "{{7*7}}/${jndi:ldap://evil.example/a}",
    "",
    "/",
    "acme-protocol/",
    None,
    5,
    ["acme-protocol/acme-sdk"],
    {"owner": "acme-protocol"},
]

HOSTILE_ADDRESSES = [
    "http://github.com/acme-protocol/acme-sdk",
    "https://evil.example/acme-protocol/acme-sdk",
    "https://github.com.evil.example/acme-protocol/acme-sdk",
    "https://github.com@evil.example/acme-protocol/acme-sdk",
    "https://evil.example/https://github.com/acme-protocol/acme-sdk",
    "javascript:alert(1)",
    "file:///etc/passwd",
    "//github.com/acme-protocol/acme-sdk",
    "https://github.com/",
    "https://github.com/acme-protocol",
]


def clean(result: ModuleResult) -> None:
    text = result.model_dump_json()
    for fragment in ("<script", "passwd", "DROP TABLE", "jndi", "evil.example", "a" * 300, ".."):
        assert fragment not in text, fragment
    assert "\\u0000" not in text


def clean_requests(registries: Provenance) -> None:
    for request in registries.requests:
        assert request.url.host in (NPM, PYPI)
        path = request.url.raw_path.decode()
        assert ".." not in path and "<" not in path and len(path) < 600


class TestHostileValues:
    @pytest.mark.parametrize("value", HOSTILE)
    async def test_npm_repository(self, make_ctx: Any, registries: Provenance, value: Any) -> None:
        address = f"https://github.com/{value}" if isinstance(value, str) else value
        registries.npm("acme-sdk", npm_document())
        registries.attestation("acme-sdk", "1.3.0", attestation(repository=address))
        result = await scan(make_ctx, registries, npm_target())
        not_read(result)
        clean(result)
        clean_requests(registries)

    @pytest.mark.parametrize("value", HOSTILE_ADDRESSES)
    async def test_npm_repository_address(
        self, make_ctx: Any, registries: Provenance, value: str
    ) -> None:
        registries.npm("acme-sdk", npm_document())
        registries.attestation("acme-sdk", "1.3.0", attestation(repository=value))
        result = await scan(make_ctx, registries, npm_target())
        not_read(result)
        clean(result)

    @pytest.mark.parametrize("value", [*HOSTILE, "/etc/passwd", ".github//x.yml", "a/./b.yml"])
    async def test_npm_workflow(self, make_ctx: Any, registries: Provenance, value: Any) -> None:
        if value == "acme-protocol/":
            value = "workflows/"
        if value in ("acme-protocol/acme-sdk", "../acme-sdk"):
            value = "../x.yml"
        registries.npm("acme-sdk", npm_document())
        registries.attestation("acme-sdk", "1.3.0", attestation(workflow=value))
        result = await scan(make_ctx, registries, npm_target())
        if value in ("acme-protocol/" + "a" * 5_000,):
            not_read(result)
        elif provenance_findings(result):
            # A value that happens to be a plain path is kept as it is.
            finding = one(result, "package.provenance.publisher")
            assert packages._WORKFLOW_RE.fullmatch(finding.state["workflow"])
        else:
            not_read(result)
        clean(result)

    @pytest.mark.parametrize("value", HOSTILE)
    async def test_pypi_repository(self, make_ctx: Any, registries: Provenance, value: Any) -> None:
        registries.pypi("acme-sdk", pypi_document())
        registries.integrity(
            "acme-sdk", "2.4.1", "acme_sdk.tar.gz", pypi_provenance(repository=value)
        )
        registries.integrity("acme-sdk", "1.0.0", "acme_sdk.tar.gz", pypi_provenance())
        result = await scan(make_ctx, registries, pypi_target())
        not_read(result)
        clean(result)
        clean_requests(registries)

    @pytest.mark.parametrize("value", HOSTILE)
    async def test_pypi_workflow(self, make_ctx: Any, registries: Provenance, value: Any) -> None:
        registries.pypi("acme-sdk", pypi_document())
        registries.integrity(
            "acme-sdk", "2.4.1", "acme_sdk.tar.gz", pypi_provenance(workflow=value)
        )
        result = await scan(make_ctx, registries, pypi_target())
        for finding in provenance_findings(result):
            assert finding.kind == "package.provenance.publisher"
            assert packages._WORKFLOW_RE.fullmatch(finding.state["workflow"])
            assert len(finding.state["workflow"]) <= packages.MAX_WORKFLOW_CHARS
        if not provenance_findings(result):
            not_read(result)
        clean(result)

    @pytest.mark.parametrize("value", HOSTILE)
    async def test_pypi_kind(self, make_ctx: Any, registries: Provenance, value: Any) -> None:
        registries.pypi("acme-sdk", pypi_document())
        registries.integrity("acme-sdk", "2.4.1", "acme_sdk.tar.gz", pypi_provenance(kind=value))
        result = await scan(make_ctx, registries, pypi_target())
        not_read(result)
        clean(result)

    @pytest.mark.parametrize("value", HOSTILE)
    async def test_environment_is_dropped(
        self, make_ctx: Any, registries: Provenance, value: Any
    ) -> None:
        registries.pypi("acme-sdk", pypi_document())
        registries.integrity(
            "acme-sdk", "2.4.1", "acme_sdk.tar.gz", pypi_provenance(environment=value)
        )
        result = await scan(make_ctx, registries, pypi_target())
        assert result.status is ModuleStatus.OK
        finding = one(result, "package.provenance.publisher")
        assert finding.evidence["environment"] == ""
        assert finding.state["repository"] == "acme-protocol/acme-sdk"
        clean(result)

    @pytest.mark.parametrize("value", HOSTILE)
    async def test_trusted_publisher(
        self, make_ctx: Any, registries: Provenance, value: Any
    ) -> None:
        document = npm_document()
        document["versions"]["1.3.0"]["_npmUser"]["trustedPublisher"] = {"id": value}
        registries.npm("acme-sdk", document)
        registries.attestation("acme-sdk", "1.3.0", attestation())
        result = await scan(make_ctx, registries, npm_target())
        finding = one(result, "package.provenance.publisher")
        assert "trusted_publisher" not in finding.evidence
        clean(result)

    @pytest.mark.parametrize(
        "address",
        [
            "https://evil.example/-/npm/v1/attestations/acme-sdk@1.3.0",
            "https://registry.npmjs.org/../../x",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "<script>alert(1)</script>",
            "a" * 100_000,
            None,
            5,
        ],
    )
    async def test_the_address_in_the_record_is_not_followed(
        self, make_ctx: Any, registries: Provenance, address: Any
    ) -> None:
        document = npm_document()
        document["versions"]["1.3.0"]["dist"]["attestations"]["url"] = address
        registries.npm("acme-sdk", document)
        registries.attestation("acme-sdk", "1.3.0", attestation())
        result = await scan(make_ctx, registries, npm_target())
        one(result, "package.provenance.publisher")
        assert registries.paths(NPM, "/-/") == ["/-/npm/v1/attestations/acme-sdk@1.3.0"]
        clean(result)
        clean_requests(registries)

    @pytest.mark.parametrize(
        "version",
        ["../1.2.0", "1.2.0/../../x", "<script>", "1.2.0?x=1", "1" * 500, "1.2.0 ", "1.2.0\n", ""],
    )
    async def test_versions(self, make_ctx: Any, registries: Provenance, version: str) -> None:
        # A version with an unusable name is passed over when the order is worked out.
        document = unattested(npm_document(), "1.3.0")
        document["versions"][version] = document["versions"].pop("1.2.0")
        document["time"][version] = document["time"].pop("1.2.0")
        registries.npm("acme-sdk", document)
        pypi = pypi_document()
        pypi["releases"][version] = pypi["releases"].pop("1.0.0")
        registries.pypi("acme-sdk", pypi)
        target = Target(root_domain=ROOT, npm_packages=["acme-sdk"], pypi_packages=["acme-sdk"])
        result = await scan(make_ctx, registries, target)
        assert [f.kind for f in provenance_findings(result)] == [
            "package.provenance.absent",
            "package.provenance.absent",
        ]
        clean(result)
        clean_requests(registries)


class TestPersonalData:
    async def test_npm_publisher_never_appears(self, make_ctx: Any, registries: Provenance) -> None:
        document = npm_document()
        for entry in document["versions"].values():
            entry["_npmUser"].update(
                name="Alice Private",
                email="alice.private@mail.example",
                approver={"name": "Bob Private", "email": "bob.private@mail.example"},
            )
            entry["_npmUser"]["trustedPublisher"]["email"] = "ci.private@mail.example"
            entry["_npmUser"]["trustedPublisher"]["name"] = "Carol Private"
        registries.npm("acme-sdk", document)
        registries.attestation("acme-sdk", "1.3.0", attestation())
        ctx = make_ctx(handler=registries)
        result = await Packages().run(npm_target(), ctx)
        one(result, "package.provenance.publisher")
        no_personal_data(result)
        text = result.model_dump_json()
        for fragment in ("Private", "GitHub Actions", "oidc:", "approver"):
            assert fragment not in text
        remembered = json.dumps(list(ctx.cache.data.values()))
        assert "rivate" not in remembered and "@" not in remembered

    @pytest.mark.parametrize("missing", [(), ("1.3.0",), ("1.2.0", "1.3.0")])
    async def test_npm_every_outcome(
        self, make_ctx: Any, registries: Provenance, missing: tuple[str, ...]
    ) -> None:
        registries.npm("acme-sdk", unattested(npm_document(), *missing))
        registries.attestation("acme-sdk", "1.3.0", attestation())
        result = await scan(make_ctx, registries, npm_target())
        assert len(provenance_findings(result)) == 1
        no_personal_data(result)
        assert "alice" not in json.dumps(
            [f.model_dump(mode="json") for f in provenance_findings(result)]
        )

    async def test_a_person_in_place_of_the_trusted_publisher(
        self, make_ctx: Any, registries: Provenance
    ) -> None:
        document = npm_document()
        document["versions"]["1.3.0"]["_npmUser"]["trustedPublisher"] = {
            "id": "alice.private@mail.example"
        }
        registries.npm("acme-sdk", document)
        registries.attestation("acme-sdk", "1.3.0", attestation())
        result = await scan(make_ctx, registries, npm_target())
        one(result, "package.provenance.publisher")
        no_personal_data(result)

    async def test_pypi_publisher_with_an_address(
        self, make_ctx: Any, registries: Provenance
    ) -> None:
        registries.pypi("acme-sdk", pypi_document())
        registries.integrity(
            "acme-sdk",
            "2.4.1",
            "acme_sdk.tar.gz",
            pypi_provenance(
                kind="Google",
                email="release.private@mail.example",
                repository="release.private@mail.example",
                workflow="release.private@mail.example",
                environment="release.private@mail.example",
            ),
        )
        result = await scan(make_ctx, registries, pypi_target())
        finding = one(result, "package.provenance.publisher")
        assert finding.state == {"kind": "google", "repository": "", "workflow": ""}
        assert finding.evidence["environment"] == ""
        no_personal_data(result)

    async def test_an_address_in_the_record(self, make_ctx: Any, registries: Provenance) -> None:
        registries.npm("acme-sdk", npm_document())
        registries.attestation(
            "acme-sdk",
            "1.3.0",
            attestation(repository="https://github.com/alice.private@mail.example/acme-sdk"),
        )
        result = await scan(make_ctx, registries, npm_target())
        not_read(result)
        no_personal_data(result)


class TestHosts:
    async def test_only_the_two_registries(self, make_ctx: Any, registries: Provenance) -> None:
        registries.npm("acme-sdk", npm_document())
        registries.attestation("acme-sdk", "1.3.0", attestation())
        registries.pypi("acme-sdk", pypi_document())
        registries.integrity("acme-sdk", "1.0.0", "acme_sdk.tar.gz", pypi_provenance())
        target = Target(
            root_domain=ROOT, npm_packages=["acme-sdk"], pypi_packages=["acme-sdk"], github_org=ORG
        )
        result = await scan(make_ctx, registries, target)
        assert [f.kind for f in provenance_findings(result)] == [
            "package.provenance.publisher",
            "package.provenance.lost",
        ]
        assert {r.url.host for r in registries.requests} == {NPM, PYPI}
        assert {r.url.scheme for r in registries.requests} == {"https"}
        assert {r.method for r in registries.requests} <= {"GET", "HEAD"}
        assert all(r.content == b"" for r in registries.requests)

    async def test_a_redirect_is_not_followed(self, make_ctx: Any, registries: Provenance) -> None:
        registries.pypi("acme-sdk", pypi_document())
        registries.integrity(
            "acme-sdk",
            "2.4.1",
            "acme_sdk.tar.gz",
            httpx.Response(302, headers={"location": "https://evil.example/provenance"}),
        )
        not_read(await scan(make_ctx, registries, pypi_target()))
        assert {r.url.host for r in registries.requests} == {PYPI}

    async def test_few_requests_for_each_package(
        self, make_ctx: Any, registries: Provenance
    ) -> None:
        registries.pypi("acme-sdk", pypi_document())
        registries.npm("acme-sdk", npm_document())
        registries.attestation("acme-sdk", "1.3.0", attestation())
        target = Target(root_domain=ROOT, npm_packages=["acme-sdk"], pypi_packages=["acme-sdk"])
        await scan(make_ctx, registries, target)
        assert len(registries.paths(NPM, "/-/")) <= 1
        assert len(registries.paths(PYPI, "/integrity/")) <= 2


class TestReading:
    @pytest.mark.parametrize(
        "value",
        ["acme-protocol/acme-sdk", "a/b", "Acme.Protocol/acme_sdk.js", "_x/y"],
    )
    def test_repository_names(self, value: str) -> None:
        assert repository_text(value) == value

    @pytest.mark.parametrize("value", HOSTILE)
    def test_bad_repository_names(self, value: Any) -> None:
        assert repository_text(value) == ""
        assert repository_text(value, nested=True) == ""

    def test_nested_repository_names(self) -> None:
        assert repository_text("a/b/c") == ""
        assert repository_text("a/b/c", nested=True) == "a/b/c"
        assert repository_text("a/../c", nested=True) == ""
        assert repository_text("/".join("abcdefgh"), nested=True) == ""

    @pytest.mark.parametrize(
        "value", ["release.yml", ".github/workflows/release.yml", ".gitlab-ci.yml"]
    )
    def test_workflow_paths(self, value: str) -> None:
        assert workflow_text(value) == value

    @pytest.mark.parametrize(
        "value",
        ["", "/etc/passwd", "../x.yml", "a/../b.yml", "a//b.yml", "a/./b.yml", "a b.yml", "a/"],
    )
    def test_bad_workflow_paths(self, value: Any) -> None:
        assert workflow_text(value) == ""

    @pytest.mark.parametrize("value", ["<script>", "a" * 201, "a.yml\n", "a.yml?x", None, 5])
    def test_more_bad_workflow_paths(self, value: Any) -> None:
        assert workflow_text(value) == ""

    def test_file_names(self) -> None:
        assert file_text("acme_sdk-2.4.1-py3-none-any.whl") == "acme_sdk-2.4.1-py3-none-any.whl"
        assert file_text("acme_sdk-1!2.0+local.tar.gz") == "acme_sdk-1!2.0+local.tar.gz"
        for bad in ("", ".hidden", "a/b", "a..b", "a b", "a" * 201, "a%2fb", None, 5):
            assert file_text(bad) == ""

    def test_environments(self) -> None:
        assert environment_text("release") == "release"
        assert environment_text("PyPI release") == "PyPI release"
        for bad in ("", " x", "<b>", "a" * 101, "a@b", "a\nb", None, 5):
            assert environment_text(bad) == ""

    def test_source_repository(self) -> None:
        assert source_repository("https://github.com/a/b") == ("github", "a/b")
        assert source_repository("git+https://github.com/a/b@refs/heads/main") == ("github", "a/b")
        assert source_repository("https://github.com/a/b.git") == ("github", "a/b")
        assert source_repository("https://GitHub.com/a/b") == ("github", "a/b")
        assert source_repository("https://gitlab.com/a/b/c") == ("gitlab", "a/b/c")
        assert source_repository("https://github.com/a/b/c") == ("github", "")
        for bad in HOSTILE_ADDRESSES:
            assert source_repository(bad)[1] == ""

    def test_version_before(self) -> None:
        times = {
            "1.0.0": packages.parse_date("2024-01-01T00:00:00Z"),
            "1.1.0": packages.parse_date("2025-01-01T00:00:00Z"),
            "2.0.0": packages.parse_date("2026-01-01T00:00:00Z"),
            "1.1.1": packages.parse_date("2026-02-01T00:00:00Z"),
        }
        known = {k: v for k, v in times.items() if v is not None}
        assert version_before("2.0.0", known) == ("1.1.0", True)
        assert version_before("1.0.0", known) == ("", True)
        assert version_before("9.9.9", known) == ("", False)
        assert version_before("1.0.0", {}) == ("", False)

    def test_addresses(self) -> None:
        assert (
            packages.npm_provenance_url("@acme/sdk", "1.0.0")
            == "https://registry.npmjs.org/-/npm/v1/attestations/@acme%2fsdk@1.0.0"
        )
        assert (
            packages.pypi_provenance_url("acme-sdk", "1!2.0+x", "acme_sdk-1!2.0+x.tar.gz")
            == "https://pypi.org/integrity/acme-sdk/1%212.0%2Bx/acme_sdk-1%212.0%2Bx.tar.gz/provenance"
        )
