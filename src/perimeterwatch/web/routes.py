"""Every page of the hosted service.

Two rules hold for every route below:
- The tenant is taken from the signed-in session, never from the address or a form.
- An object that belongs to another tenant is reported as not found.
"""

from __future__ import annotations

from datetime import timedelta
from importlib import resources
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from perimeterwatch.branding import user_agent
from perimeterwatch.config import Settings
from perimeterwatch.core.diff import compute_diff
from perimeterwatch.core.errors import ValidationError
from perimeterwatch.core.models import (
    Category,
    Finding,
    JobBoardRef,
    SafeRef,
    ScanMode,
    Sensitivity,
    Severity,
    Target,
    utcnow,
)
from perimeterwatch.core.module import all_modules
from perimeterwatch.core.severity import KINDS
from perimeterwatch.report.build import ReportData, _redact_personal, build_report
from perimeterwatch.report.render_html import render_html
from perimeterwatch.report.render_json import render_json
from perimeterwatch.safety.authorisation import check_dns, new_token, record_name, record_value
from perimeterwatch.safety.domains import (
    registrable_domain,
    validate_domain,
    validate_eth_address,
    validate_github_org,
    validate_slug,
)
from perimeterwatch.storage.claims import release_other_claims
from perimeterwatch.storage.repo import TenantRepo, _aware
from perimeterwatch.storage.tables import AlertDelivery, Scan, TargetRow
from perimeterwatch.web import auth, legal, mail
from perimeterwatch.web.app import site_context
from perimeterwatch.web.deps import (
    Auth,
    NotSignedIn,
    client_ip,
    get_db,
    get_settings,
    parse_uuid,
    require_anon_csrf,
    require_auth,
    require_csrf,
    require_editor,
    session_cookie_name,
)
from perimeterwatch.worker import alerts
from perimeterwatch.worker.queue import QueueError, TableQueue

router = APIRouter()

SignedIn = Annotated[Auth, Depends(require_auth)]
Editor = Annotated[Auth, Depends(require_editor)]
Db = Annotated[Session, Depends(get_db)]
Config = Annotated[Settings, Depends(get_settings)]

# How the public page groups the checks: (label, icon, module names). A check that
# is named nowhere falls into the group of its category, so a new check appears
# on the page without anyone editing this table. Breach exposure is left out:
# it needs paid data and is presented as coming later.
PUBLIC_GROUPS: tuple[tuple[str, str, frozenset[str]], ...] = (
    (
        "Domains and DNS",
        "globe",
        frozenset(
            {
                "dns_resolve",
                "dnssec_quality",
                "domain_registration",
                "nameserver_health",
                "subdomains",
                "takeover",
            }
        ),
    ),
    (
        "Servers and certificates",
        "server",
        frozenset(
            {"http_probe", "origin_exposure", "security_contact", "tls_certs", "web_archive"}
        ),
    ),
    (
        "Email and lookalikes",
        "mail",
        frozenset({"email_posture", "lookalikes", "phishing_lists", "spf_chain"}),
    ),
    ("Public code and packages", "code", frozenset()),
    ("Web3", "hexagon", frozenset()),
    ("Reachable services", "radar", frozenset()),
)
CATEGORY_GROUP = {
    Category.SURFACE: "Domains and DNS",
    Category.TAKEOVER: "Domains and DNS",
    Category.EMAIL: "Email and lookalikes",
    Category.LOOKALIKE: "Email and lookalikes",
    Category.SECRETS: "Public code and packages",
    Category.SUPPLY_CHAIN: "Public code and packages",
    Category.WEB3: "Web3",
    Category.VULN: "Reachable services",
}


def public_checks() -> list[tuple[str, str, list[tuple[str, str]]]]:
    """(group, icon, [(title, depth)]) for every check the public page lists."""
    named = {name: label for label, _, names in PUBLIC_GROUPS for name in names}
    grouped: dict[str, list[tuple[str, str]]] = {label: [] for label, _, _ in PUBLIC_GROUPS}
    specs = sorted((m.spec for m in all_modules().values()), key=lambda s: (s.mode.rank, s.title))
    for spec in specs:
        label = named.get(spec.name) or CATEGORY_GROUP.get(spec.category)
        if label is not None:
            grouped[label].append((spec.title, spec.mode.value))
    return [(label, icon, grouped[label]) for label, icon, _ in PUBLIC_GROUPS]


SENT_MESSAGE = (
    "If that address can sign in, a link is on its way. It works once and expires in 15 minutes."
)


def page(
    request: Request, name: str, who: Auth | None, status: int = 200, **context: Any
) -> HTMLResponse:
    templates = request.app.state.templates
    context.update(who=who, csrf=who.csrf if who else getattr(request.state, "anon_csrf", ""))
    for key, value in site_context(request).items():
        context.setdefault(key, value)
    return templates.TemplateResponse(request, name, context, status_code=status)  # type: ignore[no-any-return]


def back(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def target_or_404(who: Auth, raw_id: str) -> TargetRow:
    row = who.repo.get_target_by_id(parse_uuid(raw_id))
    if row is None:
        raise HTTPException(404, "Not found.")
    return row


def scan_or_404(who: Auth, raw_id: str) -> Scan:
    scan = who.repo.get_scan(parse_uuid(raw_id))
    if scan is None:
        raise HTTPException(404, "Not found.")
    return scan


def is_verified(repo: TenantRepo, target: TargetRow) -> bool:
    verification = repo.get_verification(target.id)
    return bool(verification and verification.verified_at)


def listed(finding: Finding) -> Finding:
    """How a finding appears in a list: personal details masked until it is opened."""
    return _redact_personal(finding) if finding.sensitivity is Sensitivity.PERSONAL else finding


# -- health and sign-in ------------------------------------------------------------


@router.get("/report.css")
def report_css() -> Response:
    """The report's stylesheet, shared by the pages so both look the same."""
    css = resources.files("perimeterwatch.report").joinpath("templates/report.css").read_text()
    return Response(css, media_type="text/css", headers={"Cache-Control": "max-age=3600"})


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


def visitor(request: Request, db: Session) -> Auth | None:
    """Who is looking at a public page, if they are signed in."""
    try:
        return require_auth(request, db)
    except NotSignedIn:
        return None


@router.get("/", response_class=HTMLResponse)
def home(request: Request, db: Db, settings: Config) -> Response:
    """The public page: what the service does, and how to reach its operator."""
    if visitor(request, db) is not None:
        return back("/targets")
    checks = public_checks()
    return page(
        request,
        "home.html",
        None,
        checks=checks,
        check_count=sum(len(items) for _, _, items in checks),
        kind_count=len(KINDS),
        scan_sources=settings.scan_sources,
        contact_url=settings.contact_url,
    )


@router.get("/legal", response_class=HTMLResponse)
def legal_index(request: Request, db: Db) -> Response:
    pages = [legal.page(document.slug) for document in legal.DOCUMENTS]
    return page(request, "legal_index.html", visitor(request, db), pages=pages)


@router.get("/legal/{slug}", response_class=HTMLResponse)
def legal_page(request: Request, db: Db, slug: str) -> Response:
    found = legal.page(slug)
    if found is None:
        raise HTTPException(404, "Not found.")
    return page(request, "legal.html", visitor(request, db), doc=found, documents=legal.DOCUMENTS)


@router.get("/.well-known/security.txt")
def security_txt(settings: Config) -> Response:
    """RFC 9116. Answered only when the operator has named a contact."""
    if not settings.security_email:
        raise HTTPException(404, "Not found.")
    base = settings.base_url.rstrip("/")
    # The first day of a month about half a year ahead, so the text is the same all month.
    now = utcnow()
    month = now.month + 6
    expires = now.replace(
        year=now.year + (month - 1) // 12, month=(month - 1) % 12 + 1, day=1,
        hour=0, minute=0, second=0, microsecond=0,
    )  # fmt: skip
    lines = [
        f"Contact: mailto:{settings.security_email}",
        f"Expires: {expires.strftime('%Y-%m-%dT%H:%M:%S.000Z')}",
        "Preferred-Languages: en",
        f"Canonical: {base}/.well-known/security.txt",
        f"Policy: {base}/legal/vulnerability-disclosure",
    ]
    return Response(
        "\n".join(lines) + "\n",
        media_type="text/plain; charset=utf-8",
        headers={"Cache-Control": "max-age=3600"},
    )


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request) -> Response:
    return page(request, "login.html", None, sent=False, message="")


@router.post("/login", response_class=HTMLResponse, dependencies=[Depends(require_anon_csrf)])
def login_submit(
    request: Request, db: Db, settings: Config, email: Annotated[str, Form(max_length=320)]
) -> Response:
    created = auth.request_link(db, settings, email, client_ip(request))
    if created is not None:
        address, token = created
        link = f"{settings.base_url.rstrip('/')}/auth/{token}"
        try:
            mail.send(
                settings,
                address,
                "Your sign-in link",
                f"Open this link to sign in:\n\n{link}\n\n"
                "It works once and expires in 15 minutes. If you did not ask for it, ignore "
                "this message.",
            )
        except mail.MailError:
            pass  # same page either way, so the form reveals nothing
    return page(request, "login.html", None, sent=True, message=SENT_MESSAGE)


@router.get("/auth/{token}", response_class=HTMLResponse)
def confirm_form(request: Request, db: Db, token: str) -> Response:
    # Opening the link only shows a button. Mail scanners that fetch links in
    # messages would otherwise use the link up before the person does.
    if len(token) > 100 or not auth.link_is_usable(db, token):
        return page(request, "login.html", None, 400, sent=False,
                    message="That sign-in link has expired or was already used. Ask for a new one.")  # fmt: skip
    return page(request, "confirm.html", None, token=token)


@router.post("/auth/{token}", dependencies=[Depends(require_anon_csrf)])
def confirm_submit(request: Request, db: Db, settings: Config, token: str) -> Response:
    signed_in = None
    if len(token) <= 100:
        signed_in = auth.sign_in(db, token, client_ip(request), request.headers.get("user-agent"))
    if signed_in is None:
        return page(request, "login.html", None, 400, sent=False,
                    message="That sign-in link has expired or was already used. Ask for a new one.")  # fmt: skip
    response = back("/targets")
    response.set_cookie(
        session_cookie_name(settings),
        signed_in.cookie,
        httponly=True,
        secure=settings.env != "dev",
        samesite="lax",
        max_age=int(auth.SESSION_MAX.total_seconds()),
        path="/",
    )
    return response


@router.post("/logout")
def logout(db: Db, settings: Config, who: Annotated[Auth, Depends(require_csrf)]) -> Response:
    who.audit("auth.signed_out", "user", str(who.user.id))
    auth.sign_out(db, who.session)
    response = back("/login")
    response.delete_cookie(session_cookie_name(settings), path="/")
    return response


# -- domains -------------------------------------------------------------------------


@router.get("/targets", response_class=HTMLResponse)
def targets(request: Request, who: SignedIn, settings: Config, error: str = "") -> Response:
    rows = []
    for row in who.repo.list_targets():
        scans = who.repo.list_scans(row.id, limit=1)
        open_findings = who.repo.list_findings(row.id, ("open",))
        rows.append(
            {
                "row": row,
                "verified": is_verified(who.repo, row),
                "last": scans[0] if scans else None,
                "high": sum(1 for f in open_findings if f.severity >= Severity.HIGH),
                "open": len(open_findings),
            }
        )
    return page(
        request, "targets.html", who, rows=rows, error=error[:300],
        limit=settings.max_targets_per_tenant,
    )  # fmt: skip


@router.post("/targets")
def add_target(
    who: Editor,
    settings: Config,
    domain: Annotated[str, Form(max_length=300)],
) -> Response:
    try:
        root = validate_domain(domain)
    except ValidationError as exc:
        return back(f"/targets?error={_quote(str(exc))}")
    if who.repo.get_target(root) is not None:
        return back(f"/targets?error={_quote(f'{root} is already on your list.')}")
    if len(who.repo.list_targets()) >= settings.max_targets_per_tenant:
        return back(f"/targets?error={_quote('You have reached the limit of domains.')}")
    row = who.repo.upsert_target(Target(root_domain=root))
    row.scan_interval_hours = settings.default_scan_interval_hours
    row.next_scan_at = utcnow() + timedelta(hours=settings.default_scan_interval_hours)
    who.audit("target.added", "target", str(row.id), domain=root)
    return back(f"/targets/{row.id}")


@router.get("/targets/{target_id}", response_class=HTMLResponse)
def target_page(
    request: Request, who: SignedIn, target_id: str, error: str = "", notice: str = ""
) -> Response:
    row = target_or_404(who, target_id)
    verification = who.repo.get_verification(row.id)
    findings = [
        {"id": f.id, "status": f.status, "first_seen": _aware(f.first_seen),
         "finding": listed(Finding.model_validate(f.body))}
        for f in who.repo.list_findings(row.id)
    ]  # fmt: skip
    return page(
        request, "target.html", who,
        target=row,
        config=who.repo.target_model(row),
        verification=verification,
        verified=bool(verification and verification.verified_at),
        record_name=record_name(row.root_domain),
        record_value=record_value(verification.token) if verification else "",
        findings=findings,
        scans=who.repo.list_scans(row.id, limit=15),
        can_scan=bool(verification and verification.verified_at)
        or not request.app.state.settings.scan_requires_verification,
        error=error[:300],
        notice=notice[:300],
    )  # fmt: skip


@router.post("/targets/{target_id}/settings")
def target_settings(
    who: Editor,
    target_id: str,
    github_org: Annotated[str, Form(max_length=60)] = "",
    safe: Annotated[str, Form(max_length=60)] = "",
    job_board_kind: Annotated[str, Form(max_length=20)] = "",
    job_board: Annotated[str, Form(max_length=80)] = "",
    interval: Annotated[str, Form(max_length=5)] = "24",
) -> Response:
    row = target_or_404(who, target_id)
    target = who.repo.target_model(row)
    try:
        target.github_org = validate_github_org(github_org) if github_org.strip() else None
        target.safes = (
            [SafeRef(chain="eth", address=validate_eth_address(safe))] if safe.strip() else []
        )
        target.job_board = None
        if job_board.strip():
            if job_board_kind not in ("greenhouse", "lever"):
                raise ValidationError("Choose Greenhouse or Lever for the job board.")
            target.job_board = JobBoardRef(
                kind=job_board_kind, value=validate_slug(job_board, "job board name")
            )
        hours = int(interval) if interval.isdigit() else -1
        if hours not in (0, 24, 72, 168):
            raise ValidationError("Choose one of the offered scan intervals.")
    except ValidationError as exc:
        return back(f"/targets/{row.id}?error={_quote(str(exc))}")
    row = who.repo.upsert_target(Target.model_validate(target.model_dump()))
    row.scan_interval_hours = hours or None
    row.next_scan_at = utcnow() + timedelta(hours=hours) if hours else None
    who.audit("target.updated", "target", str(row.id))
    return back(f"/targets/{row.id}?notice=Saved.")


@router.post("/targets/{target_id}/delete")
def delete_target(
    who: Editor, target_id: str, confirm: Annotated[str, Form(max_length=300)] = ""
) -> Response:
    row = target_or_404(who, target_id)
    if confirm.strip().lower() != row.root_domain:
        return back(f"/targets/{row.id}?error={_quote('Type the domain name to confirm.')}")
    who.repo.remove_target(row.root_domain)
    who.audit("target.removed", "target", str(row.id), domain=row.root_domain)
    return back("/targets")


# -- proof of domain control ------------------------------------------------------------


@router.post("/targets/{target_id}/verify/start")
def verify_start(who: Editor, target_id: str) -> Response:
    row = target_or_404(who, target_id)
    if who.repo.get_verification(row.id) is None:
        who.repo.create_verification(row.id, new_token())
        who.audit("verification.started", "target", str(row.id))
    return back(f"/targets/{row.id}#verify")


@router.post("/targets/{target_id}/verify/check")
async def verify_check(db: Db, who: Editor, settings: Config, target_id: str) -> Response:
    row = target_or_404(who, target_id)
    verification = who.repo.get_verification(row.id)
    if verification is None:
        return back(f"/targets/{row.id}#verify")
    result = await check_dns(
        row.root_domain, verification.token, never_contact=settings.never_contact
    )
    now = utcnow()
    verification.last_checked_at = now
    verification.last_result = result.detail[:200]
    who.audit("verification.checked", "target", str(row.id), verified=result.verified)
    if not result.verified:
        verification.consecutive_failures += 1
        return back(f"/targets/{row.id}?error={_quote(result.detail)}#verify")
    verification.verified_at = now
    verification.consecutive_failures = 0
    for tenant_id in release_other_claims(db, row.root_domain, who.tenant_id):
        alerts.queue_notice(
            db,
            tenant_id=tenant_id,
            subject=f"{row.root_domain}: another organisation proved control",
            body=(
                f"Another organisation has proved control of {row.root_domain} with a DNS "
                "record. Your verification for this domain is withdrawn. If this was not "
                "expected, check who can change your DNS."
            ),
        )
    return back(f"/targets/{row.id}?notice=Domain+verified.")


# -- scans -------------------------------------------------------------------------------


@router.post("/targets/{target_id}/scans")
def request_scan(
    who: Editor,
    settings: Config,
    target_id: str,
    depth: Annotated[str, Form(max_length=10)] = "passive",
) -> Response:
    row = target_or_404(who, target_id)
    try:
        mode = ScanMode(depth)
    except ValueError:
        raise HTTPException(400, "Unknown scan depth.") from None
    if settings.scan_requires_verification and not is_verified(who.repo, row):
        return back(
            f"/targets/{row.id}?error={_quote('Verify the domain before scanning it.')}#verify"
        )
    if mode is ScanMode.ACTIVE and not is_verified(who.repo, row):
        return back(
            f"/targets/{row.id}?error={_quote('Verify the domain before running active checks.')}#verify"
        )
    queue = TableQueue(timedelta(minutes=settings.min_scan_interval_minutes))
    try:
        scan = queue.enqueue_scan(who.repo, row, mode, who.user.email)
    except QueueError as exc:
        return back(f"/targets/{row.id}?error={_quote(str(exc))}")
    who.audit("scan.requested", "scan", str(scan.id), depth=mode.value)
    return back(f"/scans/{scan.id}")


def _report(who: Auth, settings: Settings, scan: Scan, *, redact: bool) -> ReportData:
    snapshot = who.repo.load_snapshot(scan)
    previous = who.repo.previous_scan(scan)
    diff = compute_diff(who.repo.load_snapshot(previous) if previous else None, snapshot)
    return build_report(
        snapshot,
        diff,
        user_agent=user_agent(settings.contact_url, settings.abuse_email),
        contact_url=settings.contact_url,
        abuse_email=settings.abuse_email,
        retention_days=settings.retention_days,
        redact_personal=redact,
    )


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_page(request: Request, who: SignedIn, settings: Config, scan_id: str) -> Response:
    scan = scan_or_404(who, scan_id)
    target = who.repo.get_target_by_id(scan.target_id)
    running = scan.status in ("queued", "running")
    # The page itself always masks personal details. They are shown on request, one
    # finding at a time, and each view is recorded.
    report = _report(who, settings, scan, redact=True) if scan.status == "done" else None
    response = page(request, "scan.html", who, scan=scan, target=target, r=report, running=running)
    if running:
        response.headers["Refresh"] = "5"
    return response


@router.get("/scans/{scan_id}/report.{fmt}")
def download_report(
    who: SignedIn, settings: Config, scan_id: str, fmt: str, personal: str = "masked"
) -> Response:
    scan = scan_or_404(who, scan_id)
    if scan.status != "done" or fmt not in ("html", "json"):
        raise HTTPException(404, "Not found.")
    full = personal == "shown"
    target = who.repo.get_target_by_id(scan.target_id)
    if full and (target is None or not is_verified(who.repo, target)):
        raise HTTPException(
            403, "Details about people are shown only while the domain is verified."
        )
    report = _report(who, settings, scan, redact=not full)
    who.audit("report.downloaded", "scan", str(scan.id), format=fmt, personal_shown=full)
    domain = report.target["root_domain"]
    name = f"{domain}-{str(scan.id)[:8]}.{fmt}"
    headers = {"Content-Disposition": f'attachment; filename="{name}"'}
    if fmt == "json":
        return Response(render_json(report), media_type="application/json", headers=headers)
    # The report carries its own styles inline, so it needs a policy of its own.
    headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
    return Response(render_html(report), media_type="text/html", headers=headers)


# -- findings ----------------------------------------------------------------------------


@router.get("/findings/{finding_id}", response_class=HTMLResponse)
def finding_page(request: Request, who: SignedIn, finding_id: str) -> Response:
    row = who.repo.get_finding(parse_uuid(finding_id))
    if row is None:
        raise HTTPException(404, "Not found.")
    finding = Finding.model_validate(row.body)
    target = who.repo.get_target_by_id(row.target_id)
    if finding.sensitivity is Sensitivity.PERSONAL and (
        target is None or not is_verified(who.repo, target)
    ):
        # Details about people are for the proven owner of the domain. If that
        # proof has gone, what was stored earlier is withheld too.
        raise HTTPException(
            403, "Details about people are shown only while the domain is verified."
        )
    if finding.sensitivity is not Sensitivity.NORMAL:
        who.audit(
            "finding.viewed", "finding", str(row.id),
            kind=finding.kind, sensitivity=finding.sensitivity.value,
        )  # fmt: skip
    return page(request, "finding.html", who, row=row, f=finding, target=target)


@router.post("/findings/{finding_id}/status")
def finding_status(
    who: Editor, finding_id: str, status: Annotated[str, Form(max_length=20)]
) -> Response:
    row = who.repo.get_finding(parse_uuid(finding_id))
    if row is None:
        raise HTTPException(404, "Not found.")
    if status not in ("open", "accepted"):
        raise HTTPException(400, "Unknown status.")
    row.status = status
    who.audit("finding.status_changed", "finding", str(row.id), status=status)
    return back(f"/findings/{row.id}")


# -- alerts ------------------------------------------------------------------------------


@router.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request, who: SignedIn, error: str = "", notice: str = "") -> Response:
    channels = [
        {"row": c, "shown": alerts.describe(c.kind, c.config), "level": Severity(c.min_severity).label}
        for c in who.repo.list_channels()
    ]  # fmt: skip
    return page(
        request, "alerts.html", who, channels=channels, deliveries=who.repo.list_deliveries(),
        error=error[:300], notice=notice[:300],
    )  # fmt: skip


@router.post("/alerts")
def add_channel(
    who: Editor,
    kind: Annotated[str, Form(max_length=20)],
    label: Annotated[str, Form(max_length=100)] = "",
    to: Annotated[str, Form(max_length=320)] = "",
    url: Annotated[str, Form(max_length=400)] = "",
    bot_token: Annotated[str, Form(max_length=100)] = "",
    chat_id: Annotated[str, Form(max_length=30)] = "",
    min_severity: Annotated[str, Form(max_length=10)] = "medium",
) -> Response:
    levels = {s.label: int(s) for s in Severity}
    try:
        if min_severity not in levels:
            raise ValidationError("Choose one of the offered alert levels.")
        if len(who.repo.list_channels()) >= 10:
            raise ValidationError("You have reached the limit of alert channels.")
        config = alerts.validate_config(
            kind, {"to": to, "url": url, "bot_token": bot_token, "chat_id": chat_id}
        )
    except ValidationError as exc:
        return back(f"/alerts?error={_quote(str(exc))}")
    clean_label = " ".join(label.split())[:100] or kind.capitalize()
    channel = who.repo.add_channel(kind, clean_label, config, levels[min_severity])
    who.audit("alert_channel.added", "alert_channel", str(channel.id), kind=kind)
    return back("/alerts?notice=Channel+added.")


@router.post("/alerts/{channel_id}/test")
def test_channel(db: Db, who: Editor, settings: Config, channel_id: str) -> Response:
    channel = who.repo.get_channel(parse_uuid(channel_id))
    if channel is None:
        raise HTTPException(404, "Not found.")
    db.add(
        AlertDelivery(
            tenant_id=who.tenant_id,
            channel_id=channel.id,
            subject="Test alert",
            body=f"This is a test from {settings.base_url}. Alerts to this channel are working.",
        )
    )
    who.audit("alert_channel.tested", "alert_channel", str(channel.id))
    return back("/alerts?notice=Test+queued.+It+is+sent+within+a+minute.")


@router.post("/alerts/{channel_id}/delete")
def delete_channel(who: Editor, channel_id: str) -> Response:
    channel_uuid = parse_uuid(channel_id)
    if not who.repo.remove_channel(channel_uuid):
        raise HTTPException(404, "Not found.")
    who.audit("alert_channel.removed", "alert_channel", str(channel_uuid))
    return back("/alerts?notice=Channel+removed.")


# -- audit log -----------------------------------------------------------------------------


@router.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, who: SignedIn) -> Response:
    if who.membership.role != "owner":
        raise HTTPException(403, "Only an owner of the organisation can read the audit log.")
    return page(request, "audit.html", who, entries=who.repo.list_audit(300))


def _quote(text: str) -> str:
    from urllib.parse import quote

    return quote(text[:300], safe="")


_ = registrable_domain
