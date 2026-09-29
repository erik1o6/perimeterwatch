"""Watch newly issued certificates for names that imitate a verified domain.

Certificate transparency logs publish every certificate as it is issued. A
self-hosted certstream server offers them as a websocket stream. This module
reads that stream and tells an organisation when a certificate is issued for a
name that contains its name and is not its own.

Rules that hold throughout:
- Only public certificate data is read. The lookalike domain is never
  contacted, and its name is written in alerts in a form that chat programs
  will not turn into a link or fetch a preview of.
- Only domains whose control has been proved are watched.
- Everything on the stream is untrusted: sizes and counts are capped, names
  are validated, and no message can stop the watcher.
- The stream carries hundreds of certificates a second, so matching uses an
  index held in memory. The database is read when the list of watched names is
  refreshed and written when there is a match to report, never per message.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import random
import uuid
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from parapet.config import Settings
from parapet.core.errors import ValidationError
from parapet.core.models import utcnow
from parapet.logging import get_logger, scrub
from parapet.safety.domains import registrable_domain, validate_hostname
from parapet.storage.db import Database
from parapet.storage.repo import Cache, TenantRepo, _aware
from parapet.storage.tables import AuditLog, DomainVerification, HttpCache, TargetRow
from parapet.worker import alerts

# The same rule as modules/lookalikes.py: a shorter name matches too much by accident.
MIN_BRAND_LENGTH = 6

MAX_MESSAGE_BYTES = 262_144
# The connection itself allows more, so that one large message is dropped
# here instead of closing the connection.
MAX_FRAME_BYTES = 4 * MAX_MESSAGE_BYTES
MAX_NAMES_PER_MESSAGE = 200
MAX_NAME_LENGTH = 253
MAX_WATCHED = 20_000
MAX_REMEMBERED = 10_000
MAX_NAMES_IN_RECORD = 10
MAX_URL_LENGTH = 400

RELOAD_EVERY = timedelta(minutes=5)
ALERT_ONCE_PER = timedelta(hours=24)
RATE_WINDOW = timedelta(hours=1)
MAX_NOTICES_PER_TENANT = 5
MAX_NOTICES_IN_TOTAL = 100
RESCAN_ONCE_PER = timedelta(hours=24)

PING_EVERY_S = 30  # the server disconnects a client that is silent for 60 seconds
OPEN_TIMEOUT_S = 20
BACKOFF_FIRST_S = 1.0
BACKOFF_MAX_S = 300.0
# A connection that lasted this long was a working one: start the backoff again.
HEALTHY_AFTER_S = 60.0

AUDIT_ACTION = "certwatch.match"
_BRAND_CACHE_NAMESPACE = "crtsh:brand:current"

log = get_logger("certwatch")

Connect = Callable[[str], Any]


@dataclass(frozen=True)
class Watched:
    """One verified domain and the name that is looked for."""

    tenant_id: uuid.UUID
    target_id: uuid.UUID
    root: str
    domain: str  # the registrable domain of root
    label: str


@dataclass(frozen=True)
class Match:
    watched: Watched
    owner: str  # the registrable domain the certificate name belongs to
    name: str


@dataclass
class Counters:
    messages: int = 0
    dropped: int = 0
    matches: int = 0
    notices: int = 0
    repeats: int = 0
    held_back: int = 0
    errors: int = 0


@dataclass
class _Index:
    by_prefix: dict[str, list[Watched]] = field(default_factory=dict)
    own: dict[uuid.UUID, frozenset[str]] = field(default_factory=dict)
    size: int = 0


def brand_label(root_domain: str) -> str | None:
    """The first label of the registrable domain, if it is long enough to watch for."""
    try:
        label = registrable_domain(root_domain).split(".")[0]
    except ValidationError:
        return None
    return label if len(label) >= MIN_BRAND_LENGTH else None


def check_url(raw: object) -> str | None:
    """A websocket address, or None when the setting is absent or unusable."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    url = raw.strip()
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    usable = (
        parsed.scheme in ("ws", "wss")
        and bool(parsed.hostname)
        and len(url) <= MAX_URL_LENGTH
        and not any(c.isspace() or ord(c) < 32 for c in url)
    )
    return url if usable else None


def names_in(raw: object) -> list[str]:
    """The certificate names in one stream message. Anything unexpected gives none.

    Understands the full and lite streams (`data.leaf_cert.all_domains`) and
    the domains-only stream (`data` is the list).
    """
    if isinstance(raw, bytes | bytearray | memoryview):
        if len(raw) > MAX_MESSAGE_BYTES:
            return []
        try:
            raw = bytes(raw).decode("utf-8")
        except UnicodeDecodeError:
            return []
    if not isinstance(raw, str) or len(raw) > MAX_MESSAGE_BYTES:
        return []
    try:
        message = json.loads(raw)
    except (ValueError, RecursionError):
        return []
    if not isinstance(message, dict):
        return []
    kind = message.get("message_type")
    data = message.get("data")
    found: object = None
    if kind == "certificate_update" and isinstance(data, dict):
        leaf = data.get("leaf_cert")
        found = leaf.get("all_domains") if isinstance(leaf, dict) else None
    elif kind == "dns_entries":
        found = data
    if not isinstance(found, list):
        return []
    names: list[str] = []
    seen: set[str] = set()
    for value in found[:MAX_NAMES_PER_MESSAGE]:
        if not isinstance(value, str) or not 0 < len(value) <= MAX_NAME_LENGTH + 2:
            continue
        name = value.strip().lower().rstrip(".").removeprefix("*.")
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names


def _under(name: str, domain: str) -> bool:
    return name == domain or name.endswith("." + domain)


def defang(name: str) -> str:
    """A form of the name that chat programs will not link to or fetch."""
    return name.replace(".", "[.]")


class CertWatcher:
    def __init__(
        self,
        settings: Settings,
        database: Database,
        *,
        connect: Connect | None = None,
        clock: Callable[[], datetime] = utcnow,
        bring_scan_forward: bool = True,
    ) -> None:
        self.settings = settings
        self.database = database
        self.url = check_url(getattr(settings, "certstream_url", None))
        self.counters = Counters()
        self._connect = connect
        self._clock = clock
        self._bring_scan_forward = bring_scan_forward
        self._index = _Index()
        self._loaded_at: datetime | None = None
        # (tenant, lookalike domain) -> when the organisation was last told
        self._told: OrderedDict[tuple[uuid.UUID, str], datetime] = OrderedDict()
        self._sent: dict[uuid.UUID, deque[datetime]] = {}
        self._sent_in_total: deque[datetime] = deque()
        self._held_back: dict[uuid.UUID, int] = {}
        self._rescanned: OrderedDict[uuid.UUID, datetime] = OrderedDict()

    # -- what is watched -----------------------------------------------------------

    def reload(self) -> int:
        """Read the verified domains and rebuild the index. Returns how many are watched."""
        with self.database.session() as db:
            rows = db.execute(
                select(TargetRow.tenant_id, TargetRow.id, TargetRow.root_domain)
                .join(DomainVerification, DomainVerification.target_id == TargetRow.id)
                .where(
                    DomainVerification.verified_at.is_not(None),
                    DomainVerification.tenant_id == TargetRow.tenant_id,
                )
                .order_by(TargetRow.created_at)
                .limit(MAX_WATCHED)
            ).all()

        index = _Index()
        own: dict[uuid.UUID, set[str]] = {}
        for tenant_id, target_id, root in rows:
            try:
                root = validate_hostname(str(root), allow_reserved=True)
                domain = registrable_domain(root)
            except ValidationError:
                continue
            own.setdefault(tenant_id, set()).add(domain)
            label = brand_label(root)
            if label is None:
                continue
            watched = Watched(tenant_id, target_id, root, domain, label)
            index.by_prefix.setdefault(label[:MIN_BRAND_LENGTH], []).append(watched)
            index.size += 1
        index.own = {tenant: frozenset(domains) for tenant, domains in own.items()}
        self._index = index
        self._loaded_at = self._clock()
        return index.size

    def reload_if_due(self) -> None:
        now = self._clock()
        if self._loaded_at is not None and now - self._loaded_at < RELOAD_EVERY:
            return
        # Set first, so that a database that is down is not asked again on every message.
        self._loaded_at = now
        try:
            self.reload()
        except Exception as exc:
            self.counters.errors += 1
            log.error("certwatch could not load domains", error=_describe(exc))

    # -- matching ------------------------------------------------------------------

    def match(self, names: Iterable[str]) -> list[Match]:
        """Names that use a watched name and are not the organisation's own.

        No database and no network are used here.
        """
        by_prefix = self._index.by_prefix
        if not by_prefix:
            return []
        matches: list[Match] = []
        for name in names:
            candidates: dict[Watched, None] = {}
            for start in range(len(name) - MIN_BRAND_LENGTH + 1):
                for watched in by_prefix.get(name[start : start + MIN_BRAND_LENGTH], ()):
                    if name.startswith(watched.label, start):
                        candidates[watched] = None
            if not candidates:
                continue
            try:
                name = validate_hostname(name, allow_reserved=True)
                owner = registrable_domain(name)
            except ValidationError:
                continue
            labels = name.split(".")
            registered = owner.split(".")[0]
            for watched in candidates:
                if _under(name, watched.root) or _under(name, watched.domain):
                    continue
                if owner in self._index.own.get(watched.tenant_id, frozenset()):
                    continue
                # Only names where the brand is part of what was registered or a
                # label of its own, not an accidental substring of a long word.
                if watched.label not in registered and watched.label not in labels:
                    continue
                matches.append(Match(watched, owner, name))
        return matches

    # -- one message -----------------------------------------------------------------

    def handle(self, raw: object) -> int:
        """Process one stream message. Returns how many notices were queued. Never raises."""
        try:
            self.counters.messages += 1
            names = names_in(raw)
            if not names:
                self.counters.dropped += 1
                return 0
            matches = self.match(names)
            if not matches:
                return 0
            self.counters.matches += len(matches)
            return self.record(matches)
        except Exception as exc:
            self.counters.errors += 1
            log.error("certwatch could not process a message", error=_describe(exc))
            return 0

    # -- telling the organisation ------------------------------------------------------

    def record(self, matches: Iterable[Match]) -> int:
        """Queue one notice for each lookalike domain that is new to its organisation."""
        grouped: dict[tuple[uuid.UUID, str], list[Match]] = {}
        for match in matches:
            grouped.setdefault((match.watched.tenant_id, match.owner), []).append(match)

        queued = 0
        now = self._clock()
        for key, group in grouped.items():
            tenant_id, owner = key
            told = self._told.get(key)
            if told is not None and now - told < ALERT_ONCE_PER:
                self.counters.repeats += 1
                continue
            if not self._within_rate(tenant_id, now):
                self.counters.held_back += 1
                self._held_back[tenant_id] = min(self._held_back.get(tenant_id, 0) + 1, 1_000_000)
                continue
            try:
                with self.database.session() as db:
                    if self._told_recently(db, tenant_id, owner, now):
                        self.counters.repeats += 1
                        self._remember(key, now)
                        continue
                    queued += self._write(db, group, owner, now)
            except Exception as exc:
                self.counters.errors += 1
                log.error("certwatch could not record a match", error=_describe(exc))
                continue
            self._remember(key, now)
            self._count_sent(tenant_id, now)
        self.counters.notices += queued
        return queued

    def _write(self, db: Session, group: list[Match], owner: str, now: datetime) -> int:
        watched = group[0].watched
        names = sorted({m.name for m in group})[:MAX_NAMES_IN_RECORD]
        domains = sorted({m.watched.domain for m in group})[:MAX_NAMES_IN_RECORD]
        repo = TenantRepo(db, watched.tenant_id)
        repo.audit(
            AUDIT_ACTION,
            actor="system",
            object_type="lookalike_domain",
            object_id=owner[:100],
            meta={"names": names, "resembles": domains},
        )
        held_back = self._held_back.pop(watched.tenant_id, 0)
        lines = [
            f"A certificate was just issued for {defang(owner)}, a domain that is not "
            f"yours and uses the name '{watched.label}'.",
            "",
            "Names on the certificate:",
            *[f"  {defang(name)}" for name in names],
            "",
            "A certificate is needed to run a website that browsers show as secure, so this "
            "can be an early sign of a site built to imitate yours. Many such domains are "
            "unrelated businesses: this is a match on the name only.",
            "",
            "The dots are written as [.] so that the name cannot be opened by accident. "
            "Parapet has not contacted the domain, and it is safer if you do not either.",
        ]
        if held_back:
            lines += [
                "",
                f"{held_back} other certificate(s) using your name were seen in the last hour "
                "and not reported one by one, because there were too many.",
            ]
        lines += ["", f"Your domains: {self.settings.base_url.rstrip('/')}/targets"]
        queued = alerts.queue_notice(
            db,
            tenant_id=watched.tenant_id,
            subject=f"{watched.domain}: a certificate using your name was issued",
            body="\n".join(lines),
        )
        if self._bring_scan_forward:
            for target_id, label in {(m.watched.target_id, m.watched.label) for m in group}:
                self._rescan_sooner(db, repo, target_id, label, now)
        return queued

    def _rescan_sooner(
        self, db: Session, repo: TenantRepo, target_id: uuid.UUID, label: str, now: datetime
    ) -> None:
        """Bring the next regular scan forward, so the certificate becomes a finding.

        Only for domains that are scanned on a schedule, and once a day at most.
        """
        last = self._rescanned.get(target_id)
        if last is not None and now - last < RESCAN_ONCE_PER:
            return
        row = repo.get_target_by_id(target_id)
        if row is None or not row.scan_interval_hours:
            return
        due = _aware(row.next_scan_at)
        if due is None or due > now:
            row.next_scan_at = now
        # The scan searches certificate records by name and keeps the answer
        # for a day. Forget it, or the scan would not see the new certificate.
        db.execute(
            delete(HttpCache).where(
                HttpCache.key == Cache._key(_BRAND_CACHE_NAMESPACE, f"%{label}%")
            )
        )
        self._rescanned[target_id] = now
        while len(self._rescanned) > MAX_REMEMBERED:
            self._rescanned.popitem(last=False)

    def _told_recently(self, db: Session, tenant_id: uuid.UUID, owner: str, now: datetime) -> bool:
        """Whether this was reported in the last day, by this worker or another."""
        found = db.scalars(
            select(AuditLog.id)
            .where(
                AuditLog.tenant_id == tenant_id,
                AuditLog.action == AUDIT_ACTION,
                AuditLog.object_id == owner[:100],
                AuditLog.created_at > now - ALERT_ONCE_PER,
            )
            .limit(1)
        ).first()
        return found is not None

    def _remember(self, key: tuple[uuid.UUID, str], now: datetime) -> None:
        self._told[key] = now
        self._told.move_to_end(key)
        while len(self._told) > MAX_REMEMBERED:
            self._told.popitem(last=False)

    def _within_rate(self, tenant_id: uuid.UUID, now: datetime) -> bool:
        cutoff = now - RATE_WINDOW
        while self._sent_in_total and self._sent_in_total[0] <= cutoff:
            self._sent_in_total.popleft()
        if len(self._sent_in_total) >= MAX_NOTICES_IN_TOTAL:
            return False
        sent = self._sent.get(tenant_id)
        if sent is None:
            return True
        while sent and sent[0] <= cutoff:
            sent.popleft()
        if not sent:
            del self._sent[tenant_id]
            return True
        return len(sent) < MAX_NOTICES_PER_TENANT

    def _count_sent(self, tenant_id: uuid.UUID, now: datetime) -> None:
        self._sent.setdefault(tenant_id, deque(maxlen=MAX_NOTICES_PER_TENANT)).append(now)
        self._sent_in_total.append(now)
        if len(self._sent) > MAX_REMEMBERED:
            cutoff = now - RATE_WINDOW
            for tenant in [t for t, sent in self._sent.items() if not sent or sent[-1] <= cutoff]:
                del self._sent[tenant]

    # -- the connection ------------------------------------------------------------------

    def _open(self, url: str) -> Any:
        if self._connect is not None:
            return self._connect(url)
        # Loaded here, so that a worker without the package still starts.
        client = importlib.import_module("websockets.asyncio.client")
        return client.connect(
            url,
            max_size=MAX_FRAME_BYTES,
            max_queue=256,
            ping_interval=PING_EVERY_S,
            ping_timeout=PING_EVERY_S,
            open_timeout=OPEN_TIMEOUT_S,
            close_timeout=5,
            compression=None,
            user_agent_header="parapet-certwatch",
        )

    async def listen_once(self, url: str, stopping: asyncio.Event) -> None:
        """Read one connection until it ends or the worker is stopping."""
        async with self._open(url) as connection:
            log.warning("certwatch connected")
            handled = 0
            async for message in connection:
                if stopping.is_set():
                    return
                self.reload_if_due()
                self.handle(message)
                handled += 1
                if handled % 256 == 0:
                    # Matching is quick, but the rest of the worker must get its turn.
                    await asyncio.sleep(0)

    async def run_forever(self, stopping: asyncio.Event) -> None:
        """Read the stream until told to stop, reconnecting as needed. Never raises."""
        url = self.url
        if url is None:
            log.warning("certwatch is off: no usable certstream_url is set")
            return
        delay = BACKOFF_FIRST_S
        loop = asyncio.get_running_loop()
        while not stopping.is_set():
            started = loop.time()
            try:
                self.reload_if_due()
                await self.listen_once(url, stopping)
                reason = "the connection was closed"
            except asyncio.CancelledError:
                raise
            except ModuleNotFoundError:
                log.error("certwatch is off: the 'websockets' package is not installed")
                return
            except Exception as exc:
                self.counters.errors += 1
                reason = _describe(exc)
            if stopping.is_set():
                break
            if loop.time() - started >= HEALTHY_AFTER_S:
                delay = BACKOFF_FIRST_S
            wait = delay * random.uniform(0.5, 1.0)  # noqa: S311 - spreads reconnects, not a secret
            log.warning("certwatch disconnected", reason=reason, retry_in_s=round(wait, 1))
            try:
                await asyncio.wait_for(stopping.wait(), wait)
            except TimeoutError:
                pass
            delay = min(delay * 2, BACKOFF_MAX_S)
        log.warning("certwatch stopped")


def _describe(exc: BaseException) -> str:
    return scrub(f"{type(exc).__name__}: {exc}")[:300]


__all__ = ["CertWatcher", "Match", "Watched", "brand_label", "check_url", "defang", "names_in"]
