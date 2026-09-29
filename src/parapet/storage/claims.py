"""One organisation at a time may hold proof of control over a domain.

This is the only code that looks across tenants, which is why it lives apart
from the tenant-scoped repository. It reads and changes verification standing
and nothing else.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from parapet.storage.tables import AuditLog, DomainVerification, TargetRow


def release_other_claims(db: Session, root_domain: str, keep_tenant: uuid.UUID) -> list[uuid.UUID]:
    """Withdraw every other tenant's standing for a domain. Returns the tenants affected."""
    rows = db.execute(
        select(DomainVerification, TargetRow)
        .join(TargetRow, TargetRow.id == DomainVerification.target_id)
        .where(
            TargetRow.root_domain == root_domain,
            DomainVerification.tenant_id != keep_tenant,
            DomainVerification.verified_at.is_not(None),
        )
    ).all()
    affected = []
    for verification, target in rows:
        verification.verified_at = None
        verification.last_result = "Another organisation proved control of this domain."
        db.add(
            AuditLog(
                tenant_id=verification.tenant_id,
                actor="system",
                action="verification.superseded",
                object_type="target",
                object_id=str(target.id),
                meta={},
            )
        )
        affected.append(verification.tenant_id)
    db.flush()
    return affected
