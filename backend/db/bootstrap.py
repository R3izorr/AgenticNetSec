from __future__ import annotations

import os
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Organization, OrganizationMember, User

DEFAULT_USER_EMAIL = os.getenv("AGENTIC_DEFAULT_USER_EMAIL", "local-demo@agenticnetsec.test").lower()
DEFAULT_ORG_SLUG = os.getenv("AGENTIC_DEFAULT_ORG_SLUG", "local-demo")


def ensure_default_principal(session: Session) -> tuple[uuid.UUID, uuid.UUID]:
    user = session.scalar(select(User).where(User.email == DEFAULT_USER_EMAIL))
    if user is None:
        user = User(
            email=DEFAULT_USER_EMAIL,
            password_hash="mvp-local-demo-no-login",
            display_name="Local Demo",
        )
        session.add(user)
        session.flush()

    organization = session.scalar(select(Organization).where(Organization.slug == DEFAULT_ORG_SLUG))
    if organization is None:
        organization = Organization(
            name="Local Demo",
            slug=DEFAULT_ORG_SLUG,
            created_by_user_id=user.id,
        )
        session.add(organization)
        session.flush()

    membership = session.scalar(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == organization.id,
            OrganizationMember.user_id == user.id,
        )
    )
    if membership is None:
        session.add(OrganizationMember(organization_id=organization.id, user_id=user.id, role="owner"))
        session.flush()

    return user.id, organization.id
