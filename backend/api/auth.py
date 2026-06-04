from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import json
import os
import re
import uuid
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.db.models import AuditLog, Organization, OrganizationMember, User
from backend.db.session import get_session

AUTH_COOKIE_NAME = os.getenv("AGENTIC_AUTH_COOKIE_NAME", "agenticnetsec_session")
AUTH_SECRET = os.getenv("AGENTIC_AUTH_SECRET", "agenticnetsec-local-dev-secret-change-me")
AUTH_TOKEN_SECONDS = int(os.getenv("AGENTIC_AUTH_TOKEN_SECONDS", "3600"))
AUTH_COOKIE_SECURE = os.getenv("AGENTIC_AUTH_COOKIE_SECURE", "").strip().lower() in {"1", "true", "yes", "on"}
AUTH_COOKIE_SAMESITE = os.getenv("AGENTIC_AUTH_COOKIE_SAMESITE", "lax").strip().lower()

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SLUG_RE = re.compile(r"[^a-z0-9]+")

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
organization_router = APIRouter(prefix="/api/v1/organization", tags=["organization"])

ROLE_PERMISSIONS = {
    "owner": {"analysis:create", "analysis:read", "members:manage", "settings:read"},
    "analyst": {"analysis:create", "analysis:read", "settings:read"},
    "viewer": {"analysis:read", "settings:read"},
}
VALID_MEMBER_ROLES = frozenset(ROLE_PERMISSIONS)


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=8, max_length=512)
    display_name: str | None = Field(default=None, max_length=200)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=512)


class MemberRoleUpdateRequest(BaseModel):
    role: str = Field(min_length=1, max_length=32)


@dataclass(frozen=True)
class CurrentPrincipal:
    user_id: uuid.UUID
    organization_id: uuid.UUID
    role: str
    email: str
    display_name: str | None
    organization_name: str
    organization_slug: str


def normalize_email(email: str) -> str:
    normalized = email.strip().lower()
    if not EMAIL_RE.match(normalized):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    return normalized


def hash_password(password: str) -> str:
    bcrypt = _load_bcrypt()
    if bcrypt is not None:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")

    crypt = _load_crypt()
    if crypt is None or not hasattr(crypt, "METHOD_BLOWFISH"):
        raise RuntimeError("bcrypt support is unavailable. Install the bcrypt package.")
    return crypt.crypt(password, crypt.mksalt(crypt.METHOD_BLOWFISH))


def verify_password(password: str, password_hash: str) -> bool:
    bcrypt = _load_bcrypt()
    if bcrypt is not None:
        try:
            return bool(bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8")))
        except ValueError:
            return False

    crypt = _load_crypt()
    if crypt is None:
        return False
    candidate = crypt.crypt(password, password_hash)
    return hmac.compare_digest(candidate or "", password_hash)


def create_access_token(user_id: uuid.UUID, organization_id: uuid.UUID) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "org_id": str(organization_id),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=AUTH_TOKEN_SECONDS)).timestamp()),
        "jti": uuid.uuid4().hex,
    }
    return _encode_jwt(payload)


def set_auth_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        AUTH_COOKIE_NAME,
        token,
        max_age=AUTH_TOKEN_SECONDS,
        httponly=True,
        secure=AUTH_COOKIE_SECURE,
        samesite=AUTH_COOKIE_SAMESITE,
        path="/",
    )


def clear_auth_cookie(response: Response) -> None:
    response.delete_cookie(
        AUTH_COOKIE_NAME,
        httponly=True,
        secure=AUTH_COOKIE_SECURE,
        samesite=AUTH_COOKIE_SAMESITE,
        path="/",
    )


def get_current_principal(
    session_token: str | None = Cookie(default=None, alias=AUTH_COOKIE_NAME),
    session: Session = Depends(get_session),
) -> CurrentPrincipal:
    if not session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")
    payload = _decode_jwt(session_token)
    user_id = _uuid_from_claim(payload.get("sub"))
    organization_id = _uuid_from_claim(payload.get("org_id"))

    user = session.scalar(select(User).where(User.id == user_id))
    if user is None or user.disabled_at is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")

    membership = session.scalar(
        select(OrganizationMember)
        .where(
            OrganizationMember.organization_id == organization_id,
            OrganizationMember.user_id == user.id,
        )
        .order_by(OrganizationMember.created_at.asc())
    )
    if membership is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")

    organization = session.scalar(select(Organization).where(Organization.id == membership.organization_id))
    if organization is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")

    return CurrentPrincipal(
        user_id=user.id,
        organization_id=organization.id,
        role=membership.role,
        email=user.email,
        display_name=user.display_name,
        organization_name=organization.name,
        organization_slug=organization.slug,
    )


def require_permission(permission: str) -> Callable[[CurrentPrincipal], CurrentPrincipal]:
    def dependency(principal: CurrentPrincipal = Depends(get_current_principal)) -> CurrentPrincipal:
        if permission not in ROLE_PERMISSIONS.get(principal.role, set()):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions.")
        return principal

    return dependency


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, response: Response, session: Session = Depends(get_session)) -> dict[str, Any]:
    email = normalize_email(str(payload.email))
    existing = session.scalar(select(User).where(func.lower(User.email) == email))
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already registered.")

    user = User(
        email=email,
        password_hash=hash_password(payload.password),
        display_name=_clean_display_name(payload.display_name),
    )
    session.add(user)
    session.flush()

    organization = Organization(
        name=_default_org_name(user),
        slug=_unique_org_slug(session, user),
        created_by_user_id=user.id,
    )
    session.add(organization)
    session.flush()

    membership = OrganizationMember(organization_id=organization.id, user_id=user.id, role="owner")
    session.add(membership)
    session.add(
        AuditLog(
            organization_id=organization.id,
            user_id=user.id,
            action="user registered",
            target_type="user",
            target_id=user.id,
            metadata_json={"email": user.email},
        )
    )
    session.commit()

    token = create_access_token(user.id, organization.id)
    set_auth_cookie(response, token)
    return _session_payload(user, organization, membership.role)


@router.post("/login")
def login(payload: LoginRequest, response: Response, session: Session = Depends(get_session)) -> dict[str, Any]:
    email = normalize_email(str(payload.email))
    user = session.scalar(select(User).where(func.lower(User.email) == email))
    if user is None or user.disabled_at is not None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    membership = session.scalar(
        select(OrganizationMember)
        .where(OrganizationMember.user_id == user.id)
        .order_by(OrganizationMember.created_at.asc())
    )
    if membership is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")
    organization = session.scalar(select(Organization).where(Organization.id == membership.organization_id))
    if organization is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    session.add(
        AuditLog(
            organization_id=organization.id,
            user_id=user.id,
            action="user logged in",
            target_type="user",
            target_id=user.id,
            metadata_json={"email": user.email},
        )
    )
    session.commit()

    token = create_access_token(user.id, organization.id)
    set_auth_cookie(response, token)
    return _session_payload(user, organization, membership.role)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(response: Response) -> None:
    clear_auth_cookie(response)
    return None


@router.get("/me")
def me(response: Response, principal: CurrentPrincipal = Depends(get_current_principal)) -> dict[str, Any]:
    if not principal:
        clear_auth_cookie(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")
    return _principal_payload(principal)


@organization_router.patch("/members/{member_id}/role")
def update_member_role(
    member_id: uuid.UUID,
    payload: MemberRoleUpdateRequest,
    principal: CurrentPrincipal = Depends(require_permission("members:manage")),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    requested_role = payload.role.strip().lower()
    if requested_role not in VALID_MEMBER_ROLES:
        raise HTTPException(status_code=400, detail="role must be one of: analyst, owner, viewer.")

    membership = session.scalar(
        select(OrganizationMember).where(
            OrganizationMember.id == member_id,
            OrganizationMember.organization_id == principal.organization_id,
        )
    )
    if membership is None:
        raise HTTPException(status_code=404, detail="Organization member not found.")

    previous_role = membership.role
    if previous_role == "owner" and requested_role != "owner":
        owner_count = session.scalar(
            select(func.count())
            .select_from(OrganizationMember)
            .where(
                OrganizationMember.organization_id == principal.organization_id,
                OrganizationMember.role == "owner",
            )
        )
        if int(owner_count or 0) <= 1:
            raise HTTPException(status_code=409, detail="Cannot change the last owner role.")

    membership.role = requested_role
    session.add(
        AuditLog(
            organization_id=principal.organization_id,
            user_id=principal.user_id,
            action="member role changed",
            target_type="organization_member",
            target_id=membership.id,
            metadata_json={
                "target_user_id": str(membership.user_id),
                "previous_role": previous_role,
                "new_role": requested_role,
            },
        )
    )
    session.commit()

    return {
        "member": {
            "id": str(membership.id),
            "organization_id": str(membership.organization_id),
            "user_id": str(membership.user_id),
            "role": membership.role,
        }
    }


def _session_payload(user: User, organization: Organization, role: str) -> dict[str, Any]:
    return {
        "user": {
            "id": str(user.id),
            "email": user.email,
            "display_name": user.display_name,
        },
        "organization": {
            "id": str(organization.id),
            "name": organization.name,
            "slug": organization.slug,
            "role": role,
        },
    }


def _principal_payload(principal: CurrentPrincipal) -> dict[str, Any]:
    return {
        "user": {
            "id": str(principal.user_id),
            "email": principal.email,
            "display_name": principal.display_name,
        },
        "organization": {
            "id": str(principal.organization_id),
            "name": principal.organization_name,
            "slug": principal.organization_slug,
            "role": principal.role,
        },
    }


def _encode_jwt(payload: dict[str, Any]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{_b64_json(header)}.{_b64_json(payload)}"
    signature = hmac.new(AUTH_SECRET.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64_bytes(signature)}"


def _decode_jwt(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")
    signing_input = f"{parts[0]}.{parts[1]}"
    expected = hmac.new(AUTH_SECRET.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    try:
        received = _unb64(parts[2])
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.") from exc
    if not hmac.compare_digest(received, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")

    try:
        header = json.loads(_unb64(parts[0]))
        payload = json.loads(_unb64(parts[1]))
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.") from exc
    if header.get("alg") != "HS256" or header.get("typ") != "JWT":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")

    exp = payload.get("exp")
    if not isinstance(exp, int) or exp <= int(datetime.now(timezone.utc).timestamp()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")
    return payload


def _b64_json(value: dict[str, Any]) -> str:
    return _b64_bytes(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _b64_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _uuid_from_claim(value: Any) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.") from exc


def _clean_display_name(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _default_org_name(user: User) -> str:
    if user.display_name:
        return f"{user.display_name} Organization"
    return f"{user.email.split('@', 1)[0]} Organization"


def _unique_org_slug(session: Session, user: User) -> str:
    seed = user.display_name or user.email.split("@", 1)[0] or "organization"
    base = SLUG_RE.sub("-", seed.lower()).strip("-") or "organization"
    base = base[:40].strip("-") or "organization"
    for _attempt in range(20):
        candidate = f"{base}-{uuid.uuid4().hex[:6]}"
        exists = session.scalar(select(Organization.id).where(Organization.slug == candidate))
        if exists is None:
            return candidate
    return f"organization-{uuid.uuid4().hex}"


def _load_bcrypt() -> Any | None:
    try:
        return importlib.import_module("bcrypt")
    except ImportError:
        return None


def _load_crypt() -> Any | None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            return importlib.import_module("crypt")
        except ImportError:
            return None
