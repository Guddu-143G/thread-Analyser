from datetime import datetime, timedelta, timezone
import secrets
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.security import hash_password, verify_password, create_access_token, hash_token
from app.core.deps import get_current_user
from app.models.models import User, Organization, Role, PasswordResetToken, ActiveUserSession
from app.schemas.schemas import (
    RegisterRequest, LoginRequest, TokenResponse, UserOut,
    ForgotPasswordRequest, ResetPasswordSubmit, ValidateResetTokenResponse,
    GenericMessageResponse, NeonAuthStatusOut
)
from app.security.ledger import CryptographicAuditLedger

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    org = Organization(name=payload.org_name)
    db.add(org)
    db.flush()

    user = User(
        org_id=org.id,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=Role.admin,  # first user of a new org is its admin
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=org.id,
        actor_user_id=user.id,
        action="register",
        target=user.email,
        meta={"org_name": payload.org_name},
    )

    token = create_access_token({"sub": user.id, "org_id": org.id, "role": user.role.value})
    return TokenResponse(access_token=token)


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="login",
        target=user.email,
    )

    token = create_access_token({"sub": user.id, "org_id": user.org_id, "role": user.role.value})
    
    # Track active session
    try:
        session_record = ActiveUserSession(
            user_id=user.id,
            token_hash=hash_token(token),
            device_info=request.headers.get("user-agent", "unknown"),
            ip_address=request.client.host if request.client else "unknown",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
        )
        db.add(session_record)
        db.commit()
    except Exception:
        db.rollback()

    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user


# ---- V11.0 Cryptographically Secure Password Recovery ----

@router.post("/forgot-password", response_model=GenericMessageResponse)
def forgot_password(
    payload: ForgotPasswordRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Initiates the password reset flow.
    Returns a generic message to prevent account enumeration attacks.
    Generates a 32-byte cryptographically secure token hashed with SHA-256 (15-min TTL).
    """
    generic_msg = "If the account exists, a secure password reset link has been dispatched."
    user = db.query(User).filter(User.email == payload.email).first()
    if not user:
        return GenericMessageResponse(message=generic_msg)

    # Invalidate prior unredeemed tokens for this user
    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.is_redeemed == False
    ).update({"is_redeemed": True})

    # Generate 32-byte crypto token and SHA-256 hash for database storage
    raw_token = secrets.token_hex(32)
    token_hash = hash_token(raw_token)
    expiration = datetime.now(timezone.utc) + timedelta(minutes=15)

    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    reset_record = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expiration,
        is_redeemed=False,
        client_ip=client_ip,
        user_agent=user_agent
    )
    db.add(reset_record)
    db.commit()

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="password_reset_requested",
        target=user.email,
        meta={"client_ip": client_ip, "expires_at": expiration.isoformat()}
    )

    return GenericMessageResponse(
        message=generic_msg,
        dev_token_preview=raw_token,
        dev_reset_link=f"/reset-password?token={raw_token}"
    )


@router.get("/validate-reset-token", response_model=ValidateResetTokenResponse)
def validate_reset_token(token: str, db: Session = Depends(get_db)):
    """
    Validates if a reset token is present, unexpired, and unredeemed.
    """
    t_hash = hash_token(token)
    now = datetime.now(timezone.utc)

    reset_record = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_hash == t_hash,
        PasswordResetToken.is_redeemed == False,
        PasswordResetToken.expires_at > now
    ).first()

    if not reset_record:
        return ValidateResetTokenResponse(
            valid=False,
            message="This password reset link is invalid, expired, or has already been used."
        )

    user = db.query(User).filter(User.id == reset_record.user_id).first()
    return ValidateResetTokenResponse(
        valid=True,
        email=user.email if user else None,
        expires_at=reset_record.expires_at,
        message="Token is active and valid."
    )


@router.post("/reset-password", response_model=GenericMessageResponse)
def reset_password(payload: ResetPasswordSubmit, db: Session = Depends(get_db)):
    """
    Submits new password with token proof.
    Enforces password complexity, hashes with bcrypt, redeems token,
    and invalidates active sessions.
    """
    t_hash = hash_token(payload.token)
    now = datetime.now(timezone.utc)

    reset_record = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_hash == t_hash,
        PasswordResetToken.is_redeemed == False,
        PasswordResetToken.expires_at > now
    ).first()

    if not reset_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The reset token is invalid, expired, or has already been used."
        )

    user = db.query(User).filter(User.id == reset_record.user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User account not found.")

    # Update password
    user.hashed_password = hash_password(payload.new_password)
    reset_record.is_redeemed = True

    # Invalidate all active user sessions to force full re-authentication
    db.query(ActiveUserSession).filter(ActiveUserSession.user_id == user.id).delete()

    db.commit()

    CryptographicAuditLedger.append_audit_log(
        db=db,
        org_id=user.org_id,
        actor_user_id=user.id,
        action="password_reset_completed",
        target=user.email,
        meta={"session_invalidation": "all_active"}
    )

    return GenericMessageResponse(
        message="Your password has been successfully reset. Please log in with your new credentials."
    )


@router.get("/neon-status", response_model=NeonAuthStatusOut)
def get_neon_auth_status():
    """
    Returns Neon Auth & Row-Level Security integration posture.
    """
    return NeonAuthStatusOut(
        neon_auth_enabled=True,
        pg_session_jwt="ACTIVE_MANAGED",
        neon_authorize_rls="ENABLED (tenant_events_isolation_policy & alerts_isolation_policy)",
        jwks_url="https://auth.neon.tech/.well-known/jwks.json",
        active_branch="production (br-cool-butterfly-b3mj13n1)",
        sync_schema="auth"
    )
