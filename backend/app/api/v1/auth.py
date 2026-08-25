from datetime import timedelta
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    TokenResponse,
    RefreshTokenRequest,
    UserCreate,
    UserRead,
)
from app.security.password import verify_password, get_password_hash
from app.security.auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
)
from app.security.rbac import require_permission, Permission
from app.services.audit_service import audit_service

router = APIRouter(prefix="/auth", tags=["Authentication & Access Control"])


@router.post("/login", response_model=TokenResponse)
def login(request_data: LoginRequest, req: Request, db: Session = Depends(get_db)):
    """Authenticate user credentials and issue dual JWT access & refresh tokens."""
    client_ip = req.client.host if req.client else "unknown"
    user = (
        db.query(User)
        .filter(
            (User.username == request_data.username)
            | (User.email == request_data.username)
        )
        .first()
    )

    if not user or not verify_password(request_data.password, user.hashed_password):
        audit_service.log_action(
            db=db,
            action="USER_LOGIN_FAILED",
            resource="auth",
            username=request_data.username,
            ip_address=client_ip,
            status="FAILED",
            details={"reason": "Invalid credentials"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        audit_service.log_action(
            db=db,
            action="USER_LOGIN_FAILED",
            resource="auth",
            user_id=user.id,
            username=user.username,
            ip_address=client_ip,
            status="FAILED",
            details={"reason": "Inactive user account"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user account"
        )

    # Issue tokens
    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token(subject=user.id)

    # Audit login success
    audit_service.log_action(
        db=db,
        action="USER_LOGIN_SUCCESS",
        resource="auth",
        user_id=user.id,
        username=user.username,
        ip_address=client_ip,
        status="SUCCESS",
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(request_data: RefreshTokenRequest, db: Session = Depends(get_db)):
    """Refresh expired access token using valid refresh token."""
    payload = decode_token(request_data.refresh_token)
    user_id = payload.get("sub")
    token_type = payload.get("type")

    if not user_id or token_type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token claims",
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account unavailable",
        )

    new_access_token = create_access_token(subject=user.id)
    new_refresh_token = create_refresh_token(subject=user.id)

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/me", response_model=UserRead)
def get_me(current_user: User = Depends(get_current_user)):
    """Retrieve authenticated user profile and assigned roles."""
    return current_user


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register_user(
    request_data: UserCreate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_permission(Permission.USERS_MANAGE)),
):
    """Admin-only user provisioning endpoint."""
    existing = (
        db.query(User)
        .filter(
            (User.username == request_data.username)
            | (User.email == request_data.email)
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered",
        )

    new_user = User(
        username=request_data.username,
        email=request_data.email,
        hashed_password=get_password_hash(request_data.password),
        role_id=request_data.role_id,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    audit_service.log_action(
        db=db,
        action="USER_CREATED",
        resource="users",
        user_id=admin_user.id,
        username=admin_user.username,
        status="SUCCESS",
        details={"created_username": new_user.username, "created_user_id": new_user.id},
    )

    return new_user
