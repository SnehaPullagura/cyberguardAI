# Authentication Architecture

## Overview
CyberGuard AI uses JWT (JSON Web Token) bearer authentication with dual access and refresh token semantics.

## Credentials & Hashing
- Passwords are never stored in plaintext.
- Password hashing uses `bcrypt` directly with automatic salt generation (`bcrypt.hashpw`).
- Generic authentication error messages (`"Incorrect username or password"`) are returned on login failure to prevent username enumeration.

## Token Lifecycle
- **Access Tokens**: Short-lived (default 30 minutes), signed with `HS256` using `SECRET_KEY`. Contained claims: `sub` (User ID), `exp` (Expiration timestamp), `type: "access"`.
- **Refresh Tokens**: Long-lived (default 7 days), signed with `HS256`. Contained claims: `sub` (User ID), `exp`, `type: "refresh"`.
- Token claims are validated on every authenticated API request via the `get_current_user` FastAPI dependency.

## Authentication Endpoints
- `POST /api/v1/auth/login`: Authenticates username/email + password. Returns access & refresh tokens.
- `POST /api/v1/auth/refresh`: Accepts valid refresh token and issues a new access/refresh token pair.
- `GET /api/v1/auth/me`: Returns authenticated user profile and assigned role.
- `POST /api/v1/auth/register`: Admin-only endpoint for provisioning user accounts (`USERS_MANAGE` permission required).
