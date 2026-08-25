# WebSocket Security & RBAC Enforcement

- **Mandatory JWT Authentication**: Handshake URL query parameters (`?token=JWT`) are validated using `decode_access_token()`.
- **Server-Side RBAC**: Role-based permissions are enforced server-side before forwarding messages. `VIEWER` connections are filtered to prevent unauthorized access to administrative streams.
- **Credential Redaction**: JWT tokens, passwords, and sensitive fields are excluded from log output and envelope payloads.
