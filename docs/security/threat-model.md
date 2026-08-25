# Threat Model & Risk Mitigations

## Threat Matrix

| Threat ID | Threat Description | Attack Surface | Risk Level | Mitigation Strategy | Verification Test |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **TM-01** | Unauthorized API Access | Protected Endpoints | **High** | Universal backend RBAC enforcement via `require_permission` on 100% of protected routes. | `test_rbac.py::test_unauthenticated_requests_rejected` |
| **TM-02** | Privilege Escalation | User Registration & Role Assignment | **High** | Restrict `POST /auth/register` to `USERS_MANAGE` permission (ADMIN role only). | `test_rbac.py::test_non_admin_cannot_register_users` |
| **TM-03** | Credential Brute Force | Authentication Endpoint | **Medium** | Rate limit `/auth/login` to 10 req/min; generic error messages on login failure. | `test_api_security.py::test_login_rate_limiting` |
| **TM-04** | Information Disclosure via Errors | Global Unhandled Exceptions | **Medium** | Global exception handler sanitizes 500 internal errors and suppresses tracebacks. | `test_api_security.py::test_exception_sanitization` |
| **TM-05** | Sensitive Credential Leakage in Audit Logs | Audit Service | **Medium** | Automatic redaction (`[REDACTED]`) of passwords, tokens, and secrets in `audit_service`. | `test_audit_security.py::test_audit_log_credential_redaction` |
| **TM-06** | Insecure Direct Object Reference (IDOR) | Alert / Incident Detail Routes | **Medium** | Object-level 404 / 403 authorization checks on ID query parameter routes. | `test_object_authorization.py::test_invalid_object_id_access` |
