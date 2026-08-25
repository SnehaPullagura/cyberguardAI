# Approval Gate & Single-Use Authorization

High-impact playbooks trigger `ResponseApprovalRequest` in `pending_approval` state. Authorized SOC analysts (`Permission.PLAYBOOKS_APPROVE`) approve or reject requests. Self-approval is strictly forbidden.
