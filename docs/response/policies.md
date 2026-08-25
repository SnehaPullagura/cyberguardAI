# Response Policies & Safety Boundaries

## Policy Hierarchy
1. **Disabled Playbook**: If `enabled == False`, execution is immediately skipped.
2. **Threshold Checks**: Event risk score and severity must meet or exceed configured thresholds.
3. **RBAC Validation**: Requester must possess `Permission.PLAYBOOKS_EXECUTE` or `Permission.RESPONSES_EXECUTE`.
4. **Safety Classification**:
   - `LOW`: Safe automated execution or dry-run.
   - `MEDIUM`: Requires incident correlation and simulation/dry-run.
   - `HIGH` / `CRITICAL`: Defaults to simulation adapter; requires explicit Approval Gate authorization before execution.
5. **Post-Approval Re-Validation**: Re-checks permissions and playbook state prior to execution.
