# Playbook Execution Engine

## Execution Mechanics
1. **Trigger Evaluation**: Safe condition evaluation on alert/incident metadata.
2. **Loop Prevention**: Max recursion depth limit (`3`) and response-generated provenance tag checks.
3. **Idempotency & Cooldown**: Distributed Redis lock (`cyberguard:playbook:lock:{playbook_id}:{entity_key}`) prevents duplicate concurrent runs.
4. **Action Sequence Dispatch**: Sequential invocation with bounded per-action timeout (default 30s) and exponential backoff retry policy for safe actions.
5. **Verification**: Dedicated `verify_handler` executed after each action to confirm state changes.
6. **Result Persistence**: Structured metrics and logs stored in `ResponseExecution` and `ResponseActionExecution` tables.
