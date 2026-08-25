# Idempotency & Cooldown Management

## Key Concepts
- **Idempotency**: Identical alerts do not trigger redundant response executions.
- **Entity Cooldown**: Prevents flapping or rapid-fire actions against the same target entity (IP, host, or user).

## Lock Mechanics
- Distributed lock key: `cyberguard:playbook:lock:{playbook_id}:{entity_key}`
- Storage: Redis with `SET key val NX EX cooldown_seconds`
- Fallback: Thread-safe in-memory cache with UTC expiry checks.
