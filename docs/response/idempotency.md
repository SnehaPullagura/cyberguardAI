# Idempotency & Cooldown Protection

`CooldownManager` utilizes Redis and DB fallback stores (`cooldown:pb:<id>:entity:<entity_id>`) to suppress duplicate executions and infinite response loops.
