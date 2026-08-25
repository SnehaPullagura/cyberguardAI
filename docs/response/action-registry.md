# Allowlisted Action Registry & Controlled Adapters

Actions must be explicitly registered in `ActionRegistry`. Arbitrary shell commands (`subprocess`), arbitrary Python (`eval`, `exec`), arbitrary SQL, or dynamic script execution are strictly prohibited.
Registered actions: `create_incident`, `update_incident`, `notify_security_team`, `enrich_event`, `quarantine_simulation`, `account_lock_simulation`, `network_block_simulation`.
