# Allowlisted Action Registry & Adapters

## Overview
The `ActionRegistry` is a centralized repository of predefined, safe defensive actions.

## Registered Allowlisted Actions

| Action Type | Risk Level | Required Permission | Description |
|---|---|---|---|
| `create_incident` | LOW | `incidents:create` | Creates or escalates an incident from an alert |
| `update_incident` | LOW | `incidents:update` | Updates status or notes on existing incident |
| `notify_security_team` | LOW | `responses:execute` | Dispatches SOC team notifications |
| `enrich_event` | LOW | `responses:execute` | Tags event with reputation and autonomous system metadata |
| `quarantine_simulation` | HIGH | `responses:execute` | Safe simulation adapter for host/container isolation |
| `account_lock_simulation` | HIGH | `responses:execute` | Safe simulation adapter for user credential lockout |
| `network_block_simulation` | CRITICAL | `responses:execute` | Safe simulation adapter for firewall perimeter blocking |

## Prohibited Behaviors
- NO arbitrary shell execution (`subprocess`, `os.system`)
- NO arbitrary code execution (`eval`, `exec`)
- NO arbitrary SQL queries or dynamic script invocation
- NO URL fetches based on untrusted event parameters
