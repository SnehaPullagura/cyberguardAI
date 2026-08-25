# Database Schemas & Data Types

## Security Events Schema (`events` Table)

| Field Name | Type | Constraints / Indexes | Description |
| :--- | :--- | :--- | :--- |
| `id` | `VARCHAR(36)` | Composite Primary Key | Internal UUID |
| `event_id` | `VARCHAR(100)` | Unique, Indexed | Business event identifier |
| `timestamp` | `TIMESTAMPTZ` | Composite Primary Key, Indexed | Log event timestamp |
| `ingested_at` | `TIMESTAMPTZ` | NOT NULL | Server ingestion timestamp |
| `source_type` | `VARCHAR(50)` | Indexed | Log collector type (syslog, winevent, nginx) |
| `category` | `VARCHAR(50)` | Indexed | Security category (authentication, process, network) |
| `action` | `VARCHAR(100)` | NOT NULL | Action performed (login_failed, process_created) |
| `severity` | `VARCHAR(20)` | Indexed | Severity level (critical, high, medium, low, info) |
| `source_ip` | `VARCHAR(45)` | Indexed | Source IPv4/IPv6 address |
| `source_user` | `VARCHAR(100)` | Indexed | User identity |
| `destination_ip` | `VARCHAR(45)` | Indexed | Destination IPv4/IPv6 address |
| `risk_score` | `FLOAT` | Default 0.0 | Calculated event risk score |
| `anomaly_score` | `FLOAT` | Default 0.0 | ML behavioral anomaly score |
| `raw_payload` | `TEXT` | Nullable | Unmodified raw log message |
| `normalized_payload` | `JSONB` | Nullable | Extracted JSON attribute tree |

## Application Tables
- `users`: User profiles, hashed passwords, active status.
- `roles`: RBAC roles (`admin`, `security_analyst`, `viewer`).
- `permissions`: Granular permission codes.
- `alerts`: Detection alerts linked to rule_id or ioc_id.
- `incidents`: Correlated incident cases.
- `audit_logs`: Immutable security audit log records with sanitized metadata.
