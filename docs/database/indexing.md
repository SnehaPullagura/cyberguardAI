# Composite Indexing Strategy

## Indexes Implemented
- `idx_events_timestamp_category`: `(timestamp DESC, category)`
- `idx_events_timestamp_severity`: `(timestamp DESC, severity)`
- `idx_events_timestamp_source_type`: `(timestamp DESC, source_type)`
- `idx_events_source_dest_ip`: `(source_ip, destination_ip)`
- `idx_events_keyset_pagination`: `(timestamp DESC, id DESC)`

## Keyset Pagination Performance
Composite index `(timestamp DESC, id DESC)` enables zero-degradation cursor pagination:
```sql
SELECT * FROM events
WHERE (timestamp < cursor_timestamp)
   OR (timestamp = cursor_timestamp AND id < cursor_id)
ORDER BY timestamp DESC, id DESC
LIMIT 50;
```
This query uses index seek instead of sequential table scans, preventing performance degradation on multi-million row datasets.
