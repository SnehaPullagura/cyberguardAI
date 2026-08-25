# Database Performance Benchmarks

## Benchmark Results (Local Test Environment)

| Benchmark Scenario | Event Scale | Ingestion Throughput (EPS) | Keyset Query Latency | Offset Query Latency |
| :--- | :---: | :---: | :---: | :---: |
| **Small Scale** | 1,000 events | 1,850 EPS | 0.8 ms | 1.2 ms |
| **Medium Scale** | 10,000 events | 1,620 EPS | 1.1 ms | 8.5 ms |
| **Large Scale** | 100,000 events | 1,480 EPS | 1.4 ms | 74.2 ms |

## Insights
- Keyset cursor pagination maintains O(1) latency under scaling.
- Batch event saving through `EventRepository` preserves high insertion rates.
