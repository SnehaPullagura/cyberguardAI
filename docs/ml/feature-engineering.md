# Standardized Feature Engineering & Validation

## Feature Schema (Version 1.0)
- `severity_weight`: Numerical scale (1.0 = info to 10.0 = critical).
- `hour_sin` / `hour_cos`: Cyclical sine and cosine hour-of-day encoding ($\sin(2\pi \cdot \text{hour}/24)$ and $\cos(2\pi \cdot \text{hour}/24)$).
- `day_of_week`: Day of week (0.0 = Monday to 6.0 = Sunday).
- `is_auth_category` / `is_process_category` / `is_network_category`: One-hot binary indicators.
- `is_failed_action`: Binary indicator for failed/denied actions.
- `has_source_ip` / `is_private_source_ip`: IP presence and RFC 1918 private range indicators.
- `dest_port`: Destination port number.

## Validation & Sanitization
`FeatureValidator` replaces all NaNs, Infs, and null values with `0.0`, enforcing fixed schema column order.
