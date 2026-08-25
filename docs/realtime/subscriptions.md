# Server-Side RBAC Subscription Filtering

The WebSocketConnectionManager enforces server-side RBAC permissions (`events:read`, `alerts:read`, `incidents:read`) before forwarding messages from Redis Pub/Sub to individual client sockets.
