# Real-Time WebSockets & Redis Pub/Sub Architecture

## Overview
CyberGuard AI delivers real-time security events, alerts, incidents, and live dashboard metrics via WebSocket connections fanned out through Redis Pub/Sub.

## Data Flow
```
Security Log Event -> Redis Queue -> Worker Process -> Persistence -> Redis Pub/Sub (cyberguard:realtime:events) -> FastAPI Async Listener -> Server-Side RBAC Filter -> WebSocketConnectionManager -> Connected React Clients
```
