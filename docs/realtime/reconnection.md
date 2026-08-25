# Client Reconnection & Heartbeat Protocol

`ReconnectingWebSocketClient` manages reconnection with exponential backoff (`CONNECTED`, `CONNECTING`, `RECONNECTING`, `DISCONNECTED`). Heartbeat PING messages are transmitted every 15 seconds to keep connections alive and clean up stale sockets.
