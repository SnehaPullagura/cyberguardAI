# Backpressure & Queue Limits

Client sockets track message buffer counts. Non-critical telemetry updates are dropped for slow clients while CRITICAL/HIGH alerts are guaranteed priority delivery.
