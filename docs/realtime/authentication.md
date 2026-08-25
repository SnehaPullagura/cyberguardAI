# WebSocket Authentication & Security

WebSocket connections require a valid JWT token via query parameter `?token=JWT_ACCESS_TOKEN`. Invalid or missing tokens result in immediate policy violation closure (code 4008 / 1008) without sensitive error or stack trace leakage.
