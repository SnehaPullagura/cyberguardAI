"""CyberGuard AI Root Application Entry Point."""

import sys
import os
import uvicorn

# Add backend directory to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from app.main import app

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    print(f"Starting CyberGuard AI Platform on http://{host}:{port}...")
    uvicorn.run("app.main:app", host=host, port=port, reload=False, app_dir="backend")
