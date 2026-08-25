import os
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )

    PROJECT_NAME: str = "CyberGuard AI"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    # Environment
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"

    # Security & Auth
    SECRET_KEY: str = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8000",
    ]

    # Database
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_USER: str = "cyberguard"
    POSTGRES_PASSWORD: str = "cyberguard_secret"
    POSTGRES_DB: str = "cyberguard_db"
    POSTGRES_PORT: int = 5432
    DATABASE_URL: Optional[str] = None

    # Redis Queue & Cache
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_URL: Optional[str] = None

    # Asynchronous Ingestion & Queue Settings
    ASYNC_INGESTION_ENABLED: bool = True
    QUEUE_NAME: str = "cyberguard:events:queue"
    DLQ_NAME: str = "cyberguard:events:dlq"
    MAX_RETRIES: int = 3
    EVENT_IDEMPOTENCY_TTL_SECONDS: int = 86400  # 24 hours

    # Time-Series Storage & Retention Settings (Phase 3)
    EVENT_RETENTION_DAYS: int = 90
    TIMESCALE_ENABLED: bool = True
    EVENT_PARTITION_INTERVAL_DAYS: int = 7

    # ML Storage Path
    ML_MODEL_DIR: str = os.path.join(os.path.dirname(__file__), "..", "ml", "artifacts")

    # Detection Rules Path
    RULES_DIR: str = os.path.join(os.path.dirname(__file__), "..", "..", "rules_repo")

    def get_database_url(self) -> str:
        if self.DATABASE_URL:
            return self.DATABASE_URL
        return (
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    def get_async_database_url(self) -> str:
        url = self.get_database_url()
        if url.startswith("postgresql://"):
            return url.replace("postgresql://", "postgresql+asyncpg://", 1)
        return url

    def get_redis_url(self) -> str:
        if self.REDIS_URL:
            return self.REDIS_URL
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/0"


settings = Settings()
