import os
import logging
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.config import settings

logger = logging.getLogger(__name__)

is_testing = os.getenv("TESTING", "0") == "1"

if is_testing:
    db_url = "sqlite:///./test_cyberguard.db"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
else:
    db_url = settings.get_database_url()
    if db_url.startswith("sqlite"):
        engine = create_engine(db_url, connect_args={"check_same_thread": False})
    else:
        try:
            engine = create_engine(
                db_url,
                pool_pre_ping=True,
                pool_size=20,
                max_overflow=10,
            )
        except Exception as e:
            logger.warning(
                f"Could not connect to PostgreSQL ({e}), falling back to SQLite for local development."
            )
            db_url = "sqlite:///./cyberguard_dev.db"
            engine = create_engine(db_url, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Dependency for obtaining database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
