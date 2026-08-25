import os

# Set testing environment mode before app initialization
os.environ["TESTING"] = "1"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app, seed_initial_data
from app.security.auth import create_access_token
from app.models.user import User
from app.queue.redis_queue import redis_queue
from app.middleware.security import reset_rate_limits

SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///./test_cyberguard.db"

engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    seed_initial_data(db)
    db.close()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def reset_queue_and_rate_limits():
    redis_queue.reset_state()
    reset_rate_limits()
    yield
    redis_queue.reset_state()
    reset_rate_limits()


@pytest.fixture
def db_session():
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db_session):
    def _override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def admin_headers(db_session):
    admin_user = db_session.query(User).filter(User.username == "admin").first()
    token = create_access_token(subject=admin_user.id)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_token(db_session):
    admin_user = db_session.query(User).filter(User.username == "admin").first()
    return create_access_token(subject=admin_user.id)
