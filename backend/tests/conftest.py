import os

import pytest
from fastapi.testclient import TestClient

# The test suite must configure its own signing key; the application has no fallback.
os.environ.setdefault("JWT_SECRET", "test-suite-only-signing-secret-with-enough-entropy-0123456789")

from app import main
from app.database import Base, make_engine
from app.models import User
from app.security import hash_password


@pytest.fixture()
def client():
    test_engine = make_engine("sqlite://")
    TestingSession = __import__("sqlalchemy.orm", fromlist=["sessionmaker"]).sessionmaker(
        bind=test_engine, autoflush=False, expire_on_commit=False
    )

    def override_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[main.get_db] = override_db
    Base.metadata.create_all(test_engine)
    with TestClient(main.app) as test_client:
        with TestingSession() as db:
            db.add(User(username="admin", email="admin@example.test", password_hash=hash_password("test-password-long"), role="admin"))
            db.add(User(username="viewer", email="viewer@example.test", password_hash=hash_password("test-password-long"), role="viewer"))
            db.commit()
        yield test_client
    main.app.dependency_overrides.clear()
    Base.metadata.drop_all(test_engine)
    test_engine.dispose()


@pytest.fixture()
def admin_headers(client):
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "test-password-long"})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture()
def viewer_headers(client):
    response = client.post("/api/v1/auth/login", json={"username": "viewer", "password": "test-password-long"})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}
