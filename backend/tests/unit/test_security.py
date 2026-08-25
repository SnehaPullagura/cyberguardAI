from app.security.password import verify_password, get_password_hash
from app.security.auth import create_access_token, create_refresh_token, decode_token


def test_password_hashing():
    plain = "MySecretPassword123!"
    hashed = get_password_hash(plain)
    assert hashed != plain
    assert verify_password(plain, hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_jwt_token_flow():
    user_id = "test-user-123"
    access_token = create_access_token(user_id)
    refresh_token = create_refresh_token(user_id)

    access_payload = decode_token(access_token)
    assert access_payload.get("sub") == user_id
    assert access_payload.get("type") == "access"

    refresh_payload = decode_token(refresh_token)
    assert refresh_payload.get("sub") == user_id
    assert refresh_payload.get("type") == "refresh"
