import pytest
from app.models import User, Role
from app.security.ws_ticket import create_ws_ticket, validate_and_consume_ws_ticket


def test_ws_ticket_generation_and_single_use_consumption(db_session):
    admin = db_session.query(User).filter(User.username == "admin").first()

    # 1. Generate short-lived ticket
    ticket = create_ws_ticket(admin)
    assert ticket.startswith("wst_")

    # 2. Consume ticket (First Attempt -> SUCCESS)
    data = validate_and_consume_ws_ticket(ticket)
    assert data is not None
    assert data["username"] == "admin"

    # 3. Consume ticket AGAIN (Second Attempt -> REJECTED, Single-Use Enforcement)
    second_attempt = validate_and_consume_ws_ticket(ticket)
    assert second_attempt is None
