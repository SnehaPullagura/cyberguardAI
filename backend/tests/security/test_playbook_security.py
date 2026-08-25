from app.response.action_registry import action_registry


def test_playbook_arbitrary_code_rejection():
    """Verify system explicitly denies arbitrary shell/code execution attempts."""
    dangerous_actions = [
        "rm -rf /",
        "import os; os.system('whoami')",
        "SELECT * FROM users",
        "exec('print(123)')",
    ]
    for act in dangerous_actions:
        assert action_registry.is_allowlisted(act) is False


def test_playbook_rbac_protection(client):
    """Verify unauthenticated/unauthorized users cannot access or modify playbooks."""
    response = client.get("/api/v1/playbooks")
    assert response.status_code == 401

    post_res = client.post("/api/v1/playbooks", json={"name": "Malicious Playbook"})
    assert post_res.status_code == 401
