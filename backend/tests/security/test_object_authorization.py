def test_invalid_object_id_access(client, admin_headers):
    # Alert non-existent ID
    res1 = client.get("/api/v1/alerts/non-existent-alert-id", headers=admin_headers)
    assert res1.status_code == 404

    # Incident non-existent ID
    res2 = client.get("/api/v1/incidents/non-existent-incident-id", headers=admin_headers)
    assert res2.status_code == 404

    # Event non-existent ID
    res3 = client.get("/api/v1/events/non-existent-event-id", headers=admin_headers)
    assert res3.status_code == 404
