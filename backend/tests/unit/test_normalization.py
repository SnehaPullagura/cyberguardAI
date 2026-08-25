from app.normalization.normalizer import normalizer


def test_syslog_ssh_failure_parsing():
    raw_log = "Failed password for invalid user root from 192.168.1.100 port 54321 ssh2"
    event = normalizer.normalize(raw_log, source_type_hint="syslog")

    assert event.source_type == "syslog"
    assert event.category == "authentication"
    assert event.action == "login_failed"
    assert event.severity == "high"
    assert event.source.ip == "192.168.1.100"
    assert event.source.user == "root"


def test_webserver_sqli_parsing():
    raw_log = '10.0.0.5 - - [25/Aug/2026:10:00:00 +0000] "GET /products?id=1%20UNION%20SELECT%20username%20from%20users HTTP/1.1" 200 450'
    event = normalizer.normalize(raw_log, source_type_hint="nginx")

    assert event.source_type == "nginx"
    assert event.category == "network"
    assert event.action == "sql_injection_attempt"
    assert event.severity == "critical"
    assert event.source.ip == "10.0.0.5"


def test_winevent_parsing():
    raw_json = '{"EventID": 4625, "Computer": "DC-01", "EventData": {"TargetUserName": "admin", "IpAddress": "172.16.0.50"}}'
    event = normalizer.normalize(raw_json, source_type_hint="winevent")

    assert event.source_type == "winevent"
    assert event.category == "authentication"
    assert event.action == "login_failed"
    assert event.severity == "high"
    assert event.source.user == "admin"
    assert event.source.ip == "172.16.0.50"
