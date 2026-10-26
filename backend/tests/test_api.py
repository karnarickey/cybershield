from datetime import datetime, timezone


def test_auth_me_and_invalid_login(client):
    assert client.get("/api/v1/auth/me").status_code == 401
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"}).status_code == 401
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "test-password-long"})
    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"
    assert response.json()["user"]["username"] == "admin"
    headers = {"Authorization": f"Bearer {response.json()['access_token']}"}
    assert client.get("/api/v1/auth/me", headers=headers).json()["role"] == "admin"


def test_login_throttles_repeated_bad_passwords(client):
    for _ in range(5):
        response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
        assert response.status_code == 401
    limited = client.post("/api/v1/auth/login", json={"username": "admin", "password": "test-password-long"})
    assert limited.status_code == 429
    assert int(limited.headers["retry-after"]) > 0


def test_incident_crud_filters_timeline_and_roles(client, admin_headers, viewer_headers):
    created = client.post("/api/v1/incidents", headers=admin_headers, json={
        "title": "Synthetic test alert", "description": "Example", "severity": "high",
        "status": "triaged", "priority": "critical", "reporter": "analyst@example.test",
        "affected_asset": "WS-11", "source_ip": "192.0.2.10", "destination_ip": "198.51.100.10",
        "detection_source": "EDR", "tags": ["test", "synthetic"], "simulated": True,
        "root_cause": "Test root cause", "business_impact": "No impact",
        "containment_notes": "Contained", "remediation_notes": "Remediated", "resolution_notes": "Resolved",
    })
    assert created.status_code == 201
    incident = created.json()
    assert incident["status"] == "triaged"
    assert incident["tags"] == ["test", "synthetic"]
    assert incident["source_ip"] == "192.0.2.10"
    updated = client.patch(f"/api/v1/incidents/{incident['id']}", headers=admin_headers, json={
        "status": "eradication", "tags": ["updated", "response"],
    })
    assert updated.json()["status"] == "eradication"
    assert updated.json()["tags"] == ["updated", "response"]
    incident_id = incident["id"]
    listing = client.get("/api/v1/incidents?severity=high&page=1&page_size=5", headers=viewer_headers)
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert client.get(f"/api/v1/incidents/{incident_id}", headers=viewer_headers).status_code == 200
    event = client.post(f"/api/v1/incidents/{incident_id}/timeline", headers=admin_headers, json={
        "event_type": "note", "description": "Analyst reviewed alert",
    })
    assert event.status_code == 201
    assert len(client.get(f"/api/v1/incidents/{incident_id}/timeline", headers=viewer_headers).json()) == 3
    assert client.post("/api/v1/incidents", headers=viewer_headers, json={"title": "forbidden"}).status_code == 403


def test_incident_date_filters_and_sort_parameters(client, admin_headers):
    records = [
        {"title": "Old critical", "severity": "critical"},
        {"title": "Mid low", "severity": "low"},
        {"title": "Recent high", "severity": "high"},
    ]
    for record in records:
        response = client.post("/api/v1/incidents", headers=admin_headers, json=record)
        assert response.status_code == 201

    endpoint = "/api/v1/incidents"
    default_order = client.get(endpoint, headers=admin_headers).json()["items"]
    assert [item["title"] for item in default_order] == ["Recent high", "Mid low", "Old critical"]
    severity_order = client.get(f"{endpoint}?sort_by=severity&sort_order=asc", headers=admin_headers).json()["items"]
    assert [item["severity"] for item in severity_order] == ["critical", "high", "low"]
    severity_descending = client.get(f"{endpoint}?sort_by=severity&sort_order=desc", headers=admin_headers).json()["items"]
    assert [item["severity"] for item in severity_descending] == ["low", "high", "critical"]
    updated_ascending = client.get(f"{endpoint}?sort_by=updated_at&sort_order=asc", headers=admin_headers).json()["items"]
    assert [item["title"] for item in updated_ascending] == ["Old critical", "Mid low", "Recent high"]
    current_date = datetime.now(timezone.utc).date().isoformat()
    filtered = client.get(
        f"{endpoint}?date_from={current_date}&date_to={current_date}&sort_by=created_at&sort_order=asc",
        headers=admin_headers,
    ).json()
    assert filtered["total"] == 3
    assert [item["title"] for item in filtered["items"]] == ["Old critical", "Mid low", "Recent high"]
    assert client.get(f"{endpoint}?sort_by=title", headers=admin_headers).status_code == 422
    assert client.get(f"{endpoint}?sort_order=sideways", headers=admin_headers).status_code == 422
    assert client.get(f"{endpoint}?date_from=2026-10-03&date_to=2026-10-01", headers=admin_headers).status_code == 422
    assert client.get(f"{endpoint}?date_from=not-a-date", headers=admin_headers).status_code == 422
    assert client.get(f"{endpoint}?date_to=2026-10-03T00:00:00", headers=admin_headers).status_code == 422


def test_evidence_ioc_validation_deduplication_and_analytics(client, admin_headers):
    incident = client.post("/api/v1/incidents", headers=admin_headers, json={"title": "IOC test"}).json()
    evidence = client.post("/api/v1/evidence", headers=admin_headers, json={
        "incident_id": incident["id"], "label": "PCAP record", "source": "sensor-1", "reference": "vault://item/7",
    })
    assert evidence.status_code == 201
    assert "file" not in evidence.json()
    ioc = {"indicator_type": "ip", "value": "2001:4860:4860::8888", "incident_id": incident["id"]}
    assert client.post("/api/v1/indicators", headers=admin_headers, json=ioc).status_code == 201
    assert client.post("/api/v1/indicators", headers=admin_headers, json=ioc).status_code == 409
    assert client.post("/api/v1/indicators", headers=admin_headers, json={"indicator_type": "ip", "value": "not-an-ip"}).status_code == 422
    email_ioc = {"indicator_type": "email", "value": "SOC.Alert@Example.test"}
    email_created = client.post("/api/v1/indicators", headers=admin_headers, json=email_ioc)
    assert email_created.status_code == 201
    assert email_created.json()["value"] == "soc.alert@example.test"
    assert client.post("/api/v1/indicators", headers=admin_headers, json={
        "indicator_type": "email", "value": "not-an-email",
    }).status_code == 422
    assert client.get("/api/v1/dashboard", headers=admin_headers).json()["total_incidents"] == 1
    assert client.get("/api/v1/analytics", headers=admin_headers).status_code == 200


def test_report_escapes_markup_and_imports_json(client, admin_headers):
    incident = client.post("/api/v1/incidents", headers=admin_headers, json={
        "title": "<script>alert(1)</script>", "simulated": True, "business_impact": "<img src=x>",
    }).json()
    client.post("/api/v1/indicators", headers=admin_headers, json={
        "indicator_type": "domain", "value": "bad.example.test", "incident_id": incident["id"],
    })
    client.post("/api/v1/indicators", headers=admin_headers, json={
        "indicator_type": "url", "value": "https://example.test/?q=<script>alert(1)</script>", "incident_id": incident["id"],
    })
    report = client.get(f"/api/v1/reports/{incident['id']}", headers=admin_headers)
    assert report.status_code == 200
    assert "<script>" not in report.text
    assert "SIMULATED / SYNTHETIC INCIDENT" in report.text
    assert "<img src=x>" not in report.text
    assert "Associated indicators of compromise" in report.text
    assert "bad.example.test" in report.text
    assert "https://example.test/?q=&lt;script&gt;alert(1)&lt;/script&gt;" in report.text
    assert any(entry["action"] == "report.view" for entry in client.get("/api/v1/audit", headers=admin_headers).json())
    imported = client.post("/api/v1/import/alerts", headers=admin_headers, files={
        "file": ("alerts.json", '[{"source_system":"sensor-a","source_id":"evt-100","timestamp":"2026-09-22T12:30:00Z","title":"Imported alert","severity":"low"},{"title":"Bad alert","severity":"urgent"}]', "application/json")
    })
    assert imported.status_code == 200
    assert imported.json()["imported"] == 1
    assert imported.json()["skipped"] == 1
    assert client.get("/api/v1/incidents", headers=admin_headers).json()["total"] == 1
    queue = client.get("/api/v1/import/alerts", headers=admin_headers)
    assert queue.status_code == 200
    assert queue.json()["total"] == 1
    alert = queue.json()["items"][0]
    assert alert["source_system"] == "sensor-a"
    assert alert["source_id"] == "evt-100"
    assert alert["source_timestamp"].startswith("2026-09-22T12:30:00")
    assert alert["review_status"] == "pending"
    assert alert["payload"]["title"] == "Imported alert"


def test_import_idempotence_csv_promotion_and_audit(client, admin_headers, viewer_headers):
    csv_data = (
        "source_system,source_id,occurred_at,title,severity,status\n"
        "sensor-b,alert-8,2026-09-23T10:00:00Z,CSV alert,high,triaged\n"
    )
    first = client.post("/api/v1/import/alerts", headers=admin_headers, files={
        "file": ("alerts.csv", csv_data, "text/csv"),
    })
    repeated = client.post("/api/v1/import/alerts", headers=admin_headers, files={
        "file": ("alerts.csv", csv_data, "text/csv"),
    })
    assert first.json() == {"imported": 1, "skipped": 0, "errors": []}
    assert repeated.json() == {"imported": 0, "skipped": 1, "errors": []}
    assert client.get("/api/v1/incidents", headers=admin_headers).json()["total"] == 0
    assert client.post("/api/v1/import/alerts/1/promote", headers=viewer_headers).status_code == 403
    promoted = client.post("/api/v1/import/alerts/1/promote", headers=admin_headers)
    assert promoted.status_code == 201
    assert promoted.json()["title"] == "CSV alert"
    assert promoted.json()["status"] == "triaged"
    assert client.post("/api/v1/import/alerts/1/promote", headers=admin_headers).status_code == 409
    queue = client.get("/api/v1/import/alerts?review_status=promoted", headers=admin_headers).json()
    assert queue["total"] == 1
    assert queue["items"][0]["promoted_incident_id"] == promoted.json()["id"]
    timeline = client.get(f"/api/v1/incidents/{promoted.json()['id']}/timeline", headers=admin_headers).json()
    assert timeline[0]["event_type"] == "alert_promoted"
    actions = {entry["action"] for entry in client.get("/api/v1/audit", headers=admin_headers).json()}
    assert "alerts.import" in actions
    assert "alerts.promote" in actions


def test_import_failure_audits_without_raw_alert_values(client, admin_headers):
    secret_text = "SensitiveMarker-DO-NOT-LOG"
    response = client.post("/api/v1/import/alerts", headers=admin_headers, files={
        "file": ("alerts.json", f'[{{"title":"{secret_text}","severity":"not-a-severity"}}]', "application/json"),
    })
    assert response.status_code == 200
    assert response.json()["imported"] == 0
    assert response.json()["skipped"] == 1
    audit_entries = client.get("/api/v1/audit", headers=admin_headers).json()
    import_audit = next(entry for entry in audit_entries if entry["action"] == "alerts.import.failed")
    assert secret_text not in import_audit["details"]
    assert secret_text not in response.text
    malformed = client.post("/api/v1/import/alerts", headers=admin_headers, files={
        "file": ("alerts.json", "{bad json", "application/json"),
    })
    assert malformed.status_code == 400
    audit_entries = client.get("/api/v1/audit", headers=admin_headers).json()
    assert any(entry["action"] == "alerts.import.failed" and "invalid_document" in entry["details"] for entry in audit_entries)


def test_metadata_hash_verification_audits_result(client, admin_headers):
    incident = client.post("/api/v1/incidents", headers=admin_headers, json={"title": "Hash verify"}).json()
    digest = "a" * 64
    evidence = client.post("/api/v1/evidence", headers=admin_headers, json={
        "incident_id": incident["id"], "label": "Metadata reference", "source": "vault", "sha256": digest,
    }).json()
    base = f"/api/v1/evidence/{evidence['id']}/verify-hash"
    verified = client.post(base, headers=admin_headers, json={"sha256": digest.upper()})
    mismatch = client.post(base, headers=admin_headers, json={"sha256": "b" * 64})
    assert verified.json() == {"evidence_id": evidence["id"], "has_recorded_hash": True, "matches": True}
    assert mismatch.json()["matches"] is False
    assert client.post(base, headers=admin_headers, json={"sha256": "bad"}).status_code == 422
    audit = client.get("/api/v1/audit", headers=admin_headers).json()
    results = [row["details"] for row in audit if row["action"] == "evidence.hash_verify"]
    assert any("matches=True" in result for result in results)
    assert any("matches=False" in result for result in results)


def test_all_requested_workflow_statuses_validate(client, admin_headers):
    statuses = ["new", "triaged", "investigating", "containment", "eradication", "recovery", "resolved", "closed"]
    for status in statuses:
        response = client.post("/api/v1/incidents", headers=admin_headers, json={"title": f"status-{status}", "status": status})
        assert response.status_code == 201
        assert response.json()["status"] == status
    for legacy_status in ("open", "contained"):
        response = client.post("/api/v1/incidents", headers=admin_headers, json={
            "title": f"legacy-status-{legacy_status}", "status": legacy_status,
        })
        assert response.status_code == 201


def test_logout_and_admin_only_delete(client, admin_headers, viewer_headers):
    incident = client.post("/api/v1/incidents", headers=admin_headers, json={"title": "delete check"}).json()
    assert client.delete(f"/api/v1/incidents/{incident['id']}", headers=viewer_headers).status_code == 403
    assert client.delete(f"/api/v1/incidents/{incident['id']}", headers=admin_headers).status_code == 204
    assert client.post("/api/v1/auth/logout", headers=admin_headers).status_code == 204
