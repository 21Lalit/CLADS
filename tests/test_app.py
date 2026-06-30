import os
import tempfile

os.environ["CLADS_DB"] = os.path.join(tempfile.gettempdir(), "clads-test.db")

from fastapi.testclient import TestClient
from app.main import app


def test_health_and_closed_loop():
    try:
        os.remove(os.environ["CLADS_DB"])
    except FileNotFoundError:
        pass
    with TestClient(app) as client:
        assert client.get("/api/health").json()["status"] == "ok"
        response = client.post("/api/simulate", json={
            "source_ip": "10.0.0.42", "destination_ip": "10.0.0.10",
            "destination_port": 443, "protocol": "TCP", "packets": 2000,
            "bytes": 1_600_000, "duration_ms": 850, "attack_type": "ddos"
        })
        assert response.status_code == 201
        result = response.json()
        assert result["risk_score"] >= 70
        assert len(result["agent_trace"]) == 5
        assert client.get("/api/metrics").json()["total_events"] == 1


def test_rejects_unknown_attack_type():
    with TestClient(app) as client:
        response = client.post("/api/simulate", json={
            "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
            "destination_port": 80, "attack_type": "unknown"
        })
        assert response.status_code == 422
