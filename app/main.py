from __future__ import annotations

import json
import os
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from threading import Lock

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .engine import Flow, run_closed_loop


ROOT = Path(__file__).parent
DB_PATH = os.getenv("CLADS_DB", str(ROOT.parent / "clads.db"))
MODE = os.getenv("CLADS_MODE", "dry-run")
db_lock = Lock()


def connect() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    db.row_factory = sqlite3.Row
    return db


def init_db() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL, source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL, attack_type TEXT NOT NULL,
            risk_score REAL NOT NULL, action TEXT NOT NULL,
            action_status TEXT NOT NULL, payload TEXT NOT NULL
        )""")


class FlowInput(BaseModel):
    source_ip: str = Field(min_length=3, max_length=45)
    destination_ip: str = Field(min_length=3, max_length=45)
    destination_port: int = Field(ge=1, le=65535)
    protocol: str = Field(default="TCP", max_length=8)
    packets: int = Field(default=120, ge=1, le=10_000_000)
    bytes: int = Field(default=96_000, ge=1, le=10_000_000_000)
    duration_ms: int = Field(default=850, ge=1, le=86_400_000)
    attack_type: str = "benign"

    @field_validator("attack_type")
    @classmethod
    def valid_attack(cls, value: str) -> str:
        allowed = {"benign", "port_scan", "brute_force", "web_attack", "botnet", "ddos"}
        if value not in allowed:
            raise ValueError(f"must be one of: {', '.join(sorted(allowed))}")
        return value


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="CLADS API",
    version="1.0.0",
    description="Closed-loop autonomous cyber-defense research MVP",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "mode": MODE, "version": app.version}


@app.post("/api/simulate", status_code=201)
def simulate(data: FlowInput):
    with db_lock, connect() as db:
        count = db.execute(
            "SELECT COUNT(*) FROM events WHERE source_ip = ?", (data.source_ip,)
        ).fetchone()[0]
        result = run_closed_loop(Flow(**data.model_dump()), count)
        cursor = db.execute(
            """INSERT INTO events
            (created_at, source_ip, destination_ip, attack_type, risk_score, action, action_status, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (result["timestamp"], data.source_ip, data.destination_ip, data.attack_type,
             result["risk_score"], result["action"], result["action_status"], json.dumps(result)),
        )
        db.commit()
        result["id"] = cursor.lastrowid
    return result


@app.get("/api/events")
def events(limit: int = 50):
    limit = max(1, min(limit, 200))
    with connect() as db:
        rows = db.execute("SELECT payload, id FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [{**json.loads(row["payload"]), "id": row["id"]} for row in rows]


@app.get("/api/metrics")
def metrics():
    with connect() as db:
        row = db.execute("""SELECT COUNT(*) total,
            COALESCE(AVG(risk_score), 0) average_risk,
            SUM(CASE WHEN risk_score >= 70 THEN 1 ELSE 0 END) critical,
            COUNT(DISTINCT source_ip) sources FROM events""").fetchone()
    return {"total_events": row["total"], "average_risk": round(row["average_risk"], 1),
            "critical_events": row["critical"] or 0, "unique_sources": row["sources"]}


@app.post("/api/actions/{event_id}/approve")
def approve(event_id: int):
    if MODE != "dry-run":
        raise HTTPException(409, "Live enforcement is not available in the hosted research build")
    with db_lock, connect() as db:
        row = db.execute("SELECT payload FROM events WHERE id = ?", (event_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Event not found")
        payload = json.loads(row["payload"])
        payload["action_status"] = "approved_dry_run"
        db.execute("UPDATE events SET action_status = ?, payload = ? WHERE id = ?",
                   (payload["action_status"], json.dumps(payload), event_id))
        db.commit()
    return {"id": event_id, "status": payload["action_status"]}

