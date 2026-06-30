from __future__ import annotations

import hashlib
import math
from dataclasses import asdict, dataclass
from datetime import datetime, timezone


ATTACK_WEIGHTS = {
    "benign": 0.08,
    "port_scan": 0.70,
    "brute_force": 0.78,
    "web_attack": 0.82,
    "botnet": 0.91,
    "ddos": 0.95,
}


@dataclass(slots=True)
class Flow:
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    packets: int
    bytes: int
    duration_ms: int
    attack_type: str = "benign"


def _jitter(flow: Flow) -> float:
    value = f"{flow.source_ip}:{flow.destination_ip}:{flow.destination_port}"
    return int(hashlib.sha256(value.encode()).hexdigest()[:4], 16) / 65535


def run_closed_loop(flow: Flow, previous_events: int = 0) -> dict:
    """Run the five CLADS agents using an explainable research baseline.

    This is intentionally deterministic. It is a functioning control-loop baseline,
    not a claim that the paper's future GraphSAGE or PPO models are trained.
    """
    volume = min(1.0, math.log1p(flow.packets + flow.bytes / 1000) / 10)
    detector = min(0.99, ATTACK_WEIGHTS.get(flow.attack_type, 0.55) * 0.78 + volume * 0.22)
    graph_context = min(0.99, detector * 0.62 + min(previous_events, 8) * 0.045 + _jitter(flow) * 0.08)
    risk = round((detector * 0.55 + graph_context * 0.45) * 100, 1)

    if risk >= 85:
        action, status = "isolate_host", "pending_approval"
    elif risk >= 70:
        action, status = "block_source", "pending_approval"
    elif risk >= 45:
        action, status = "rate_limit", "simulated"
    else:
        action, status = "observe", "simulated"

    reward = round((risk / 100) - (0.25 if action == "isolate_host" else 0.08), 3)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "flow": asdict(flow),
        "detector_score": round(detector, 3),
        "graph_score": round(graph_context, 3),
        "risk_score": risk,
        "action": action,
        "action_status": status,
        "reward": reward,
        "agent_trace": [
            {"agent": "Detection", "result": f"flow confidence {detector:.3f}"},
            {"agent": "Graph", "result": f"context score {graph_context:.3f}"},
            {"agent": "Decision", "result": f"selected {action} at risk {risk:.1f}"},
            {"agent": "Response", "result": status.replace("_", " ")},
            {"agent": "Learning", "result": f"feedback reward {reward:.3f}"},
        ],
    }

