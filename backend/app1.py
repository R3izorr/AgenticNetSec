from fastapi import FastAPI, HTTPException
import json
from fastapi.middleware.cors import CORSMiddleware
import asyncio
from nw_agents.ParameterTuningAgent import ParameterTuningAgent
from nw_agents.ReportingAgent import ReportingAgent
from nw_agents.PerformanceMonitoringAgent import PerformanceMonitoringAgent
from nw_agents.SecurityAnalysisAgent import SecurityAnalysisAgent
from nw_agents.ChatAgent import ChatAgent
from appWebsocket import broadcaster, websocket_endpoint
from config import metrics_queue, attack_queue, reports_queue
from contextlib import asynccontextmanager
import logging
import datetime
from typing import Dict, Any, List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -------------------------------------------------------------------
# Central Controller: in-memory state (aggregation + memory + roles)
# -------------------------------------------------------------------

# Latest status per node (what we already had, but now richer)
node_statuses: Dict[str, Dict[str, Any]] = {}

# Short-term memory of recent events (for temporal reasoning)
event_timeline: List[Dict[str, Any]] = []
MAX_EVENTS = 500  # keep the most recent N events

# Correlated, system-wide view (who looks like attacker/victim/benign)
correlated_view: Dict[str, Any] = {
    "attackers": [],
    "victims": [],
    "benign": [],
    "last_updated": None,
    "description": "No reports received yet.",
}

def classify_role(report: Dict[str, Any]) -> str:
    """
    Heuristic to guess node role from the report.

    Tries to use explicit 'role' if present; otherwise uses threat_type,
    severity, and natural-language summary to label node as:
      'attacker', 'victim', 'benign', 'suspicious', or 'unknown'.
    """
    # If the node agent already told us the role, just trust it.
    explicit_role = report.get("role")
    if isinstance(explicit_role, str) and explicit_role:
        return explicit_role

    threat_type = (report.get("threat_type") or report.get("attack_type") or "").lower()
    severity = (report.get("severity") or report.get("risk_level") or "").lower()
    summary = (
        report.get("summary")
        or report.get("natural_language_summary")
        or ""
    ).lower()

    # Simple DDoS / flood heuristics
    if "ddos" in threat_type or "flood" in threat_type:
        if any(word in summary for word in ["outbound", "source", "attacker", "originating"]):
            return "attacker"
        if any(word in summary for word in ["inbound", "victim", "target", "flooded"]):
            return "victim"

    # Generic attack / suspicious traffic
    if any(w in threat_type for w in ["attack", "malicious", "suspicious"]):
        if any(w in summary for w in ["sending", "originating", "scanning", "probing"]):
            return "attacker"
        if any(w in summary for w in ["receiving", "targeted", "under attack"]):
            return "victim"
        return "suspicious"

    # Benign / normal traffic
    if any(w in threat_type for w in ["benign", "normal", "clean"]) or "no malicious" in summary:
        return "benign"

    # High-severity but unclear type → treat as suspicious
    if severity in ("high", "critical"):
        return "suspicious"

    return "unknown"


def update_memory_and_correlation(report: Dict[str, Any]) -> None:
    """
    Update:
      - node_statuses: latest report per node
      - event_timeline: short-term memory of events
      - correlated_view: attackers / victims / benign + description
    """
    node_ip = report.get("node_ip", "unknown")

    # Use report timestamp if present, otherwise now
    timestamp = report.get("timestamp") or datetime.datetime.utcnow().isoformat()

    threat_type = report.get("threat_type") or report.get("attack_type") or "unknown"
    severity = report.get("severity") or report.get("risk_level") or "unknown"
    summary = (
        report.get("summary")
        or report.get("natural_language_summary")
        or ""
    )

    role = classify_role(report)

    # 1) Update per-node latest status
    node_statuses[node_ip] = {
        "last_report": report,
        "last_seen": timestamp,
        "threat_type": threat_type,
        "severity": severity,
        "role": role,
        "summary": summary,
    }

    # 2) Append to short-term memory (timeline)
    event = {
        "node_ip": node_ip,
        "timestamp": timestamp,
        "threat_type": threat_type,
        "severity": severity,
        "role": role,
    }
    event_timeline.append(event)
    if len(event_timeline) > MAX_EVENTS:
        # keep only the last MAX_EVENTS
        del event_timeline[:-MAX_EVENTS]

    # 3) Recompute high-level, correlated view
    attackers = []
    victims = []
    benign = []

    for ip, status in node_statuses.items():
        r = status.get("role", "unknown")
        if r == "attacker":
            attackers.append(ip)
        elif r == "victim":
            victims.append(ip)
        else:
            benign.append(ip)

    if attackers or victims:
        description = (
            f"Suspected attackers: {attackers or ['none']}, "
            f"victims: {victims or ['none']}."
        )
    else:
        description = "No active coordinated threats detected."

    correlated_view["attackers"] = attackers
    correlated_view["victims"] = victims
    correlated_view["benign"] = benign
    correlated_view["last_updated"] = timestamp
    correlated_view["description"] = description

    logger.info(
        f"[Controller] Updated correlation view. "
        f"Attackers={attackers}, Victims={victims}, Benign={benign}"
    )

# -------------------------------------------------------------------
# FastAPI lifespan: start background agents + websocket broadcaster
# -------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting application (controller + local agent pipeline)...")

    performance_to_tuning_queue = asyncio.Queue()
    tuning_to_performance_queue = asyncio.Queue()
    performance_to_security_queue = asyncio.Queue()
    security_to_performance_queue = asyncio.Queue()
    security_to_report_queue = asyncio.Queue()

    # Expose queues / state to the app if frontend or other services need it
    app.state.performance_to_tuning_queue = performance_to_tuning_queue
    app.state.node_statuses = node_statuses
    app.state.event_timeline = event_timeline
    app.state.correlated_view = correlated_view

    # Local node-style pipeline (for micro-testbed / single-node use)
    performance_agent = PerformanceMonitoringAgent(
        metrics_queue,
        performance_to_tuning_queue,
        tuning_to_performance_queue,
        performance_to_security_queue,
        security_to_performance_queue,
    )

    tuning_agent = ParameterTuningAgent(
        performance_to_tuning_queue, tuning_to_performance_queue
    )

    security_agent = SecurityAnalysisAgent(
        performance_to_security_queue,
        security_to_performance_queue,
        attack_queue,
        security_to_report_queue,
    )

    reporting_agent = ReportingAgent(
        security_to_report_queue, reports_queue
    )

    # You can instantiate ChatAgent later when you need it
    app.state.chat_agent = ChatAgent

    # Start background tasks
    asyncio.create_task(performance_agent.run())
    asyncio.create_task(tuning_agent.run())
    asyncio.create_task(security_agent.run())
    asyncio.create_task(reporting_agent.run())
    asyncio.create_task(broadcaster())

    yield

    logger.info("Shutting down application...")


app = FastAPI(lifespan=lifespan)

# -------------------------------------------------------------------
# CORS + WebSocket wiring (unchanged)
# -------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # React app’s origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.websocket("/ws")(websocket_endpoint)

# -------------------------------------------------------------------
# Central Controller REST API
# -------------------------------------------------------------------

@app.post("/gcreport")
async def receive_report(report: Dict[str, Any]):
    """
    Node agents (or the offline analyzer) POST their structured report here.

    Expected at minimum:
      {
        "node_ip": "192.168.1.4",
        ... other fields from ReportingAgent ...
      }
    """
    logger.info(f"[Controller] Received report: {report}")

    node_ip = report.get("node_ip")
    if not node_ip:
        # Return proper HTTP 400 if node_ip is missing
        raise HTTPException(status_code=400, detail="node_ip is required")

    # Update aggregation, memory, and correlated view
    update_memory_and_correlation(report)

    role = node_statuses[node_ip]["role"]
    return {
        "message": f"Report for {node_ip} received",
        "role": role,
    }


@app.get("/gcstatuses")
async def get_statuses():
    """
    Return the latest status for each node.

    This is what powers per-node cards / tables in the dashboard.
    """
    return node_statuses


@app.get("/gccorrelation")
async def get_correlation():
    """
    Return the controller's current system-wide view:
      - suspected attackers
      - suspected victims
      - other benign/unknown nodes
      - last update time and a short description
    """
    return correlated_view


@app.get("/gctimeline")
async def get_timeline():
    """
    Return recent events as a short-term memory buffer.
    Can be used for timelines, attack animations, or debugging.
    """
    return event_timeline


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
