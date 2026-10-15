import os
import requests
from flask import Flask, jsonify, render_template, request

# Import FalkorDB safely so the app still starts (in demo mode) even if the
# library or database is unavailable on the hosting platform.
try:
    from falkordb import FalkorDB
except Exception:  # pragma: no cover
    FalkorDB = None

app = Flask(__name__)

APP_VERSION = "v5-test"

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "6379"))
GRAPH_NAME = "ChainGuard"
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")


def _resolve_demo_mode():
    """
    DEMO_MODE=true  -> demo mode
    DEMO_MODE=false -> live mode
    not set         -> demo mode automatically when running on Render
                       (Render always sets the RENDER env variable),
                       live mode on your own laptop.
    """
    raw = os.getenv("DEMO_MODE")
    if raw is not None and raw.strip() != "":
        return raw.strip().strip('"').strip("'").lower() in ("true", "1", "yes", "on")
    return bool(os.getenv("RENDER"))


DEMO_MODE = _resolve_demo_mode()


# ---------------------------------------------------------------------------
# Fictional demo data (used only for demonstrating the interface)
# ---------------------------------------------------------------------------
DEMO_ENTITIES = [
    {"id": "user_1", "name": "Aarav Sharma", "kind": "user", "risk": None, "detail": "Finance"},
    {"id": "user_2", "name": "Priya Reddy", "kind": "user", "risk": None, "detail": "Engineering"},
    {"id": "user_3", "name": "Rohan Mehta", "kind": "user", "risk": None, "detail": "Finance"},
    {"id": "user_4", "name": "Meera Iyer", "kind": "user", "risk": None, "detail": "Engineering"},
    {"id": "ip_1", "name": "185.199.110.42", "kind": "ip", "risk": None, "detail": "External (fictional demo association; not a verdict)"},
    {"id": "ip_2", "name": "192.168.1.10", "kind": "ip", "risk": None, "detail": "Internal"},
    {"id": "ip_3", "name": "203.0.113.77", "kind": "ip", "risk": None, "detail": "Reserved documentation/demo range"},
    {"id": "ip_4", "name": "198.51.100.24", "kind": "ip", "risk": None, "detail": "Reserved documentation/demo range"},
    {"id": "device_1", "name": "Unknown-Laptop-17", "kind": "device", "risk": None, "detail": "Unrecognized"},
    {"id": "device_2", "name": "Office-Laptop-02", "kind": "device", "risk": None, "detail": "Managed"},
    {"id": "device_3", "name": "Unmanaged-Workstation-09", "kind": "device", "risk": None, "detail": "Unmanaged"},
    {"id": "device_4", "name": "Managed-Laptop-14", "kind": "device", "risk": None, "detail": "Managed"},
    {"id": "event_1", "name": "Unusual login", "kind": "event", "risk": "HIGH", "detail": "Fictional demo signal: unfamiliar device and external IP.", "timestamp": "2026-10-15 02:14 UTC"},
    {"id": "event_2", "name": "Normal office login", "kind": "event", "risk": "LOW", "detail": "Fictional demo signal: internal IP and managed device.", "timestamp": "2026-10-15 09:05 UTC"},
    {"id": "event_3", "name": "Repeated failed logins", "kind": "event", "risk": "HIGH", "detail": "Fictional demo signal: several failed attempts from an external IP.", "timestamp": "2026-10-15 03:42 UTC"},
    {"id": "event_4", "name": "Unusual access time", "kind": "event", "risk": "MEDIUM", "detail": "Fictional demo signal: access outside the usual demo schedule.", "timestamp": "2026-10-15 23:18 UTC"},
    {"id": "dept_1", "name": "Finance", "kind": "department", "risk": None, "detail": "Business unit"},
    {"id": "dept_2", "name": "Engineering", "kind": "department", "risk": None, "detail": "Business unit"},
]

DEMO_EDGES = [
    {"source": "user_1", "label": "GENERATED", "target": "event_1"},
    {"source": "event_1", "label": "FROM_IP", "target": "ip_1"},
    {"source": "event_1", "label": "ON_DEVICE", "target": "device_1"},
    {"source": "user_2", "label": "GENERATED", "target": "event_2"},
    {"source": "event_2", "label": "FROM_IP", "target": "ip_2"},
    {"source": "event_2", "label": "ON_DEVICE", "target": "device_2"},
    {"source": "user_3", "label": "GENERATED", "target": "event_3"},
    {"source": "event_3", "label": "FROM_IP", "target": "ip_3"},
    {"source": "event_3", "label": "ON_DEVICE", "target": "device_3"},
    {"source": "user_4", "label": "GENERATED", "target": "event_4"},
    {"source": "event_4", "label": "FROM_IP", "target": "ip_4"},
    {"source": "event_4", "label": "ON_DEVICE", "target": "device_4"},
    {"source": "user_1", "label": "MEMBER_OF", "target": "dept_1"},
    {"source": "user_2", "label": "MEMBER_OF", "target": "dept_2"},
    {"source": "user_3", "label": "MEMBER_OF", "target": "dept_1"},
    {"source": "user_4", "label": "MEMBER_OF", "target": "dept_2"},
]

DEMO_FINDINGS = [
    {
        "user": "Aarav Sharma", "event": "Unusual login", "ip": "185.199.110.42",
        "device": "Unknown-Laptop-17", "risk": "HIGH",
        "reason": "Fictional demo signal: login used an unfamiliar device and an external IP.",
        "timestamp": "2026-10-15 02:14 UTC",
        "recommendation": "Verify the login with the user, review authentication logs, and confirm device ownership.",
        "notice": "Synthetic demo data. This is not proof of an attack.",
    },
    {
        "user": "Rohan Mehta", "event": "Repeated failed logins", "ip": "203.0.113.77",
        "device": "Unmanaged-Workstation-09", "risk": "HIGH",
        "reason": "Fictional demo signal: several failed attempts were observed from a reserved documentation IP range.",
        "timestamp": "2026-10-15 03:42 UTC",
        "recommendation": "Review authentication logs and verify the activity before taking action.",
        "notice": "Synthetic demo data. This is not proof of an attack.",
    },
    {
        "user": "Meera Iyer", "event": "Unusual access time", "ip": "198.51.100.24",
        "device": "Managed-Laptop-14", "risk": "MEDIUM",
        "reason": "Fictional demo signal: access occurred outside the user's usual demo schedule.",
        "timestamp": "2026-10-15 23:18 UTC",
        "recommendation": "Review surrounding authentication events and continue monitoring.",
        "notice": "Synthetic demo data. This is not proof of an attack.",
    },
    {
        "user": "Priya Reddy", "event": "Normal office login", "ip": "192.168.1.10",
        "device": "Office-Laptop-02", "risk": "LOW",
        "reason": "Fictional demo signal: routine login from an internal IP and managed device.",
        "timestamp": "2026-10-15 09:05 UTC",
        "recommendation": "Continue routine monitoring and retain the event for audit history.",
        "notice": "Synthetic demo data. This is not proof of an attack.",
    },
]

RISK_PRIORITY = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


# ---------------------------------------------------------------------------
# Database helpers (live mode only)
# ---------------------------------------------------------------------------
def get_graph():
    db = FalkorDB(
        host=DB_HOST,
        port=DB_PORT,
        username=os.getenv("DB_USERNAME") or None,
        password=os.getenv("DB_PASSWORD") or None,
    )
    return db.select_graph(GRAPH_NAME)


def seed_graph():
    """Seed FalkorDB with fictional, repeatable demonstration data."""
    graph = get_graph()
    for entity in DEMO_ENTITIES:
        params = {
            "id": entity["id"],
            "kind": entity["kind"],
            "name": entity["name"],
            "detail": entity.get("detail") or "",
            "risk": entity.get("risk"),
            "timestamp": entity.get("timestamp"),
            "reason": None,
        }
        if entity["kind"] == "event":
            finding = next((f for f in DEMO_FINDINGS if f["event"] == entity["name"]), None)
            if finding:
                params["reason"] = finding["reason"]

        query = (
            "MERGE (n:Entity {id: $id}) "
            "SET n.kind = $kind, n.name = $name, n.detail = $detail"
        )
        if params["risk"]:
            query += ", n.risk = $risk"
        if params["timestamp"]:
            query += ", n.timestamp = $timestamp"
        if params["reason"]:
            query += ", n.reason = $reason"
        graph.query(query, params)

    for edge in DEMO_EDGES:
        # Relationship labels cannot be parameterised; these are fixed developer values.
        graph.query(
            "MATCH (a:Entity {id: $src}), (b:Entity {id: $dst}) "
            "MERGE (a)-[:" + edge["label"] + "]->(b)",
            {"src": edge["source"], "dst": edge["target"]},
        )


def demo_paths():
    by_id = {entity["id"]: entity for entity in DEMO_ENTITIES}
    paths = []
    for edge in DEMO_EDGES:
        event = by_id.get(edge["source"])
        connected = by_id.get(edge["target"])
        if (
            not event
            or event.get("kind") != "event"
            or not connected
            or connected.get("kind") not in ("ip", "device")
        ):
            continue
        user_edge = next(
            (i for i in DEMO_EDGES if i["target"] == event["id"] and i["label"] == "GENERATED"),
            None,
        )
        if not user_edge:
            continue
        user = by_id[user_edge["source"]]
        finding = next((i for i in DEMO_FINDINGS if i["event"] == event["name"]), {})
        paths.append({
            "user": {"id": user["id"], "name": user["name"]},
            "event": {
                "id": event["id"], "name": event["name"],
                "risk": event.get("risk") or "UNKNOWN",
                "reason": finding.get("reason", event.get("detail", "")),
                "timestamp": event.get("timestamp"),
            },
            "relationship_from_user": "GENERATED",
            "relationship_to_entity": edge["label"],
            "connected_entity": {
                "id": connected["id"], "name": connected["name"],
                "kind": connected["kind"], "detail": connected.get("detail"),
            },
            "notice": "Synthetic demo data. A graph connection is a lead for review, not proof of malicious activity.",
        })
    paths.sort(key=lambda item: RISK_PRIORITY.get(item["event"]["risk"], 3))
    return paths


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/version")
def version():
    """Quick check of which code and mode is actually running."""
    return jsonify({"version": APP_VERSION, "demo_mode": DEMO_MODE})


@app.route("/api/health")
def health():
    if DEMO_MODE:
        return jsonify({
            "status": "ok", "demo_mode": True, "database": "demo_mode",
            "message": "Using synthetic demonstration data; no live database is connected.",
        }), 200
    try:
        result = get_graph().query("RETURN 'connected' AS status")
        status = result.result_set[0][0] if result.result_set else "connected"
        return jsonify({"status": "ok", "database": status}), 200
    except Exception:
        app.logger.exception("Health check failed")
        return jsonify({
            "status": "error", "database": "unavailable",
            "message": "FalkorDB is not reachable. Set DEMO_MODE=true or start the database.",
        }), 503


@app.route("/api/seed", methods=["POST", "GET"])
def seed():
    if DEMO_MODE:
        return jsonify({
            "status": "ok", "demo_mode": True,
            "message": "Fictional demo data is ready. No database write was needed.",
        })
    try:
        seed_graph()
        return jsonify({"status": "ok", "message": "Fictional demo data loaded into FalkorDB."})
    except Exception:
        app.logger.exception("Could not seed graph")
        return jsonify({"error": "Could not seed FalkorDB. Check that the database is running."}), 503


@app.route("/api/graph")
def graph_data():
    if DEMO_MODE:
        return jsonify({
            "nodes": DEMO_ENTITIES, "edges": DEMO_EDGES,
            "demo_mode": True, "message": "Synthetic demo graph data",
        })
    try:
        graph = get_graph()
        node_result = graph.query(
            "MATCH (n:Entity) RETURN n.id, n.name, n.kind, n.risk, n.detail, n.timestamp"
        )
        edge_result = graph.query(
            "MATCH (a:Entity)-[r]->(b:Entity) RETURN a.id, type(r), b.id"
        )
        nodes = [
            {"id": r[0], "name": r[1], "kind": r[2], "risk": r[3], "detail": r[4], "timestamp": r[5]}
            for r in node_result.result_set
        ]
        edges = [
            {"source": r[0], "label": r[1], "target": r[2]}
            for r in edge_result.result_set
        ]
        return jsonify({"nodes": nodes, "edges": edges})
    except Exception:
        app.logger.exception("Could not load graph")
        return jsonify({"error": "Could not load the graph from FalkorDB."}), 503


@app.route("/api/investigate")
def investigate():
    if DEMO_MODE:
        return jsonify({"findings": DEMO_FINDINGS, "demo_mode": True})
    try:
        result = get_graph().query("""
            MATCH (u:Entity {kind: 'user'})-[:GENERATED]->(e:Entity {kind: 'event'})
                  -[:FROM_IP]->(ip:Entity), (e)-[:ON_DEVICE]->(d:Entity)
            RETURN u.name, e.name, ip.name, d.name, e.risk, e.reason, e.timestamp
        """)
        findings = []
        for row in result.result_set:
            risk = row[4] or "UNKNOWN"
            if risk == "HIGH":
                rec = "Verify the login with the user, review authentication logs, and confirm device ownership."
            elif risk == "MEDIUM":
                rec = "Review surrounding authentication events and continue monitoring."
            else:
                rec = "Continue routine monitoring and retain the event for audit history."
            findings.append({
                "user": row[0], "event": row[1], "ip": row[2], "device": row[3],
                "risk": risk, "reason": row[5] or "No explanation available",
                "timestamp": row[6], "recommendation": rec,
                "notice": "Demo rule-based classification; investigate further before concluding an attack occurred.",
            })
        findings.sort(key=lambda item: RISK_PRIORITY.get(item["risk"], 3))
        return jsonify({"findings": findings})
    except Exception:
        app.logger.exception("Investigation failed")
        return jsonify({"error": "Investigation failed while querying FalkorDB."}), 503


@app.route("/api/investigate-paths")
def investigate_paths():
    if DEMO_MODE:
        paths = demo_paths()
        return jsonify({"path_count": len(paths), "paths": paths, "demo_mode": True})
    try:
        result = get_graph().query("""
            MATCH (u:Entity {kind: 'user'})-[:GENERATED]->(e:Entity {kind: 'event'})-[r]->(c:Entity)
            WHERE c.kind IN ['ip', 'device']
            RETURN u.id, u.name, e.id, e.name, e.risk, e.reason, e.timestamp,
                   type(r), c.id, c.name, c.kind, c.detail
        """)
        paths = []
        for row in result.result_set:
            paths.append({
                "user": {"id": row[0], "name": row[1]},
                "event": {
                    "id": row[2], "name": row[3], "risk": row[4] or "UNKNOWN",
                    "reason": row[5] or "No explanation available", "timestamp": row[6],
                },
                "relationship_from_user": "GENERATED",
                "relationship_to_entity": row[7],
                "connected_entity": {"id": row[8], "name": row[9], "kind": row[10], "detail": row[11]},
                "notice": "A graph connection is a lead for review, not proof of malicious activity.",
            })
        paths.sort(key=lambda item: RISK_PRIORITY.get(item["event"]["risk"], 3))
        return jsonify({"path_count": len(paths), "paths": paths})
    except Exception:
        app.logger.exception("Path investigation failed")
        return jsonify({
            "error": "Path investigation failed while querying FalkorDB.",
            "path_count": 0, "paths": [],
        }), 503


@app.route("/api/ai-explain", methods=["POST"])
def ai_explain():
    data = request.get_json(silent=True) or {}
    question = str(data.get("question", "")).strip()
    if not question:
        return jsonify({"error": "Please provide a question."}), 400

    # Render cannot reach an Ollama model running on your laptop, so hosted
    # demo mode returns a transparent, rule-based explanation instead.
    if DEMO_MODE:
        answer = (
            "Demo-mode explanation (rule-based, not generated by a live language model):\n\n"
            "An unfamiliar device combined with an external IP can be worth reviewing because "
            "the combination may differ from a user's normal access pattern. It is not proof of "
            "an attack by itself. Confirm the user's activity, check authentication logs, compare "
            "device ownership and expected location, and review related events before taking action.\n\n"
            "This dashboard uses fictional sample identities and events. The IP/device links are "
            "illustrative investigation leads, not verified threat intelligence."
        )
        return jsonify({"answer": answer, "mode": "demo_rule_based", "demo_mode": True})

    prompt = (
        "You are ChainGuard AI, an assistant explaining security investigation data. "
        "Be concise, practical, and cautious. A graph connection is a lead, not proof of malicious activity. "
        "The dashboard may contain synthetic demo data. Do not claim an IP is malicious without evidence.\n\n"
        "User question: " + question
    )
    try:
        response = requests.post(
            OLLAMA_URL.rstrip("/") + "/api/generate",
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=120,
        )
        response.raise_for_status()
        result = response.json()
        return jsonify({"answer": str(result.get("response", "")).strip(), "mode": "local_ollama"})
    except requests.RequestException:
        app.logger.exception("Local AI request failed")
        return jsonify({
            "error": "Could not reach local Ollama. Start Ollama and confirm the model is installed, "
                     "or enable DEMO_MODE for hosted demo explanations."
        }), 503


if __name__ == "__main__":
    # Local development only. On Render, gunicorn starts the app instead.
    app.run(
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true",
        host="127.0.0.1",
        port=int(os.getenv("PORT", "5000")),
    )