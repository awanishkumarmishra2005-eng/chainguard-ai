import os
import uuid
import requests
from flask import Flask, jsonify, render_template, request

from falkor_store import (
    FalkorConfigError,
    FalkorDependencyError,
    FalkorSettings,
    connect_graph,
)

app = Flask(__name__)
APP_VERSION = "v6-graph-agent"
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")
MAX_QUESTION_LENGTH = 1500
MAX_ANSWER_LENGTH = 5000
MAX_SESSION_LENGTH = 100


def _resolve_demo_mode():
    raw = os.getenv("DEMO_MODE")
    if raw is not None and raw.strip():
        return raw.strip().strip('"').strip("'").lower() in ("true", "1", "yes", "on")
    return False


def _resolve_flag(name, default=False):
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().strip('"').strip("'").lower() in ("true", "1", "yes", "on")


DEMO_MODE = _resolve_demo_mode()
GRAPH_WRITES_ENABLED = _resolve_flag("ALLOW_GRAPH_WRITES")

# Fictional sample data for demonstration only.
DEMO_ENTITIES = [
    {"id": "user_1", "name": "Aarav Sharma", "kind": "user", "risk": None, "detail": "Finance"},
    {"id": "user_2", "name": "Priya Reddy", "kind": "user", "risk": None, "detail": "Engineering"},
    {"id": "user_3", "name": "Rohan Mehta", "kind": "user", "risk": None, "detail": "Finance"},
    {"id": "user_4", "name": "Meera Iyer", "kind": "user", "risk": None, "detail": "Engineering"},
    {"id": "ip_1", "name": "185.199.110.42", "kind": "ip", "risk": None, "detail": "Fictional demo association; not a verdict"},
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
    {"user": "Aarav Sharma", "event": "Unusual login", "ip": "185.199.110.42",
     "device": "Unknown-Laptop-17", "risk": "HIGH",
     "reason": "Fictional demo signal: login used an unfamiliar device and an external IP.",
     "timestamp": "2026-10-15 02:14 UTC",
     "recommendation": "Verify the login with the user, review authentication logs, and confirm device ownership.",
     "notice": "Synthetic demo data. This is not proof of an attack."},
    {"user": "Rohan Mehta", "event": "Repeated failed logins", "ip": "203.0.113.77",
     "device": "Unmanaged-Workstation-09", "risk": "HIGH",
     "reason": "Fictional demo signal: several failed attempts were observed from a reserved documentation IP range.",
     "timestamp": "2026-10-15 03:42 UTC",
     "recommendation": "Review authentication logs and verify the activity before taking action.",
     "notice": "Synthetic demo data. This is not proof of an attack."},
    {"user": "Meera Iyer", "event": "Unusual access time", "ip": "198.51.100.24",
     "device": "Managed-Laptop-14", "risk": "MEDIUM",
     "reason": "Fictional demo signal: access occurred outside the user's usual demo schedule.",
     "timestamp": "2026-10-15 23:18 UTC",
     "recommendation": "Review surrounding authentication events and continue monitoring.",
     "notice": "Synthetic demo data. This is not proof of an attack."},
    {"user": "Priya Reddy", "event": "Normal office login", "ip": "192.168.1.10",
     "device": "Office-Laptop-02", "risk": "LOW",
     "reason": "Fictional demo signal: routine login from an internal IP and managed device.",
     "timestamp": "2026-10-15 09:05 UTC",
     "recommendation": "Continue routine monitoring and retain the event for audit history.",
     "notice": "Synthetic demo data. This is not proof of an attack."},
]
RISK_PRIORITY = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def get_graph():
    return connect_graph(FalkorSettings.from_env())


def graph_error_message(exc):
    """Return a safe error suitable for an API response or log entry."""

    if isinstance(exc, (FalkorConfigError, FalkorDependencyError)):
        return str(exc)
    return "FalkorDB is unavailable. Check the configured endpoint and network access."


def graph_status():
    """Probe the configured graph without changing its contents."""

    settings = FalkorSettings.from_env()
    result = connect_graph(settings).query("RETURN 'connected' AS status")
    status = result.result_set[0][0] if result.result_set else "connected"
    return settings, status


def seed_graph():
    """Seed FalkorDB with fictional, repeatable demonstration data."""
    graph = get_graph()
    for entity in DEMO_ENTITIES:
        params = {
            "id": entity["id"], "kind": entity["kind"], "name": entity["name"],
            "detail": entity.get("detail") or "", "risk": entity.get("risk"),
            "timestamp": entity.get("timestamp"), "reason": None,
        }
        if entity["kind"] == "event":
            finding = next((f for f in DEMO_FINDINGS if f["event"] == entity["name"]), None)
            if finding:
                params["reason"] = finding["reason"]
        query = "MERGE (n:Entity {id: $id}) SET n.kind = $kind, n.name = $name, n.detail = $detail"
        if params["risk"]:
            query += ", n.risk = $risk"
        if params["timestamp"]:
            query += ", n.timestamp = $timestamp"
        if params["reason"]:
            query += ", n.reason = $reason"
        graph.query(query, params)

    for edge in DEMO_EDGES:
        graph.query(
            "MATCH (a:Entity {id: $src}), (b:Entity {id: $dst}) "
            "MERGE (a)-[:" + edge["label"] + "]->(b)",
            {"src": edge["source"], "dst": edge["target"]},
        )


def demo_paths():
    by_id = {entity["id"]: entity for entity in DEMO_ENTITIES}
    paths = []
    for edge in DEMO_EDGES:
        event, connected = by_id.get(edge["source"]), by_id.get(edge["target"])
        if not event or event.get("kind") != "event" or not connected:
            continue
        if connected.get("kind") not in ("ip", "device"):
            continue
        user_edge = next((e for e in DEMO_EDGES
                          if e["target"] == event["id"] and e["label"] == "GENERATED"), None)
        if not user_edge:
            continue
        user = by_id[user_edge["source"]]
        finding = next((f for f in DEMO_FINDINGS if f["event"] == event["name"]), {})
        paths.append({
            "user": {"id": user["id"], "name": user["name"]},
            "event": {"id": event["id"], "name": event["name"],
                      "risk": event.get("risk") or "UNKNOWN",
                      "reason": finding.get("reason", event.get("detail", "")),
                      "timestamp": event.get("timestamp")},
            "relationship_from_user": "GENERATED",
            "relationship_to_entity": edge["label"],
            "connected_entity": {"id": connected["id"], "name": connected["name"],
                                 "kind": connected["kind"], "detail": connected.get("detail")},
            "notice": "Synthetic demo data. A graph connection is a lead, not proof of malicious activity.",
        })
    paths.sort(key=lambda item: RISK_PRIORITY.get(item["event"]["risk"], 3))
    return paths


def retrieve_graph_evidence(limit=60):
    result = get_graph().query("""
        MATCH (n:Entity)-[r]->(m:Entity)
        RETURN n.id, n.name, n.kind, n.risk, n.detail,
               type(r), m.id, m.name, m.kind
        LIMIT $limit
    """, {"limit": int(limit)})
    return [
        {"id": row[0], "name": row[1], "kind": row[2], "risk": row[3],
         "detail": row[4], "relationship": row[5], "connected_id": row[6],
         "connected_name": row[7], "connected_kind": row[8]}
        for row in result.result_set
    ]


def retrieve_session_memory(session_id, limit=5):
    result = get_graph().query("""
        MATCH (m:InvestigationMemory {session_id: $session_id})
        RETURN m.question, m.answer, m.created_at
        ORDER BY m.created_at DESC
        LIMIT $limit
    """, {"session_id": session_id, "limit": int(limit)})
    return [{"question": row[0], "answer": row[1], "created_at": row[2]}
            for row in result.result_set]


def save_session_memory(session_id, question, answer):
    get_graph().query("""
        CREATE (:InvestigationMemory {
            id: $id, session_id: $session_id,
            question: $question, answer: $answer,
            created_at: timestamp()
        })
    """, {"id": str(uuid.uuid4()), "session_id": session_id,
          "question": question[:MAX_QUESTION_LENGTH],
          "answer": answer[:MAX_ANSWER_LENGTH]})


def local_ollama_answer(prompt):
    response = requests.post(
        OLLAMA_URL.rstrip("/") + "/api/generate",
        json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
        timeout=120,
    )
    response.raise_for_status()
    return str(response.json().get("response", "")).strip()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/version")
def version():
    try:
        graph_config = FalkorSettings.from_env().public_summary()
        graph_config_error = None
    except FalkorConfigError as exc:
        graph_config = None
        graph_config_error = str(exc)
    return jsonify({
        "version": APP_VERSION, "demo_mode": DEMO_MODE,
        "graph_writes_enabled": GRAPH_WRITES_ENABLED,
        "demo_env_value": os.getenv("DEMO_MODE"),
        "graph_config": graph_config,
        "graph_config_error": graph_config_error,
        "ollama_url_configured": bool(OLLAMA_URL), "ollama_model": OLLAMA_MODEL,
    })


@app.route("/api/health")
def health():
    if DEMO_MODE:
        return jsonify({"status": "ok", "demo_mode": True, "database": "demo_mode",
                        "application": "ok", "graph": "demo_mode",
                        "message": "Synthetic demo data; no live database is connected."}), 200
    try:
        settings, status = graph_status()
        return jsonify({"status": "ok", "application": "ok", "graph": "ok",
                        "database": status, "graph_config": settings.public_summary()}), 200
    except Exception as exc:
        message = graph_error_message(exc)
        app.logger.warning("FalkorDB health check unavailable: %s", message)
        return jsonify({"status": "ok", "application": "ok", "graph": "unavailable",
                        "database": "unavailable", "message": message}), 200


@app.route("/api/seed", methods=["POST", "GET"])
def seed():
    if DEMO_MODE:
        return jsonify({"status": "ok", "demo_mode": True,
                        "message": "Fictional demo data is ready; no database write was needed."})
    if not GRAPH_WRITES_ENABLED:
        return jsonify({
            "error": "Graph writes are disabled. Set ALLOW_GRAPH_WRITES=true only in an authorized local or test environment."
        }), 403
    try:
        seed_graph()
        return jsonify({"status": "ok", "message": "Fictional sample graph loaded into FalkorDB."})
    except Exception as exc:
        message = graph_error_message(exc)
        app.logger.warning("Could not seed graph: %s", message)
        return jsonify({"error": message}), 503


@app.route("/api/graph")
def graph_data():
    if DEMO_MODE:
        return jsonify({"nodes": DEMO_ENTITIES, "edges": DEMO_EDGES,
                        "demo_mode": True, "message": "Synthetic demo graph data"})
    try:
        graph = get_graph()
        node_result = graph.query(
            "MATCH (n:Entity) RETURN n.id, n.name, n.kind, n.risk, n.detail, n.timestamp"
        )
        edge_result = graph.query(
            "MATCH (a:Entity)-[r]->(b:Entity) RETURN a.id, type(r), b.id"
        )
        nodes = [{"id": r[0], "name": r[1], "kind": r[2], "risk": r[3],
                  "detail": r[4], "timestamp": r[5]} for r in node_result.result_set]
        edges = [{"source": r[0], "label": r[1], "target": r[2]}
                 for r in edge_result.result_set]
        return jsonify({"nodes": nodes, "edges": edges})
    except Exception as exc:
        message = graph_error_message(exc)
        app.logger.warning("Could not load graph: %s", message)
        return jsonify({"error": message}), 503


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
            rec = ("Verify the login with the user, review authentication logs, and confirm device ownership."
                   if risk == "HIGH" else
                   "Review surrounding authentication events and continue monitoring."
                   if risk == "MEDIUM" else
                   "Continue routine monitoring and retain the event for audit history.")
            findings.append({"user": row[0], "event": row[1], "ip": row[2], "device": row[3],
                             "risk": risk, "reason": row[5] or "No explanation available",
                             "timestamp": row[6], "recommendation": rec,
                             "notice": "Rule-based classification; investigate before concluding an attack occurred."})
        findings.sort(key=lambda item: RISK_PRIORITY.get(item["risk"], 3))
        return jsonify({"findings": findings})
    except Exception as exc:
        message = graph_error_message(exc)
        app.logger.warning("Investigation failed: %s", message)
        return jsonify({"error": message}), 503


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
                "event": {"id": row[2], "name": row[3], "risk": row[4] or "UNKNOWN",
                          "reason": row[5] or "No explanation available", "timestamp": row[6]},
                "relationship_from_user": "GENERATED", "relationship_to_entity": row[7],
                "connected_entity": {"id": row[8], "name": row[9], "kind": row[10], "detail": row[11]},
                "notice": "A graph connection is a lead for review, not proof of malicious activity.",
            })
        paths.sort(key=lambda item: RISK_PRIORITY.get(item["event"]["risk"], 3))
        return jsonify({"path_count": len(paths), "paths": paths})
    except Exception as exc:
        message = graph_error_message(exc)
        app.logger.warning("Path investigation failed: %s", message)
        return jsonify({"error": message,
                        "path_count": 0, "paths": []}), 503


@app.route("/api/ai-explain", methods=["POST"])
def ai_explain():
    data = request.get_json(silent=True) or {}
    question = str(data.get("question", "")).strip()[:MAX_QUESTION_LENGTH]
    if not question:
        return jsonify({"error": "Please provide a question."}), 400
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
        "You are ChainGuard AI, an assistant explaining cybersecurity investigation evidence. "
        "Be concise, practical, and cautious. A graph connection is a lead, not proof "
        "of malicious activity. Never claim an IP is malicious without evidence. "
        "Clearly separate observed facts from possible risks. "
        "Recommend safe investigation steps.\n\n"
    )

    try:
        graph_result = get_graph().query("""
            MATCH (u:Entity {kind: 'user'})-[:GENERATED]->(e:Entity {kind: 'event'})-[r]->(c:Entity)
            WHERE c.kind IN ['ip', 'device']
            RETURN u.id, u.name, e.id, e.name, e.risk, e.reason, e.timestamp,
                   type(r), c.id, c.name, c.kind, c.detail
        """)

        evidence = []
        for row in graph_result.result_set:
            evidence.append({
                "user": {"id": row[0], "name": row[1]},
                "event": {
                    "id": row[2],
                    "name": row[3],
                    "risk": row[4] or "UNKNOWN",
                    "reason": row[5] or "No explanation available",
                    "timestamp": row[6],
                },
                "relationship": "GENERATED -> " + str(row[7]),
                "connected_entity": {
                    "id": row[8],
                    "name": row[9],
                    "kind": row[10],
                    "detail": row[11],
                },
            })

        import json
        evidence_text = json.dumps(evidence[:20], ensure_ascii=False, default=str)

        prompt += (
            "Graph evidence follows. Treat it as the only source of observed facts. "
            "The records may be fictional demo data. Do not infer that a connection "
            "proves an attack.\n\n"
            "GRAPH EVIDENCE:\n" + evidence_text +
            "\n\nUSER QUESTION:\n" + question
        )
    except Exception as exc:
        message = graph_error_message(exc)
        app.logger.warning("Could not retrieve graph evidence for AI explanation: %s", message)
        return jsonify({"error": message}), 503

    try:
        return jsonify({"answer": local_ollama_answer(prompt), "mode": "local_ollama"})
    except requests.RequestException:
        app.logger.warning("Local AI request unavailable")
        return jsonify({"error": "Could not reach local Ollama. Start Ollama and confirm the model is installed."}), 503


@app.route("/api/agent-chat", methods=["POST"])
def agent_chat():
    data = request.get_json(silent=True) or {}
    question = str(data.get("question", "")).strip()[:MAX_QUESTION_LENGTH]
    session_id = str(data.get("session_id", "default")).strip()[:MAX_SESSION_LENGTH] or "default"
    if not question:
        return jsonify({"error": "Please provide a question."}), 400
    if DEMO_MODE:
        return jsonify({
            "error": "Graph agent requires live FalkorDB and local Ollama.",
            "demo_mode": True,
            "message": "Set DEMO_MODE=false and start both services for local agent mode.",
        }), 503
    try:
        evidence = retrieve_graph_evidence()
        if not evidence:
            return jsonify({"error": "No graph evidence found. Seed the graph first."}), 404
        memories = retrieve_session_memory(session_id)
        prompt = f"""
You are ChainGuard AI, a cautious cybersecurity investigation assistant.
Use only supplied graph evidence and prior notes. Separate facts from hypotheses.
A connection alone is not proof of malicious activity. Do not claim to perform actions.
If evidence is insufficient, say so and suggest a safe next step.

GRAPH EVIDENCE:
{evidence}

PRIOR INVESTIGATION NOTES:
{memories}

USER QUESTION:
{question}

Respond with: Graph evidence; Why it may matter; Uncertainties; Suggested next step.
"""
        answer = local_ollama_answer(prompt)
        if not answer:
            return jsonify({"error": "Ollama returned an empty answer."}), 502
        if GRAPH_WRITES_ENABLED:
            save_session_memory(session_id, question, answer)
        memory_persistence = "enabled" if GRAPH_WRITES_ENABLED else "disabled"
        notice = (
            "Investigation aid only. Graph links and model explanations are not proof of an attack."
            if GRAPH_WRITES_ENABLED else
            "Investigation aid only. This response was not saved because graph writes are disabled."
        )
        return jsonify({
            "answer": answer, "session_id": session_id, "evidence": evidence,
            "memory_items_used": len(memories), "memory_persistence": memory_persistence,
            "mode": "falkordb_ollama_agent", "notice": notice,
        })
    except requests.RequestException:
        app.logger.warning("Agent Ollama request unavailable")
        return jsonify({"error": "Could not reach local Ollama. Check that Ollama is running."}), 503
    except Exception as exc:
        message = graph_error_message(exc)
        app.logger.warning("Graph agent request failed: %s", message)
        return jsonify({"error": message}), 503


@app.route("/api/memory/<session_id>", methods=["GET"])
def get_memory(session_id):
    session_id = str(session_id).strip()[:MAX_SESSION_LENGTH]
    if DEMO_MODE:
        return jsonify({"session_id": session_id, "memory": [], "demo_mode": True,
                        "message": "Persistent memory is available in local live mode only."})
    try:
        return jsonify({"session_id": session_id, "memory": retrieve_session_memory(session_id, limit=20)})
    except Exception as exc:
        message = graph_error_message(exc)
        app.logger.warning("Memory retrieval failed: %s", message)
        return jsonify({"error": message}), 503


if __name__ == "__main__":
    app.run(
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true",
        host="127.0.0.1",
        port=int(os.getenv("PORT", "5000")),
    )
