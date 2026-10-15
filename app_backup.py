from flask import Flask, jsonify, render_template
from falkordb import FalkorDB

app = Flask(__name__)
DB_HOST = "localhost"
DB_PORT = 6379
GRAPH_NAME = "ChainGuard"


def get_graph():
    db = FalkorDB(host=DB_HOST, port=DB_PORT)
    return db.select_graph(GRAPH_NAME)


def seed_graph():
    """Create repeatable fictional security-demo data in FalkorDB.

    All people, devices, events, and relationships below are synthetic demo data.
    A graph connection is an investigation lead, not proof of an attack.
    """
    graph = get_graph()

    entities = [
        # People
        ("user_1", "user", "Aarav Sharma", None, None, "Finance"),
        ("user_2", "user", "Priya Reddy", None, None, "Engineering"),
        ("user_3", "user", "Rohan Mehta", None, None, "Finance"),
        ("user_4", "user", "Meera Iyer", None, None, "Engineering"),
        # IP addresses
        ("ip_1", "ip", "185.199.110.42", None, None, "External"),
        ("ip_2", "ip", "192.168.1.10", None, None, "Internal"),
        ("ip_3", "ip", "203.0.113.77", None, None, "External (reserved demo range)"),
        ("ip_4", "ip", "198.51.100.24", None, None, "External (reserved demo range)"),
        # Devices
        ("device_1", "device", "Unknown-Laptop-17", None, None, "Unrecognized"),
        ("device_2", "device", "Office-Laptop-02", None, None, "Managed"),
        ("device_3", "device", "Unmanaged-Workstation-09", None, None, "Unmanaged"),
        ("device_4", "device", "Managed-Laptop-14", None, None, "Managed"),
        # Events: risk is a demo rule label, not a confirmed attack verdict.
        ("event_1", "event", "Unusual login", "HIGH", "Fictional demo signal: login used an unfamiliar device and an external IP.", "2026-10-15 02:14 UTC"),
        ("event_2", "event", "Normal office login", "LOW", "Fictional demo signal: routine login from an internal IP and managed device.", "2026-10-15 09:05 UTC"),
        ("event_3", "event", "Repeated failed logins", "HIGH", "Fictional demo signal: several failed attempts were observed from an external IP.", "2026-10-15 03:42 UTC"),
        ("event_4", "event", "Unusual access time", "MEDIUM", "Fictional demo signal: access occurred outside the user's usual demo schedule.", "2026-10-15 23:18 UTC"),
        # Departments
        ("dept_1", "department", "Finance", None, None, "Business unit"),
        ("dept_2", "department", "Engineering", None, None, "Business unit"),
    ]

    for entity_id, kind, name, risk, reason, extra in entities:
        # The last field is stored as detail for people/devices/IPs, or timestamp for events.
        query = (
            "MERGE (n:Entity {id: '" + entity_id + "'}) "
            "SET n.kind = '" + kind + "', n.name = '" + name.replace("'", "\\'") + "'"
        )
        if risk:
            query += ", n.risk = '" + risk + "'"
        if reason:
            query += ", n.reason = '" + reason.replace("'", "\\'") + "'"
        if kind == "event" and extra:
            query += ", n.timestamp = '" + extra + "'"
        elif extra:
            query += ", n.detail = '" + extra.replace("'", "\\'") + "'"
        graph.query(query)

    relationships = [
        # User -> event -> IP/device
        ("user_1", "GENERATED", "event_1"),
        ("event_1", "FROM_IP", "ip_1"),
        ("event_1", "ON_DEVICE", "device_1"),
        ("user_2", "GENERATED", "event_2"),
        ("event_2", "FROM_IP", "ip_2"),
        ("event_2", "ON_DEVICE", "device_2"),
        ("user_3", "GENERATED", "event_3"),
        ("event_3", "FROM_IP", "ip_3"),
        ("event_3", "ON_DEVICE", "device_3"),
        ("user_4", "GENERATED", "event_4"),
        ("event_4", "FROM_IP", "ip_4"),
        ("event_4", "ON_DEVICE", "device_4"),
        # User -> department
        ("user_1", "MEMBER_OF", "dept_1"),
        ("user_2", "MEMBER_OF", "dept_2"),
        ("user_3", "MEMBER_OF", "dept_1"),
        ("user_4", "MEMBER_OF", "dept_2"),
    ]

    for source_id, rel_type, target_id in relationships:
        graph.query(
            "MATCH (a:Entity {id: '" + source_id + "'}), "
            "(b:Entity {id: '" + target_id + "'}) "
            "MERGE (a)-[:" + rel_type + "]->(b)"
        )


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/health")
def health():
    try:
        result = get_graph().query("RETURN 'connected' AS status")
        status = result.result_set[0][0] if result.result_set else "connected"
        return jsonify({"status": "ok", "database": status})
    except Exception as error:
        app.logger.exception("Health check failed")
        return jsonify({"status": "error", "message": str(error)}), 503


@app.route("/api/seed", methods=["POST"])
def seed():
    try:
        seed_graph()
        return jsonify({
            "message": "Fictional demo security graph created successfully.",
            "note": "These are synthetic records for demonstration, not real people or confirmed attacks."
        })
    except Exception as error:
        app.logger.exception("Could not seed demo graph")
        return jsonify({"error": str(error)}), 500


@app.route("/api/graph")
def graph_data():
    try:
        graph = get_graph()
        node_result = graph.query(
            "MATCH (n:Entity) RETURN n.id, n.name, n.kind, n.risk, n.detail, n.timestamp"
        )
        edge_result = graph.query(
            "MATCH (a:Entity)-[r]->(b:Entity) RETURN a.id, type(r), b.id"
        )
        nodes = [
            {"id": row[0], "name": row[1], "kind": row[2], "risk": row[3],
             "detail": row[4], "timestamp": row[5]}
            for row in node_result.result_set
        ]
        edges = [
            {"source": row[0], "label": row[1], "target": row[2]}
            for row in edge_result.result_set
        ]
        return jsonify({"nodes": nodes, "edges": edges})
    except Exception as error:
        app.logger.exception("Could not load graph")
        return jsonify({"error": str(error)}), 500


@app.route("/api/investigate")
def investigate():
    try:
        result = get_graph().query("""
            MATCH (u:Entity {kind: 'user'})-[:GENERATED]->(e:Entity {kind: 'event'})
                  -[:FROM_IP]->(ip:Entity), (e)-[:ON_DEVICE]->(d:Entity)
            RETURN u.name, e.name, ip.name, d.name, e.risk, e.reason, e.timestamp
        """)
        findings = []
        for row in result.result_set:
            risk = row[4] or "UNKNOWN"
            findings.append({
                "user": row[0], "event": row[1], "ip": row[2], "device": row[3],
                "risk": risk, "reason": row[5] or "No explanation available",
                "timestamp": row[6],
                "recommendation": (
                    "Verify the login with the user, review authentication logs, and confirm device ownership."
                    if risk == "HIGH" else
                    "Review surrounding authentication events and continue monitoring."
                    if risk == "MEDIUM" else
                    "Continue routine monitoring and retain the event for audit history."
                ),
                "notice": "Demo rule-based classification; investigate further before concluding an attack occurred."
            })
        priority = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        findings.sort(key=lambda item: priority.get(item["risk"], 3))
        return jsonify({"findings": findings})
    except Exception as error:
        app.logger.exception("Investigation failed")
        return jsonify({"error": str(error)}), 500


@app.route("/api/investigate-paths")
def investigate_paths():
    """Return graph-backed user -> event -> IP/device paths for synthetic demo data."""
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
                    "reason": row[5] or "No explanation available", "timestamp": row[6]
                },
                "relationship_from_user": "GENERATED",
                "relationship_to_entity": row[7],
                "connected_entity": {"id": row[8], "name": row[9], "kind": row[10], "detail": row[11]},
                "notice": "Synthetic demo data. A graph connection is a lead for review, not proof of malicious activity."
            })
        priority = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        paths.sort(key=lambda p: priority.get(p["event"]["risk"], 3))
        return jsonify({"path_count": len(paths), "paths": paths})
    except Exception as error:
        app.logger.exception("Path investigation failed")
        return jsonify({"error": str(error), "path_count": 0, "paths": []}), 500


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
