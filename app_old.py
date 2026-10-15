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
if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)