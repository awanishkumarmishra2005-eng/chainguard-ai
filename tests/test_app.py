import unittest
from unittest.mock import patch

import app


class AppHealthTests(unittest.TestCase):
    def setUp(self):
        self.client = app.app.test_client()
        self.demo_mode = app.DEMO_MODE
        self.graph_writes_enabled = app.GRAPH_WRITES_ENABLED

    def tearDown(self):
        app.DEMO_MODE = self.demo_mode
        app.GRAPH_WRITES_ENABLED = self.graph_writes_enabled

    def test_demo_health_identifies_synthetic_data(self):
        app.DEMO_MODE = True

        response = self.client.get("/api/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["application"], "ok")
        self.assertEqual(response.get_json()["graph"], "demo_mode")
        self.assertEqual(response.get_json()["database"], "demo_mode")

    def test_demo_graph_returns_fictional_nodes_and_relationships(self):
        app.DEMO_MODE = True

        response = self.client.get("/api/graph")
        body = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["demo_mode"])
        self.assertGreater(len(body["nodes"]), 0)
        self.assertGreater(len(body["edges"]), 0)

    def test_demo_investigation_returns_findings(self):
        app.DEMO_MODE = True

        response = self.client.get("/api/investigate")
        body = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["demo_mode"])
        self.assertGreater(len(body["findings"]), 0)

    def test_demo_paths_returns_connected_paths(self):
        app.DEMO_MODE = True

        response = self.client.get("/api/investigate-paths")
        body = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["demo_mode"])
        self.assertGreater(body["path_count"], 0)
        self.assertEqual(body["path_count"], len(body["paths"]))

    def test_graph_outage_does_not_make_flask_health_look_down(self):
        app.DEMO_MODE = False
        with patch("app.graph_status", side_effect=OSError("connection refused")):
            response = self.client.get("/api/health")

        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["application"], "ok")
        self.assertEqual(body["graph"], "unavailable")
        self.assertEqual(body["database"], "unavailable")
        self.assertNotIn("connection refused", body["message"])

    def test_graph_endpoint_reports_outage_without_false_success(self):
        app.DEMO_MODE = False
        with patch("app.get_graph", side_effect=OSError("connection refused")):
            response = self.client.get("/api/graph")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["error"], "FalkorDB is unavailable. Check the configured endpoint and network access.")

    def test_live_seed_is_disabled_without_explicit_write_permission(self):
        app.DEMO_MODE = False
        app.GRAPH_WRITES_ENABLED = False

        response = self.client.post("/api/seed")

        self.assertEqual(response.status_code, 403)
        self.assertIn("Graph writes are disabled", response.get_json()["error"])

    def test_agent_chat_is_read_only_when_graph_writes_are_disabled(self):
        app.DEMO_MODE = False
        app.GRAPH_WRITES_ENABLED = False
        evidence = [{"id": "event_1", "connected_id": "ip_1"}]
        with patch("app.retrieve_graph_evidence", return_value=evidence), \
                patch("app.retrieve_session_memory", return_value=[]), \
                patch("app.local_ollama_answer", return_value="safe answer"), \
                patch("app.save_session_memory") as save_memory:
            response = self.client.post(
                "/api/agent-chat",
                json={"question": "What evidence is present?", "session_id": "test"},
            )

        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["memory_persistence"], "disabled")
        save_memory.assert_not_called()

    def test_demo_explanation_does_not_claim_live_ai(self):
        app.DEMO_MODE = True

        response = self.client.post("/api/ai-explain", json={"question": "Why?"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["mode"], "demo_rule_based")
        self.assertTrue(response.get_json()["demo_mode"])


if __name__ == "__main__":
    unittest.main()
