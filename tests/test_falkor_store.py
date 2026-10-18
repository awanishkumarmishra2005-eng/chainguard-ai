import os
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from redis.exceptions import AuthenticationError, ConnectionError as RedisConnectionError, ResponseError

from falkor_store import (
    FalkorConfigError,
    FalkorSettings,
    connect_graph,
    probe_graph,
)


class FalkorSettingsTests(unittest.TestCase):
    def test_defaults_match_local_graph_without_exposing_credentials(self):
        settings = FalkorSettings.from_env({})

        self.assertEqual(settings.host, "localhost")
        self.assertEqual(settings.port, 6379)
        self.assertEqual(settings.graph_name, "ChainGuard")
        self.assertFalse(settings.tls)
        self.assertNotIn("password", settings.public_summary())

    def test_invalid_port_is_clear_and_sanitized(self):
        with self.assertRaisesRegex(FalkorConfigError, "FALKORDB_PORT must be an integer"):
            FalkorSettings.from_env({"FALKORDB_PORT": "not-a-port"})

    def test_secure_url_is_supported_without_returning_its_secret(self):
        settings = FalkorSettings.from_env({
            "FALKORDB_URL": "falkors://graph-user:example-password@db.example.test:6380",
            "FALKORDB_GRAPH_NAME": "ChainGuard",
        })

        self.assertTrue(settings.tls)
        self.assertEqual(settings.public_summary()["host"], "db.example.test")
        self.assertTrue(settings.public_summary()["auth_configured"])
        self.assertNotIn("example-password", repr(settings.public_summary()))

    @patch("falkor_store.FalkorDB")
    def test_connection_uses_environment_settings_and_selects_graph(self, client_class):
        graph = object()
        client_class.return_value.select_graph.return_value = graph
        settings = FalkorSettings.from_env({
            "FALKORDB_HOST": "db.example.test",
            "FALKORDB_PORT": "6380",
            "FALKORDB_USERNAME": "graph-user",
            "FALKORDB_PASSWORD": "example-password",
            "FALKORDB_GRAPH_NAME": "ChainGuard_Test",
            "FALKORDB_TLS": "true",
        })

        self.assertIs(connect_graph(settings), graph)
        client_class.assert_called_once_with(
            host="db.example.test",
            port=6380,
            username="graph-user",
            password="example-password",
            socket_connect_timeout=5,
            socket_timeout=10,
            ssl=True,
            ssl_cert_reqs="required",
        )
        client_class.return_value.select_graph.assert_called_once_with("ChainGuard_Test")

    def test_probe_accepts_authenticated_read_only_query_and_closes_client(self):
        client = MagicMock()
        graph = MagicMock()
        graph.ro_query.return_value = SimpleNamespace(result_set=[])
        client.select_graph.return_value = graph
        settings = replace(
            FalkorSettings.from_env({}),
            username="graph-user",
            password="example-password",
        )
        with patch("falkor_store.connect_client", return_value=client):
            result = probe_graph(settings)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["database"], "connected")
        self.assertEqual(result["checks"]["authentication"], "ok")
        self.assertEqual(result["checks"]["query"], "ok")
        graph.ro_query.assert_called_once()
        client.close.assert_called_once_with()

    def test_probe_classifies_graph_query_permission_failure_without_leaking_error(self):
        client = MagicMock()
        graph = MagicMock()
        graph.ro_query.side_effect = ResponseError("secret provider detail")
        client.select_graph.return_value = graph
        with patch("falkor_store.connect_client", return_value=client):
            result = probe_graph(FalkorSettings.from_env({}))

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error_code"], "graph_query_failed")
        self.assertNotIn("secret provider detail", result["message"])
        client.close.assert_called_once_with()

    def test_probe_distinguishes_connection_and_authentication_failures(self):
        with patch("falkor_store.connect_client", side_effect=RedisConnectionError("private host")):
            connection_result = probe_graph(FalkorSettings.from_env({}))
        with patch("falkor_store.connect_client", side_effect=AuthenticationError("secret detail")):
            auth_result = probe_graph(FalkorSettings.from_env({}))

        self.assertEqual(connection_result["error_code"], "connection_failed")
        self.assertEqual(auth_result["error_code"], "authentication_failed")
        self.assertNotIn("private host", connection_result["message"])
        self.assertNotIn("secret detail", auth_result["message"])

    def test_probe_rejects_malformed_result_without_false_success(self):
        client = MagicMock()
        graph = MagicMock()
        graph.ro_query.return_value = object()
        client.select_graph.return_value = graph
        with patch("falkor_store.connect_client", return_value=client):
            result = probe_graph(FalkorSettings.from_env({}))

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error_code"], "probe_failed")
        client.close.assert_called_once_with()


@unittest.skipUnless(
    os.getenv("RUN_FALKORDB_INTEGRATION") == "1",
    "set RUN_FALKORDB_INTEGRATION=1 to run the live FalkorDB test",
)
class LiveFalkorDBTests(unittest.TestCase):
    def test_test_graph_can_be_updated_and_read(self):
        from falkor_store import connect_graph

        settings = FalkorSettings.from_env({
            **os.environ,
            "FALKORDB_GRAPH_NAME": os.getenv("FALKORDB_TEST_GRAPH", "ChainGuard_Test"),
        })
        graph = connect_graph(settings)
        graph.query(
            "MERGE (n:IntegrationTest {id: $id}) SET n.status = $status",
            {"id": "falkor-integration-check", "status": "ok"},
        )
        result = graph.query(
            "MATCH (n:IntegrationTest {id: $id}) RETURN n.status",
            {"id": "falkor-integration-check"},
        )
        self.assertEqual(result.result_set, [["ok"]])
