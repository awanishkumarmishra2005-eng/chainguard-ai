"""Small, environment-driven FalkorDB connection boundary.

This module deliberately contains no application data or credentials.  It
turns configuration errors into safe, actionable messages and leaves network
errors to the Flask layer, which can degrade gracefully when the optional
graph service is unavailable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit

try:
    from falkordb import FalkorDB
except Exception as exc:  # pragma: no cover - depends on the environment
    FalkorDB = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


class FalkorConfigError(ValueError):
    """A safe-to-display FalkorDB configuration error."""


class FalkorDependencyError(RuntimeError):
    """The optional FalkorDB client package is not available."""


@dataclass(frozen=True)
class FalkorSettings:
    """Resolved connection settings.

    ``url`` may contain credentials when a provider supplies a URI.  It is
    kept in memory only and is never included in ``public_summary`` or logs.
    """

    url: str | None
    host: str
    port: int
    username: str | None
    password: str | None
    graph_name: str
    tls: bool
    ssl_cert_reqs: str | None
    ssl_ca_certs: str | None
    connect_timeout: int
    socket_timeout: int

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "FalkorSettings":
        env = os.environ if environ is None else environ

        url = cls._value(env, "FALKORDB_URL", "DB_URL")
        if url:
            parsed = urlsplit(url)
            if parsed.scheme.lower() not in {"falkor", "falkors", "redis", "rediss"}:
                raise FalkorConfigError(
                    "FALKORDB_URL must use falkor://, falkors://, redis://, or rediss://"
                )
            if not parsed.hostname:
                raise FalkorConfigError("FALKORDB_URL must include a database host")
            try:
                if parsed.port is not None and not 1 <= parsed.port <= 65535:
                    raise FalkorConfigError("FALKORDB_URL port must be between 1 and 65535")
            except ValueError as exc:
                raise FalkorConfigError("FALKORDB_URL must contain a valid port") from exc

        host = cls._value(env, "FALKORDB_HOST", "DB_HOST") or "localhost"
        port = cls._positive_int(env, "FALKORDB_PORT", "DB_PORT", default=6379)
        graph_name = cls._value(env, "FALKORDB_GRAPH_NAME", "GRAPH_NAME") or "ChainGuard"
        if not graph_name.strip():
            raise FalkorConfigError("FALKORDB_GRAPH_NAME must not be empty")

        tls_value = cls._value(env, "FALKORDB_TLS", "DB_TLS")
        tls = cls._boolean(tls_value, "FALKORDB_TLS", default=False)
        if url and urlsplit(url).scheme.lower() in {"falkors", "rediss"}:
            tls = True

        cert_reqs = cls._value(env, "FALKORDB_SSL_CERT_REQS")
        if cert_reqs is None:
            cert_reqs = "required" if tls else None
        elif cert_reqs.lower() not in {"required", "optional", "none"}:
            raise FalkorConfigError(
                "FALKORDB_SSL_CERT_REQS must be required, optional, or none"
            )
        elif cert_reqs.lower() == "none":
            cert_reqs = None
        else:
            cert_reqs = cert_reqs.lower()

        return cls(
            url=url,
            host=host,
            port=port,
            username=cls._value(env, "FALKORDB_USERNAME", "DB_USERNAME"),
            password=cls._value(env, "FALKORDB_PASSWORD", "DB_PASSWORD"),
            graph_name=graph_name,
            tls=tls,
            ssl_cert_reqs=cert_reqs,
            ssl_ca_certs=cls._value(env, "FALKORDB_SSL_CA_CERTS"),
            connect_timeout=cls._positive_int(
                env, "FALKORDB_CONNECT_TIMEOUT", default=5
            ),
            socket_timeout=cls._positive_int(
                env, "FALKORDB_SOCKET_TIMEOUT", default=10
            ),
        )

    @staticmethod
    def _value(environ: dict[str, str], *names: str) -> str | None:
        for name in names:
            value = environ.get(name)
            if value is not None and value.strip():
                return value.strip()
        return None

    @classmethod
    def _positive_int(
        cls,
        environ: dict[str, str],
        *names: str,
        default: int,
    ) -> int:
        raw = cls._value(environ, *names)
        if raw is None:
            return default
        try:
            value = int(raw)
        except (TypeError, ValueError) as exc:
            raise FalkorConfigError(f"{names[0]} must be an integer") from exc
        if value <= 0 or (names[0] in {"FALKORDB_PORT", "DB_PORT"} and value > 65535):
            suffix = " between 1 and 65535" if names[0] in {"FALKORDB_PORT", "DB_PORT"} else " greater than zero"
            raise FalkorConfigError(f"{names[0]} must be{suffix}")
        return value

    @staticmethod
    def _boolean(value: str | None, name: str, *, default: bool) -> bool:
        if value is None:
            return default
        normalized = value.lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
        raise FalkorConfigError(f"{name} must be true or false")

    def public_summary(self) -> dict[str, object]:
        """Return only non-secret connection metadata for diagnostics."""

        display_host = self.host
        display_port = self.port
        url_has_auth = False
        if self.url:
            parsed = urlsplit(self.url)
            display_host = parsed.hostname or "configured-url"
            display_port = parsed.port or (6380 if self.tls else 6379)
            url_has_auth = bool(parsed.username or parsed.password)
        return {
            "host": display_host,
            "port": display_port,
            "graph": self.graph_name,
            "tls": self.tls,
            "auth_configured": bool(self.username or self.password or url_has_auth),
        }


def connect_graph(settings: FalkorSettings | None = None):
    """Create a FalkorDB graph handle without changing graph contents."""

    if FalkorDB is None:
        detail = type(_IMPORT_ERROR).__name__ if _IMPORT_ERROR else "missing package"
        raise FalkorDependencyError(f"FalkorDB client unavailable ({detail})")

    settings = settings or FalkorSettings.from_env()
    kwargs: dict[str, object] = {
        "socket_connect_timeout": settings.connect_timeout,
        "socket_timeout": settings.socket_timeout,
    }
    if settings.username:
        kwargs["username"] = settings.username
    if settings.password:
        kwargs["password"] = settings.password
    if settings.tls:
        kwargs["ssl"] = True
        kwargs["ssl_cert_reqs"] = settings.ssl_cert_reqs or "required"
        if settings.ssl_ca_certs:
            kwargs["ssl_ca_certs"] = settings.ssl_ca_certs

    if settings.url:
        client = FalkorDB.from_url(settings.url, **kwargs)
    else:
        client = FalkorDB(host=settings.host, port=settings.port, **kwargs)
    return client.select_graph(settings.graph_name)
