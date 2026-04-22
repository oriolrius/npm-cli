"""Pytest fixtures for npm-cli tests."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from npm_cli.client import NPMClient


# Schema shape for POST /api/nginx/certificates enforced by NPM v2.14.
# Source: github.com/NginxProxyManager/nginx-proxy-manager
#   backend/schema/paths/nginx/certificates/post.json
#   backend/schema/components/certificate-object.json
CERT_CREATE_TOP_ALLOWED = {"provider", "nice_name", "domain_names", "meta"}
CERT_META_ALLOWED = {
    "certificate",
    "certificate_key",
    "dns_challenge",
    "dns_provider_credentials",
    "dns_provider",
    "letsencrypt_certificate",
    "propagation_seconds",
    "key_type",
}


def validate_cert_create_body(body: dict) -> list[str]:
    """Return a list of schema violations (empty = valid)."""
    errors: list[str] = []
    if "provider" not in body:
        errors.append("missing required 'provider'")
    extra_top = set(body) - CERT_CREATE_TOP_ALLOWED
    if extra_top:
        errors.append(f"unexpected top-level keys: {sorted(extra_top)}")
    extra_meta = set(body.get("meta", {})) - CERT_META_ALLOWED
    if extra_meta:
        errors.append(f"unexpected meta keys: {sorted(extra_meta)}")
    return errors


class MockNPMTransport(httpx.MockTransport):
    """An httpx transport that enforces v2.14 schema and records calls."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        super().__init__(self._handler)

    def _handler(self, request: httpx.Request) -> httpx.Response:
        body = {}
        if request.content:
            import json

            try:
                body = json.loads(request.content)
            except ValueError:
                body = {}

        self.calls.append(
            {
                "method": request.method,
                "path": request.url.path,
                "query": dict(request.url.params),
                "body": body,
            }
        )

        path = request.url.path

        if path == "/api/nginx/certificates" and request.method == "POST":
            errors = validate_cert_create_body(body)
            if errors:
                return httpx.Response(
                    400,
                    json={
                        "error": {
                            "code": 400,
                            "message": "; ".join(errors),
                        }
                    },
                )
            return httpx.Response(
                201,
                json={
                    "id": 42,
                    "provider": body["provider"],
                    "domain_names": body["domain_names"],
                    "meta": body.get("meta", {}),
                },
            )

        if path == "/api/nginx/certificates/test-http" and request.method == "POST":
            # v2.14 requires {"domains": [...]} — reject anything else.
            if list(body.keys()) != ["domains"] or not isinstance(
                body.get("domains"), list
            ):
                return httpx.Response(
                    400,
                    json={
                        "error": {
                            "code": 400,
                            "message": "data must have required property 'domains'",
                        }
                    },
                )
            return httpx.Response(
                200, json={d: "ok" for d in body["domains"]}
            )

        return httpx.Response(404, json={"error": "not found"})


@pytest.fixture()
def mock_transport() -> MockNPMTransport:
    return MockNPMTransport()


@pytest.fixture()
def client(mock_transport: MockNPMTransport) -> NPMClient:
    c = NPMClient("http://npm.test", token="test-token")
    # Swap the internal httpx client for one bound to our mock transport.
    c._client = httpx.Client(transport=mock_transport, timeout=5.0)
    return c
