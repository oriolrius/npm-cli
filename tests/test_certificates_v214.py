"""Regression tests: npm-cli must comply with NPM v2.14 cert schema.

These tests reproduce the 400-response failures observed against a real
NPM v2.14 server before the fix, and verify the fixed client/CLI produce
request bodies that the v2.14 schema accepts.
"""

from __future__ import annotations

from click.testing import CliRunner

from npm_cli.client import NPMClient
from npm_cli.main import cli


# --- Client-level tests -----------------------------------------------------


def test_create_certificate_http_challenge_minimal(client: NPMClient, mock_transport):
    """HTTP-01 create must NOT include letsencrypt_email / letsencrypt_agree."""
    result = client.create_certificate(
        {
            "provider": "letsencrypt",
            "domain_names": ["foo.example.com"],
            "meta": {"dns_challenge": False},
        }
    )
    assert result["id"] == 42
    sent = mock_transport.calls[-1]["body"]
    assert "letsencrypt_email" not in sent.get("meta", {})
    assert "letsencrypt_agree" not in sent.get("meta", {})


def test_create_certificate_rejects_legacy_meta(client: NPMClient):
    """The mock enforces v2.14 — legacy meta keys must 400."""
    import httpx
    import pytest

    with pytest.raises(httpx.HTTPStatusError) as exc:
        client.create_certificate(
            {
                "provider": "letsencrypt",
                "domain_names": ["foo.example.com"],
                "meta": {
                    "letsencrypt_email": "me@x.com",
                    "letsencrypt_agree": True,
                    "dns_challenge": False,
                },
            }
        )
    assert exc.value.response.status_code == 400


def test_create_certificate_dns_challenge_shape(client: NPMClient, mock_transport):
    """DNS-challenge create uses allowed meta keys only."""
    client.create_certificate(
        {
            "provider": "letsencrypt",
            "domain_names": ["*.example.com"],
            "meta": {
                "dns_challenge": True,
                "dns_provider": "cloudflare",
                "dns_provider_credentials": "dns_cloudflare_api_token=xxx",
                "propagation_seconds": 30,
            },
        }
    )
    sent_meta = mock_transport.calls[-1]["body"]["meta"]
    assert sent_meta["dns_challenge"] is True
    assert sent_meta["dns_provider"] == "cloudflare"
    assert "letsencrypt_email" not in sent_meta


def test_test_http_challenge_uses_domains_array(client: NPMClient, mock_transport):
    """test-http must POST {"domains": [...]} — not {"domain": "..."}."""
    result = client.test_http_challenge(["foo.example.com", "bar.example.com"])
    assert result == {"foo.example.com": "ok", "bar.example.com": "ok"}
    sent = mock_transport.calls[-1]["body"]
    assert sent == {"domains": ["foo.example.com", "bar.example.com"]}
    assert "domain" not in sent


def test_test_http_challenge_accepts_single_string(client: NPMClient, mock_transport):
    """Backwards-compat: a single string is wrapped into a list."""
    client.test_http_challenge("foo.example.com")
    assert mock_transport.calls[-1]["body"] == {"domains": ["foo.example.com"]}


# --- CLI-level tests --------------------------------------------------------


def _invoke(client: NPMClient, args: list[str], monkeypatch):
    """Invoke the CLI with a pre-constructed client injected into the context.

    The group callback in main.cli rebuilds the client from env/config, so we
    patch the lookup to return empty settings AND force NPMClient() to return
    our pre-configured instance.
    """
    from npm_cli import main as main_mod

    monkeypatch.setattr(
        main_mod, "get_server_config", lambda *a, **kw: ("http://npm.test", None, None, "t")
    )
    monkeypatch.setattr(main_mod, "NPMClient", lambda *a, **kw: client)

    runner = CliRunner()
    # Also pass -o json so we can ignore table rendering differences.
    return runner.invoke(cli, ["-o", "json", *args])


def test_cli_certs_create_strips_legacy_email(client: NPMClient, mock_transport, monkeypatch):
    result = _invoke(
        client,
        ["certs", "create", "-d", "foo.example.com", "--email", "me@x.com"],
        monkeypatch,
    )
    assert result.exit_code == 0, result.output
    sent_meta = mock_transport.calls[-1]["body"]["meta"]
    assert "letsencrypt_email" not in sent_meta
    assert "letsencrypt_agree" not in sent_meta
    # Warning about the deprecated flag should be surfaced.
    assert "ignored" in result.output.lower() or "deprecated" in result.output.lower()


def test_cli_certs_create_dns_requires_provider(client: NPMClient, monkeypatch):
    result = _invoke(
        client,
        ["certs", "create", "-d", "foo.example.com", "--dns-challenge"],
        monkeypatch,
    )
    assert result.exit_code != 0


def test_cli_certs_test_http_sends_domains_array(client: NPMClient, mock_transport, monkeypatch):
    result = _invoke(
        client,
        ["certs", "test-http", "-d", "a.example.com", "-d", "b.example.com"],
        monkeypatch,
    )
    assert result.exit_code == 0, result.output
    assert mock_transport.calls[-1]["body"] == {
        "domains": ["a.example.com", "b.example.com"]
    }
