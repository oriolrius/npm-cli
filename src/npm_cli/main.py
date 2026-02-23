"""NPM CLI - Main entry point."""

import click
from rich.console import Console

from . import __version__
from .client import NPMClient
from .config import clear_token, get_server_config, load_tokens
from .output import (
    console,
    format_output,
    print_dict,
    print_error,
    print_info,
    print_success,
    print_table,
)

# Pass context to subcommands
pass_client = click.make_pass_decorator(NPMClient, ensure=True)


class Context:
    """CLI context."""

    def __init__(self):
        self.client: NPMClient | None = None
        self.output: str = "table"
        self.server_key: str = "default"


pass_context = click.make_pass_decorator(Context, ensure=True)


@click.group()
@click.option("--url", envvar="NPM_URL", help="NPM server URL")
@click.option("--user", envvar="NPM_USER", help="NPM username/email")
@click.option("--password", envvar="NPM_PASS", help="NPM password")
@click.option("--token", envvar="NPM_TOKEN", help="JWT token")
@click.option("--server", "-s", default="default", help="Server profile from config")
@click.option(
    "--output",
    "-o",
    type=click.Choice(["table", "json", "yaml"]),
    default="table",
    help="Output format",
)
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
@click.version_option(version=__version__)
@click.pass_context
def cli(ctx, url, user, password, token, server, output, quiet):
    """NPM CLI - Full-featured CLI for Nginx Proxy Manager.

    Manage proxy hosts, certificates, streams, users, and more from the command line.

    Configuration can be provided via:
      - Command line options (--url, --user, etc.)
      - Environment variables (NPM_URL, NPM_USER, NPM_PASS, NPM_TOKEN)
      - Config file (~/.npm-cli.yaml)

    Examples:
      npm-cli auth login --url http://npm:81 --user admin@example.com
      npm-cli proxy list
      npm-cli certs download 5 --output ./certs/
    """
    ctx.ensure_object(Context)
    ctx.obj.output = output
    ctx.obj.server_key = server

    # Get configuration
    final_url, final_user, final_password, final_token = get_server_config(
        url, user, password, token, server
    )

    if final_url:
        ctx.obj.client = NPMClient(final_url, final_token)


# ============================================================================
# AUTH Commands
# ============================================================================


@cli.group()
def auth():
    """Authentication commands."""
    pass


@auth.command("login")
@click.option("--url", required=True, help="NPM server URL")
@click.option("--user", required=True, help="Username/email")
@click.option("--password", prompt=True, hide_input=True, help="Password")
@click.pass_context
def auth_login(ctx, url, user, password):
    """Login and save credentials."""
    client = NPMClient(url)
    try:
        token = client.login(user, password, ctx.obj.server_key)
        print_success(f"Logged in successfully. Token cached for server '{ctx.obj.server_key}'")
    except Exception as e:
        print_error(f"Login failed: {e}")
        raise SystemExit(1)


@auth.command("logout")
@click.pass_context
def auth_logout(ctx):
    """Clear saved token."""
    clear_token(ctx.obj.server_key)
    print_success(f"Token cleared for server '{ctx.obj.server_key}'")


@auth.command("status")
@click.pass_context
def auth_status(ctx):
    """Show current authentication status."""
    if ctx.obj.client and ctx.obj.client.token:
        try:
            status = ctx.obj.client.get_status()
            print_success(f"Authenticated to {ctx.obj.client.base_url}")
            print_info(f"NPM Version: {status.get('version', {})}")
        except Exception as e:
            print_error(f"Token invalid or expired: {e}")
    else:
        print_warning("Not authenticated. Run 'npm-cli auth login' first.")


@auth.command("token")
@click.pass_context
def auth_token(ctx):
    """Print current token."""
    tokens = load_tokens()
    token = tokens.get(ctx.obj.server_key)
    if token:
        click.echo(token)
    else:
        print_error("No token found")
        raise SystemExit(1)


# ============================================================================
# USERS Commands
# ============================================================================


@cli.group()
def users():
    """User management commands."""
    pass


@users.command("list")
@click.pass_context
def users_list(ctx):
    """List all users."""
    data = ctx.obj.client.list_users()
    format_output(data, ctx.obj.output, ["id", "name", "email", "roles", "is_disabled"])


@users.command("get")
@click.argument("user_id", type=int)
@click.pass_context
def users_get(ctx, user_id):
    """Get user details."""
    data = ctx.obj.client.get_user(user_id)
    format_output(data, ctx.obj.output)


@users.command("create")
@click.option("--name", required=True, help="User name")
@click.option("--email", required=True, help="User email")
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
@click.option("--roles", default="user", help="Roles (comma-separated)")
@click.pass_context
def users_create(ctx, name, email, password, roles):
    """Create a new user."""
    data = {
        "name": name,
        "email": email,
        "secret": password,
        "roles": roles.split(","),
    }
    result = ctx.obj.client.create_user(data)
    print_success(f"User created with ID: {result['id']}")
    format_output(result, ctx.obj.output)


@users.command("delete")
@click.argument("user_id", type=int)
@click.confirmation_option(prompt="Are you sure you want to delete this user?")
@click.pass_context
def users_delete(ctx, user_id):
    """Delete a user."""
    ctx.obj.client.delete_user(user_id)
    print_success(f"User {user_id} deleted")


@users.command("permissions")
@click.argument("user_id", type=int)
@click.pass_context
def users_permissions(ctx, user_id):
    """Show user permissions."""
    data = ctx.obj.client.get_user_permissions(user_id)
    format_output(data, ctx.obj.output)


# ============================================================================
# PROXY Commands
# ============================================================================


@cli.group()
def proxy():
    """Proxy host management commands."""
    pass


@proxy.command("list")
@click.pass_context
def proxy_list(ctx):
    """List all proxy hosts."""
    data = ctx.obj.client.list_proxy_hosts()
    format_output(
        data,
        ctx.obj.output,
        ["id", "domain_names", "forward_host", "forward_port", "enabled", "ssl_forced"],
    )


@proxy.command("get")
@click.argument("host_id", type=int)
@click.pass_context
def proxy_get(ctx, host_id):
    """Get proxy host details."""
    data = ctx.obj.client.get_proxy_host(host_id)
    format_output(data, ctx.obj.output)


@proxy.command("create")
@click.option("--domain", "-d", required=True, multiple=True, help="Domain name(s)")
@click.option("--forward-host", "-f", required=True, help="Forward hostname/IP")
@click.option("--forward-port", "-p", required=True, type=int, help="Forward port")
@click.option("--scheme", type=click.Choice(["http", "https"]), default="http")
@click.option("--ssl/--no-ssl", default=False, help="Enable SSL")
@click.option("--cert-id", type=int, help="Certificate ID")
@click.option("--force-ssl/--no-force-ssl", default=False)
@click.option("--http2/--no-http2", default=False)
@click.option("--block-exploits/--no-block-exploits", default=True)
@click.option("--websocket/--no-websocket", default=False)
@click.option("--access-list-id", type=int, default=0)
@click.option("--advanced-config", default="", help="Custom Nginx config")
@click.pass_context
def proxy_create(
    ctx,
    domain,
    forward_host,
    forward_port,
    scheme,
    ssl,
    cert_id,
    force_ssl,
    http2,
    block_exploits,
    websocket,
    access_list_id,
    advanced_config,
):
    """Create a new proxy host."""
    data = {
        "domain_names": list(domain),
        "forward_host": forward_host,
        "forward_port": forward_port,
        "forward_scheme": scheme,
        "ssl_forced": force_ssl,
        "hsts_enabled": False,
        "hsts_subdomains": False,
        "http2_support": http2,
        "block_exploits": block_exploits,
        "allow_websocket_upgrade": websocket,
        "access_list_id": access_list_id,
        "certificate_id": cert_id or 0,
        "advanced_config": advanced_config,
        "meta": {"letsencrypt_agree": False, "dns_challenge": False},
        "locations": [],
    }
    result = ctx.obj.client.create_proxy_host(data)
    print_success(f"Proxy host created with ID: {result['id']}")
    format_output(result, ctx.obj.output)


@proxy.command("update")
@click.argument("host_id", type=int)
@click.option("--domain", "-d", multiple=True, help="Domain name(s)")
@click.option("--forward-host", "-f", help="Forward hostname/IP")
@click.option("--forward-port", "-p", type=int, help="Forward port")
@click.option("--scheme", type=click.Choice(["http", "https"]))
@click.option("--cert-id", type=int, help="Certificate ID")
@click.option("--force-ssl/--no-force-ssl", default=None)
@click.option("--http2/--no-http2", default=None)
@click.option("--block-exploits/--no-block-exploits", default=None)
@click.option("--websocket/--no-websocket", default=None)
@click.pass_context
def proxy_update(
    ctx,
    host_id,
    domain,
    forward_host,
    forward_port,
    scheme,
    cert_id,
    force_ssl,
    http2,
    block_exploits,
    websocket,
):
    """Update a proxy host."""
    # Get current data
    current = ctx.obj.client.get_proxy_host(host_id)

    # Update only provided fields
    if domain:
        current["domain_names"] = list(domain)
    if forward_host:
        current["forward_host"] = forward_host
    if forward_port:
        current["forward_port"] = forward_port
    if scheme:
        current["forward_scheme"] = scheme
    if cert_id is not None:
        current["certificate_id"] = cert_id
    if force_ssl is not None:
        current["ssl_forced"] = force_ssl
    if http2 is not None:
        current["http2_support"] = http2
    if block_exploits is not None:
        current["block_exploits"] = block_exploits
    if websocket is not None:
        current["allow_websocket_upgrade"] = websocket

    result = ctx.obj.client.update_proxy_host(host_id, current)
    print_success(f"Proxy host {host_id} updated")
    format_output(result, ctx.obj.output)


@proxy.command("delete")
@click.argument("host_id", type=int)
@click.confirmation_option(prompt="Are you sure you want to delete this proxy host?")
@click.pass_context
def proxy_delete(ctx, host_id):
    """Delete a proxy host."""
    ctx.obj.client.delete_proxy_host(host_id)
    print_success(f"Proxy host {host_id} deleted")


@proxy.command("enable")
@click.argument("host_id", type=int)
@click.pass_context
def proxy_enable(ctx, host_id):
    """Enable a proxy host."""
    ctx.obj.client.enable_proxy_host(host_id)
    print_success(f"Proxy host {host_id} enabled")


@proxy.command("disable")
@click.argument("host_id", type=int)
@click.pass_context
def proxy_disable(ctx, host_id):
    """Disable a proxy host."""
    ctx.obj.client.disable_proxy_host(host_id)
    print_success(f"Proxy host {host_id} disabled")


# ============================================================================
# REDIRECT Commands
# ============================================================================


@cli.group()
def redirect():
    """Redirection host management commands."""
    pass


@redirect.command("list")
@click.pass_context
def redirect_list(ctx):
    """List all redirection hosts."""
    data = ctx.obj.client.list_redirection_hosts()
    format_output(
        data, ctx.obj.output, ["id", "domain_names", "forward_domain_name", "forward_http_code", "enabled"]
    )


@redirect.command("get")
@click.argument("host_id", type=int)
@click.pass_context
def redirect_get(ctx, host_id):
    """Get redirection host details."""
    data = ctx.obj.client.get_redirection_host(host_id)
    format_output(data, ctx.obj.output)


@redirect.command("create")
@click.option("--domain", "-d", required=True, multiple=True, help="Domain name(s)")
@click.option("--forward-url", "-f", required=True, help="Target URL")
@click.option("--http-code", type=click.Choice(["301", "302", "303", "307", "308"]), default="301")
@click.option("--scheme", type=click.Choice(["auto", "http", "https"]), default="auto")
@click.option("--preserve-path/--no-preserve-path", default=True)
@click.option("--ssl/--no-ssl", default=False)
@click.option("--cert-id", type=int, help="Certificate ID")
@click.option("--block-exploits/--no-block-exploits", default=True)
@click.pass_context
def redirect_create(ctx, domain, forward_url, http_code, scheme, preserve_path, ssl, cert_id, block_exploits):
    """Create a new redirection host."""
    data = {
        "domain_names": list(domain),
        "forward_domain_name": forward_url,
        "forward_http_code": int(http_code),
        "forward_scheme": scheme,
        "preserve_path": preserve_path,
        "certificate_id": cert_id or 0,
        "ssl_forced": ssl,
        "block_exploits": block_exploits,
        "hsts_enabled": False,
        "hsts_subdomains": False,
        "http2_support": False,
        "meta": {},
        "advanced_config": "",
    }
    result = ctx.obj.client.create_redirection_host(data)
    print_success(f"Redirection host created with ID: {result['id']}")


@redirect.command("delete")
@click.argument("host_id", type=int)
@click.confirmation_option(prompt="Are you sure?")
@click.pass_context
def redirect_delete(ctx, host_id):
    """Delete a redirection host."""
    ctx.obj.client.delete_redirection_host(host_id)
    print_success(f"Redirection host {host_id} deleted")


@redirect.command("enable")
@click.argument("host_id", type=int)
@click.pass_context
def redirect_enable(ctx, host_id):
    """Enable a redirection host."""
    ctx.obj.client.enable_redirection_host(host_id)
    print_success(f"Redirection host {host_id} enabled")


@redirect.command("disable")
@click.argument("host_id", type=int)
@click.pass_context
def redirect_disable(ctx, host_id):
    """Disable a redirection host."""
    ctx.obj.client.disable_redirection_host(host_id)
    print_success(f"Redirection host {host_id} disabled")


# ============================================================================
# DEAD (404) Commands
# ============================================================================


@cli.group()
def dead():
    """404 host management commands."""
    pass


@dead.command("list")
@click.pass_context
def dead_list(ctx):
    """List all 404 hosts."""
    data = ctx.obj.client.list_dead_hosts()
    format_output(data, ctx.obj.output, ["id", "domain_names", "enabled"])


@dead.command("get")
@click.argument("host_id", type=int)
@click.pass_context
def dead_get(ctx, host_id):
    """Get 404 host details."""
    data = ctx.obj.client.get_dead_host(host_id)
    format_output(data, ctx.obj.output)


@dead.command("create")
@click.option("--domain", "-d", required=True, multiple=True, help="Domain name(s)")
@click.option("--ssl/--no-ssl", default=False)
@click.option("--cert-id", type=int, help="Certificate ID")
@click.pass_context
def dead_create(ctx, domain, ssl, cert_id):
    """Create a new 404 host."""
    data = {
        "domain_names": list(domain),
        "certificate_id": cert_id or 0,
        "ssl_forced": ssl,
        "hsts_enabled": False,
        "hsts_subdomains": False,
        "http2_support": False,
        "advanced_config": "",
        "meta": {},
    }
    result = ctx.obj.client.create_dead_host(data)
    print_success(f"404 host created with ID: {result['id']}")


@dead.command("delete")
@click.argument("host_id", type=int)
@click.confirmation_option(prompt="Are you sure?")
@click.pass_context
def dead_delete(ctx, host_id):
    """Delete a 404 host."""
    ctx.obj.client.delete_dead_host(host_id)
    print_success(f"404 host {host_id} deleted")


@dead.command("enable")
@click.argument("host_id", type=int)
@click.pass_context
def dead_enable(ctx, host_id):
    """Enable a 404 host."""
    ctx.obj.client.enable_dead_host(host_id)
    print_success(f"404 host {host_id} enabled")


@dead.command("disable")
@click.argument("host_id", type=int)
@click.pass_context
def dead_disable(ctx, host_id):
    """Disable a 404 host."""
    ctx.obj.client.disable_dead_host(host_id)
    print_success(f"404 host {host_id} disabled")


# ============================================================================
# STREAMS Commands
# ============================================================================


@cli.group()
def streams():
    """Stream (TCP/UDP) management commands."""
    pass


@streams.command("list")
@click.pass_context
def streams_list(ctx):
    """List all streams."""
    data = ctx.obj.client.list_streams()
    format_output(
        data, ctx.obj.output, ["id", "incoming_port", "forwarding_host", "forwarding_port", "enabled"]
    )


@streams.command("get")
@click.argument("stream_id", type=int)
@click.pass_context
def streams_get(ctx, stream_id):
    """Get stream details."""
    data = ctx.obj.client.get_stream(stream_id)
    format_output(data, ctx.obj.output)


@streams.command("create")
@click.option("--incoming-port", "-i", required=True, type=int, help="Incoming port")
@click.option("--forward-host", "-f", required=True, help="Forward hostname/IP")
@click.option("--forward-port", "-p", required=True, type=int, help="Forward port")
@click.option("--tcp/--udp", default=True, help="Protocol (default: TCP)")
@click.pass_context
def streams_create(ctx, incoming_port, forward_host, forward_port, tcp):
    """Create a new stream."""
    data = {
        "incoming_port": incoming_port,
        "forwarding_host": forward_host,
        "forwarding_port": forward_port,
        "tcp_forwarding": tcp,
        "udp_forwarding": not tcp,
        "meta": {},
    }
    result = ctx.obj.client.create_stream(data)
    print_success(f"Stream created with ID: {result['id']}")


@streams.command("delete")
@click.argument("stream_id", type=int)
@click.confirmation_option(prompt="Are you sure?")
@click.pass_context
def streams_delete(ctx, stream_id):
    """Delete a stream."""
    ctx.obj.client.delete_stream(stream_id)
    print_success(f"Stream {stream_id} deleted")


@streams.command("enable")
@click.argument("stream_id", type=int)
@click.pass_context
def streams_enable(ctx, stream_id):
    """Enable a stream."""
    ctx.obj.client.enable_stream(stream_id)
    print_success(f"Stream {stream_id} enabled")


@streams.command("disable")
@click.argument("stream_id", type=int)
@click.pass_context
def streams_disable(ctx, stream_id):
    """Disable a stream."""
    ctx.obj.client.disable_stream(stream_id)
    print_success(f"Stream {stream_id} disabled")


# ============================================================================
# CERTS Commands
# ============================================================================


@cli.group()
def certs():
    """Certificate management commands."""
    pass


@certs.command("list")
@click.pass_context
def certs_list(ctx):
    """List all certificates."""
    data = ctx.obj.client.list_certificates()
    format_output(data, ctx.obj.output, ["id", "nice_name", "domain_names", "provider", "expires_on"])


@certs.command("get")
@click.argument("cert_id", type=int)
@click.pass_context
def certs_get(ctx, cert_id):
    """Get certificate details."""
    data = ctx.obj.client.get_certificate(cert_id)
    format_output(data, ctx.obj.output)


@certs.command("create")
@click.option("--domain", "-d", required=True, multiple=True, help="Domain name(s)")
@click.option("--email", "-e", required=True, help="Let's Encrypt email")
@click.option("--dns-challenge/--http-challenge", default=False, help="Use DNS challenge")
@click.option("--dns-provider", help="DNS provider name")
@click.option("--dns-credentials", help="DNS provider credentials")
@click.option("--propagation-seconds", type=int, default=30, help="DNS propagation wait")
@click.pass_context
def certs_create(ctx, domain, email, dns_challenge, dns_provider, dns_credentials, propagation_seconds):
    """Create a new Let's Encrypt certificate."""
    data = {
        "provider": "letsencrypt",
        "domain_names": list(domain),
        "meta": {
            "letsencrypt_email": email,
            "letsencrypt_agree": True,
            "dns_challenge": dns_challenge,
        },
    }
    if dns_challenge and dns_provider:
        data["meta"]["dns_provider"] = dns_provider
        data["meta"]["dns_provider_credentials"] = dns_credentials or ""
        data["meta"]["propagation_seconds"] = propagation_seconds

    result = ctx.obj.client.create_certificate(data)
    print_success(f"Certificate created with ID: {result['id']}")
    format_output(result, ctx.obj.output)


@certs.command("download")
@click.argument("cert_id", type=int)
@click.option("--output", "-o", default=".", help="Output directory")
@click.pass_context
def certs_download(ctx, cert_id, output):
    """Download certificate files as ZIP."""
    import zipfile
    from io import BytesIO
    from pathlib import Path

    data = ctx.obj.client.download_certificate(cert_id)

    # Get cert info for folder name
    cert_info = ctx.obj.client.get_certificate(cert_id)
    cert_name = cert_info.get("nice_name", f"cert_{cert_id}")

    output_dir = Path(output) / cert_name
    output_dir.mkdir(parents=True, exist_ok=True)

    # Extract ZIP
    with zipfile.ZipFile(BytesIO(data)) as zf:
        zf.extractall(output_dir)

    print_success(f"Certificate downloaded to {output_dir}")
    for f in output_dir.iterdir():
        print_info(f"  {f.name}")


@certs.command("download-all")
@click.option("--output", "-o", default=".", help="Output directory")
@click.pass_context
def certs_download_all(ctx, output):
    """Download all certificates."""
    import zipfile
    from io import BytesIO
    from pathlib import Path

    certs = ctx.obj.client.list_certificates()
    print_info(f"Downloading {len(certs)} certificates...")

    for cert in certs:
        cert_id = cert["id"]
        cert_name = cert.get("nice_name", f"cert_{cert_id}")

        try:
            data = ctx.obj.client.download_certificate(cert_id)
            output_dir = Path(output) / cert_name
            output_dir.mkdir(parents=True, exist_ok=True)

            with zipfile.ZipFile(BytesIO(data)) as zf:
                zf.extractall(output_dir)

            print_success(f"Downloaded: {cert_name}")
        except Exception as e:
            print_error(f"Failed to download {cert_name}: {e}")

    print_success(f"All certificates downloaded to {output}")


@certs.command("renew")
@click.argument("cert_id", type=int)
@click.pass_context
def certs_renew(ctx, cert_id):
    """Renew a certificate."""
    result = ctx.obj.client.renew_certificate(cert_id)
    print_success(f"Certificate {cert_id} renewed")
    format_output(result, ctx.obj.output)


@certs.command("delete")
@click.argument("cert_id", type=int)
@click.confirmation_option(prompt="Are you sure you want to delete this certificate?")
@click.pass_context
def certs_delete(ctx, cert_id):
    """Delete a certificate."""
    ctx.obj.client.delete_certificate(cert_id)
    print_success(f"Certificate {cert_id} deleted")


@certs.command("dns-providers")
@click.pass_context
def certs_dns_providers(ctx):
    """List available DNS providers."""
    data = ctx.obj.client.list_dns_providers()
    format_output(data, ctx.obj.output)


@certs.command("test-http")
@click.option("--domain", "-d", required=True, help="Domain to test")
@click.pass_context
def certs_test_http(ctx, domain):
    """Test HTTP challenge for a domain."""
    result = ctx.obj.client.test_http_challenge(domain)
    format_output(result, ctx.obj.output)


# ============================================================================
# ACCESS Commands
# ============================================================================


@cli.group()
def access():
    """Access list management commands."""
    pass


@access.command("list")
@click.pass_context
def access_list(ctx):
    """List all access lists."""
    data = ctx.obj.client.list_access_lists()
    format_output(data, ctx.obj.output, ["id", "name", "satisfy_any"])


@access.command("get")
@click.argument("list_id", type=int)
@click.pass_context
def access_get(ctx, list_id):
    """Get access list details."""
    data = ctx.obj.client.get_access_list(list_id)
    format_output(data, ctx.obj.output)


@access.command("create")
@click.option("--name", required=True, help="Access list name")
@click.option("--satisfy-any/--satisfy-all", default=True)
@click.option("--pass-auth/--no-pass-auth", default=False)
@click.pass_context
def access_create(ctx, name, satisfy_any, pass_auth):
    """Create a new access list."""
    data = {
        "name": name,
        "satisfy_any": satisfy_any,
        "pass_auth": pass_auth,
        "items": [],
        "clients": [],
        "meta": {},
    }
    result = ctx.obj.client.create_access_list(data)
    print_success(f"Access list created with ID: {result['id']}")


@access.command("delete")
@click.argument("list_id", type=int)
@click.confirmation_option(prompt="Are you sure?")
@click.pass_context
def access_delete(ctx, list_id):
    """Delete an access list."""
    ctx.obj.client.delete_access_list(list_id)
    print_success(f"Access list {list_id} deleted")


# ============================================================================
# AUDIT Commands
# ============================================================================


@cli.group()
def audit():
    """Audit log commands."""
    pass


@audit.command("list")
@click.pass_context
def audit_list(ctx):
    """List audit log entries."""
    data = ctx.obj.client.list_audit_log()
    format_output(data, ctx.obj.output, ["id", "created_on", "object_type", "action", "meta"])


@audit.command("get")
@click.argument("entry_id", type=int)
@click.pass_context
def audit_get(ctx, entry_id):
    """Get audit log entry details."""
    data = ctx.obj.client.get_audit_entry(entry_id)
    format_output(data, ctx.obj.output)


# ============================================================================
# SETTINGS Commands
# ============================================================================


@cli.group()
def settings():
    """Settings management commands."""
    pass


@settings.command("list")
@click.pass_context
def settings_list(ctx):
    """List all settings."""
    data = ctx.obj.client.list_settings()
    format_output(data, ctx.obj.output, ["id", "name", "value"])


@settings.command("get")
@click.argument("setting_id")
@click.pass_context
def settings_get(ctx, setting_id):
    """Get setting value."""
    data = ctx.obj.client.get_setting(setting_id)
    format_output(data, ctx.obj.output)


@settings.command("set")
@click.argument("setting_id")
@click.argument("value")
@click.pass_context
def settings_set(ctx, setting_id, value):
    """Update a setting."""
    result = ctx.obj.client.update_setting(setting_id, {"value": value})
    print_success(f"Setting {setting_id} updated")


# ============================================================================
# REPORTS Commands
# ============================================================================


@cli.command("reports")
@click.pass_context
def reports(ctx):
    """Get host statistics report."""
    data = ctx.obj.client.get_host_report()
    format_output(data, ctx.obj.output)


# ============================================================================
# VERSION Command
# ============================================================================


@cli.command("version")
@click.pass_context
def version(ctx):
    """Show NPM server version."""
    if ctx.obj.client:
        status = ctx.obj.client.get_status()
        print_info(f"NPM Server Version: {status.get('version', 'unknown')}")
    print_info(f"NPM CLI Version: {__version__}")


if __name__ == "__main__":
    cli()
