"""NPM API Client."""

from typing import Any

import httpx

from .config import save_token


class NPMClient:
    """Nginx Proxy Manager API client."""

    def __init__(self, url: str, token: str | None = None):
        """Initialize client."""
        self.base_url = url.rstrip("/")
        self.token = token
        self._client = httpx.Client(timeout=30.0)

    def _headers(self) -> dict[str, str]:
        """Get request headers."""
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _request(
        self,
        method: str,
        endpoint: str,
        json: dict | None = None,
        params: dict | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Make API request."""
        url = f"{self.base_url}/api{endpoint}"
        response = self._client.request(
            method, url, headers=self._headers(), json=json, params=params, **kwargs
        )
        return response

    def get(self, endpoint: str, params: dict | None = None) -> Any:
        """GET request."""
        resp = self._request("GET", endpoint, params=params)
        resp.raise_for_status()
        return resp.json()

    def post(self, endpoint: str, json: dict | None = None) -> Any:
        """POST request."""
        resp = self._request("POST", endpoint, json=json)
        resp.raise_for_status()
        return resp.json()

    def put(self, endpoint: str, json: dict | None = None) -> Any:
        """PUT request."""
        resp = self._request("PUT", endpoint, json=json)
        resp.raise_for_status()
        return resp.json()

    def delete(self, endpoint: str) -> bool:
        """DELETE request."""
        resp = self._request("DELETE", endpoint)
        resp.raise_for_status()
        return True

    def download(self, endpoint: str) -> bytes:
        """Download binary content."""
        resp = self._request("GET", endpoint)
        resp.raise_for_status()
        return resp.content

    def upload(self, endpoint: str, files: dict) -> Any:
        """Upload files."""
        url = f"{self.base_url}/api{endpoint}"
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        resp = self._client.post(url, headers=headers, files=files)
        resp.raise_for_status()
        return resp.json()

    # Authentication
    def login(self, identity: str, secret: str, server_key: str = "default") -> str:
        """Login and get token."""
        resp = self.post("/tokens", {"identity": identity, "secret": secret})
        self.token = resp["token"]
        save_token(server_key, self.token)
        return self.token

    def refresh_token(self) -> str:
        """Refresh current token."""
        resp = self.get("/tokens")
        self.token = resp["token"]
        return self.token

    # Status
    def get_status(self) -> dict:
        """Get API status."""
        return self.get("/")

    # Users
    def list_users(self) -> list:
        """List all users."""
        return self.get("/users")

    def get_user(self, user_id: int) -> dict:
        """Get user by ID."""
        return self.get(f"/users/{user_id}")

    def create_user(self, data: dict) -> dict:
        """Create user."""
        return self.post("/users", data)

    def update_user(self, user_id: int, data: dict) -> dict:
        """Update user."""
        return self.put(f"/users/{user_id}", data)

    def delete_user(self, user_id: int) -> bool:
        """Delete user."""
        return self.delete(f"/users/{user_id}")

    def get_user_permissions(self, user_id: int) -> dict:
        """Get user permissions."""
        return self.get(f"/users/{user_id}/permissions")

    def update_user_permissions(self, user_id: int, data: dict) -> dict:
        """Update user permissions."""
        return self.put(f"/users/{user_id}/permissions", data)

    # Proxy Hosts
    def list_proxy_hosts(self) -> list:
        """List all proxy hosts."""
        return self.get("/nginx/proxy-hosts")

    def get_proxy_host(self, host_id: int) -> dict:
        """Get proxy host by ID."""
        return self.get(f"/nginx/proxy-hosts/{host_id}")

    def create_proxy_host(self, data: dict) -> dict:
        """Create proxy host."""
        return self.post("/nginx/proxy-hosts", data)

    def update_proxy_host(self, host_id: int, data: dict) -> dict:
        """Update proxy host."""
        return self.put(f"/nginx/proxy-hosts/{host_id}", data)

    def delete_proxy_host(self, host_id: int) -> bool:
        """Delete proxy host."""
        return self.delete(f"/nginx/proxy-hosts/{host_id}")

    def enable_proxy_host(self, host_id: int) -> dict:
        """Enable proxy host."""
        return self.post(f"/nginx/proxy-hosts/{host_id}/enable")

    def disable_proxy_host(self, host_id: int) -> dict:
        """Disable proxy host."""
        return self.post(f"/nginx/proxy-hosts/{host_id}/disable")

    # Redirection Hosts
    def list_redirection_hosts(self) -> list:
        """List all redirection hosts."""
        return self.get("/nginx/redirection-hosts")

    def get_redirection_host(self, host_id: int) -> dict:
        """Get redirection host by ID."""
        return self.get(f"/nginx/redirection-hosts/{host_id}")

    def create_redirection_host(self, data: dict) -> dict:
        """Create redirection host."""
        return self.post("/nginx/redirection-hosts", data)

    def update_redirection_host(self, host_id: int, data: dict) -> dict:
        """Update redirection host."""
        return self.put(f"/nginx/redirection-hosts/{host_id}", data)

    def delete_redirection_host(self, host_id: int) -> bool:
        """Delete redirection host."""
        return self.delete(f"/nginx/redirection-hosts/{host_id}")

    def enable_redirection_host(self, host_id: int) -> dict:
        """Enable redirection host."""
        return self.post(f"/nginx/redirection-hosts/{host_id}/enable")

    def disable_redirection_host(self, host_id: int) -> dict:
        """Disable redirection host."""
        return self.post(f"/nginx/redirection-hosts/{host_id}/disable")

    # Dead Hosts (404)
    def list_dead_hosts(self) -> list:
        """List all dead hosts."""
        return self.get("/nginx/dead-hosts")

    def get_dead_host(self, host_id: int) -> dict:
        """Get dead host by ID."""
        return self.get(f"/nginx/dead-hosts/{host_id}")

    def create_dead_host(self, data: dict) -> dict:
        """Create dead host."""
        return self.post("/nginx/dead-hosts", data)

    def update_dead_host(self, host_id: int, data: dict) -> dict:
        """Update dead host."""
        return self.put(f"/nginx/dead-hosts/{host_id}", data)

    def delete_dead_host(self, host_id: int) -> bool:
        """Delete dead host."""
        return self.delete(f"/nginx/dead-hosts/{host_id}")

    def enable_dead_host(self, host_id: int) -> dict:
        """Enable dead host."""
        return self.post(f"/nginx/dead-hosts/{host_id}/enable")

    def disable_dead_host(self, host_id: int) -> dict:
        """Disable dead host."""
        return self.post(f"/nginx/dead-hosts/{host_id}/disable")

    # Streams
    def list_streams(self) -> list:
        """List all streams."""
        return self.get("/nginx/streams")

    def get_stream(self, stream_id: int) -> dict:
        """Get stream by ID."""
        return self.get(f"/nginx/streams/{stream_id}")

    def create_stream(self, data: dict) -> dict:
        """Create stream."""
        return self.post("/nginx/streams", data)

    def update_stream(self, stream_id: int, data: dict) -> dict:
        """Update stream."""
        return self.put(f"/nginx/streams/{stream_id}", data)

    def delete_stream(self, stream_id: int) -> bool:
        """Delete stream."""
        return self.delete(f"/nginx/streams/{stream_id}")

    def enable_stream(self, stream_id: int) -> dict:
        """Enable stream."""
        return self.post(f"/nginx/streams/{stream_id}/enable")

    def disable_stream(self, stream_id: int) -> dict:
        """Disable stream."""
        return self.post(f"/nginx/streams/{stream_id}/disable")

    # Certificates
    def list_certificates(self) -> list:
        """List all certificates."""
        return self.get("/nginx/certificates")

    def get_certificate(self, cert_id: int) -> dict:
        """Get certificate by ID."""
        return self.get(f"/nginx/certificates/{cert_id}")

    def create_certificate(self, data: dict) -> dict:
        """Create certificate."""
        return self.post("/nginx/certificates", data)

    def delete_certificate(self, cert_id: int) -> bool:
        """Delete certificate."""
        return self.delete(f"/nginx/certificates/{cert_id}")

    def download_certificate(self, cert_id: int) -> bytes:
        """Download certificate as ZIP."""
        return self.download(f"/nginx/certificates/{cert_id}/download")

    def renew_certificate(self, cert_id: int) -> dict:
        """Renew certificate."""
        return self.post(f"/nginx/certificates/{cert_id}/renew")

    def upload_certificate(self, cert_id: int, cert_file: str, key_file: str) -> dict:
        """Upload custom certificate."""
        with open(cert_file, "rb") as cf, open(key_file, "rb") as kf:
            files = {
                "certificate": ("certificate.pem", cf),
                "certificate_key": ("certificate_key.pem", kf),
            }
            return self.upload(f"/nginx/certificates/{cert_id}/upload", files)

    def list_dns_providers(self) -> list:
        """List DNS providers."""
        return self.get("/nginx/certificates/dns-providers")

    def test_http_challenge(self, domain: str) -> dict:
        """Test HTTP challenge for domain."""
        return self.post("/nginx/certificates/test-http", {"domain": domain})

    def validate_certificate(self, data: dict) -> dict:
        """Validate certificate."""
        return self.post("/nginx/certificates/validate", data)

    # Access Lists
    def list_access_lists(self) -> list:
        """List all access lists."""
        return self.get("/nginx/access-lists")

    def get_access_list(self, list_id: int) -> dict:
        """Get access list by ID."""
        return self.get(f"/nginx/access-lists/{list_id}")

    def create_access_list(self, data: dict) -> dict:
        """Create access list."""
        return self.post("/nginx/access-lists", data)

    def update_access_list(self, list_id: int, data: dict) -> dict:
        """Update access list."""
        return self.put(f"/nginx/access-lists/{list_id}", data)

    def delete_access_list(self, list_id: int) -> bool:
        """Delete access list."""
        return self.delete(f"/nginx/access-lists/{list_id}")

    # Audit Log
    def list_audit_log(self) -> list:
        """List audit log entries."""
        return self.get("/audit-log")

    def get_audit_entry(self, entry_id: int) -> dict:
        """Get audit log entry."""
        return self.get(f"/audit-log/{entry_id}")

    # Settings
    def list_settings(self) -> list:
        """List all settings."""
        return self.get("/settings")

    def get_setting(self, setting_id: str) -> dict:
        """Get setting by ID."""
        return self.get(f"/settings/{setting_id}")

    def update_setting(self, setting_id: str, data: dict) -> dict:
        """Update setting."""
        return self.put(f"/settings/{setting_id}", data)

    # Reports
    def get_host_report(self) -> dict:
        """Get host statistics report."""
        return self.get("/reports/hosts")
