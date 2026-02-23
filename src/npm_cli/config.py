"""Configuration management for NPM CLI."""

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel


class ServerConfig(BaseModel):
    """Server configuration."""

    url: str
    user: str | None = None
    token: str | None = None


class Config(BaseModel):
    """Main configuration."""

    default_server: str = "default"
    servers: dict[str, ServerConfig] = {}
    output: str = "table"


CONFIG_PATH = Path.home() / ".npm-cli.yaml"
TOKEN_CACHE_PATH = Path.home() / ".npm-cli-tokens.yaml"


def load_config() -> Config:
    """Load configuration from file."""
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            data = yaml.safe_load(f) or {}
        return Config(**data)
    return Config()


def save_config(config: Config) -> None:
    """Save configuration to file."""
    with open(CONFIG_PATH, "w") as f:
        yaml.dump(config.model_dump(), f, default_flow_style=False)


def load_tokens() -> dict[str, str]:
    """Load cached tokens."""
    if TOKEN_CACHE_PATH.exists():
        with open(TOKEN_CACHE_PATH) as f:
            return yaml.safe_load(f) or {}
    return {}


def save_token(server_key: str, token: str) -> None:
    """Save token for a server."""
    tokens = load_tokens()
    tokens[server_key] = token
    TOKEN_CACHE_PATH.touch(mode=0o600)
    with open(TOKEN_CACHE_PATH, "w") as f:
        yaml.dump(tokens, f)


def clear_token(server_key: str) -> None:
    """Clear token for a server."""
    tokens = load_tokens()
    tokens.pop(server_key, None)
    with open(TOKEN_CACHE_PATH, "w") as f:
        yaml.dump(tokens, f)


def get_server_config(
    url: str | None = None,
    user: str | None = None,
    password: str | None = None,
    token: str | None = None,
    server: str | None = None,
) -> tuple[str, str | None, str | None, str | None]:
    """Get server configuration from args, env, or config file."""
    config = load_config()
    tokens = load_tokens()

    # Determine server key
    server_key = server or config.default_server

    # Get from config if exists
    server_cfg = config.servers.get(server_key, ServerConfig(url=""))

    # Priority: CLI args > env vars > config file
    final_url = url or os.environ.get("NPM_URL") or server_cfg.url
    final_user = user or os.environ.get("NPM_USER") or server_cfg.user
    final_password = password or os.environ.get("NPM_PASS")
    final_token = token or os.environ.get("NPM_TOKEN") or tokens.get(server_key)

    return final_url, final_user, final_password, final_token
