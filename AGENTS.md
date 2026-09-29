# NPM CLI - Claude Code Guidelines

## Project Overview

Full-featured Python CLI for Nginx Proxy Manager (NPM). Wraps the NPM REST API into a `click`-based CLI with rich terminal output.

## Quick Reference

- **Entry point**: `src/npm_cli/main.py` → `cli()` function
- **Package name**: `npm-cli` (import as `npm_cli`)
- **Version**: Defined in `src/npm_cli/__init__.py`
- **Config files**: `~/.npm-cli.yaml` (server profiles), `~/.npm-cli-tokens.yaml` (JWT tokens)

## Build & Run

```bash
uv sync                          # Install dependencies
uv run npm-cli --help            # Run the CLI
uv run npm-cli auth login --url http://npm:81 --user admin@example.com
```

## Development

```bash
uv sync --extra dev              # Install dev dependencies
uv run pytest                    # Run tests (if any)
uv run black src/                # Format code
uv run ruff check src/           # Lint
uv run mypy src/                 # Type check
```

## Code Style

- **Formatter**: black (line-length 100)
- **Linter**: ruff (line-length 100, rules: E, F, W, I, UP, B, C4)
- **Type checking**: mypy (strict mode, Python 3.9 target)
- **Python target**: 3.9+ (use `str | None` syntax — requires `from __future__ import annotations` for 3.9 compat, currently not used)

## Architecture

```
src/npm_cli/
├── __init__.py   - Version string only
├── main.py       - All Click command groups and commands
├── client.py     - NPMClient: httpx-based API client with typed methods
├── config.py     - Pydantic config models, YAML persistence, token management
└── output.py     - Rich-based formatters (table, JSON, YAML, status messages)
```

## Key Patterns

- **CLI framework**: Click with `@click.group()` / `@click.command()` decorators
- **Context passing**: Custom `Context` object via `click.make_pass_decorator`
- **HTTP client**: `httpx.Client` (sync), all requests go through `NPMClient._request()`
- **Output**: `format_output(data, format, columns)` handles table/JSON/YAML rendering
- **Config priority**: CLI args > env vars (`NPM_URL`, `NPM_USER`, `NPM_PASS`, `NPM_TOKEN`) > config file
- **Multi-server**: `--server/-s` flag selects a named server profile

## API Reference

The `openapi-schema.json` file contains the full Nginx Proxy Manager API spec. Consult it when adding new endpoints or verifying request/response shapes.

## Versioning

Bump version in `src/npm_cli/__init__.py` — it's the single source of truth (referenced by `pyproject.toml` indirectly via hatchling).
