# npm_cli Package - Claude Code Guidelines

## Module Responsibilities

| Module | Role | Key class/function |
|--------|------|-------------------|
| `main.py` | CLI commands (Click groups) | `cli()`, command groups: `auth`, `users`, `proxy`, `redirect`, `dead`, `streams`, `certs`, `access`, `audit`, `settings` |
| `client.py` | HTTP API wrapper | `NPMClient` — all API calls, auth, file upload/download |
| `config.py` | Config & token persistence | `Config`, `ServerConfig`, `get_server_config()`, `save_token()` |
| `output.py` | Terminal output formatting | `format_output()`, `print_table()`, `print_dict()`, `print_success/error/warning/info()` |

## Adding a New Command

1. Add the API method to `NPMClient` in `client.py` (follow existing pattern: thin wrapper around `self.get/post/put/delete`)
2. Add the Click command in `main.py` under the appropriate `@group.command()` section
3. Use `format_output(data, ctx.obj.output, columns)` for displaying results
4. Use `print_success()` / `print_error()` for status messages

## Adding a New Command Group

1. Create the group with `@cli.group()` in `main.py`
2. Add commands under it with `@group.command("name")`
3. Follow the section separator pattern (`# === GROUP Commands ===`)

## Conventions

- All CLI commands receive context via `@click.pass_context` and access the client as `ctx.obj.client`
- Destructive commands (delete) use `@click.confirmation_option`
- Boolean flags use `--flag/--no-flag` pattern with sensible defaults
- Multiple values use `multiple=True` (e.g., `--domain/-d`)
- The client does NOT raise custom exceptions — it relies on `httpx` status errors (`resp.raise_for_status()`)

## Known Gaps

- Client has `update_*` methods for users, redirections, dead hosts, streams, and access lists — but no corresponding CLI `update` commands exist yet
- `keyring` is declared as a dependency but unused
- `print_warning` is defined in `output.py` but not imported in `main.py` (used in `auth_status`)
- No null-check on `ctx.obj.client` before calling API methods — commands crash with `AttributeError` if not authenticated
