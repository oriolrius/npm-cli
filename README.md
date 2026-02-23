# NPM CLI

Full-featured command-line interface for [Nginx Proxy Manager](https://nginxproxymanager.com/).

Manage proxy hosts, SSL certificates, streams, users, and more - all from your terminal.

## Features

- **100% GUI Coverage** - Every feature available in the web UI is accessible via CLI
- **Multiple Output Formats** - Table, JSON, or YAML output
- **Multi-Server Support** - Manage multiple NPM instances with profiles
- **Secure Credential Storage** - Token caching with proper permissions
- **Shell Completion** - Bash, Zsh, and Fish support

## Installation

```bash
# Using uv (recommended)
uv pip install git+https://github.com/oriolrius/npm-cli.git

# From source with uv
git clone https://github.com/oriolrius/npm-cli.git
cd npm-cli
uv sync

# Using pip
pip install git+https://github.com/oriolrius/npm-cli.git
```

## Quick Start

```bash
# Login to your NPM server
npm-cli auth login --url http://npm.example.com:81 --user admin@example.com

# List all proxy hosts
npm-cli proxy list

# Create a new proxy host
npm-cli proxy create \
  --domain app.example.com \
  --forward-host 192.168.1.10 \
  --forward-port 3000 \
  --ssl --cert-id 5

# Download all certificates
npm-cli certs download-all --output ./certs/
```

## Commands

### Authentication
```bash
npm-cli auth login      # Interactive login
npm-cli auth logout     # Clear saved token
npm-cli auth status     # Check authentication status
npm-cli auth token      # Print current token
```

### Proxy Hosts
```bash
npm-cli proxy list                    # List all proxy hosts
npm-cli proxy get <id>                # Get details
npm-cli proxy create [OPTIONS]        # Create new proxy host
npm-cli proxy update <id> [OPTIONS]   # Update proxy host
npm-cli proxy delete <id>             # Delete proxy host
npm-cli proxy enable <id>             # Enable proxy host
npm-cli proxy disable <id>            # Disable proxy host
```

### Redirection Hosts
```bash
npm-cli redirect list                 # List redirections
npm-cli redirect get <id>             # Get details
npm-cli redirect create [OPTIONS]     # Create redirection
npm-cli redirect delete <id>          # Delete redirection
npm-cli redirect enable <id>          # Enable
npm-cli redirect disable <id>         # Disable
```

### 404 Hosts
```bash
npm-cli dead list                     # List 404 hosts
npm-cli dead get <id>                 # Get details
npm-cli dead create [OPTIONS]         # Create 404 host
npm-cli dead delete <id>              # Delete
npm-cli dead enable <id>              # Enable
npm-cli dead disable <id>             # Disable
```

### Streams (TCP/UDP)
```bash
npm-cli streams list                  # List streams
npm-cli streams get <id>              # Get details
npm-cli streams create [OPTIONS]      # Create stream
npm-cli streams delete <id>           # Delete stream
npm-cli streams enable <id>           # Enable
npm-cli streams disable <id>          # Disable
```

### Certificates
```bash
npm-cli certs list                    # List certificates
npm-cli certs get <id>                # Get details
npm-cli certs create [OPTIONS]        # Create Let's Encrypt cert
npm-cli certs download <id>           # Download cert files
npm-cli certs download-all            # Download all certs
npm-cli certs renew <id>              # Renew certificate
npm-cli certs delete <id>             # Delete certificate
npm-cli certs dns-providers           # List DNS providers
npm-cli certs test-http --domain X    # Test HTTP challenge
```

### Access Lists
```bash
npm-cli access list                   # List access lists
npm-cli access get <id>               # Get details
npm-cli access create [OPTIONS]       # Create access list
npm-cli access delete <id>            # Delete access list
```

### Users
```bash
npm-cli users list                    # List users
npm-cli users get <id>                # Get details
npm-cli users create [OPTIONS]        # Create user
npm-cli users delete <id>             # Delete user
npm-cli users permissions <id>        # Show permissions
```

### Other
```bash
npm-cli settings list                 # List settings
npm-cli settings get <id>             # Get setting
npm-cli settings set <id> <value>     # Update setting
npm-cli audit list                    # List audit log
npm-cli audit get <id>                # Get audit entry
npm-cli reports                       # Host statistics
npm-cli version                       # Show versions
```

## Configuration

### Environment Variables
```bash
export NPM_URL=http://npm.example.com:81
export NPM_USER=admin@example.com
export NPM_PASS=yourpassword
export NPM_TOKEN=your-jwt-token
```

### Config File (~/.npm-cli.yaml)
```yaml
default_server: production

servers:
  production:
    url: http://npm.example.com:81
    user: admin@example.com
  staging:
    url: http://npm-staging.example.com:81
    user: admin@example.com

output: table
```

### Server Selection
```bash
npm-cli --server production proxy list
npm-cli --server staging certs list
```

## Output Formats

```bash
# Table (default)
npm-cli proxy list

# JSON
npm-cli --output json proxy list

# YAML
npm-cli --output yaml proxy list

# Combine with jq
npm-cli -o json proxy list | jq '.[] | select(.enabled == false)'
```

## Examples

### Create a proxy with SSL
```bash
npm-cli proxy create \
  --domain api.example.com \
  --forward-host 192.168.1.100 \
  --forward-port 8080 \
  --scheme http \
  --ssl \
  --cert-id 5 \
  --force-ssl \
  --http2 \
  --websocket \
  --block-exploits
```

### Create Let's Encrypt certificate
```bash
npm-cli certs create \
  --domain new.example.com \
  --email admin@example.com
```

### Create certificate with DNS challenge
```bash
npm-cli certs create \
  --domain "*.example.com" \
  --email admin@example.com \
  --dns-challenge \
  --dns-provider cloudflare \
  --dns-credentials "dns_cloudflare_api_token=YOUR_TOKEN"
```

### Create TCP stream
```bash
npm-cli streams create \
  --incoming-port 3306 \
  --forward-host 192.168.1.50 \
  --forward-port 3306 \
  --tcp
```

### Batch disable all hosts
```bash
npm-cli -o json proxy list | jq -r '.[].id' | xargs -I {} npm-cli proxy disable {}
```

## Development

```bash
# Clone
git clone https://github.com/oriolrius/npm-cli.git
cd npm-cli

# Install with uv (recommended)
uv sync --all-extras

# Or with pip
pip install -e ".[dev]"

# Run tests
pytest

# Format code
ruff format src/
ruff check src/ --fix

# Type check
mypy src/
```

## License

MIT License - see [LICENSE](LICENSE) file.

## Author

Oriol Rius ([@oriolrius](https://github.com/oriolrius))
