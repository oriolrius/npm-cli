# NPM CLI Design

## Overview

Full-featured CLI for Nginx Proxy Manager covering 100% of GUI functionality.

## Command Structure

```
npm-cli [OPTIONS] COMMAND [ARGS]

Options:
  --url URL          NPM server URL (or NPM_URL env)
  --user EMAIL       NPM username (or NPM_USER env)
  --password PASS    NPM password (or NPM_PASS env)
  --token TOKEN      JWT token (or NPM_TOKEN env)
  --output FORMAT    Output format: table, json, yaml (default: table)
  --quiet            Suppress non-essential output
  --version          Show version
  --help             Show help
```

## Commands

### Authentication
```
npm-cli auth login                    # Interactive login, saves token
npm-cli auth logout                   # Clear saved token
npm-cli auth status                   # Show current auth status
npm-cli auth token                    # Print current token
```

### Users
```
npm-cli users list                    # List all users
npm-cli users get <id>                # Get user details
npm-cli users create                  # Create user (interactive)
npm-cli users update <id>             # Update user
npm-cli users delete <id>             # Delete user
npm-cli users permissions <id>        # Show/set permissions
npm-cli users 2fa enable <id>         # Enable 2FA
npm-cli users 2fa disable <id>        # Disable 2FA
npm-cli users 2fa backup-codes <id>   # Get backup codes
```

### Proxy Hosts
```
npm-cli proxy list                    # List all proxy hosts
npm-cli proxy get <id>                # Get proxy host details
npm-cli proxy create                  # Create proxy host
  --domain DOMAIN                     # Domain name(s), comma-separated
  --forward-host HOST                 # Forward hostname/IP
  --forward-port PORT                 # Forward port
  --scheme http|https                 # Forward scheme
  --ssl                               # Enable SSL
  --cert-id ID                        # Certificate ID
  --force-ssl                         # Force SSL
  --http2                             # Enable HTTP/2
  --block-exploits                    # Block common exploits
  --websocket                         # Enable websocket support
  --access-list ID                    # Access list ID
  --advanced-config CONFIG            # Custom Nginx config
npm-cli proxy update <id>             # Update proxy host
npm-cli proxy delete <id>             # Delete proxy host
npm-cli proxy enable <id>             # Enable proxy host
npm-cli proxy disable <id>            # Disable proxy host
```

### Redirection Hosts
```
npm-cli redirect list                 # List all redirections
npm-cli redirect get <id>             # Get redirection details
npm-cli redirect create               # Create redirection
  --domain DOMAIN                     # Domain name(s)
  --forward-url URL                   # Target URL
  --scheme auto|http|https            # Redirect scheme
  --http-code 301|302|303|307|308     # HTTP redirect code
  --ssl                               # Enable SSL
  --cert-id ID                        # Certificate ID
  --preserve-path                     # Preserve path in redirect
  --block-exploits                    # Block common exploits
npm-cli redirect update <id>          # Update redirection
npm-cli redirect delete <id>          # Delete redirection
npm-cli redirect enable <id>          # Enable redirection
npm-cli redirect disable <id>         # Disable redirection
```

### 404 Hosts (Dead Hosts)
```
npm-cli dead list                     # List all 404 hosts
npm-cli dead get <id>                 # Get 404 host details
npm-cli dead create                   # Create 404 host
  --domain DOMAIN                     # Domain name(s)
  --ssl                               # Enable SSL
  --cert-id ID                        # Certificate ID
npm-cli dead update <id>              # Update 404 host
npm-cli dead delete <id>              # Delete 404 host
npm-cli dead enable <id>              # Enable 404 host
npm-cli dead disable <id>             # Disable 404 host
```

### Streams (TCP/UDP)
```
npm-cli streams list                  # List all streams
npm-cli streams get <id>              # Get stream details
npm-cli streams create                # Create stream
  --incoming-port PORT                # Incoming port
  --forward-host HOST                 # Forward hostname/IP
  --forward-port PORT                 # Forward port
  --protocol tcp|udp                  # Protocol (default: tcp)
npm-cli streams update <id>           # Update stream
npm-cli streams delete <id>           # Delete stream
npm-cli streams enable <id>           # Enable stream
npm-cli streams disable <id>          # Disable stream
```

### Certificates
```
npm-cli certs list                    # List all certificates
npm-cli certs get <id>                # Get certificate details
npm-cli certs create                  # Create Let's Encrypt cert
  --domain DOMAIN                     # Domain name(s), comma-separated
  --email EMAIL                       # Let's Encrypt email
  --dns-challenge                     # Use DNS challenge
  --dns-provider PROVIDER             # DNS provider name
  --dns-credentials CREDS             # DNS provider credentials
  --propagation-seconds SEC           # DNS propagation wait time
npm-cli certs upload <id>             # Upload custom certificate
  --cert FILE                         # Certificate file
  --key FILE                          # Private key file
  --chain FILE                        # Chain file (optional)
npm-cli certs download <id>           # Download certificate
  --output DIR                        # Output directory
npm-cli certs renew <id>              # Renew certificate
npm-cli certs delete <id>             # Delete certificate
npm-cli certs test-http               # Test HTTP challenge
  --domain DOMAIN                     # Domain to test
npm-cli certs validate                # Validate certificate
npm-cli certs dns-providers           # List DNS providers
```

### Access Lists
```
npm-cli access list                   # List all access lists
npm-cli access get <id>               # Get access list details
npm-cli access create                 # Create access list
  --name NAME                         # Access list name
  --satisfy any|all                   # Satisfy condition
  --pass-auth                         # Pass auth to upstream
  --items USER:PASS,...               # Auth items
  --clients allow:IP,deny:IP,...      # Client rules
npm-cli access update <id>            # Update access list
npm-cli access delete <id>            # Delete access list
```

### Audit Log
```
npm-cli audit list                    # List audit log entries
  --limit N                           # Limit entries
  --offset N                          # Offset for pagination
npm-cli audit get <id>                # Get audit entry details
```

### Settings
```
npm-cli settings list                 # List all settings
npm-cli settings get <id>             # Get setting value
npm-cli settings set <id> <value>     # Update setting
```

### Reports
```
npm-cli reports hosts                 # Host statistics report
```

### Utility
```
npm-cli version                       # Show NPM server version
npm-cli schema                        # Download OpenAPI schema
npm-cli completion                    # Generate shell completion
  --shell bash|zsh|fish               # Shell type
```

## Configuration

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

### Environment Variables
```
NPM_URL       - Server URL
NPM_USER      - Username/email
NPM_PASS      - Password
NPM_TOKEN     - JWT token (cached)
```

### Server Selection
```
npm-cli --server production proxy list
npm-cli --server staging certs list
```

## Output Formats

### Table (default)
```
ID  │ Domain           │ Forward              │ SSL │ Status
────┼──────────────────┼──────────────────────┼─────┼────────
1   │ app.example.com  │ http://192.168.1.10  │ ✓   │ enabled
2   │ api.example.com  │ http://192.168.1.11  │ ✓   │ enabled
```

### JSON
```json
[{"id": 1, "domain": "app.example.com", ...}]
```

### YAML
```yaml
- id: 1
  domain: app.example.com
```

## Examples

```bash
# Login and save credentials
npm-cli auth login --url http://npm.example.com:81 --user admin@example.com

# List all proxy hosts
npm-cli proxy list

# Create a new proxy host with SSL
npm-cli proxy create \
  --domain app.example.com \
  --forward-host 192.168.1.10 \
  --forward-port 3000 \
  --ssl --cert-id 5 --force-ssl

# Download certificate
npm-cli certs download 5 --output ./certs/

# Create Let's Encrypt certificate
npm-cli certs create --domain new.example.com --email admin@example.com

# Batch operations with JSON output
npm-cli --output json proxy list | jq '.[] | select(.enabled == false)'
```
