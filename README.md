# Isilon MCP Server

[![PyPI version](https://badge.fury.io/py/isilon-mcp-server.svg)](https://badge.fury.io/py/isilon-mcp-server)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://github.com/sachdev27/isilon-mcp-server/workflows/Tests/badge.svg)](https://github.com/sachdev27/isilon-mcp-server/actions)
[![codecov](https://codecov.io/gh/sachdev27/isilon-mcp-server/branch/main/graph/badge.svg)](https://codecov.io/gh/sachdev27/isilon-mcp-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A professional-grade **Model Context Protocol (MCP) server** for Dell PowerScale (Isilon) OneFS API integration. This server enables AI assistants like Claude to interact with PowerScale storage clusters through a comprehensive set of tools generated from the OneFS 9.7 REST API specification.

## Features

- 🚀 **Complete API Coverage**: 2,434 operations across 46 categories
- 🔐 **Secure Authentication**: Basic Auth with TLS support
- 📦 **Dynamic Tool Generation**: Auto-generates MCP tools from OpenAPI spec
- 🔄 **Multiple Transports**: stdio (Claude Desktop) and HTTP/SSE (n8n)
- 📝 **Comprehensive Logging**: Structured JSON and colored console output
- ⚡ **Async/Await**: Built on httpx for high-performance async operations
- 🛡️ **Credential-Free Mode**: Explore available tools without credentials

## Supported API Categories

| Category | Operations | Description |
|----------|------------|-------------|
| Auth | 373 | Authentication, users, groups, roles, providers |
| Protocols | 351 | SMB, NFS, HDFS, S3, HTTP, FTP, Swift |
| Sync | 185 | SyncIQ replication policies, reports, jobs |
| Cluster | 167 | Cluster management, nodes, configuration |
| Network | 153 | Networking, subnets, pools, interfaces |
| Datamover | 151 | Data migration, accounts, policies |
| Cloud | 136 | CloudPools, tiering, accounts |
| Snapshot | 117 | Snapshot schedules, aliases, locks |
| Upgrade | 85 | Cluster upgrade management |
| Event | 83 | Event channels, alerts, settings |
| Quota | 78 | SmartQuotas management |
| Job | 72 | Job engine, policies, reports |
| ... | ... | And 34 more categories! |

## Quick Start

### Prerequisites

- Python 3.10 or higher
- Access to a Dell PowerScale cluster with REST API enabled
- API credentials with appropriate permissions

### Installation

#### From PyPI (Recommended)

```bash
# Install the package
pip install isilon-mcp-server

# Or install with HTTP server support for n8n
pip install "isilon-mcp-server[http]"
```

#### From Source

```bash
# Clone the repository
git clone https://github.com/sachdev27/isilon-mcp-server.git
cd isilon-mcp-server

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the package
pip install -e .

# Or install with HTTP server support for n8n
pip install -e ".[http]"
```

### Configuration

1. Copy the example environment file:
```bash
cp .env.example .env
```

2. Edit `.env` with your PowerScale credentials:
```env
ISILON_HOST=your-powerscale-host
ISILON_USERNAME=admin
ISILON_PASSWORD=your-secure-password
ISILON_PORT=8080
ISILON_TLS_VERIFY=true
```

### Running the Server

#### stdio Transport (for Claude Desktop)

```bash
# Using the CLI
isilon-mcp

# Or using Python module
python -m isilon_mcp.main
```

#### HTTP/SSE Transport (for n8n or web clients)

```bash
# Start HTTP server
python -m isilon_mcp.http_server

# With custom host/port
python -m isilon_mcp.http_server --host 0.0.0.0 --port 8000
```

## Claude Desktop Integration

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "isilon": {
      "command": "/path/to/venv/bin/python",
      "args": ["-m", "isilon_mcp.main"],
      "cwd": "/path/to/isilon-mcp-server",
      "env": {
        "ISILON_HOST": "your-powerscale-host",
        "ISILON_USERNAME": "admin",
        "ISILON_PASSWORD": "your-password"
      }
    }
  }
}
```

## n8n Integration

1. Start the HTTP server:
```bash
python -m isilon_mcp.http_server --host 0.0.0.0 --port 8000
```

2. In n8n, add an MCP Client node pointing to:
```
http://localhost:8000/sse
```

## Example Usage

Once connected, you can ask Claude to:

- "List all SMB shares on the cluster"
- "Show me the cluster health status"
- "Create a new NFS export for /ifs/data/project1"
- "Get all snapshots older than 30 days"
- "Show active SyncIQ policies"
- "List users in the local provider"

## Project Structure

```
isilon-mcp-server/
├── isilon_mcp/
│   ├── __init__.py          # Package exports
│   ├── api_client.py        # Async HTTP client with Basic Auth
│   ├── config.py            # Pydantic configuration models
│   ├── exceptions.py        # Exception hierarchy
│   ├── http_server.py       # HTTP/SSE transport for n8n
│   ├── logging_config.py    # Structured logging
│   ├── main.py              # CLI entry point (stdio)
│   ├── server.py            # Core MCP server
│   └── tool_generator.py    # OpenAPI to MCP tool generator
├── powerscale_9.7_comprehensive_openapi.json  # Full API spec
├── pyproject.toml           # Package configuration
├── requirements-mcp.txt     # Dependencies
├── .env.example             # Configuration template
└── README.md                # This file
```

## Development

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# With coverage
pytest --cov=isilon_mcp --cov-report=html
```

### Code Quality

```bash
# Format code
black isilon_mcp/
isort isilon_mcp/

# Lint
ruff check isilon_mcp/

# Type checking
mypy isilon_mcp/
```

## API Reference

### Tool Naming Convention

Tools are named using the pattern:
```
{category}_{operationId}
```

Examples:
- `auth_list_providers` - List authentication providers
- `protocols_list_smb_shares` - List SMB shares
- `snapshot_create_snapshot` - Create a new snapshot
- `cluster_get_cluster_config` - Get cluster configuration

### Authentication

The server uses HTTP Basic Authentication with your PowerScale credentials. All requests are made over HTTPS by default.

### Error Handling

The server provides detailed error messages for:
- Authentication failures
- Connection errors
- Rate limiting
- API validation errors

## Security Considerations

1. **Never commit `.env` files** - They contain sensitive credentials
2. **Use TLS verification** - Set `ISILON_TLS_VERIFY=true` in production
3. **Principle of least privilege** - Use API users with minimal required permissions
4. **Read-only mode** - Set `READ_ONLY_MODE=true` for monitoring-only access

## Troubleshooting

### Connection Issues

```bash
# Test connection manually
curl -k -u username:password https://your-host:8080/platform/18/cluster/config
```

### Certificate Errors

If using self-signed certificates:
```env
ISILON_TLS_VERIFY=false  # Only for testing!
```

### Debug Mode

Enable detailed logging:
```env
LOG_LEVEL=DEBUG
DEBUG_HTTP=true
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## Acknowledgments

- [Dell PowerScale](https://www.dell.com/en-us/dt/storage/powerscale.htm) for the comprehensive REST API
- [Model Context Protocol](https://modelcontextprotocol.io/) for the MCP specification
- [Anthropic Claude](https://www.anthropic.com/) for AI assistant integration
