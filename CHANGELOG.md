# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-10

### Added
- Initial release of isilon-mcp-server
- Complete MCP server implementation for Dell PowerScale OneFS 9.7 API
- Support for 950+ API operations across 46 categories
- Dynamic tool generation from OpenAPI specifications
- Basic Authentication with TLS support
- stdio transport for Claude Desktop integration
- HTTP/SSE transport for n8n and web clients
- Comprehensive test suite with 37+ unit tests
- Full OpenAPI v18 (OneFS 9.7) specification
- Async/await support using httpx
- Structured logging with configurable levels
- Environment-based configuration with python-dotenv
- Read-only mode for safe operations
- Per-request credential support for multi-cluster management

### Features
- **Authentication**: Secure Basic Auth with TLS certificate verification
- **Multi-Transport**: stdio and HTTP/SSE transports
- **Tool Generation**: Automatic MCP tool creation from OpenAPI specs
- **Error Handling**: Comprehensive exception hierarchy
- **Logging**: Structured JSON and colored console output
- **Configuration**: Pydantic-based config with environment variables
- **Testing**: pytest-based test suite with coverage reports

### API Coverage
- Auth (53 operations): Users, groups, roles, providers
- Protocols (70 operations): SMB, NFS, HDFS, S3, HTTP
- Cluster (32 operations): Configuration, nodes, status
- Storage Pools (15 operations): Capacity, tiers, status
- Snapshots (21 operations): Schedules, policies, management
- Sync/Replication (31 operations): Policies, jobs, reports
- Quotas (12 operations): Limits, usage, management
- Events (12 operations): Alerts, channels, notifications
- And 38+ more categories

### Documentation
- Comprehensive README with quick start guide
- API reference documentation
- Integration guides for Claude Desktop and n8n
- Troubleshooting section
- Security best practices

[1.0.0]: https://github.com/sachdev27/isilon-mcp-server/releases/tag/v1.0.0
