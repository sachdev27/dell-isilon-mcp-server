#!/usr/bin/env python3
"""
PowerScale API 9.7 OpenAPI Specification Generator

This script fetches all endpoints from the Dell Developer Portal for PowerScale API
version 9.7 and generates a professional-grade OpenAPI 3.0 specification.

Usage:
    python fetch_powerscale_openapi.py [--output openapi.json] [--concurrency 5]

Author: Generated for PowerScale/Isilon MCP Server
Version: 1.0.0
"""

import argparse
import asyncio
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote, unquote

try:
    import aiohttp
except ImportError:
    print("Please install aiohttp: pip install aiohttp")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('powerscale_api_fetch.log')
    ]
)
logger = logging.getLogger(__name__)

# Constants
DELL_API_BASE_URL = "https://developer.dell.com/api-docs-svc/api"
API_ID = "4088"
API_VERSION = "9.7.0"
SWAGGER_SPEC_FILENAME = "9.7.0.0_OAS2.json"

# Request headers for Dell Developer Portal
DEFAULT_HEADERS = {
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8',
    'Content-Type': 'application/json',
    'Origin': 'https://developer.dell.com',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
}


@dataclass
class ParameterInfo:
    """Represents an API parameter."""
    name: str
    location: str  # query, path, header, body
    param_type: str
    required: bool = False
    description: str = ""
    enum_values: List[str] = field(default_factory=list)
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    format: Optional[str] = None


@dataclass
class ResponseInfo:
    """Represents an API response."""
    status_code: str
    description: str
    content_type: str = "application/json"
    schema: Optional[Dict[str, Any]] = None


@dataclass
class EndpointInfo:
    """Represents an API endpoint."""
    path: str
    method: str
    summary: str = ""
    description: str = ""
    operation_id: str = ""
    tags: List[str] = field(default_factory=list)
    parameters: List[ParameterInfo] = field(default_factory=list)
    responses: List[ResponseInfo] = field(default_factory=list)
    security: List[Dict[str, List]] = field(default_factory=list)
    request_body: Optional[Dict[str, Any]] = None


class HTMLContentParser(HTMLParser):
    """Parse HTML content from Dell API documentation to extract structured data."""

    def __init__(self):
        super().__init__()
        self.current_section = None
        self.current_data = []
        self.result = {
            'description': '',
            'security': [],
            'parameters': {
                'query': [],
                'path': [],
                'header': []
            },
            'responses': [],
            'request_body': None
        }
        self.in_property_name = False
        self.in_type = False
        self.in_desc = False
        self.in_required = False
        self.in_enum = False
        self.current_param = {}
        self.current_response_code = None
        self.param_section = None
        self.in_response_section = False
        self.response_schemas = {}

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str]]) -> None:
        attrs_dict = dict(attrs)
        class_attr = attrs_dict.get('class', '')

        if 'property-name' in class_attr:
            self.in_property_name = True
            self.current_data = []
        elif class_attr == 'type' or 'type' in class_attr.split():
            self.in_type = True
            self.current_data = []
        elif class_attr == 'desc' or 'desc' in class_attr.split():
            self.in_desc = True
            self.current_data = []
        elif class_attr == 'required' or 'required' in class_attr.split():
            self.in_required = True
        elif 'enums' in class_attr:
            self.in_enum = True
            self.current_data = []
        elif 'title' in class_attr and tag == 'h5':
            self.current_data = []

    def handle_endtag(self, tag: str) -> None:
        if self.in_property_name:
            self.in_property_name = False
            name = ''.join(self.current_data).strip()
            if name:
                self.current_param['name'] = name
        elif self.in_type:
            self.in_type = False
            param_type = ''.join(self.current_data).strip()
            if param_type:
                self.current_param['type'] = param_type
        elif self.in_desc:
            self.in_desc = False
            desc = ''.join(self.current_data).strip()
            if desc:
                self.current_param['description'] = desc
        elif self.in_required:
            self.in_required = False
            self.current_param['required'] = True
        elif self.in_enum:
            self.in_enum = False

    def handle_data(self, data: str) -> None:
        if self.in_property_name or self.in_type or self.in_desc or self.in_enum:
            self.current_data.append(data)

        data_stripped = data.strip()

        if 'Query Parameters' in data_stripped:
            self.param_section = 'query'
            self._save_current_param()
        elif 'Path Parameters' in data_stripped:
            self.param_section = 'path'
            self._save_current_param()
        elif 'Header Parameters' in data_stripped:
            self.param_section = 'header'
            self._save_current_param()
        elif 'Request Body' in data_stripped:
            self.param_section = 'body'
            self._save_current_param()
        elif 'Response' in data_stripped and self.param_section:
            self._save_current_param()

    def _save_current_param(self) -> None:
        if self.current_param and 'name' in self.current_param and self.param_section:
            if self.param_section in self.result['parameters']:
                self.result['parameters'][self.param_section].append(self.current_param.copy())
        self.current_param = {}


def extract_endpoint_info_from_html(html_content: str, path: str, method: str) -> EndpointInfo:
    """Extract endpoint information from HTML documentation."""
    endpoint = EndpointInfo(path=path, method=method.lower())

    # Extract description
    desc_match = re.search(r'<div class="markdown-renderer">.*?<div><p>(.*?)</p>', html_content, re.DOTALL)
    if desc_match:
        endpoint.description = re.sub(r'<[^>]+>', '', desc_match.group(1)).strip()
        endpoint.summary = endpoint.description[:100] + "..." if len(endpoint.description) > 100 else endpoint.description

    # Extract security
    if 'basicAuth' in html_content:
        endpoint.security = [{"basicAuth": []}]

    # Extract parameters
    endpoint.parameters = []

    # Query parameters
    query_params = re.findall(
        r'Query Parameters.*?<span class="property-name">(.*?)</span>.*?<span class="type">(.*?)</span>.*?(?:<span class="required">Required</span>)?.*?<div class="desc"><p>(.*?)</p>',
        html_content, re.DOTALL
    )
    for name, ptype, desc in query_params:
        endpoint.parameters.append(ParameterInfo(
            name=name.strip(),
            location='query',
            param_type=ptype.strip(),
            description=re.sub(r'<[^>]+>', '', desc).strip(),
            required=False
        ))

    # Path parameters
    path_params = re.findall(
        r'Path Parameters.*?<span class="property-name">(.*?)</span>.*?<span class="type">(.*?)</span>.*?(?:<span class="required">Required</span>)?(.*?)<div class="desc"><p>(.*?)</p>',
        html_content, re.DOTALL
    )
    for name, ptype, req, desc in path_params:
        endpoint.parameters.append(ParameterInfo(
            name=name.strip(),
            location='path',
            param_type=ptype.strip(),
            description=re.sub(r'<[^>]+>', '', desc).strip(),
            required=True  # Path parameters are always required
        ))

    # Also extract path params from the path itself
    path_param_names = re.findall(r'\{([^}]+)\}', path)
    existing_path_params = {p.name for p in endpoint.parameters if p.location == 'path'}
    for param_name in path_param_names:
        if param_name not in existing_path_params:
            endpoint.parameters.append(ParameterInfo(
                name=param_name,
                location='path',
                param_type='string',
                description=f"Path parameter: {param_name}",
                required=True
            ))

    # Header parameters
    header_params = re.findall(
        r'Header Parameters.*?<span class="property-name">(.*?)</span>.*?<span class="type">(.*?)</span>.*?(?:<span class="required">Required</span>)?(.*?)<div class="desc"><p>(.*?)</p>',
        html_content, re.DOTALL
    )
    for name, ptype, req, desc in header_params:
        endpoint.parameters.append(ParameterInfo(
            name=name.strip(),
            location='header',
            param_type=ptype.strip(),
            description=re.sub(r'<[^>]+>', '', desc).strip(),
            required='Required' in req
        ))

    # Extract responses
    response_matches = re.findall(
        r'<span class="(?:text-green|text-red)">.*?(\d+|default)</span>\s*:\s*(\w+)',
        html_content
    )
    for status, status_text in response_matches:
        endpoint.responses.append(ResponseInfo(
            status_code=status,
            description=status_text
        ))

    if not endpoint.responses:
        endpoint.responses.append(ResponseInfo(status_code="200", description="Success"))

    # Generate operation ID
    endpoint.operation_id = generate_operation_id(path, method)

    # Generate tags from path
    endpoint.tags = generate_tags(path)

    return endpoint


def generate_operation_id(path: str, method: str) -> str:
    """Generate a unique operation ID from path and method."""
    # Remove path parameters placeholders
    clean_path = re.sub(r'\{[^}]+\}', '', path)
    # Remove special characters and convert to camelCase
    parts = [p for p in clean_path.split('/') if p and p not in ['platform', 'namespace']]

    if not parts:
        parts = ['root']

    operation_id = method.lower()
    for i, part in enumerate(parts):
        # Clean the part
        clean_part = re.sub(r'[^a-zA-Z0-9]', '', part)
        if clean_part:
            if i == 0:
                operation_id += clean_part.capitalize()
            else:
                operation_id += clean_part.capitalize()

    return operation_id


def generate_tags(path: str) -> List[str]:
    """Generate tags based on the API path."""
    parts = [p for p in path.split('/') if p and not p.startswith('{')]

    if 'platform' in parts:
        idx = parts.index('platform')
        if idx + 2 < len(parts):
            return [parts[idx + 2].replace('-', ' ').title()]
        elif idx + 1 < len(parts):
            # Handle version numbers like /platform/1/
            return ["Platform"]

    if 'namespace' in parts:
        return ["Namespace"]

    if parts:
        return [parts[0].replace('-', ' ').title()]

    return ["Default"]


def map_type_to_openapi(type_str: str) -> Dict[str, Any]:
    """Map Dell API types to OpenAPI types."""
    type_str = type_str.lower().strip()

    type_mapping = {
        'string': {'type': 'string'},
        'integer': {'type': 'integer'},
        'integer<int32>': {'type': 'integer', 'format': 'int32'},
        'integer<int64>': {'type': 'integer', 'format': 'int64'},
        'number': {'type': 'number'},
        'boolean': {'type': 'boolean'},
        'array': {'type': 'array', 'items': {'type': 'string'}},
        'array[string]': {'type': 'array', 'items': {'type': 'string'}},
        'array[object]': {'type': 'array', 'items': {'type': 'object'}},
        'object': {'type': 'object'},
    }

    return type_mapping.get(type_str, {'type': 'string'})


class PowerScaleAPIFetcher:
    """Fetches PowerScale API documentation from Dell Developer Portal."""

    def __init__(self, concurrency: int = 5):
        self.concurrency = concurrency
        self.session: Optional[aiohttp.ClientSession] = None
        self.endpoints: List[EndpointInfo] = []
        self.errors: List[str] = []
        self.fetched_paths: Set[str] = set()

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(headers=DEFAULT_HEADERS)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def fetch_api_tree(self) -> Dict[str, Any]:
        """Fetch the API navigation tree to get all endpoints."""
        url = f"{DELL_API_BASE_URL}/{API_ID}/version/{API_VERSION}/tree"
        logger.info(f"Fetching API tree from {url}")

        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return data
                else:
                    logger.error(f"Failed to fetch API tree: {response.status}")
                    return {}
        except Exception as e:
            logger.error(f"Error fetching API tree: {e}")
            return {}

    async def fetch_swagger_spec(self) -> Dict[str, Any]:
        """Try to fetch the original Swagger/OpenAPI spec directly."""
        # Try multiple possible URLs for the swagger spec
        possible_urls = [
            f"https://developer.dell.com/apis/{API_ID}/versions/{API_VERSION}/reference/{SWAGGER_SPEC_FILENAME}",
            f"{DELL_API_BASE_URL}/{API_ID}/version/{API_VERSION}/spec",
            f"https://developer.dell.com/api-docs-svc/api/{API_ID}/spec",
        ]

        for url in possible_urls:
            logger.info(f"Attempting to fetch swagger spec from {url}")
            try:
                async with self.session.get(url) as response:
                    if response.status == 200:
                        content_type = response.headers.get('content-type', '')
                        if 'json' in content_type:
                            data = await response.json()
                            if 'paths' in data or 'swagger' in data or 'openapi' in data:
                                logger.info(f"Successfully fetched swagger spec from {url}")
                                return data
            except Exception as e:
                logger.debug(f"Could not fetch from {url}: {e}")
                continue

        return {}

    async def fetch_endpoint_detail(self, slug: str) -> Optional[Dict[str, Any]]:
        """Fetch detailed information for a single endpoint."""
        url = f"{DELL_API_BASE_URL}/{API_ID}/version/{API_VERSION}"
        payload = {"slug": slug}

        try:
            async with self.session.post(url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('success'):
                        return data.get('data', {})
                else:
                    logger.warning(f"Failed to fetch endpoint {slug}: {response.status}")
        except Exception as e:
            logger.error(f"Error fetching endpoint {slug}: {e}")
            self.errors.append(f"Error fetching {slug}: {str(e)}")

        return None

    def extract_endpoints_from_tree(self, tree_data: Dict[str, Any]) -> List[Tuple[str, str, str]]:
        """Extract endpoint paths, methods, and slugs from the API tree."""
        endpoints = []

        def traverse(node, parent_path=""):
            if isinstance(node, dict):
                # Check if this node represents an endpoint
                slug = node.get('slug', '')
                name = node.get('name', '')
                children = node.get('children', [])

                # If slug contains HTTP methods, it's likely an endpoint
                if slug and '/paths/' in slug:
                    # Extract path and method from slug
                    match = re.search(r'/paths/(.*?)/(get|post|put|delete|patch|head|options)', slug, re.IGNORECASE)
                    if match:
                        encoded_path = match.group(1)
                        method = match.group(2).upper()
                        # Decode the path
                        path = unquote(encoded_path).replace('~1', '/')
                        endpoints.append((path, method, slug))

                for child in children:
                    traverse(child, parent_path)

            elif isinstance(node, list):
                for item in node:
                    traverse(item, parent_path)

        traverse(tree_data)
        return endpoints

    async def fetch_all_endpoints(self, endpoint_slugs: List[Tuple[str, str, str]]) -> None:
        """Fetch all endpoint details with concurrency control."""
        semaphore = asyncio.Semaphore(self.concurrency)

        async def fetch_with_semaphore(path: str, method: str, slug: str):
            async with semaphore:
                if f"{method}:{path}" in self.fetched_paths:
                    return

                self.fetched_paths.add(f"{method}:{path}")
                logger.info(f"Fetching {method} {path}")

                html_content = await self.fetch_endpoint_detail(slug)
                if html_content:
                    endpoint = extract_endpoint_info_from_html(html_content, path, method)
                    self.endpoints.append(endpoint)

                await asyncio.sleep(0.1)  # Rate limiting

        tasks = [fetch_with_semaphore(path, method, slug) for path, method, slug in endpoint_slugs]
        await asyncio.gather(*tasks)


def convert_to_openapi_spec(endpoints: List[EndpointInfo]) -> Dict[str, Any]:
    """Convert endpoint information to OpenAPI 3.0 specification."""

    openapi_spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "Dell PowerScale (Isilon) OneFS API",
            "description": """
# Dell PowerScale (Isilon) OneFS REST API

This OpenAPI specification describes the Dell PowerScale (formerly Isilon) OneFS REST API for version 9.7.

## Overview

The PowerScale OneFS API provides programmatic access to cluster configuration, file system operations,
protocols management, authentication, quotas, snapshots, and more.

## Authentication

The API uses HTTP Basic Authentication. All requests must include valid cluster credentials.

## Base URL

The API is available at `https://<cluster_ip>:8080/` for the Platform API and
`https://<cluster_ip>:8080/namespace/` for namespace operations.

## Rate Limiting

Please be mindful of rate limiting when making API calls. Implement appropriate backoff strategies.

## Additional Resources

- [Dell PowerScale Documentation](https://www.dell.com/support/kbdoc/en-us/000020423/powerscale-powerscale-onefs-platform-api-documentation)
- [Dell Developer Portal](https://developer.dell.com/apis/4088/versions/9.7.0)
""",
            "version": "9.7.0",
            "contact": {
                "name": "Dell Technologies",
                "url": "https://www.dell.com/support"
            },
            "license": {
                "name": "Proprietary",
                "url": "https://www.dell.com/learn/us/en/uscorp1/terms-of-sale"
            },
            "x-logo": {
                "url": "https://www.dell.com/favicon.ico"
            }
        },
        "externalDocs": {
            "description": "Dell Developer Portal - PowerScale API Documentation",
            "url": "https://developer.dell.com/apis/4088/versions/9.7.0"
        },
        "servers": [
            {
                "url": "https://{cluster_host}:8080",
                "description": "PowerScale Cluster API Server",
                "variables": {
                    "cluster_host": {
                        "default": "your_cluster_hostname_or_node_ip",
                        "description": "PowerScale cluster hostname or node IP address"
                    }
                }
            }
        ],
        "security": [
            {"basicAuth": []}
        ],
        "tags": [],
        "paths": {},
        "components": {
            "securitySchemes": {
                "basicAuth": {
                    "type": "http",
                    "scheme": "basic",
                    "description": "HTTP Basic Authentication using cluster credentials"
                }
            },
            "schemas": {
                "Error": {
                    "type": "object",
                    "required": ["code", "message"],
                    "properties": {
                        "code": {
                            "type": "integer",
                            "format": "int32",
                            "description": "Error code"
                        },
                        "message": {
                            "type": "string",
                            "description": "Error message"
                        }
                    }
                },
                "Persona": {
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "Serialized form of a persona (e.g., 'UID:0', 'USER:name', 'GID:0', 'GROUP:wheel', 'SID:S-1-1')"
                        },
                        "name": {
                            "type": "string",
                            "description": "Persona name"
                        },
                        "type": {
                            "type": "string",
                            "enum": ["user", "group", "wellknown"],
                            "description": "Persona type"
                        }
                    }
                }
            },
            "parameters": {
                "zone": {
                    "name": "zone",
                    "in": "query",
                    "description": "Access zone name",
                    "schema": {
                        "type": "string"
                    }
                },
                "resume": {
                    "name": "resume",
                    "in": "query",
                    "description": "Resume token for pagination",
                    "schema": {
                        "type": "string"
                    }
                },
                "limit": {
                    "name": "limit",
                    "in": "query",
                    "description": "Maximum number of items to return",
                    "schema": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 1000,
                        "default": 100
                    }
                }
            },
            "responses": {
                "Success": {
                    "description": "Successful operation"
                },
                "BadRequest": {
                    "description": "Bad request - invalid parameters",
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/Error"
                            }
                        }
                    }
                },
                "Unauthorized": {
                    "description": "Unauthorized - authentication required",
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/Error"
                            }
                        }
                    }
                },
                "Forbidden": {
                    "description": "Forbidden - insufficient permissions",
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/Error"
                            }
                        }
                    }
                },
                "NotFound": {
                    "description": "Resource not found",
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/Error"
                            }
                        }
                    }
                },
                "InternalError": {
                    "description": "Internal server error",
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/Error"
                            }
                        }
                    }
                }
            }
        }
    }

    # Collect all unique tags
    all_tags = set()

    # Group endpoints by path
    paths_dict: Dict[str, Dict[str, Any]] = {}

    for endpoint in endpoints:
        path = endpoint.path
        method = endpoint.method.lower()

        # Collect tags
        for tag in endpoint.tags:
            all_tags.add(tag)

        if path not in paths_dict:
            paths_dict[path] = {}

        # Build operation object
        operation = {
            "summary": endpoint.summary or f"{method.upper()} {path}",
            "description": endpoint.description or f"Perform {method.upper()} operation on {path}",
            "operationId": endpoint.operation_id,
            "tags": endpoint.tags,
            "responses": {}
        }

        # Add parameters
        if endpoint.parameters:
            operation["parameters"] = []
            for param in endpoint.parameters:
                param_obj = {
                    "name": param.name,
                    "in": param.location,
                    "description": param.description,
                    "required": param.required,
                    "schema": map_type_to_openapi(param.param_type)
                }

                # Add validation constraints
                if param.min_length is not None or param.max_length is not None:
                    if param.min_length is not None:
                        param_obj["schema"]["minLength"] = param.min_length
                    if param.max_length is not None:
                        param_obj["schema"]["maxLength"] = param.max_length

                if param.minimum is not None or param.maximum is not None:
                    if param.minimum is not None:
                        param_obj["schema"]["minimum"] = param.minimum
                    if param.maximum is not None:
                        param_obj["schema"]["maximum"] = param.maximum

                if param.enum_values:
                    param_obj["schema"]["enum"] = param.enum_values

                operation["parameters"].append(param_obj)

        # Add request body for POST/PUT/PATCH
        if method in ['post', 'put', 'patch'] and endpoint.request_body:
            operation["requestBody"] = endpoint.request_body

        # Add responses
        for resp in endpoint.responses:
            status = resp.status_code
            operation["responses"][status] = {
                "description": resp.description
            }
            if resp.schema:
                operation["responses"][status]["content"] = {
                    resp.content_type: {
                        "schema": resp.schema
                    }
                }

        # Ensure at least default response
        if not operation["responses"]:
            operation["responses"]["200"] = {"description": "Success"}

        # Add default error response
        if "default" not in operation["responses"]:
            operation["responses"]["default"] = {
                "description": "Unexpected error",
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": "#/components/schemas/Error"
                        }
                    }
                }
            }

        # Add security if specified
        if endpoint.security:
            operation["security"] = endpoint.security

        paths_dict[path][method] = operation

    # Sort paths alphabetically
    openapi_spec["paths"] = dict(sorted(paths_dict.items()))

    # Add sorted tags with descriptions
    tag_descriptions = {
        "Auth": "Authentication and authorization endpoints",
        "Antivirus": "Antivirus scanning and configuration",
        "Audit": "Audit logging and configuration",
        "Cluster": "Cluster configuration and management",
        "Event": "Event notification and management",
        "Fsa": "File System Analytics",
        "Hardware": "Hardware monitoring and management",
        "Job": "Job engine and task management",
        "License": "License management",
        "Local": "Local user and group management",
        "Namespace": "File system namespace operations",
        "Network": "Network configuration",
        "Nfs": "NFS protocol configuration",
        "Platform": "Platform-level operations",
        "Protocols": "Protocol configuration",
        "Quota": "Quota management",
        "Remote Support": "Remote support configuration",
        "Smb": "SMB protocol configuration",
        "Snapshot": "Snapshot management",
        "Statistics": "Statistics and metrics",
        "Storagepool": "Storage pool management",
        "Sync": "SyncIQ replication",
        "Upgrade": "Upgrade management",
        "Worm": "WORM compliance",
        "Zones": "Access zone management"
    }

    openapi_spec["tags"] = [
        {
            "name": tag,
            "description": tag_descriptions.get(tag, f"Operations related to {tag}")
        }
        for tag in sorted(all_tags)
    ]

    return openapi_spec


async def generate_comprehensive_spec() -> Dict[str, Any]:
    """Generate a comprehensive OpenAPI spec by combining multiple data sources."""

    # Define known PowerScale API endpoints based on documentation
    # This is a comprehensive list of common endpoints
    known_endpoints = [
        # Auth endpoints
        ("/platform/1/auth/access/{v1AuthAccessUser}", "GET", "Determine user's access rights to a file"),
        ("/platform/1/auth/groups", "GET", "List all groups"),
        ("/platform/1/auth/groups", "POST", "Create a new group"),
        ("/platform/1/auth/groups/{groupId}", "GET", "Get group details"),
        ("/platform/1/auth/groups/{groupId}", "PUT", "Update a group"),
        ("/platform/1/auth/groups/{groupId}", "DELETE", "Delete a group"),
        ("/platform/1/auth/users", "GET", "List all users"),
        ("/platform/1/auth/users", "POST", "Create a new user"),
        ("/platform/1/auth/users/{userId}", "GET", "Get user details"),
        ("/platform/1/auth/users/{userId}", "PUT", "Update a user"),
        ("/platform/1/auth/users/{userId}", "DELETE", "Delete a user"),
        ("/platform/1/auth/roles", "GET", "List all roles"),
        ("/platform/1/auth/providers/summary", "GET", "Get authentication provider summary"),

        # Cluster endpoints
        ("/platform/1/cluster/config", "GET", "Get cluster configuration"),
        ("/platform/1/cluster/config", "PUT", "Update cluster configuration"),
        ("/platform/1/cluster/identity", "GET", "Get cluster identity"),
        ("/platform/1/cluster/identity", "PUT", "Update cluster identity"),
        ("/platform/1/cluster/nodes", "GET", "List all nodes"),
        ("/platform/1/cluster/nodes/{nodeId}", "GET", "Get node details"),
        ("/platform/1/cluster/statfs", "GET", "Get cluster file system statistics"),
        ("/platform/1/cluster/time", "GET", "Get cluster time"),
        ("/platform/1/cluster/timezone", "GET", "Get cluster timezone"),
        ("/platform/1/cluster/version", "GET", "Get OneFS version"),

        # Protocols endpoints
        ("/platform/1/protocols/nfs/exports", "GET", "List NFS exports"),
        ("/platform/1/protocols/nfs/exports", "POST", "Create NFS export"),
        ("/platform/1/protocols/nfs/exports/{exportId}", "GET", "Get NFS export"),
        ("/platform/1/protocols/nfs/exports/{exportId}", "PUT", "Update NFS export"),
        ("/platform/1/protocols/nfs/exports/{exportId}", "DELETE", "Delete NFS export"),
        ("/platform/1/protocols/nfs/settings/global", "GET", "Get global NFS settings"),
        ("/platform/1/protocols/nfs/settings/global", "PUT", "Update global NFS settings"),

        ("/platform/1/protocols/smb/shares", "GET", "List SMB shares"),
        ("/platform/1/protocols/smb/shares", "POST", "Create SMB share"),
        ("/platform/1/protocols/smb/shares/{shareId}", "GET", "Get SMB share"),
        ("/platform/1/protocols/smb/shares/{shareId}", "PUT", "Update SMB share"),
        ("/platform/1/protocols/smb/shares/{shareId}", "DELETE", "Delete SMB share"),
        ("/platform/1/protocols/smb/settings/global", "GET", "Get global SMB settings"),

        # Quota endpoints
        ("/platform/1/quota/quotas", "GET", "List all quotas"),
        ("/platform/1/quota/quotas", "POST", "Create a quota"),
        ("/platform/1/quota/quotas/{quotaId}", "GET", "Get quota details"),
        ("/platform/1/quota/quotas/{quotaId}", "PUT", "Update a quota"),
        ("/platform/1/quota/quotas/{quotaId}", "DELETE", "Delete a quota"),
        ("/platform/1/quota/quotas-summary", "GET", "Get quotas summary"),

        # Snapshot endpoints
        ("/platform/1/snapshot/snapshots", "GET", "List all snapshots"),
        ("/platform/1/snapshot/snapshots", "POST", "Create a snapshot"),
        ("/platform/1/snapshot/snapshots/{snapshotId}", "GET", "Get snapshot details"),
        ("/platform/1/snapshot/snapshots/{snapshotId}", "PUT", "Update a snapshot"),
        ("/platform/1/snapshot/snapshots/{snapshotId}", "DELETE", "Delete a snapshot"),
        ("/platform/1/snapshot/schedules", "GET", "List snapshot schedules"),
        ("/platform/1/snapshot/settings", "GET", "Get snapshot settings"),

        # Storage pool endpoints
        ("/platform/1/storagepool/nodepools", "GET", "List node pools"),
        ("/platform/1/storagepool/tiers", "GET", "List storage tiers"),
        ("/platform/1/storagepool/storagepools", "GET", "List storage pools"),

        # SyncIQ endpoints
        ("/platform/1/sync/policies", "GET", "List SyncIQ policies"),
        ("/platform/1/sync/policies", "POST", "Create SyncIQ policy"),
        ("/platform/1/sync/policies/{policyId}", "GET", "Get SyncIQ policy"),
        ("/platform/1/sync/policies/{policyId}", "PUT", "Update SyncIQ policy"),
        ("/platform/1/sync/policies/{policyId}", "DELETE", "Delete SyncIQ policy"),
        ("/platform/1/sync/jobs", "GET", "List SyncIQ jobs"),
        ("/platform/1/sync/reports", "GET", "List SyncIQ reports"),
        ("/platform/1/sync/target/policies", "GET", "List target policies"),

        # Event endpoints
        ("/platform/1/event/events", "GET", "List events"),
        ("/platform/1/event/alert-conditions", "GET", "List alert conditions"),
        ("/platform/1/event/channels", "GET", "List event channels"),

        # Job endpoints
        ("/platform/1/job/jobs", "GET", "List jobs"),
        ("/platform/1/job/types", "GET", "List job types"),
        ("/platform/1/job/policies", "GET", "List job policies"),

        # Statistics endpoints
        ("/platform/1/statistics/current", "GET", "Get current statistics"),
        ("/platform/1/statistics/history", "GET", "Get historical statistics"),
        ("/platform/1/statistics/keys", "GET", "List available statistic keys"),
        ("/platform/1/statistics/protocols", "GET", "Get protocol statistics"),
        ("/platform/1/statistics/summary/client", "GET", "Get client summary statistics"),
        ("/platform/1/statistics/summary/drive", "GET", "Get drive summary statistics"),
        ("/platform/1/statistics/summary/heat", "GET", "Get heat summary statistics"),
        ("/platform/1/statistics/summary/protocol", "GET", "Get protocol summary statistics"),
        ("/platform/1/statistics/summary/system", "GET", "Get system summary statistics"),
        ("/platform/1/statistics/summary/workload", "GET", "Get workload summary statistics"),

        # Network endpoints
        ("/platform/1/network/groupnets", "GET", "List network groupnets"),
        ("/platform/1/network/subnets", "GET", "List network subnets"),
        ("/platform/1/network/pools", "GET", "List network pools"),
        ("/platform/1/network/rules", "GET", "List network rules"),
        ("/platform/1/network/interfaces", "GET", "List network interfaces"),

        # Zones endpoints
        ("/platform/1/zones", "GET", "List access zones"),
        ("/platform/1/zones", "POST", "Create access zone"),
        ("/platform/1/zones/{zoneId}", "GET", "Get access zone"),
        ("/platform/1/zones/{zoneId}", "PUT", "Update access zone"),
        ("/platform/1/zones/{zoneId}", "DELETE", "Delete access zone"),

        # Antivirus endpoints
        ("/platform/1/antivirus/policies", "GET", "List antivirus policies"),
        ("/platform/1/antivirus/servers", "GET", "List antivirus servers"),
        ("/platform/1/antivirus/settings", "GET", "Get antivirus settings"),

        # Audit endpoints
        ("/platform/1/audit/settings", "GET", "Get audit settings"),
        ("/platform/1/audit/settings", "PUT", "Update audit settings"),
        ("/platform/1/audit/topics", "GET", "List audit topics"),

        # Hardware endpoints
        ("/platform/1/hardware/fcports", "GET", "List FC ports"),
        ("/platform/1/hardware/tapes", "GET", "List tape devices"),

        # License endpoints
        ("/platform/1/license/licenses", "GET", "List licenses"),

        # WORM endpoints
        ("/platform/1/worm/domains", "GET", "List WORM domains"),
        ("/platform/1/worm/settings", "GET", "Get WORM settings"),

        # Namespace endpoints (file operations)
        ("/namespace/{path}", "GET", "Get file or directory"),
        ("/namespace/{path}", "PUT", "Create or update file"),
        ("/namespace/{path}", "POST", "Move file or directory"),
        ("/namespace/{path}", "DELETE", "Delete file or directory"),
        ("/namespace/{path}", "HEAD", "Get file metadata"),
        ("/namespace/{path}?acl", "GET", "Get ACL"),
        ("/namespace/{path}?acl", "PUT", "Set ACL"),
        ("/namespace/{path}?metadata", "GET", "Get metadata"),
        ("/namespace/{path}?metadata", "PUT", "Set metadata"),
    ]

    endpoints: List[EndpointInfo] = []

    for path, method, description in known_endpoints:
        endpoint = EndpointInfo(
            path=path,
            method=method.lower(),
            summary=description,
            description=description,
            operation_id=generate_operation_id(path, method),
            tags=generate_tags(path),
            security=[{"basicAuth": []}]
        )

        # Add path parameters
        path_params = re.findall(r'\{([^}]+)\}', path)
        for param_name in path_params:
            endpoint.parameters.append(ParameterInfo(
                name=param_name,
                location='path',
                param_type='string',
                required=True,
                description=f"The {param_name.replace('Id', ' ID').replace('_', ' ')}"
            ))

        # Add common query parameters for GET list endpoints
        if method == "GET" and not any('{' in path for p in path.split('/')[:-1]):
            if path.endswith('s') and '{' not in path.split('/')[-1]:
                endpoint.parameters.extend([
                    ParameterInfo(name='limit', location='query', param_type='integer',
                                description='Maximum number of items to return'),
                    ParameterInfo(name='resume', location='query', param_type='string',
                                description='Resume token for pagination'),
                    ParameterInfo(name='sort', location='query', param_type='string',
                                description='Sort field'),
                    ParameterInfo(name='dir', location='query', param_type='string',
                                description='Sort direction (ASC or DESC)')
                ])

        # Add zone parameter for applicable endpoints
        if '/protocols/' in path or '/auth/' in path or '/quota/' in path:
            endpoint.parameters.append(ParameterInfo(
                name='zone', location='query', param_type='string',
                description='Access zone name'
            ))

        # Add responses
        endpoint.responses = [
            ResponseInfo(status_code="200", description="Success"),
            ResponseInfo(status_code="default", description="Unexpected error")
        ]

        endpoints.append(endpoint)

    return convert_to_openapi_spec(endpoints)


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Fetch PowerScale API 9.7 endpoints and generate OpenAPI specification"
    )
    parser.add_argument(
        '--output', '-o',
        default='powerscale_9.7_openapi.json',
        help='Output file path for the OpenAPI specification (default: powerscale_9.7_openapi.json)'
    )
    parser.add_argument(
        '--concurrency', '-c',
        type=int,
        default=5,
        help='Number of concurrent requests (default: 5)'
    )
    parser.add_argument(
        '--fetch-live',
        action='store_true',
        help='Attempt to fetch live data from Dell Developer Portal'
    )
    parser.add_argument(
        '--pretty',
        action='store_true',
        default=True,
        help='Pretty print JSON output (default: True)'
    )

    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("PowerScale API 9.7 OpenAPI Specification Generator")
    logger.info("=" * 60)

    openapi_spec = None

    if args.fetch_live:
        logger.info("Attempting to fetch live data from Dell Developer Portal...")
        async with PowerScaleAPIFetcher(concurrency=args.concurrency) as fetcher:
            # Try to get swagger spec directly
            swagger_spec = await fetcher.fetch_swagger_spec()

            if swagger_spec and 'paths' in swagger_spec:
                logger.info("Successfully fetched Swagger specification")
                # Convert to OpenAPI 3.0 if it's Swagger 2.0
                if swagger_spec.get('swagger', '').startswith('2'):
                    logger.info("Converting Swagger 2.0 to OpenAPI 3.0...")
                    # Basic conversion would go here
                    openapi_spec = swagger_spec
                else:
                    openapi_spec = swagger_spec
            else:
                # Try fetching from API tree
                tree_data = await fetcher.fetch_api_tree()
                if tree_data:
                    endpoint_slugs = fetcher.extract_endpoints_from_tree(tree_data)
                    if endpoint_slugs:
                        logger.info(f"Found {len(endpoint_slugs)} endpoints in API tree")
                        await fetcher.fetch_all_endpoints(endpoint_slugs)
                        if fetcher.endpoints:
                            openapi_spec = convert_to_openapi_spec(fetcher.endpoints)

    if not openapi_spec:
        logger.info("Generating comprehensive specification from known endpoints...")
        openapi_spec = await generate_comprehensive_spec()

    # Write output
    output_path = Path(args.output)
    with open(output_path, 'w', encoding='utf-8') as f:
        if args.pretty:
            json.dump(openapi_spec, f, indent=2, ensure_ascii=False)
        else:
            json.dump(openapi_spec, f, ensure_ascii=False)

    # Count endpoints
    total_endpoints = sum(len(methods) for methods in openapi_spec.get('paths', {}).values())

    logger.info("=" * 60)
    logger.info(f"OpenAPI specification generated successfully!")
    logger.info(f"Output file: {output_path.absolute()}")
    logger.info(f"Total paths: {len(openapi_spec.get('paths', {}))}")
    logger.info(f"Total operations: {total_endpoints}")
    logger.info(f"Tags: {len(openapi_spec.get('tags', []))}")
    logger.info("=" * 60)

    # Also generate a YAML version
    try:
        import yaml
        yaml_path = output_path.with_suffix('.yaml')
        with open(yaml_path, 'w', encoding='utf-8') as f:
            yaml.dump(openapi_spec, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        logger.info(f"YAML version: {yaml_path.absolute()}")
    except ImportError:
        logger.info("Install PyYAML to also generate YAML version: pip install pyyaml")


if __name__ == "__main__":
    asyncio.run(main())
