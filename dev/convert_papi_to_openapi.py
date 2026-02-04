#!/usr/bin/env python3
"""
Convert Isilon SDK PAPI Schemas to OpenAPI 3.0.3 format.
Allows filtering by API version to include only necessary endpoints.
"""

import json
import re
from typing import Dict, List, Set, Any
from collections import defaultdict


# Configure deduplication strategy
# When True, only keeps the latest version of each endpoint
# When False, includes all versions
USE_LATEST_VERSION_ONLY: bool = True

# Configure which API categories to include (empty means all)
# Example: INCLUDE_CATEGORIES = ["antivirus", "auth", "snapshot"]
INCLUDE_CATEGORIES: List[str] = []  # Empty = include all categories


def extract_version_from_path(path: str) -> int:
    """Extract API version number from path like /3/antivirus/policies"""
    match = re.match(r'^/(\d+)/', path)
    if match:
        return int(match.group(1))
    return 0  # For paths without version prefix


def extract_category_from_path(path: str) -> str:
    """Extract API category from path like /3/antivirus/policies -> antivirus"""
    match = re.match(r'^/\d+/([^/]+)', path)
    if match:
        return match.group(1)
    return "other"


def get_path_without_version(path: str) -> str:
    """Get path without version number: /3/antivirus/policies -> /antivirus/policies"""
    return re.sub(r'^/\d+/', '/', path)


def should_include_endpoint(path: str) -> bool:
    """Determine if endpoint should be included based on filters"""
    category = extract_category_from_path(path)
    
    # Apply category filter
    if INCLUDE_CATEGORIES and category not in INCLUDE_CATEGORIES:
        return False
    
    return True


def deduplicate_endpoints(papi_schema: Dict) -> Dict:
    """Keep only the latest version of each endpoint.
    
    For example, if both /3/antivirus/policies and /7/antivirus/policies exist,
    only keep /7/antivirus/policies.
    
    Args:
        papi_schema: Original PAPI schema with all versions
        
    Returns:
        Deduplicated schema with only latest versions
    """
    if not USE_LATEST_VERSION_ONLY:
        return papi_schema
    
    # Group endpoints by path without version
    endpoint_groups = defaultdict(list)
    
    for path, schema in papi_schema.items():
        if not isinstance(schema, dict):
            continue
        
        base_path = get_path_without_version(path)
        version = extract_version_from_path(path)
        endpoint_groups[base_path].append((version, path, schema))
    
    # Keep only the latest version of each endpoint
    deduplicated = {}
    for base_path, versions in endpoint_groups.items():
        # Sort by version number (highest first)
        versions.sort(key=lambda x: x[0], reverse=True)
        latest_version, latest_path, latest_schema = versions[0]
        deduplicated[latest_path] = latest_schema
    
    return deduplicated


def convert_path_params(path: str) -> str:
    """
    Convert PAPI path format to OpenAPI format.
    /3/antivirus/policies/<NAME> -> /platform/3/antivirus/policies/{Name}
    """
    # Add platform prefix
    openapi_path = f"/platform{path}"
    
    # Convert parameter syntax
    # <NAME> -> {Name}
    # <ID> -> {Id}
    # <PATH+> -> {Path}
    def replace_param(match):
        param = match.group(1).rstrip('+*')
        # Convert to PascalCase
        param_name = ''.join(word.capitalize() for word in param.split('_'))
        return f"{{{param_name}}}"
    
    openapi_path = re.sub(r'<([^>]+)>', replace_param, openapi_path)
    
    return openapi_path


def extract_parameters_from_schema(path: str, method: str, schema: Dict) -> List[Dict]:
    """Extract parameters from PAPI schema for a specific HTTP method"""
    parameters = []
    
    # Extract path parameters from URL
    path_params = re.findall(r'\{([^}]+)\}', path)
    for param in path_params:
        parameters.append({
            "name": param,
            "in": "path",
            "required": True,
            "schema": {"type": "string"},
            "description": f"Path parameter: {param}"
        })
    
    # Extract query parameters from GET_args or method_args
    args_key = f"{method}_args"
    if args_key in schema:
        args_schema = schema[args_key]
        if isinstance(args_schema, dict) and "properties" in args_schema:
            for param_name, param_def in args_schema["properties"].items():
                param_type = param_def.get("type", "string")
                parameters.append({
                    "name": param_name,
                    "in": "query",
                    "required": param_def.get("required", False),
                    "schema": {"type": param_type if isinstance(param_type, str) else "string"},
                    "description": param_def.get("description", f"Query parameter: {param_name}")
                })
    
    return parameters


def extract_request_body(method: str, schema: Dict) -> Dict:
    """Extract request body schema for POST/PUT/PATCH methods"""
    if method not in ["POST", "PUT", "PATCH"]:
        return {}
    
    body_key = f"{method}_input_schema"
    if body_key in schema:
        return {
            "required": True,
            "content": {
                "application/json": {
                    "schema": schema[body_key]
                }
            }
        }
    
    return {}


def extract_responses(method: str, schema: Dict) -> Dict:
    """Extract response schemas"""
    responses = {}
    
    output_key = f"{method}_output_schema"
    if output_key in schema:
        responses["200"] = {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "schema": schema[output_key]
                }
            }
        }
    else:
        responses["200"] = {
            "description": "Successful response"
        }
    
    # Add common error responses
    responses["400"] = {"description": "Bad request"}
    responses["401"] = {"description": "Unauthorized"}
    responses["404"] = {"description": "Not found"}
    responses["500"] = {"description": "Internal server error"}
    
    return responses


def convert_papi_to_openapi(papi_schema: Dict) -> Dict:
    """Convert PAPI schema to OpenAPI 3.0.3 specification"""
    
    # Deduplicate endpoints (keep only latest versions)
    if USE_LATEST_VERSION_ONLY:
        print("Deduplicating endpoints (keeping only latest versions)...")
        papi_schema = deduplicate_endpoints(papi_schema)
        print(f"After deduplication: {len(papi_schema)} unique endpoints")
    
    openapi_spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "PowerScale OneFS REST API",
            "description": "REST API for Dell PowerScale (Isilon) storage system",
            "version": "9.7.0",
            "contact": {
                "name": "Dell Technologies",
                "url": "https://www.dell.com/support/home/en-us/product-support/product/isilon-onefs/overview"
            }
        },
        "servers": [
            {
                "url": "https://{cluster}:8080",
                "description": "PowerScale cluster",
                "variables": {
                    "cluster": {
                        "default": "localhost",
                        "description": "PowerScale cluster hostname or IP"
                    }
                }
            }
        ],
        "security": [
            {"basicAuth": []}
        ],
        "components": {
            "securitySchemes": {
                "basicAuth": {
                    "type": "http",
                    "scheme": "basic",
                    "description": "Basic authentication with username and password"
                }
            }
        },
        "paths": {}
    }
    
    stats = {
        "total_endpoints": 0,
        "included_endpoints": 0,
        "excluded_endpoints": 0,
        "by_version": defaultdict(int),
        "by_category": defaultdict(int),
        "by_method": defaultdict(int)
    }
    
    for papi_path, endpoint_schema in papi_schema.items():
        stats["total_endpoints"] += 1
        
        # Skip if endpoint_schema is not a dict
        if not isinstance(endpoint_schema, dict):
            stats["excluded_endpoints"] += 1
            continue
        
        # Check if endpoint should be included
        if not should_include_endpoint(papi_path):
            stats["excluded_endpoints"] += 1
            continue
        
        stats["included_endpoints"] += 1
        version = extract_version_from_path(papi_path)
        category = extract_category_from_path(papi_path)
        stats["by_version"][version] += 1
        stats["by_category"][category] += 1
        
        # Convert path format
        openapi_path = convert_path_params(papi_path)
        
        # Initialize path if not exists
        if openapi_path not in openapi_spec["paths"]:
            openapi_spec["paths"][openapi_path] = {}
        
        # Process each HTTP method
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        for method in methods:
            method_key = f"{method}_args"
            if method_key in endpoint_schema or f"{method}_output_schema" in endpoint_schema:
                stats["by_method"][method] += 1
                
                operation = {
                    "summary": f"{method} {papi_path}",
                    "operationId": f"{method.lower()}_{papi_path.replace('/', '_').strip('_')}",
                    "tags": [category],
                    "parameters": extract_parameters_from_schema(openapi_path, method, endpoint_schema),
                    "responses": extract_responses(method, endpoint_schema)
                }
                
                # Add request body for POST/PUT/PATCH
                request_body = extract_request_body(method, endpoint_schema)
                if request_body:
                    operation["requestBody"] = request_body
                
                openapi_spec["paths"][openapi_path][method.lower()] = operation
    
    return openapi_spec, stats


def main():
    print("=" * 80)
    print("PAPI Schema to OpenAPI 3.0.3 Converter")
    print("=" * 80)
    
    # Load PAPI schema
    papi_file = "Isilon SDK PAPI Schemas 9.7.0.json"
    print(f"\n📖 Loading PAPI schema from: {papi_file}")
    
    with open(papi_file, 'r') as f:
        papi_schema = json.load(f)
    
    print(f"✓ Loaded {len(papi_schema)} endpoints from PAPI schema")
    
    # Show filter configuration
    print("\n⚙️  Filter Configuration:")
    if USE_LATEST_VERSION_ONLY:
        print(f"   - Version Strategy: Latest version only (deduplication enabled)")
    else:
        print(f"   - Version Strategy: All versions")
    
    if INCLUDE_CATEGORIES:
        print(f"   - Categories: {', '.join(INCLUDE_CATEGORIES)}")
    else:
        print(f"   - Categories: ALL")
    
    # Convert to OpenAPI
    print("\n🔄 Converting to OpenAPI format...")
    openapi_spec, stats = convert_papi_to_openapi(papi_schema)
    
    # Display statistics
    print("\n📊 Conversion Statistics:")
    print(f"   - Total PAPI endpoints: {stats['total_endpoints']}")
    print(f"   - Included endpoints: {stats['included_endpoints']}")
    print(f"   - Excluded endpoints: {stats['excluded_endpoints']}")
    
    print("\n   Endpoints by Version:")
    for version in sorted(stats['by_version'].keys()):
        print(f"      v{version}: {stats['by_version'][version]} endpoints")
    
    print("\n   Top Categories:")
    for category, count in sorted(stats['by_category'].items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"      {category}: {count} endpoints")
    
    print("\n   HTTP Methods:")
    for method, count in sorted(stats['by_method'].items()):
        print(f"      {method}: {count} operations")
    
    # Save OpenAPI spec
    output_file = "openapi_from_papi.json"
    print(f"\n💾 Saving OpenAPI spec to: {output_file}")
    
    with open(output_file, 'w') as f:
        json.dump(openapi_spec, f, indent=2)
    
    print(f"✓ Saved {len(openapi_spec['paths'])} unique paths")
    print("\n✅ Conversion complete!")
    print("\n💡 Tip: Edit USE_LATEST_VERSION_ONLY at the top of this script")
    print("   to control whether to keep all versions or only the latest.")
    print("   Edit INCLUDE_CATEGORIES to filter by API category.")


if __name__ == "__main__":
    main()
