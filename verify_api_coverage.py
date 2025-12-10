#!/usr/bin/env python3
"""
PowerScale API Coverage Verification Tool

This script fetches the actual API structure from Dell Developer Portal
and compares it against our generated OpenAPI specification to verify
full coverage.

Usage:
    python verify_api_coverage.py [--spec powerscale_9.7_comprehensive_openapi.json]

Author: Generated for PowerScale/Isilon MCP Server
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import unquote

try:
    import requests
except ImportError:
    print("Please install requests: pip install requests")
    sys.exit(1)

# Configuration
API_ID = "4088"
API_VERSION = "9.7.0"
SPEC_FILE = "9.7.0.0_OAS2.json"

DELL_BASE_URL = "https://developer.dell.com"
API_DOCS_URL = f"{DELL_BASE_URL}/api-docs-svc/api/{API_ID}/version/{API_VERSION}"

HEADERS = {
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8',
    'Content-Type': 'application/json',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
}


def fetch_api_navigation() -> Dict:
    """Fetch the navigation tree from Dell Developer Portal."""
    session = requests.Session()
    session.headers.update(HEADERS)

    # Try multiple endpoints to get the API structure
    endpoints_to_try = [
        f"{API_DOCS_URL}/tree",
        f"{API_DOCS_URL}/navigation",
        f"{API_DOCS_URL}/sidebar",
        f"{DELL_BASE_URL}/api-docs-svc/api/{API_ID}/navigation",
        f"{DELL_BASE_URL}/apis/{API_ID}/versions/{API_VERSION}/reference",
    ]

    for url in endpoints_to_try:
        print(f"Trying: {url}")
        try:
            response = session.get(url, timeout=30)
            print(f"  Status: {response.status_code}")

            if response.status_code == 200:
                try:
                    data = response.json()
                    if data:
                        print(f"  ✓ Got JSON response with {len(str(data))} chars")
                        return data
                except json.JSONDecodeError:
                    # Check if it's HTML with embedded data
                    if 'paths' in response.text or 'swagger' in response.text:
                        print(f"  Found API data in HTML response")
        except Exception as e:
            print(f"  Error: {e}")

    return {}


def fetch_swagger_spec_direct() -> Dict:
    """Try to fetch the Swagger/OpenAPI spec directly."""
    session = requests.Session()
    session.headers.update(HEADERS)

    # Various URLs where the spec might be available
    spec_urls = [
        f"{DELL_BASE_URL}/apis/{API_ID}/versions/{API_VERSION}/reference/{SPEC_FILE}",
        f"{DELL_BASE_URL}/api-docs-svc/api/{API_ID}/spec",
        f"{DELL_BASE_URL}/api-docs-svc/api/{API_ID}/version/{API_VERSION}/spec",
        f"{DELL_BASE_URL}/api-docs-svc/api/{API_ID}/swagger",
        f"{DELL_BASE_URL}/api-docs-svc/api/{API_ID}/openapi",
    ]

    for url in spec_urls:
        print(f"Trying spec URL: {url}")
        try:
            response = session.get(url, timeout=30)
            print(f"  Status: {response.status_code}")

            if response.status_code == 200:
                content_type = response.headers.get('content-type', '')

                # Check if JSON
                if 'json' in content_type or response.text.strip().startswith('{'):
                    try:
                        data = response.json()
                        # Check if it's a valid OpenAPI/Swagger spec
                        if 'paths' in data:
                            path_count = len(data.get('paths', {}))
                            print(f"  ✓ Found spec with {path_count} paths!")
                            return data
                        elif 'swagger' in data or 'openapi' in data:
                            print(f"  ✓ Found OpenAPI spec!")
                            return data
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            print(f"  Error: {e}")

    return {}


def extract_endpoints_from_nav(nav_data: Dict) -> Set[Tuple[str, str]]:
    """Extract all endpoints (path, method) from navigation data."""
    endpoints = set()

    def traverse(node):
        if isinstance(node, dict):
            slug = node.get('slug', '')
            children = node.get('children', [])

            # Parse slug to extract path and method
            # Format: /9.7.0.0_OAS2.json/paths/~1platform~11~1auth~1users/get
            if '/paths/' in slug:
                match = re.search(r'/paths/(.*?)/(get|post|put|delete|patch|head|options)$',
                                slug, re.IGNORECASE)
                if match:
                    encoded_path = match.group(1)
                    method = match.group(2).upper()
                    # Decode path
                    path = unquote(encoded_path).replace('~1', '/').replace('~0', '~')
                    endpoints.add((path, method))

            for child in children:
                traverse(child)

        elif isinstance(node, list):
            for item in node:
                traverse(item)

    traverse(nav_data)
    return endpoints


def extract_endpoints_from_spec(spec_data: Dict) -> Set[Tuple[str, str]]:
    """Extract all endpoints from an OpenAPI/Swagger spec."""
    endpoints = set()

    paths = spec_data.get('paths', {})
    for path, methods in paths.items():
        if isinstance(methods, dict):
            for method in methods.keys():
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
                    endpoints.add((path, method.upper()))

    return endpoints


def load_local_spec(spec_path: str) -> Dict:
    """Load the locally generated OpenAPI spec."""
    path = Path(spec_path)
    if not path.exists():
        print(f"Error: Spec file not found: {spec_path}")
        return {}

    with open(path, 'r') as f:
        return json.load(f)


def analyze_coverage(local_endpoints: Set[Tuple[str, str]],
                    remote_endpoints: Set[Tuple[str, str]]) -> Dict:
    """Analyze coverage between local and remote endpoints."""

    # Normalize paths for comparison (handle minor differences)
    def normalize_path(path: str) -> str:
        # Remove trailing slashes
        path = path.rstrip('/')
        # Normalize parameter names
        path = re.sub(r'\{[^}]+\}', '{param}', path)
        return path.lower()

    local_normalized = {(normalize_path(p), m) for p, m in local_endpoints}
    remote_normalized = {(normalize_path(p), m) for p, m in remote_endpoints}

    # Find matches and differences
    matched = local_normalized & remote_normalized
    missing_in_local = remote_normalized - local_normalized
    extra_in_local = local_normalized - remote_normalized

    return {
        'local_count': len(local_endpoints),
        'remote_count': len(remote_endpoints),
        'matched_count': len(matched),
        'missing_count': len(missing_in_local),
        'extra_count': len(extra_in_local),
        'coverage_percent': (len(matched) / len(remote_endpoints) * 100) if remote_endpoints else 0,
        'missing_endpoints': sorted(missing_in_local),
        'extra_endpoints': sorted(extra_in_local),
    }


def count_endpoints_by_category(endpoints: Set[Tuple[str, str]]) -> Dict[str, int]:
    """Count endpoints by API category."""
    categories = {}

    for path, method in endpoints:
        parts = path.split('/')

        # Extract category from path
        if 'platform' in parts:
            idx = parts.index('platform')
            if idx + 2 < len(parts):
                category = parts[idx + 2]
            else:
                category = 'platform'
        elif 'namespace' in parts:
            category = 'namespace'
        else:
            category = 'other'

        categories[category] = categories.get(category, 0) + 1

    return dict(sorted(categories.items()))


def main():
    parser = argparse.ArgumentParser(description='Verify PowerScale API coverage')
    parser.add_argument(
        '--spec', '-s',
        default='powerscale_9.7_comprehensive_openapi.json',
        help='Path to local OpenAPI spec file'
    )
    parser.add_argument(
        '--output', '-o',
        default='coverage_report.json',
        help='Output file for coverage report'
    )

    args = parser.parse_args()

    print("=" * 70)
    print("PowerScale API Coverage Verification Tool")
    print("=" * 70)
    print()

    # Step 1: Load local spec
    print("Step 1: Loading local OpenAPI specification...")
    local_spec = load_local_spec(args.spec)

    if not local_spec:
        print("Failed to load local spec. Creating from scratch...")
        local_endpoints = set()
    else:
        local_endpoints = extract_endpoints_from_spec(local_spec)
        print(f"  ✓ Loaded {len(local_endpoints)} endpoints from local spec")

    # Step 2: Try to fetch remote spec directly
    print()
    print("Step 2: Attempting to fetch remote API specification...")
    remote_spec = fetch_swagger_spec_direct()

    remote_endpoints = set()
    if remote_spec and 'paths' in remote_spec:
        remote_endpoints = extract_endpoints_from_spec(remote_spec)
        print(f"  ✓ Found {len(remote_endpoints)} endpoints in remote spec")
    else:
        print("  ✗ Could not fetch remote spec directly")

        # Try navigation tree
        print()
        print("Step 3: Trying to fetch API navigation tree...")
        nav_data = fetch_api_navigation()

        if nav_data:
            remote_endpoints = extract_endpoints_from_nav(nav_data)
            if remote_endpoints:
                print(f"  ✓ Extracted {len(remote_endpoints)} endpoints from navigation")

    # Step 3: Analyze coverage
    print()
    print("=" * 70)
    print("Coverage Analysis")
    print("=" * 70)

    if remote_endpoints:
        analysis = analyze_coverage(local_endpoints, remote_endpoints)

        print(f"""
Local Specification:
  - Total Endpoints: {analysis['local_count']}

Remote API (Dell Portal):
  - Total Endpoints: {analysis['remote_count']}

Coverage:
  - Matched: {analysis['matched_count']}
  - Missing in Local: {analysis['missing_count']}
  - Extra in Local: {analysis['extra_count']}
  - Coverage: {analysis['coverage_percent']:.1f}%
""")

        if analysis['missing_endpoints']:
            print("Missing Endpoints (first 20):")
            for path, method in analysis['missing_endpoints'][:20]:
                print(f"  - {method} {path}")
            if len(analysis['missing_endpoints']) > 20:
                print(f"  ... and {len(analysis['missing_endpoints']) - 20} more")

        # Save report
        report = {
            'local_spec': args.spec,
            'analysis': analysis,
            'local_categories': count_endpoints_by_category(local_endpoints),
            'remote_categories': count_endpoints_by_category(remote_endpoints) if remote_endpoints else {},
        }

        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=list)

        print(f"\nDetailed report saved to: {args.output}")

    else:
        print("""
⚠️  Could not fetch remote API data from Dell Developer Portal.

This is expected because the Dell Developer Portal API requires:
1. Valid session cookies from an authenticated browser session
2. Or direct access to the OpenAPI spec file

Alternative verification methods:

1. MANUAL VERIFICATION:
   - Visit: https://developer.dell.com/apis/4088/versions/9.7.0/reference
   - Count the endpoints in the sidebar
   - Compare with our generated spec

2. DOWNLOAD SPEC MANUALLY:
   - Open browser DevTools (F12) → Network tab
   - Navigate the Dell API documentation
   - Look for requests to '/api-docs-svc/api/' endpoints
   - Find and download the full specification

3. USE SESSION COOKIES:
   - Copy cookies from your browser (after logging in)
   - Add them to this script's session

Based on PowerScale 9.7 documentation, the API includes approximately:
   - 1000+ total endpoints across all categories
   - Our current spec covers the main categories

Local Specification Analysis:
""")

        # Show local spec analysis
        print(f"  Total Paths: {len(local_spec.get('paths', {}))}")
        print(f"  Total Operations: {len(local_endpoints)}")
        print()
        print("  Endpoints by Category:")
        categories = count_endpoints_by_category(local_endpoints)
        for cat, count in categories.items():
            print(f"    - {cat}: {count}")

    print()
    print("=" * 70)


if __name__ == "__main__":
    main()
