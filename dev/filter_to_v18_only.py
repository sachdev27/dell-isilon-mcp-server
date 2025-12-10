#!/usr/bin/env python3
"""
Filter OpenAPI spec to OneFS 9.7 (API version 18) endpoints only.

This script:
1. Reads the comprehensive OpenAPI spec
2. Identifies all unique endpoint patterns
3. For each pattern, keeps only the LATEST version (preferring v18 for OneFS 9.7)
4. Removes all older API versions (1-17)
5. Outputs a clean spec with no duplicate endpoint functionality

According to PowerScale docs:
- OneFS 9.7.0.0 = API version 18
- Use /platform/18/<resource> for latest
- Older versions preserved but deprecated

Usage:
    python filter_to_v18_only.py --input openapi.json --output openapi_v18.json
"""

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple


def extract_version_and_pattern(path: str) -> Tuple[int, str]:
    """
    Extract API version and normalized pattern from path.

    Examples:
        /platform/1/cluster/config -> (1, '/platform/VERSION/cluster/config')
        /platform/18/protocols/smb/shares -> (18, '/platform/VERSION/protocols/smb/shares')
        /namespace/ifs/data -> (0, '/namespace/{path}')

    Returns:
        (version_number, normalized_pattern)
    """
    # Handle namespace endpoints (no version)
    if path.startswith('/namespace/'):
        return (0, '/namespace/{path}')

    # Handle platform endpoints with version
    platform_match = re.match(r'^/platform/(\d+)(/.*)', path)
    if platform_match:
        version = int(platform_match.group(1))
        rest_of_path = platform_match.group(2)
        pattern = f'/platform/VERSION{rest_of_path}'
        return (version, pattern)

    # Handle local endpoints with version
    local_match = re.match(r'^/platform/(\d+)/local(/.*)', path)
    if local_match:
        version = int(local_match.group(1))
        rest_of_path = local_match.group(2)
        pattern = f'/platform/VERSION/local{rest_of_path}'
        return (version, pattern)

    # Unknown pattern
    return (0, path)


def normalize_path_params(path: str) -> str:
    """
    Normalize path parameters to make patterns comparable.

    Examples:
        /platform/1/auth/users/{v1AuthUser} -> /platform/1/auth/users/{id}
        /platform/18/auth/users/{userId} -> /platform/18/auth/users/{id}
    """
    # Replace all parameter names with {id} for comparison
    normalized = re.sub(r'\{[^}]+\}', '{id}', path)
    return normalized


def should_keep_path(path: str, version: int, target_version: int = 18) -> bool:
    """
    Determine if a path should be kept based on version.

    Rules:
    1. Keep namespace endpoints (version 0)
    2. For platform endpoints, prefer target_version (18)
    3. If target_version doesn't exist for a pattern, keep highest version
    """
    if version == 0:  # namespace
        return True

    return version == target_version


def filter_to_latest_version(openapi_spec: Dict[str, Any], target_version: int = 18) -> Dict[str, Any]:
    """
    Filter OpenAPI spec to keep only the latest API version for each endpoint pattern.

    Per PowerScale docs: If endpoint was introduced in v1 and not updated,
    it's still accessible via v18. We keep only the HIGHEST version of each endpoint.

    Args:
        openapi_spec: Full OpenAPI specification
        target_version: Target API version (default 18 for OneFS 9.7)

    Returns:
        Filtered OpenAPI spec with only latest versions
    """
    paths = openapi_spec.get('paths', {})

    # Group paths by their normalized pattern
    # Key: (normalized_pattern, method)
    # Value: List of (original_path, version, path_spec)
    pattern_groups: Dict[Tuple[str, str], List[Tuple[str, int, Dict]]] = defaultdict(list)

    for path, path_item in paths.items():
        version, pattern = extract_version_and_pattern(path)
        normalized = normalize_path_params(pattern)

        # For each HTTP method in this path
        for method in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
            if method in path_item:
                key = (normalized, method)
                pattern_groups[key].append((path, version, path_item[method]))

    # For each pattern group, select the HIGHEST version only
    selected_paths: Dict[str, Dict[str, Any]] = {}

    for (pattern, method), candidates in pattern_groups.items():
        # Sort by version descending and take the highest
        candidates.sort(key=lambda x: x[1], reverse=True)
        highest = candidates[0]

        path, version, spec = highest

        # Update the path to use target version if it's lower
        # Per docs: /platform/1/resource/x at v18 -> access via /platform/18/resource/x
        if version < target_version and version > 0:  # Don't change namespace
            # Replace version number in path
            updated_path = re.sub(r'^/platform/\d+/', f'/platform/{target_version}/', path)
            path = updated_path

            # Update operationId to reflect new version
            if 'operationId' in spec:
                old_id = spec['operationId']
                # Replace version prefix in operationId (e.g., get1ClusterConfig -> get18ClusterConfig)
                new_id = re.sub(r'^(get|post|put|delete|patch)(\d+)', rf'\g<1>{target_version}', old_id)
                spec = spec.copy()
                spec['operationId'] = new_id

        # Add to selected paths
        if path not in selected_paths:
            selected_paths[path] = {}

        selected_paths[path][method] = spec

    # Build new spec
    filtered_spec = openapi_spec.copy()
    filtered_spec['paths'] = selected_paths

    # Update info
    if 'info' in filtered_spec:
        filtered_spec['info']['title'] = f"{filtered_spec['info'].get('title', 'PowerScale API')} v{target_version} (OneFS 9.7)"
        filtered_spec['info']['description'] = (
            f"PowerScale OneFS 9.7.0.0 API (version {target_version}). "
            "This specification includes only the latest/highest API version for each endpoint. "
            "All paths use v18 URIs per OneFS API versioning rules."
        )

    return filtered_spec


def get_statistics(openapi_spec: Dict[str, Any]) -> Dict[str, Any]:
    """Get statistics about the OpenAPI spec."""
    paths = openapi_spec.get('paths', {})

    # Count by version
    version_counts: Dict[int, int] = defaultdict(int)
    method_counts: Dict[str, int] = defaultdict(int)

    for path, path_item in paths.items():
        version, _ = extract_version_and_pattern(path)

        for method in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
            if method in path_item:
                version_counts[version] += 1
                method_counts[method] += 1

    return {
        'total_paths': len(paths),
        'total_operations': sum(method_counts.values()),
        'version_distribution': dict(sorted(version_counts.items())),
        'method_distribution': dict(method_counts),
        'tags': len(openapi_spec.get('tags', []))
    }


def main():
    parser = argparse.ArgumentParser(
        description='Filter OpenAPI spec to OneFS 9.7 (API v18) endpoints only'
    )
    parser.add_argument(
        '--input', '-i',
        required=True,
        help='Input OpenAPI JSON file'
    )
    parser.add_argument(
        '--output', '-o',
        required=True,
        help='Output OpenAPI JSON file'
    )
    parser.add_argument(
        '--target-version', '-v',
        type=int,
        default=18,
        help='Target API version (default: 18 for OneFS 9.7)'
    )
    parser.add_argument(
        '--pretty',
        action='store_true',
        default=True,
        help='Pretty print JSON (default: True)'
    )

    args = parser.parse_args()

    # Load input
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        return 1

    print(f"Loading OpenAPI spec from {input_path}...")
    with open(input_path, 'r', encoding='utf-8') as f:
        openapi_spec = json.load(f)

    # Get before statistics
    before_stats = get_statistics(openapi_spec)
    print("\n=== Before Filtering ===")
    print(f"Total paths: {before_stats['total_paths']}")
    print(f"Total operations: {before_stats['total_operations']}")
    print(f"Version distribution: {before_stats['version_distribution']}")
    print(f"Method distribution: {before_stats['method_distribution']}")

    # Filter to target version
    print(f"\nFiltering to API version {args.target_version} (OneFS 9.7)...")
    filtered_spec = filter_to_latest_version(openapi_spec, args.target_version)

    # Get after statistics
    after_stats = get_statistics(filtered_spec)
    print("\n=== After Filtering ===")
    print(f"Total paths: {after_stats['total_paths']}")
    print(f"Total operations: {after_stats['total_operations']}")
    print(f"Version distribution: {after_stats['version_distribution']}")
    print(f"Method distribution: {after_stats['method_distribution']}")

    # Calculate reduction
    reduction = before_stats['total_operations'] - after_stats['total_operations']
    reduction_pct = (reduction / before_stats['total_operations']) * 100 if before_stats['total_operations'] > 0 else 0
    print(f"\nRemoved {reduction} duplicate operations ({reduction_pct:.1f}% reduction)")

    # Save output
    output_path = Path(args.output)
    print(f"\nSaving filtered spec to {output_path}...")
    with open(output_path, 'w', encoding='utf-8') as f:
        if args.pretty:
            json.dump(filtered_spec, f, indent=2, ensure_ascii=False)
        else:
            json.dump(filtered_spec, f, ensure_ascii=False)

    print(f"✓ Successfully created {output_path}")
    print(f"  {after_stats['total_paths']} paths")
    print(f"  {after_stats['total_operations']} operations")
    print(f"  {after_stats['tags']} tags")

    return 0


if __name__ == '__main__':
    exit(main())
