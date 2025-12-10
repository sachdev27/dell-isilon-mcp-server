#!/usr/bin/env python3
"""
PowerScale API 9.7 - Batch OpenAPI Spec Generator

This script fetches ALL endpoints from the Dell Developer Portal for PowerScale API
version 9.7 in batches and generates a comprehensive OpenAPI 3.0 specification.

It uses the actual Dell API structure discovered from the developer portal.

Usage:
    python fetch_openapi_batch.py [--batch-size 10] [--output openapi.json]

Author: Generated for PowerScale/Isilon MCP Server
"""

import argparse
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote, unquote
import concurrent.futures

try:
    import requests
except ImportError:
    print("Please install requests: pip install requests")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
API_ID = "4088"
API_VERSION = "9.7.0"
SPEC_FILE = "9.7.0.0_OAS2.json"

# Dell Developer Portal API
DELL_BASE_URL = "https://developer.dell.com"
API_DOCS_URL = f"{DELL_BASE_URL}/api-docs-svc/api/{API_ID}/version/{API_VERSION}"

# Headers mimicking browser request
HEADERS = {
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8',
    'Content-Type': 'application/json',
    'Origin': 'https://developer.dell.com',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
}


@dataclass
class EndpointInfo:
    """Stores information about an API endpoint."""
    path: str
    method: str
    slug: str
    summary: str = ""
    description: str = ""
    parameters: List[Dict] = field(default_factory=list)
    request_body: Optional[Dict] = None
    responses: Dict[str, Dict] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    security: List[Dict] = field(default_factory=list)


class PowerScaleBatchFetcher:
    """Fetches PowerScale API documentation in batches from Dell Developer Portal."""

    def __init__(self, batch_size: int = 10, delay: float = 0.5):
        self.batch_size = batch_size
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.endpoints: List[EndpointInfo] = []
        self.failed_slugs: List[str] = []
        self.all_endpoint_slugs: List[Tuple[str, str, str]] = []  # (path, method, slug)

    def get_navigation_structure(self) -> Dict:
        """Fetch the navigation structure to discover all endpoints."""
        # First, let's try to get the sidebar/navigation data
        nav_url = f"{API_DOCS_URL}/navigation"

        logger.info(f"Fetching navigation structure...")

        try:
            response = self.session.get(nav_url, timeout=30)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.debug(f"Navigation fetch failed: {e}")

        return {}

    def discover_all_endpoints(self) -> List[Tuple[str, str, str]]:
        """
        Discover all API endpoints by querying the reference documentation structure.
        Returns list of (path, method, slug) tuples.
        """
        endpoints = []

        # Known API sections based on Dell PowerScale documentation structure
        # These are the main categories in the 9.7.0.0_OAS2.json specification
        api_sections = [
            # Platform API sections with version numbers
            ("platform", "1", "antivirus"),
            ("platform", "1", "audit"),
            ("platform", "1", "auth"),
            ("platform", "1", "certificate"),
            ("platform", "1", "cloud"),
            ("platform", "1", "cluster"),
            ("platform", "1", "datamover"),
            ("platform", "1", "debug"),
            ("platform", "1", "dedupe"),
            ("platform", "1", "event"),
            ("platform", "1", "filepool"),
            ("platform", "1", "fsa"),
            ("platform", "1", "hardware"),
            ("platform", "1", "healthcheck"),
            ("platform", "1", "id-resolution"),
            ("platform", "1", "job"),
            ("platform", "1", "license"),
            ("platform", "1", "local"),
            ("platform", "1", "network"),
            ("platform", "1", "performance"),
            ("platform", "1", "protocols"),
            ("platform", "1", "quota"),
            ("platform", "1", "remotesupport"),
            ("platform", "1", "snapshot"),
            ("platform", "1", "statistics"),
            ("platform", "1", "storagepool"),
            ("platform", "1", "sync"),
            ("platform", "1", "upgrade"),
            ("platform", "1", "worm"),
            ("platform", "1", "zones"),
            # Platform API version 3+
            ("platform", "3", "antivirus"),
            ("platform", "3", "audit"),
            ("platform", "3", "auth"),
            ("platform", "3", "cluster"),
            ("platform", "3", "event"),
            ("platform", "3", "fsa"),
            ("platform", "3", "hardware"),
            ("platform", "3", "job"),
            ("platform", "3", "network"),
            ("platform", "3", "protocols"),
            ("platform", "3", "quota"),
            ("platform", "3", "snapshot"),
            ("platform", "3", "statistics"),
            ("platform", "3", "storagepool"),
            ("platform", "3", "sync"),
            ("platform", "3", "zones"),
            # Higher versions
            ("platform", "4", "protocols"),
            ("platform", "4", "quota"),
            ("platform", "4", "statistics"),
            ("platform", "5", "protocols"),
            ("platform", "5", "statistics"),
            ("platform", "6", "protocols"),
            ("platform", "7", "protocols"),
            ("platform", "7", "statistics"),
            ("platform", "8", "statistics"),
            ("platform", "9", "statistics"),
            ("platform", "10", "statistics"),
            ("platform", "11", "statistics"),
            ("platform", "12", "statistics"),
            ("platform", "14", "auth"),
            ("platform", "14", "protocols"),
            ("platform", "15", "protocols"),
            ("platform", "16", "protocols"),
            # Namespace API
            ("namespace", None, None),
        ]

        # Standard HTTP methods
        methods = ["get", "post", "put", "delete", "patch", "head"]

        # Generate comprehensive endpoint list based on common patterns
        endpoint_patterns = self._generate_endpoint_patterns()

        for path, method in endpoint_patterns:
            # Create slug format: /SPEC_FILE/paths/~1path~1segments/method
            encoded_path = path.replace('/', '~1')
            slug = f"/{SPEC_FILE}/paths/{encoded_path}/{method}"
            endpoints.append((path, method.upper(), slug))

        logger.info(f"Discovered {len(endpoints)} potential endpoints")
        return endpoints

    def _generate_endpoint_patterns(self) -> List[Tuple[str, str]]:
        """Generate comprehensive list of endpoint patterns."""
        patterns = []

        # ============================================
        # AUTH ENDPOINTS (platform/1/auth/*)
        # ============================================
        auth_resources = [
            "access/{v1AuthAccessUser}",
            "groups",
            "groups/{v1AuthGroupsGroup}",
            "groups/{v1AuthGroupsGroup}/members",
            "groups/{v1AuthGroupsGroup}/members/{v1GroupMember}",
            "id",
            "log-level",
            "log-level/{v1AuthLogLevelLevel}",
            "mapping/dump",
            "mapping/identities",
            "mapping/identities/{v1MappingIdentity}",
            "mapping/import",
            "mapping/users/lookup",
            "mapping/users/rules",
            "mapping/users/rules/{v1MappingUsersRule}",
            "netgroups",
            "privileges",
            "providers/ads",
            "providers/ads/{v1ProvidersAdsId}",
            "providers/ads/{v1ProvidersAdsId}/controllers",
            "providers/ads/{v1ProvidersAdsId}/domains",
            "providers/ads/{v1ProvidersAdsId}/search",
            "providers/file",
            "providers/file/{v1ProvidersFileId}",
            "providers/krb5",
            "providers/krb5/{v1ProvidersKrb5Id}",
            "providers/ldap",
            "providers/ldap/{v1ProvidersLdapId}",
            "providers/local",
            "providers/local/{v1ProvidersLocalId}",
            "providers/nis",
            "providers/nis/{v1ProvidersNisId}",
            "providers/summary",
            "roles",
            "roles/{v1AuthRolesRole}",
            "roles/{v1AuthRolesRole}/members",
            "roles/{v1AuthRolesRole}/members/{v1AuthRolesMember}",
            "roles/{v1AuthRolesRole}/privileges",
            "settings/acls",
            "settings/global",
            "settings/krb5/defaults",
            "settings/krb5/domains",
            "settings/krb5/domains/{v1SettingsKrb5Domain}",
            "settings/krb5/realms",
            "settings/krb5/realms/{v1SettingsKrb5Realm}",
            "settings/mapping",
            "shells",
            "users",
            "users/{v1AuthUsersUser}",
            "users/{v1AuthUsersUser}/change-password",
            "users/{v1AuthUsersUser}/member-of",
            "users/{v1AuthUsersUser}/tokens",
            "wellknowns",
        ]

        for resource in auth_resources:
            path = f"/platform/1/auth/{resource}"
            patterns.append((path, "get"))
            if "{" not in resource or resource.endswith("}"):
                if "settings" in resource or "mapping" in resource:
                    patterns.append((path, "put"))
                elif not resource.endswith("summary") and not resource.endswith("wellknowns"):
                    patterns.append((path, "post"))
                    patterns.append((path, "put"))
                    patterns.append((path, "delete"))

        # ============================================
        # CLUSTER ENDPOINTS (platform/1/cluster/*)
        # ============================================
        cluster_resources = [
            "config",
            "email",
            "email/settings",
            "external-ips",
            "identity",
            "internal-networks",
            "node",
            "nodes",
            "nodes/{v1ClusterNode}",
            "nodes/{v1ClusterNode}/drives",
            "nodes/{v1ClusterNode}/drives/{v1ClusterNodeDrive}",
            "nodes/{v1ClusterNode}/hardware",
            "nodes/{v1ClusterNode}/partitions",
            "nodes/{v1ClusterNode}/sensors",
            "nodes/{v1ClusterNode}/sleds",
            "nodes/{v1ClusterNode}/state",
            "nodes/{v1ClusterNode}/state/readonly",
            "nodes/{v1ClusterNode}/state/serviceled",
            "nodes/{v1ClusterNode}/state/smartfail",
            "nodes/{v1ClusterNode}/status",
            "nodes/{v1ClusterNode}/status/batterystatus",
            "owner",
            "patches",
            "patches/{v1ClusterPatch}",
            "statfs",
            "time",
            "timezone",
            "timezone/regions",
            "timezone/settings",
            "version",
        ]

        for resource in cluster_resources:
            path = f"/platform/1/cluster/{resource}"
            patterns.append((path, "get"))
            if "config" in resource or "identity" in resource or "settings" in resource:
                patterns.append((path, "put"))
            if "{" in resource and not resource.endswith("readonly"):
                patterns.append((path, "put"))

        # ============================================
        # PROTOCOLS - NFS ENDPOINTS
        # ============================================
        nfs_resources = [
            "aliases",
            "aliases/{v1NfsAliasId}",
            "check",
            "exports",
            "exports/{v1NfsExportId}",
            "exports-summary",
            "log-level",
            "netgroup",
            "netgroup/check",
            "netgroup/flush",
            "nlm/locks",
            "nlm/sessions",
            "nlm/sessions/{v1NfsNlmSessionId}",
            "nlm/waiters",
            "settings/export",
            "settings/global",
            "settings/zone",
        ]

        for resource in nfs_resources:
            path = f"/platform/1/protocols/nfs/{resource}"
            patterns.append((path, "get"))
            if "exports" in resource and "{" not in resource:
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # Also add newer protocol versions
        for version in ["2", "3", "4"]:
            for resource in ["exports", "exports/{NfsExportId}", "settings/export", "settings/global"]:
                path = f"/platform/{version}/protocols/nfs/{resource}"
                patterns.append((path, "get"))
                if "settings" in resource:
                    patterns.append((path, "put"))

        # ============================================
        # PROTOCOLS - SMB ENDPOINTS
        # ============================================
        smb_resources = [
            "log-level",
            "log-level/{v1SmbLogLevelLevel}",
            "openfiles",
            "sessions",
            "sessions/{v1SmbSession}",
            "settings/global",
            "settings/share",
            "shares",
            "shares/{v1SmbShareId}",
            "shares-summary",
        ]

        for resource in smb_resources:
            path = f"/platform/1/protocols/smb/{resource}"
            patterns.append((path, "get"))
            if "shares" in resource and "{" not in resource:
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))
            if "{" in resource and "log-level" not in resource:
                patterns.append((path, "delete"))

        # ============================================
        # QUOTA ENDPOINTS
        # ============================================
        quota_resources = [
            "license",
            "quotas",
            "quotas/{v1QuotaQuotaId}",
            "quotas-summary",
            "reports",
            "reports/{v1QuotaReportId}",
            "reports/{v1QuotaReportId}/about",
            "reports-summary",
            "settings/mappings",
            "settings/mappings/{v1QuotaSettingsMapping}",
            "settings/notifications",
            "settings/reports",
        ]

        for resource in quota_resources:
            path = f"/platform/1/quota/{resource}"
            patterns.append((path, "get"))
            if "quotas" == resource:
                patterns.append((path, "post"))
            if "{" in resource:
                patterns.append((path, "put"))
                patterns.append((path, "delete"))
            if "settings" in resource:
                patterns.append((path, "put"))

        # ============================================
        # SNAPSHOT ENDPOINTS
        # ============================================
        snapshot_resources = [
            "aliases",
            "aliases/{v1SnapshotAliasId}",
            "changelists",
            "changelists/{v1SnapshotChangelistId}",
            "license",
            "pending",
            "pending/{v1SnapshotPendingId}",
            "repstates",
            "schedules",
            "schedules/{v1SnapshotScheduleId}",
            "settings",
            "snapshots",
            "snapshots/{v1SnapshotSnapshotId}",
            "snapshots/{v1SnapshotSnapshotId}/locks",
            "snapshots/{v1SnapshotSnapshotId}/locks/{v1SnapshotLockId}",
            "snapshots-summary",
        ]

        for resource in snapshot_resources:
            path = f"/platform/1/snapshot/{resource}"
            patterns.append((path, "get"))
            if resource in ["aliases", "schedules", "snapshots"]:
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # ============================================
        # SYNC (SyncIQ) ENDPOINTS
        # ============================================
        sync_resources = [
            "jobs",
            "jobs/{v1SyncJobId}",
            "license",
            "performance-rules",
            "performance-rules/{v1SyncRuleId}",
            "policies",
            "policies/{v1SyncPolicyId}",
            "policies/{v1SyncPolicyId}/reset",
            "policies/{v1SyncPolicyId}/target-cancel",
            "reports",
            "reports/{v1SyncReportId}",
            "reports/{v1SyncReportId}/subreports",
            "reports/{v1SyncReportId}/subreports/{v1SyncSubreportId}",
            "rules",
            "rules/{v1SyncRuleId}",
            "service",
            "service/policies",
            "service/target",
            "settings",
            "target/policies",
            "target/policies/{v1TargetPolicyId}",
            "target/reports",
            "target/reports/{v1TargetReportId}",
            "target/reports/{v1TargetReportId}/subreports",
        ]

        for resource in sync_resources:
            path = f"/platform/1/sync/{resource}"
            patterns.append((path, "get"))
            if resource in ["jobs", "performance-rules", "policies", "rules"]:
                patterns.append((path, "post"))
            if "{" in resource or resource == "settings" or resource == "service":
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # ============================================
        # STATISTICS ENDPOINTS
        # ============================================
        statistics_resources = [
            "current",
            "history",
            "keys",
            "keys/{v1StatisticsKey}",
            "operations",
            "protocols",
            "summary/client",
            "summary/drive",
            "summary/heat",
            "summary/protocol",
            "summary/protocol-stats",
            "summary/system",
            "summary/workload",
        ]

        for resource in statistics_resources:
            path = f"/platform/1/statistics/{resource}"
            patterns.append((path, "get"))

        # ============================================
        # STORAGEPOOL ENDPOINTS
        # ============================================
        storagepool_resources = [
            "compatibilities/class/active",
            "compatibilities/class/available",
            "compatibilities/ssd/active",
            "compatibilities/ssd/available",
            "nodepools",
            "nodepools/{v1StoragepoolNodepoolId}",
            "settings",
            "status",
            "storagepools",
            "suggested-protection",
            "tiers",
            "tiers/{v1StoragepoolTierId}",
            "unprovisioned",
        ]

        for resource in storagepool_resources:
            path = f"/platform/1/storagepool/{resource}"
            patterns.append((path, "get"))
            if "nodepools" == resource or "tiers" == resource:
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # ============================================
        # NETWORK ENDPOINTS
        # ============================================
        network_resources = [
            "dnscache",
            "dnscache/flush",
            "external",
            "groupnets",
            "groupnets/{v1GroupnetId}",
            "groupnets/{v1GroupnetId}/subnets",
            "groupnets/{v1GroupnetId}/subnets/{v1SubnetId}",
            "groupnets/{v1GroupnetId}/subnets/{v1SubnetId}/pools",
            "groupnets/{v1GroupnetId}/subnets/{v1SubnetId}/pools/{v1PoolId}",
            "interfaces",
            "pools",
            "rules",
            "rules/{v1NetworkRuleId}",
            "subnets",
        ]

        for resource in network_resources:
            path = f"/platform/1/network/{resource}"
            patterns.append((path, "get"))
            if resource in ["groupnets", "rules"]:
                patterns.append((path, "post"))
            if "{" in resource:
                patterns.append((path, "put"))
                patterns.append((path, "delete"))

        # ============================================
        # ZONES ENDPOINTS
        # ============================================
        zones_resources = [
            "",
            "{v1ZonesZone}",
        ]

        for resource in zones_resources:
            path = f"/platform/1/zones/{resource}" if resource else "/platform/1/zones"
            patterns.append((path, "get"))
            if not resource:
                patterns.append((path, "post"))
            else:
                patterns.append((path, "put"))
                patterns.append((path, "delete"))

        # ============================================
        # EVENT ENDPOINTS
        # ============================================
        event_resources = [
            "alert-conditions",
            "alert-conditions/{v1EventAlertConditionId}",
            "categories",
            "channels",
            "channels/{v1EventChannelId}",
            "eventgroup-definitions",
            "eventgroup-definitions/{v1EventEventgroupDefinitionId}",
            "eventgroup-occurrences",
            "eventgroup-occurrences/{v1EventEventgroupOccurrenceId}",
            "eventlists",
            "events",
            "settings",
        ]

        for resource in event_resources:
            path = f"/platform/1/event/{resource}"
            patterns.append((path, "get"))
            if resource in ["alert-conditions", "channels"]:
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # ============================================
        # JOB ENDPOINTS
        # ============================================
        job_resources = [
            "events",
            "jobs",
            "jobs/{v1JobJobId}",
            "policies",
            "policies/{v1JobPolicyId}",
            "recent",
            "reports",
            "reports/{v1JobReportId}",
            "statistics",
            "types",
            "types/{v1JobTypeId}",
        ]

        for resource in job_resources:
            path = f"/platform/1/job/{resource}"
            patterns.append((path, "get"))
            if resource == "jobs":
                patterns.append((path, "post"))
            if "{" in resource:
                patterns.append((path, "put"))

        # ============================================
        # ANTIVIRUS ENDPOINTS
        # ============================================
        antivirus_resources = [
            "policies",
            "policies/{v1AntivirusPolicyId}",
            "quarantine",
            "quarantine/{v1AntivirusQuarantinePathId}",
            "reports/scans",
            "reports/threats",
            "scan",
            "servers",
            "servers/{v1AntivirusServerId}",
            "settings",
        ]

        for resource in antivirus_resources:
            path = f"/platform/1/antivirus/{resource}"
            patterns.append((path, "get"))
            if resource in ["policies", "servers"]:
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # ============================================
        # AUDIT ENDPOINTS
        # ============================================
        audit_resources = [
            "logs",
            "progress",
            "settings",
            "settings/global",
            "topics",
            "topics/{v1AuditTopicId}",
        ]

        for resource in audit_resources:
            path = f"/platform/1/audit/{resource}"
            patterns.append((path, "get"))
            if resource == "topics":
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # ============================================
        # HARDWARE ENDPOINTS
        # ============================================
        hardware_resources = [
            "fcports",
            "fcports/{v1HardwareFcportId}",
            "tapes",
            "tapes/{v1HardwareTapeName}",
        ]

        for resource in hardware_resources:
            path = f"/platform/1/hardware/{resource}"
            patterns.append((path, "get"))
            if "{" in resource:
                patterns.append((path, "put"))

        # ============================================
        # LICENSE ENDPOINTS
        # ============================================
        license_resources = [
            "generate",
            "licenses",
            "licenses/{v1LicenseLicense}",
        ]

        for resource in license_resources:
            path = f"/platform/1/license/{resource}"
            patterns.append((path, "get"))
            if resource == "licenses":
                patterns.append((path, "post"))

        # ============================================
        # WORM ENDPOINTS
        # ============================================
        worm_resources = [
            "domains",
            "domains/{v1WormDomainId}",
            "settings",
        ]

        for resource in worm_resources:
            path = f"/platform/1/worm/{resource}"
            patterns.append((path, "get"))
            if resource == "domains":
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))

        # ============================================
        # FSA (File System Analytics) ENDPOINTS
        # ============================================
        fsa_resources = [
            "path",
            "results",
            "results/{v1FsaResultId}",
            "results/{v1FsaResultId}/directories",
            "results/{v1FsaResultId}/histogram",
            "results/{v1FsaResultId}/top-dirs",
            "results/{v1FsaResultId}/top-files",
            "settings",
        ]

        for resource in fsa_resources:
            path = f"/platform/1/fsa/{resource}"
            patterns.append((path, "get"))
            if "settings" in resource:
                patterns.append((path, "put"))

        # ============================================
        # NAMESPACE (File System) ENDPOINTS
        # ============================================
        namespace_patterns = [
            ("/namespace/{NamespacePath}", "get"),
            ("/namespace/{NamespacePath}", "put"),
            ("/namespace/{NamespacePath}", "post"),
            ("/namespace/{NamespacePath}", "delete"),
            ("/namespace/{NamespacePath}", "head"),
            # Additional namespace operations with query params
            ("/namespace/{DirectoryPath}", "get"),
            ("/namespace/{DirectoryPath}", "put"),
            ("/namespace/{DirectoryPath}", "delete"),
        ]

        patterns.extend(namespace_patterns)

        # ============================================
        # DEDUPE ENDPOINTS
        # ============================================
        dedupe_resources = [
            "dedupe-summary",
            "inline-settings",
            "reports",
            "reports/{v1DedupeReportId}",
            "settings",
        ]

        for resource in dedupe_resources:
            path = f"/platform/1/dedupe/{resource}"
            patterns.append((path, "get"))
            if "settings" in resource:
                patterns.append((path, "put"))

        # ============================================
        # UPGRADE ENDPOINTS
        # ============================================
        upgrade_resources = [
            "cluster",
            "cluster/add-nodes",
            "cluster/add-remaining-nodes",
            "cluster/archive",
            "cluster/assess",
            "cluster/commit",
            "cluster/firmware",
            "cluster/firmware/assess",
            "cluster/firmware/progress",
            "cluster/firmware/status",
            "cluster/nodes",
            "cluster/nodes/{v1UpgradeClusterNode}",
            "cluster/patch/patches",
            "cluster/patch/patches/{v1UpgradeClusterPatchPatch}",
            "cluster/resume",
            "cluster/rollback",
        ]

        for resource in upgrade_resources:
            path = f"/platform/1/upgrade/{resource}"
            patterns.append((path, "get"))
            if "commit" in resource or "resume" in resource or "rollback" in resource:
                patterns.append((path, "post"))
            if "{" in resource:
                patterns.append((path, "put"))

        # ============================================
        # CLOUD ENDPOINTS
        # ============================================
        cloud_resources = [
            "access",
            "access/{v1CloudAccessGuid}",
            "accounts",
            "accounts/{v1CloudAccountId}",
            "jobs",
            "jobs/{v1CloudJobId}",
            "jobs-files",
            "pools",
            "pools/{v1CloudPoolId}",
            "proxies",
            "proxies/{v1CloudProxyId}",
            "settings",
        ]

        for resource in cloud_resources:
            path = f"/platform/1/cloud/{resource}"
            patterns.append((path, "get"))
            if resource in ["access", "accounts", "jobs", "pools", "proxies"]:
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # ============================================
        # FILEPOOL ENDPOINTS
        # ============================================
        filepool_resources = [
            "default-policy",
            "policies",
            "policies/{v1FilepoolPolicyId}",
            "templates",
            "templates/{v1FilepoolTemplateId}",
        ]

        for resource in filepool_resources:
            path = f"/platform/1/filepool/{resource}"
            patterns.append((path, "get"))
            if resource in ["policies", "templates"]:
                patterns.append((path, "post"))
            if "{" in resource or "default-policy" in resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # ============================================
        # API ENDPOINTS (platform/latest/*)
        # ============================================
        api_resources = [
            "",
            "summary",
        ]

        for resource in api_resources:
            path = f"/platform/latest" if not resource else f"/platform/latest/{resource}"
            patterns.append((path, "get"))

        # ============================================
        # AVSCAN ENDPOINTS (platform/*/avscan/*)
        # ============================================
        avscan_resources = [
            "files",
            "files/{v1AvscanFileId}",
            "jobs",
            "jobs/{v1AvscanJobId}",
            "nodes",
            "nodes/{v1AvscanNodeId}",
            "nodes/{v1AvscanNodeId}/files",
            "settings",
        ]

        for resource in avscan_resources:
            path = f"/platform/1/avscan/{resource}"
            patterns.append((path, "get"))
            if resource in ["jobs"]:
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # ============================================
        # CATALOG ENDPOINTS (platform/*/catalog/*)
        # ============================================
        catalog_resources = [
            "fields",
            "fields/{v1CatalogFieldId}",
            "settings",
        ]

        for resource in catalog_resources:
            path = f"/platform/1/catalog/{resource}"
            patterns.append((path, "get"))
            if resource == "fields":
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # ============================================
        # CERTIFICATE ENDPOINTS (platform/*/certificate/*)
        # ============================================
        certificate_resources = [
            "authority",
            "authority/{v1CertificateAuthorityId}",
            "server",
            "server/{v1CertificateServerId}",
            "settings",
        ]

        for resource in certificate_resources:
            path = f"/platform/1/certificate/{resource}"
            patterns.append((path, "get"))
            if resource in ["authority", "server"]:
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # Add higher version certificate endpoints
        for version in ["4", "10", "11"]:
            cert_v_resources = [
                "authority",
                "authority/{CertificateAuthorityId}",
                "server",
                "server/{CertificateServerId}",
                "settings",
            ]
            for resource in cert_v_resources:
                path = f"/platform/{version}/certificate/{resource}"
                patterns.append((path, "get"))
                if resource in ["authority", "server"]:
                    patterns.append((path, "post"))
                if "{" in resource or "settings" in resource:
                    patterns.append((path, "put"))
                if "{" in resource:
                    patterns.append((path, "delete"))

        # ============================================
        # CLUSTER MODE ENDPOINTS
        # ============================================
        clustermode_resources = [
            "nodes",
            "nodes/{v1ClusterModeNode}",
        ]

        for resource in clustermode_resources:
            path = f"/platform/1/cluster/mode/{resource}" if resource else "/platform/1/cluster/mode"
            patterns.append((path, "get"))
            if "{" in resource:
                patterns.append((path, "put"))

        # ============================================
        # CONFIG ENDPOINTS (platform/*/config/*)
        # ============================================
        config_resources = [
            "exports",
            "exports/{v1ConfigExportId}",
            "imports",
            "imports/{v1ConfigImportId}",
            "settings",
        ]

        for resource in config_resources:
            path = f"/platform/1/config/{resource}"
            patterns.append((path, "get"))
            if resource in ["exports", "imports"]:
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # ============================================
        # DATAMOVER ENDPOINTS (platform/*/datamover/*)
        # ============================================
        datamover_resources = [
            "accounts",
            "accounts/{v1DatamoverAccountId}",
            "base-policies",
            "base-policies/{v1DatamoverBasePolicyId}",
            "certificates",
            "certificates/{v1DatamoverCertificateId}",
            "datasets",
            "datasets/{v1DatamoverDatasetId}",
            "historical-jobs",
            "historical-jobs/{v1DatamoverHistoricalJobId}",
            "jobs",
            "jobs/{v1DatamoverJobId}",
            "policies",
            "policies/{v1DatamoverPolicyId}",
            "settings",
            "throttling-policies",
            "throttling-policies/{v1DatamoverThrottlingPolicyId}",
        ]

        for resource in datamover_resources:
            path = f"/platform/1/datamover/{resource}"
            patterns.append((path, "get"))
            if resource in ["accounts", "base-policies", "certificates", "datasets", "jobs", "policies", "throttling-policies"]:
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # Add higher API versions for datamover (14, 15, 16)
        for version in ["14", "15", "16", "17", "18"]:
            datamover_v_resources = [
                "accounts",
                "accounts/{DatamoverAccountId}",
                "policies",
                "policies/{DatamoverPolicyId}",
                "jobs",
                "jobs/{DatamoverJobId}",
                "datasets",
                "datasets/{DatamoverDatasetId}",
                "settings",
            ]
            for resource in datamover_v_resources:
                path = f"/platform/{version}/datamover/{resource}"
                patterns.append((path, "get"))
                if not "{" in resource and resource != "settings":
                    patterns.append((path, "post"))
                if "{" in resource or "settings" in resource:
                    patterns.append((path, "put"))
                if "{" in resource:
                    patterns.append((path, "delete"))

        # ============================================
        # DEBUG ENDPOINTS (platform/*/debug/*)
        # ============================================
        debug_resources = [
            "stats",
            "stats/export",
        ]

        for resource in debug_resources:
            path = f"/platform/1/debug/{resource}"
            patterns.append((path, "get"))
            if "export" in resource:
                patterns.append((path, "post"))

        # ============================================
        # FILE FILTER ENDPOINTS (platform/*/filefilter/*)
        # ============================================
        filefilter_resources = [
            "settings",
        ]

        for resource in filefilter_resources:
            path = f"/platform/1/filefilter/{resource}"
            patterns.append((path, "get"))
            patterns.append((path, "put"))

        # ============================================
        # FILESYSTEM ENDPOINTS (platform/*/filesystem/*)
        # ============================================
        filesystem_resources = [
            "settings",
        ]

        for resource in filesystem_resources:
            path = f"/platform/1/filesystem/{resource}"
            patterns.append((path, "get"))
            patterns.append((path, "put"))

        # ============================================
        # FSA INDEX ENDPOINTS
        # ============================================
        fsa_index_resources = [
            "results/{v1FsaResultId}/directories/{v1FsaDirectory}",
            "results/{v1FsaResultId}/histogram/{v1FsaHistogramStat}",
            "results/{v1FsaResultId}/histogram/{v1FsaHistogramStat}/by-file-attribute",
            "results/{v1FsaResultId}/top-dirs/{v1FsaTopDir}",
            "results/{v1FsaResultId}/top-files/{v1FsaTopFile}",
        ]

        for resource in fsa_index_resources:
            path = f"/platform/1/fsa/{resource}"
            patterns.append((path, "get"))

        # ============================================
        # GROUPNETS SUMMARY ENDPOINTS
        # ============================================
        groupnets_summary_resources = [
            "summary",
        ]

        for resource in groupnets_summary_resources:
            path = f"/platform/1/network/groupnets/{resource}"
            patterns.append((path, "get"))

        # ============================================
        # HARDENING ENDPOINTS (platform/*/hardening/*)
        # ============================================
        hardening_resources = [
            "reports",
            "reports/{v1HardeningReportId}",
            "settings",
            "state",
            "status",
        ]

        for resource in hardening_resources:
            path = f"/platform/1/hardening/{resource}"
            patterns.append((path, "get"))
            if resource == "state":
                patterns.append((path, "post"))
            if "settings" in resource:
                patterns.append((path, "put"))

        # ============================================
        # HEALTHCHECK ENDPOINTS (platform/*/healthcheck/*)
        # ============================================
        healthcheck_resources = [
            "autoupdate",
            "checklists",
            "checklists/{v1HealthcheckChecklistId}",
            "definitions",
            "definitions/{v1HealthcheckDefinitionId}",
            "evaluations",
            "evaluations/{v1HealthcheckEvaluationId}",
            "items",
            "items/{v1HealthcheckItemId}",
            "parameters",
            "parameters/{v1HealthcheckParameterId}",
            "schedule",
            "schedules",
            "schedules/{v1HealthcheckScheduleId}",
            "settings",
        ]

        for resource in healthcheck_resources:
            path = f"/platform/1/healthcheck/{resource}"
            patterns.append((path, "get"))
            if resource in ["checklists", "evaluations", "schedules"]:
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource or "schedule" == resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # ============================================
        # ID RESOLUTION ENDPOINTS
        # ============================================
        id_resolution_resources = [
            "paths",
            "lins",
        ]

        for resource in id_resolution_resources:
            path = f"/platform/1/id-resolution/{resource}"
            patterns.append((path, "get"))

        # ID Resolution Zones
        id_resolution_zones_resources = [
            "{v1IdResolutionZone}/paths",
            "{v1IdResolutionZone}/lins",
        ]

        for resource in id_resolution_zones_resources:
            path = f"/platform/1/id-resolution/zones/{resource}"
            patterns.append((path, "get"))

        # ============================================
        # IPMI ENDPOINTS (platform/*/ipmi/*)
        # ============================================
        ipmi_resources = [
            "config",
            "config/node",
        ]

        for resource in ipmi_resources:
            path = f"/platform/1/ipmi/{resource}"
            patterns.append((path, "get"))
            patterns.append((path, "put"))

        # ============================================
        # KEYMANAGER ENDPOINTS (platform/*/keymanager/*)
        # ============================================
        keymanager_resources = [
            "cluster",
            "cluster/keys",
            "cluster/keys/{v1KeymanagerKeyId}",
            "cluster/rekey",
            "sed",
            "sed/master-key",
            "sed/migrate",
            "sed/settings",
            "sed/status",
        ]

        for resource in keymanager_resources:
            path = f"/platform/1/keymanager/{resource}"
            patterns.append((path, "get"))
            if resource in ["cluster/keys", "cluster/rekey", "sed/migrate"]:
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource or "master-key" in resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # ============================================
        # LFN (Long File Name) ENDPOINTS
        # ============================================
        lfn_resources = [
            "settings",
        ]

        for resource in lfn_resources:
            path = f"/platform/1/lfn/{resource}"
            patterns.append((path, "get"))
            patterns.append((path, "put"))

        # ============================================
        # NETWORK FIREWALL ENDPOINTS
        # ============================================
        network_firewall_resources = [
            "policies",
            "policies/{v1NetworkFirewallPolicyId}",
            "rules",
            "rules/{v1NetworkFirewallRuleId}",
            "settings",
            "dscp",
            "dscp/rules",
            "dscp/rules/{v1NetworkFirewallDscpRuleId}",
            "dscp/settings",
        ]

        for resource in network_firewall_resources:
            path = f"/platform/1/network/firewall/{resource}"
            patterns.append((path, "get"))
            if resource in ["policies", "rules", "dscp/rules"]:
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # ============================================
        # OS ENDPOINTS (platform/*/os/*)
        # ============================================
        os_resources = [
            "security",
            "security/settings",
        ]

        for resource in os_resources:
            path = f"/platform/1/os/{resource}"
            patterns.append((path, "get"))
            if "settings" in resource:
                patterns.append((path, "put"))

        # ============================================
        # PAPI ENDPOINTS (platform/*/papi/*)
        # ============================================
        papi_resources = [
            "settings",
        ]

        for resource in papi_resources:
            path = f"/platform/1/papi/{resource}"
            patterns.append((path, "get"))
            patterns.append((path, "put"))

        # ============================================
        # PERFORMANCE ENDPOINTS (platform/*/performance/*)
        # ============================================
        performance_resources = [
            "datasets",
            "datasets/{v1PerformanceDatasetId}",
            "datasets/{v1PerformanceDatasetId}/workloads",
            "datasets/{v1PerformanceDatasetId}/workloads/{v1PerformanceWorkloadId}",
            "settings",
            "workloads",
            "workloads/{v1PerformanceWorkloadId}",
        ]

        for resource in performance_resources:
            path = f"/platform/1/performance/{resource}"
            patterns.append((path, "get"))
            if resource in ["datasets", "workloads"]:
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # Higher versions for performance
        for version in ["7", "14"]:
            perf_v_resources = [
                "datasets",
                "datasets/{PerformanceDatasetId}",
                "settings",
            ]
            for resource in perf_v_resources:
                path = f"/platform/{version}/performance/{resource}"
                patterns.append((path, "get"))
                if resource == "datasets":
                    patterns.append((path, "post"))
                if "{" in resource or "settings" in resource:
                    patterns.append((path, "put"))
                if "{" in resource:
                    patterns.append((path, "delete"))

        # ============================================
        # PROTOCOLS - HDFS ENDPOINTS
        # ============================================
        hdfs_resources = [
            "crypto",
            "crypto/settings",
            "fsimage",
            "fsimage/job",
            "fsimage/settings",
            "log-level",
            "proxyusers",
            "proxyusers/{v1ProtocolsHdfsProxyuserId}",
            "racks",
            "racks/{v1ProtocolsHdfsRackId}",
            "ranger-plugin",
            "ranger-plugin/settings",
            "settings",
        ]

        for resource in hdfs_resources:
            path = f"/platform/1/protocols/hdfs/{resource}"
            patterns.append((path, "get"))
            if resource in ["proxyusers", "racks"]:
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # Higher versions for HDFS
        for version in ["4", "5", "7"]:
            hdfs_v_resources = [
                "proxyusers",
                "proxyusers/{ProtocolsHdfsProxyuserId}",
                "racks",
                "racks/{ProtocolsHdfsRackId}",
                "settings",
            ]
            for resource in hdfs_v_resources:
                path = f"/platform/{version}/protocols/hdfs/{resource}"
                patterns.append((path, "get"))
                if resource in ["proxyusers", "racks"]:
                    patterns.append((path, "post"))
                if "{" in resource or "settings" in resource:
                    patterns.append((path, "put"))
                if "{" in resource:
                    patterns.append((path, "delete"))

        # ============================================
        # PROTOCOLS - HTTP ENDPOINTS
        # ============================================
        http_resources = [
            "settings",
        ]

        for resource in http_resources:
            path = f"/platform/1/protocols/http/{resource}"
            patterns.append((path, "get"))
            patterns.append((path, "put"))

        # ============================================
        # PROTOCOLS - FTP ENDPOINTS
        # ============================================
        ftp_resources = [
            "settings",
        ]

        for resource in ftp_resources:
            path = f"/platform/1/protocols/ftp/{resource}"
            patterns.append((path, "get"))
            patterns.append((path, "put"))

        # ============================================
        # PROTOCOLS - NDMP ENDPOINTS
        # ============================================
        ndmp_resources = [
            "contexts",
            "contexts/{v1NdmpContextId}",
            "contexts-bre",
            "contexts-bre/{v1NdmpContextBreId}",
            "diagnostics",
            "dumpdates",
            "dumpdates/{v1NdmpDumpdateId}",
            "logs",
            "sessions",
            "sessions/{v1NdmpSessionId}",
            "settings/dmas",
            "settings/global",
            "settings/preferred-ips",
            "settings/variables",
            "settings/variables/{v1NdmpSettingsVariableId}",
            "users",
            "users/{v1NdmpUserId}",
        ]

        for resource in ndmp_resources:
            path = f"/platform/1/protocols/ndmp/{resource}"
            patterns.append((path, "get"))
            if resource in ["users"]:
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # ============================================
        # PROTOCOLS - SWIFT ENDPOINTS (S3)
        # ============================================
        swift_resources = [
            "accounts",
            "accounts/{v1SwiftAccountId}",
        ]

        for resource in swift_resources:
            path = f"/platform/1/protocols/swift/{resource}"
            patterns.append((path, "get"))
            if resource == "accounts":
                patterns.append((path, "post"))
            if "{" in resource:
                patterns.append((path, "put"))
                patterns.append((path, "delete"))

        # ============================================
        # PROTOCOLS - S3 ENDPOINTS
        # ============================================
        s3_resources = [
            "buckets",
            "buckets/{v1S3BucketId}",
            "keys",
            "keys/{v1S3KeyId}",
            "log-level",
            "mykeys",
            "settings",
            "settings/global",
            "settings/zone",
        ]

        for resource in s3_resources:
            path = f"/platform/1/protocols/s3/{resource}"
            patterns.append((path, "get"))
            if resource in ["buckets", "keys"]:
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))
            if "{" in resource:
                patterns.append((path, "delete"))

        # Higher versions for S3
        for version in ["10", "12", "14", "16"]:
            s3_v_resources = [
                "buckets",
                "buckets/{S3BucketId}",
                "settings",
                "settings/global",
                "settings/zone",
            ]
            for resource in s3_v_resources:
                path = f"/platform/{version}/protocols/s3/{resource}"
                patterns.append((path, "get"))
                if resource == "buckets":
                    patterns.append((path, "post"))
                if "{" in resource or "settings" in resource:
                    patterns.append((path, "put"))
                if "{" in resource:
                    patterns.append((path, "delete"))

        # ============================================
        # SECURITY ENDPOINTS (platform/*/security/*)
        # ============================================
        security_resources = [
            "settings",
            "check",
        ]

        for resource in security_resources:
            path = f"/platform/1/security/{resource}"
            patterns.append((path, "get"))
            if resource == "settings":
                patterns.append((path, "put"))

        # ============================================
        # SNAPSHOT CHANGELISTS ENDPOINTS
        # ============================================
        snapshot_changelists_resources = [
            "{v1SnapshotChangelistId}/entries",
            "{v1SnapshotChangelistId}/entries/{v1SnapshotChangelistEntry}",
            "{v1SnapshotChangelistId}/diff-regions",
            "{v1SnapshotChangelistId}/lins",
            "{v1SnapshotChangelistId}/lins/{v1SnapshotChangelistLin}",
        ]

        for resource in snapshot_changelists_resources:
            path = f"/platform/1/snapshot/changelists/{resource}"
            patterns.append((path, "get"))

        # ============================================
        # STORAGEPOOL NODETYPES ENDPOINTS
        # ============================================
        storagepool_nodetypes_resources = [
            "",
            "{v1StoragepoolNodetypeId}",
        ]

        for resource in storagepool_nodetypes_resources:
            path = f"/platform/1/storagepool/nodetypes/{resource}" if resource else "/platform/1/storagepool/nodetypes"
            patterns.append((path, "get"))

        # ============================================
        # SUPPORTASSIST ENDPOINTS
        # ============================================
        supportassist_resources = [
            "license",
            "settings",
            "settings/contact",
            "settings/connection",
            "settings/telemetry",
            "status",
            "tasks",
            "tasks/{v1SupportassistTaskId}",
            "terms",
            "terms/{v1SupportassistTermsId}",
        ]

        for resource in supportassist_resources:
            path = f"/platform/1/supportassist/{resource}"
            patterns.append((path, "get"))
            if resource == "tasks":
                patterns.append((path, "post"))
            if "{" in resource or "settings" in resource:
                patterns.append((path, "put"))

        # Higher versions for supportassist
        for version in ["16", "17"]:
            support_v_resources = [
                "settings",
                "status",
                "tasks",
                "tasks/{SupportassistTaskId}",
            ]
            for resource in support_v_resources:
                path = f"/platform/{version}/supportassist/{resource}"
                patterns.append((path, "get"))
                if resource == "tasks":
                    patterns.append((path, "post"))
                if "{" in resource or "settings" in resource:
                    patterns.append((path, "put"))

        # ============================================
        # SYNC SERVICE ENDPOINTS
        # ============================================
        sync_service_resources = [
            "policies/{v1SyncServicePolicyId}",
            "policies/{v1SyncServicePolicyId}/cancel",
            "target/policies",
            "target/policies/{v1SyncServiceTargetPolicyId}",
            "target/policies/{v1SyncServiceTargetPolicyId}/cancel",
        ]

        for resource in sync_service_resources:
            path = f"/platform/1/sync/service/{resource}"
            patterns.append((path, "get"))
            if "cancel" in resource:
                patterns.append((path, "post"))
            if "{" in resource and "cancel" not in resource:
                patterns.append((path, "put"))

        # ============================================
        # SYNC TARGET ENDPOINTS
        # ============================================
        sync_target_resources = [
            "policies/{v1SyncTargetPolicyId}",
            "policies/{v1SyncTargetPolicyId}/cancel",
            "reports",
            "reports/{v1SyncTargetReportId}",
            "reports/{v1SyncTargetReportId}/subreports",
            "reports/{v1SyncTargetReportId}/subreports/{v1SyncTargetSubreportId}",
        ]

        for resource in sync_target_resources:
            path = f"/platform/1/sync/target/{resource}"
            patterns.append((path, "get"))
            if "cancel" in resource:
                patterns.append((path, "post"))
            if "{" in resource and "cancel" not in resource and "subreports" not in resource:
                patterns.append((path, "put"))
                patterns.append((path, "delete"))

        # Higher versions for sync
        for version in ["3", "4", "5", "6", "7", "14", "15"]:
            sync_v_resources = [
                "jobs",
                "jobs/{SyncJobId}",
                "policies",
                "policies/{SyncPolicyId}",
                "reports",
                "reports/{SyncReportId}",
                "settings",
            ]
            for resource in sync_v_resources:
                path = f"/platform/{version}/sync/{resource}"
                patterns.append((path, "get"))
                if resource in ["jobs", "policies"]:
                    patterns.append((path, "post"))
                if "{" in resource or "settings" in resource:
                    patterns.append((path, "put"))
                if "{" in resource:
                    patterns.append((path, "delete"))

        # ============================================
        # UPGRADE CLUSTER ENDPOINTS
        # ============================================
        upgrade_cluster_resources = [
            "nodes/{v1UpgradeClusterNode}/firmware",
            "nodes/{v1UpgradeClusterNode}/firmware/device",
            "nodes/{v1UpgradeClusterNode}/firmware/status",
        ]

        for resource in upgrade_cluster_resources:
            path = f"/platform/1/upgrade/cluster/{resource}"
            patterns.append((path, "get"))
            if "device" in resource:
                patterns.append((path, "put"))

        # ============================================
        # ZONES SUMMARY ENDPOINTS
        # ============================================
        zones_summary_resources = [
            "summary",
        ]

        for resource in zones_summary_resources:
            path = f"/platform/1/zones/{resource}"
            patterns.append((path, "get"))

        # ============================================
        # REMOTESUPPORT ENDPOINTS
        # ============================================
        remotesupport_resources = [
            "connectemc",
            "connectemc/settings",
        ]

        for resource in remotesupport_resources:
            path = f"/platform/1/remotesupport/{resource}"
            patterns.append((path, "get"))
            if "settings" in resource:
                patterns.append((path, "put"))

        # ============================================
        # LOCAL ENDPOINTS (platform/*/local/*)
        # ============================================
        local_resources = [
            "cluster/mode",
            "cluster/mode/nodes",
            "cluster/mode/nodes/{v1LocalClusterModeNode}",
        ]

        for resource in local_resources:
            path = f"/platform/1/local/{resource}"
            patterns.append((path, "get"))
            if "{" in resource:
                patterns.append((path, "put"))

        # ============================================
        # HIGHER VERSION AUTH ENDPOINTS (v14, v17, v18)
        # ============================================
        for version in ["7", "14", "17", "18"]:
            auth_v_resources = [
                "access/{AuthAccessUser}",
                "groups",
                "groups/{AuthGroupsGroup}",
                "groups/{AuthGroupsGroup}/members",
                "providers/ads",
                "providers/ads/{ProvidersAdsId}",
                "providers/file",
                "providers/file/{ProvidersFileId}",
                "providers/ldap",
                "providers/ldap/{ProvidersLdapId}",
                "providers/local",
                "providers/local/{ProvidersLocalId}",
                "providers/nis",
                "providers/nis/{ProvidersNisId}",
                "roles",
                "roles/{AuthRolesRole}",
                "roles/{AuthRolesRole}/members",
                "roles/{AuthRolesRole}/privileges",
                "users",
                "users/{AuthUsersUser}",
                "settings/acls",
                "settings/global",
            ]
            for resource in auth_v_resources:
                path = f"/platform/{version}/auth/{resource}"
                patterns.append((path, "get"))
                if resource in ["groups", "providers/ads", "providers/file", "providers/ldap", "providers/local", "providers/nis", "roles", "users"]:
                    patterns.append((path, "post"))
                if "{" in resource or "settings" in resource:
                    patterns.append((path, "put"))
                if "{" in resource:
                    patterns.append((path, "delete"))

        # ============================================
        # HIGHER VERSION PROTOCOLS - SMB (v4, v6, v7, v12, v14)
        # ============================================
        for version in ["4", "6", "7", "12", "14"]:
            smb_v_resources = [
                "shares",
                "shares/{SmbShareId}",
                "openfiles",
                "sessions",
                "sessions/{SmbSession}",
                "settings/global",
                "settings/share",
            ]
            for resource in smb_v_resources:
                path = f"/platform/{version}/protocols/smb/{resource}"
                patterns.append((path, "get"))
                if resource == "shares":
                    patterns.append((path, "post"))
                if "{" in resource or "settings" in resource:
                    patterns.append((path, "put"))
                if "{" in resource:
                    patterns.append((path, "delete"))

        # ============================================
        # HIGHER VERSION PROTOCOLS - NFS (v2, v4, v15, v16)
        # ============================================
        for version in ["2", "4", "15", "16"]:
            nfs_v_resources = [
                "aliases",
                "aliases/{NfsAliasId}",
                "exports",
                "exports/{NfsExportId}",
                "settings/export",
                "settings/global",
                "settings/zone",
            ]
            for resource in nfs_v_resources:
                path = f"/platform/{version}/protocols/nfs/{resource}"
                patterns.append((path, "get"))
                if resource in ["aliases", "exports"]:
                    patterns.append((path, "post"))
                if "{" in resource or "settings" in resource:
                    patterns.append((path, "put"))
                if "{" in resource:
                    patterns.append((path, "delete"))

        # ============================================
        # HIGHER VERSION QUOTA ENDPOINTS
        # ============================================
        for version in ["1", "12", "15", "17"]:
            quota_v_resources = [
                "quotas",
                "quotas/{QuotaQuotaId}",
                "quotas-summary",
                "reports",
                "reports/{QuotaReportId}",
                "settings/mappings",
                "settings/notifications",
                "settings/reports",
            ]
            for resource in quota_v_resources:
                path = f"/platform/{version}/quota/{resource}"
                patterns.append((path, "get"))
                if resource == "quotas":
                    patterns.append((path, "post"))
                if "{" in resource or "settings" in resource:
                    patterns.append((path, "put"))
                if "{" in resource:
                    patterns.append((path, "delete"))

        # ============================================
        # HIGHER VERSION CLUSTER ENDPOINTS
        # ============================================
        for version in ["3", "4", "5", "10", "11", "12", "14", "15", "16"]:
            cluster_v_resources = [
                "config",
                "identity",
                "nodes",
                "nodes/{ClusterNode}",
                "time",
                "timezone",
                "version",
                "statfs",
            ]
            for resource in cluster_v_resources:
                path = f"/platform/{version}/cluster/{resource}"
                patterns.append((path, "get"))
                if "config" in resource or "identity" in resource or "time" in resource or "timezone" in resource:
                    patterns.append((path, "put"))
                if "{" in resource:
                    patterns.append((path, "put"))

        # ============================================
        # HIGHER VERSION EVENT ENDPOINTS
        # ============================================
        for version in ["3", "4", "7", "14"]:
            event_v_resources = [
                "alert-conditions",
                "alert-conditions/{EventAlertConditionId}",
                "channels",
                "channels/{EventChannelId}",
                "eventgroup-definitions",
                "eventgroup-occurrences",
                "events",
                "settings",
            ]
            for resource in event_v_resources:
                path = f"/platform/{version}/event/{resource}"
                patterns.append((path, "get"))
                if resource in ["alert-conditions", "channels"]:
                    patterns.append((path, "post"))
                if "{" in resource or "settings" in resource:
                    patterns.append((path, "put"))
                if "{" in resource:
                    patterns.append((path, "delete"))

        # ============================================
        # HIGHER VERSION SNAPSHOT ENDPOINTS
        # ============================================
        for version in ["1", "4", "11", "12"]:
            snapshot_v_resources = [
                "aliases",
                "aliases/{SnapshotAliasId}",
                "changelists",
                "changelists/{SnapshotChangelistId}",
                "schedules",
                "schedules/{SnapshotScheduleId}",
                "settings",
                "snapshots",
                "snapshots/{SnapshotSnapshotId}",
                "snapshots-summary",
            ]
            for resource in snapshot_v_resources:
                path = f"/platform/{version}/snapshot/{resource}"
                patterns.append((path, "get"))
                if resource in ["aliases", "schedules", "snapshots"]:
                    patterns.append((path, "post"))
                if "{" in resource or "settings" in resource:
                    patterns.append((path, "put"))
                if "{" in resource:
                    patterns.append((path, "delete"))

        # ============================================
        # HIGHER VERSION STORAGEPOOL ENDPOINTS
        # ============================================
        for version in ["5", "9", "14"]:
            storagepool_v_resources = [
                "nodepools",
                "nodepools/{StoragepoolNodepoolId}",
                "settings",
                "status",
                "tiers",
                "tiers/{StoragepoolTierId}",
            ]
            for resource in storagepool_v_resources:
                path = f"/platform/{version}/storagepool/{resource}"
                patterns.append((path, "get"))
                if resource in ["nodepools", "tiers"]:
                    patterns.append((path, "post"))
                if "{" in resource or "settings" in resource:
                    patterns.append((path, "put"))
                if "{" in resource:
                    patterns.append((path, "delete"))

        # ============================================
        # HIGHER VERSION NETWORK ENDPOINTS
        # ============================================
        for version in ["7", "10", "12", "14"]:
            network_v_resources = [
                "dnscache",
                "external",
                "groupnets",
                "groupnets/{GroupnetId}",
                "groupnets/{GroupnetId}/subnets",
                "groupnets/{GroupnetId}/subnets/{SubnetId}",
                "groupnets/{GroupnetId}/subnets/{SubnetId}/pools",
                "groupnets/{GroupnetId}/subnets/{SubnetId}/pools/{PoolId}",
                "interfaces",
                "pools",
                "rules",
                "rules/{NetworkRuleId}",
            ]
            for resource in network_v_resources:
                path = f"/platform/{version}/network/{resource}"
                patterns.append((path, "get"))
                if resource in ["groupnets", "rules"]:
                    patterns.append((path, "post"))
                if "{" in resource:
                    patterns.append((path, "put"))
                    patterns.append((path, "delete"))

        # ============================================
        # HIGHER VERSION CLOUD ENDPOINTS
        # ============================================
        for version in ["7", "12", "13", "14"]:
            cloud_v_resources = [
                "access",
                "access/{CloudAccessGuid}",
                "accounts",
                "accounts/{CloudAccountId}",
                "jobs",
                "jobs/{CloudJobId}",
                "pools",
                "pools/{CloudPoolId}",
                "proxies",
                "proxies/{CloudProxyId}",
                "settings",
            ]
            for resource in cloud_v_resources:
                path = f"/platform/{version}/cloud/{resource}"
                patterns.append((path, "get"))
                if resource in ["access", "accounts", "jobs", "pools", "proxies"]:
                    patterns.append((path, "post"))
                if "{" in resource or "settings" in resource:
                    patterns.append((path, "put"))
                if "{" in resource:
                    patterns.append((path, "delete"))

        # ============================================
        # HIGHER VERSION UPGRADE ENDPOINTS
        # ============================================
        for version in ["3", "7", "10", "11", "14"]:
            upgrade_v_resources = [
                "cluster",
                "cluster/assess",
                "cluster/commit",
                "cluster/firmware",
                "cluster/firmware/assess",
                "cluster/firmware/status",
                "cluster/nodes",
                "cluster/nodes/{UpgradeClusterNode}",
            ]
            for resource in upgrade_v_resources:
                path = f"/platform/{version}/upgrade/{resource}"
                patterns.append((path, "get"))
                if "commit" in resource or "assess" in resource:
                    patterns.append((path, "post"))
                if "{" in resource:
                    patterns.append((path, "put"))

        # ============================================
        # HIGHER VERSION ANTIVIRUS ENDPOINTS
        # ============================================
        for version in ["3", "7"]:
            antivirus_v_resources = [
                "policies",
                "policies/{AntivirusPolicyId}",
                "quarantine",
                "servers",
                "servers/{AntivirusServerId}",
                "settings",
            ]
            for resource in antivirus_v_resources:
                path = f"/platform/{version}/antivirus/{resource}"
                patterns.append((path, "get"))
                if resource in ["policies", "servers"]:
                    patterns.append((path, "post"))
                if "{" in resource or "settings" in resource:
                    patterns.append((path, "put"))
                if "{" in resource:
                    patterns.append((path, "delete"))

        # ============================================
        # HIGHER VERSION AUDIT ENDPOINTS
        # ============================================
        for version in ["7", "14"]:
            audit_v_resources = [
                "logs",
                "progress",
                "settings",
                "settings/global",
                "topics",
                "topics/{AuditTopicId}",
            ]
            for resource in audit_v_resources:
                path = f"/platform/{version}/audit/{resource}"
                patterns.append((path, "get"))
                if resource == "topics":
                    patterns.append((path, "post"))
                if "{" in resource or "settings" in resource:
                    patterns.append((path, "put"))
                if "{" in resource:
                    patterns.append((path, "delete"))

        # ============================================
        # HIGHER VERSION JOB ENDPOINTS
        # ============================================
        for version in ["3", "7", "10", "14"]:
            job_v_resources = [
                "events",
                "jobs",
                "jobs/{JobJobId}",
                "policies",
                "policies/{JobPolicyId}",
                "recent",
                "reports",
                "statistics",
                "types",
                "types/{JobTypeId}",
            ]
            for resource in job_v_resources:
                path = f"/platform/{version}/job/{resource}"
                patterns.append((path, "get"))
                if resource == "jobs":
                    patterns.append((path, "post"))
                if "{" in resource:
                    patterns.append((path, "put"))

        # ============================================
        # HIGHER VERSION FSA ENDPOINTS
        # ============================================
        for version in ["3", "5", "6"]:
            fsa_v_resources = [
                "path",
                "results",
                "results/{FsaResultId}",
                "settings",
            ]
            for resource in fsa_v_resources:
                path = f"/platform/{version}/fsa/{resource}"
                patterns.append((path, "get"))
                if "settings" in resource:
                    patterns.append((path, "put"))

        # ============================================
        # HIGHER VERSION ZONES ENDPOINTS
        # ============================================
        for version in ["3", "4"]:
            zones_v_resources = [
                "",
                "{ZonesZone}",
            ]
            for resource in zones_v_resources:
                path = f"/platform/{version}/zones/{resource}" if resource else f"/platform/{version}/zones"
                patterns.append((path, "get"))
                if not resource:
                    patterns.append((path, "post"))
                else:
                    patterns.append((path, "put"))
                    patterns.append((path, "delete"))

        # ============================================
        # HIGHER VERSION WORM ENDPOINTS
        # ============================================
        for version in ["4"]:
            worm_v_resources = [
                "domains",
                "domains/{WormDomainId}",
                "settings",
            ]
            for resource in worm_v_resources:
                path = f"/platform/{version}/worm/{resource}"
                patterns.append((path, "get"))
                if resource == "domains":
                    patterns.append((path, "post"))
                if "{" in resource or "settings" in resource:
                    patterns.append((path, "put"))

        return patterns

    def fetch_endpoint_details(self, slug: str) -> Optional[str]:
        """Fetch HTML documentation for a single endpoint."""
        payload = {"slug": slug}

        try:
            response = self.session.post(
                API_DOCS_URL,
                json=payload,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    return data.get('data', '')
            elif response.status_code == 429:
                logger.warning("Rate limited, waiting...")
                time.sleep(5)
                return self.fetch_endpoint_details(slug)

        except requests.exceptions.RequestException as e:
            logger.error(f"Request error for {slug}: {e}")
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON response for {slug}")

        return None

    def parse_endpoint_html(self, html: str, path: str, method: str) -> EndpointInfo:
        """Parse HTML documentation to extract endpoint information."""
        endpoint = EndpointInfo(
            path=path,
            method=method.lower(),
            slug=""
        )

        # Extract description from markdown-renderer
        desc_match = re.search(r'<div class="markdown-renderer">.*?<div><p>(.*?)</p>', html, re.DOTALL)
        if desc_match:
            endpoint.description = re.sub(r'<[^>]+>', '', desc_match.group(1)).strip()
            endpoint.summary = endpoint.description[:100] + ("..." if len(endpoint.description) > 100 else "")

        # Check for security
        if 'basicAuth' in html:
            endpoint.security = [{"basicAuth": []}]

        # Extract parameters
        endpoint.parameters = []

        # Query parameters
        query_section = re.search(r'Query Parameters.*?(?=Path Parameters|Header Parameters|Request Body|Responses|$)', html, re.DOTALL)
        if query_section:
            params = self._extract_parameters(query_section.group(0), 'query')
            endpoint.parameters.extend(params)

        # Path parameters
        path_section = re.search(r'Path Parameters.*?(?=Header Parameters|Request Body|Responses|$)', html, re.DOTALL)
        if path_section:
            params = self._extract_parameters(path_section.group(0), 'path')
            endpoint.parameters.extend(params)

        # Also extract path params from the path itself
        path_params_in_path = re.findall(r'\{([^}]+)\}', path)
        existing_path_params = {p['name'] for p in endpoint.parameters if p.get('in') == 'path'}

        for param_name in path_params_in_path:
            if param_name not in existing_path_params:
                endpoint.parameters.append({
                    'name': param_name,
                    'in': 'path',
                    'required': True,
                    'schema': {'type': 'string'},
                    'description': f'{param_name} parameter'
                })

        # Header parameters
        header_section = re.search(r'Header Parameters.*?(?=Request Body|Responses|$)', html, re.DOTALL)
        if header_section:
            params = self._extract_parameters(header_section.group(0), 'header')
            endpoint.parameters.extend(params)

        # Extract response codes
        endpoint.responses = {}
        response_matches = re.findall(r'<span class="(?:text-green|text-red)">.*?(\d{3}|default)</span>\s*:?\s*(\w+)?', html)

        for match in response_matches:
            code = match[0] if match[0] else 'default'
            desc = match[1] if len(match) > 1 and match[1] else 'Response'
            endpoint.responses[code] = {'description': desc}

        if not endpoint.responses:
            endpoint.responses['200'] = {'description': 'Success'}

        endpoint.responses['default'] = {
            'description': 'Error',
            'content': {
                'application/json': {
                    'schema': {'$ref': '#/components/schemas/Error'}
                }
            }
        }

        # Generate tags from path
        endpoint.tags = self._generate_tags(path)

        return endpoint

    def _extract_parameters(self, html_section: str, location: str) -> List[Dict]:
        """Extract parameters from an HTML section."""
        params = []

        # Find all parameter rows
        param_pattern = re.compile(
            r'<span class="property-name">\s*([^<]+)\s*</span>.*?'
            r'<span class="type">\s*([^<]+)\s*</span>.*?'
            r'(?:<span class="required">Required</span>)?.*?'
            r'(?:<div class="desc"><p>(.*?)</p></div>)?',
            re.DOTALL
        )

        for match in param_pattern.finditer(html_section):
            name = match.group(1).strip()
            param_type = match.group(2).strip().lower()
            description = match.group(3)

            if description:
                description = re.sub(r'<[^>]+>', '', description).strip()
            else:
                description = f'{name} parameter'

            # Determine if required
            is_required = 'Required' in match.group(0) or location == 'path'

            # Map type
            schema = self._map_type(param_type)

            params.append({
                'name': name,
                'in': location,
                'required': is_required,
                'schema': schema,
                'description': description
            })

        return params

    def _map_type(self, type_str: str) -> Dict:
        """Map type string to OpenAPI schema."""
        type_str = type_str.lower()

        if 'integer' in type_str:
            schema = {'type': 'integer'}
            if 'int32' in type_str:
                schema['format'] = 'int32'
            elif 'int64' in type_str:
                schema['format'] = 'int64'
            return schema
        elif 'number' in type_str:
            return {'type': 'number'}
        elif 'boolean' in type_str:
            return {'type': 'boolean'}
        elif 'array' in type_str:
            if 'object' in type_str:
                return {'type': 'array', 'items': {'type': 'object'}}
            return {'type': 'array', 'items': {'type': 'string'}}
        elif 'object' in type_str:
            return {'type': 'object'}
        else:
            return {'type': 'string'}

    def _generate_tags(self, path: str) -> List[str]:
        """Generate tags from path."""
        parts = [p for p in path.split('/') if p and not p.startswith('{')]

        if 'platform' in parts:
            idx = parts.index('platform')
            if idx + 2 < len(parts):
                tag = parts[idx + 2]
                # Clean up tag
                tag = tag.replace('-', ' ').title()
                return [tag]

        if 'namespace' in parts:
            return ['Namespace']

        return ['Default']

    def fetch_batch(self, batch: List[Tuple[str, str, str]], batch_num: int, total_batches: int):
        """Fetch a batch of endpoints."""
        logger.info(f"Processing batch {batch_num}/{total_batches} ({len(batch)} endpoints)")

        for i, (path, method, slug) in enumerate(batch):
            try:
                html = self.fetch_endpoint_details(slug)

                if html:
                    endpoint = self.parse_endpoint_html(html, path, method)
                    self.endpoints.append(endpoint)
                    logger.debug(f"  ✓ {method} {path}")
                else:
                    self.failed_slugs.append(slug)
                    logger.debug(f"  ✗ {method} {path} (no data)")

                # Rate limiting
                time.sleep(self.delay)

            except Exception as e:
                logger.error(f"  ✗ Error processing {method} {path}: {e}")
                self.failed_slugs.append(slug)

    def fetch_all_batches(self):
        """Fetch all endpoints in batches."""
        # Discover endpoints
        self.all_endpoint_slugs = self.discover_all_endpoints()

        if not self.all_endpoint_slugs:
            logger.error("No endpoints discovered!")
            return

        # Split into batches
        batches = [
            self.all_endpoint_slugs[i:i + self.batch_size]
            for i in range(0, len(self.all_endpoint_slugs), self.batch_size)
        ]

        total_batches = len(batches)
        logger.info(f"Processing {len(self.all_endpoint_slugs)} endpoints in {total_batches} batches")

        for batch_num, batch in enumerate(batches, 1):
            self.fetch_batch(batch, batch_num, total_batches)

        logger.info(f"Completed: {len(self.endpoints)} successful, {len(self.failed_slugs)} failed")

    def build_openapi_spec(self) -> Dict[str, Any]:
        """Build OpenAPI 3.0 specification from collected endpoints."""
        spec = {
            "openapi": "3.0.3",
            "info": {
                "title": "Dell PowerScale (Isilon) OneFS API",
                "description": """# Dell PowerScale OneFS REST API

This OpenAPI 3.0 specification describes the Dell PowerScale (formerly Isilon) OneFS REST API version 9.7.

## Overview

PowerScale OneFS API provides programmatic access to:
- **Cluster Management**: Configuration, nodes, identity
- **Protocols**: NFS exports, SMB shares, HDFS, S3
- **File System**: Namespace operations, ACLs, quotas
- **Data Protection**: Snapshots, SyncIQ replication, NDMP
- **Security**: Authentication, authorization, audit
- **Storage**: Pools, tiers, CloudPools
- **Monitoring**: Statistics, events, jobs

## Authentication

All API requests require HTTP Basic Authentication with cluster credentials.

## Base URLs

- Platform API: `https://<cluster>:8080/platform/`
- Namespace API: `https://<cluster>:8080/namespace/`

## Common Parameters

- `zone`: Access zone context for operations
- `resume`: Pagination token for large result sets
- `limit`: Maximum items to return (default varies by endpoint)
- `sort`: Sort field
- `dir`: Sort direction (ASC/DESC)
""",
                "version": "9.7.0",
                "contact": {
                    "name": "Dell Technologies Support",
                    "url": "https://www.dell.com/support/kbdoc/en-us/000020423/powerscale-powerscale-onefs-platform-api-documentation"
                },
                "license": {
                    "name": "Proprietary",
                    "url": "https://www.dell.com/learn/us/en/uscorp1/terms-of-sale"
                },
                "x-logo": {
                    "url": "https://upload.wikimedia.org/wikipedia/commons/1/18/Dell_logo_2016.svg"
                }
            },
            "externalDocs": {
                "description": "Dell Developer Portal - PowerScale API",
                "url": "https://developer.dell.com/apis/4088/versions/9.7.0"
            },
            "servers": [
                {
                    "url": "https://{cluster}:8080",
                    "description": "PowerScale OneFS Cluster",
                    "variables": {
                        "cluster": {
                            "default": "your-cluster-ip-or-hostname",
                            "description": "Cluster management IP or hostname"
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
                        "description": "HTTP Basic Authentication with cluster credentials"
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
                                "description": "Human-readable error message"
                            }
                        }
                    },
                    "Persona": {
                        "type": "object",
                        "description": "User/group identity reference",
                        "properties": {
                            "id": {
                                "type": "string",
                                "description": "Serialized identity (UID:0, USER:name, GID:0, GROUP:name, SID:S-1-1)"
                            },
                            "name": {
                                "type": "string",
                                "description": "Name (when combined with type)"
                            },
                            "type": {
                                "type": "string",
                                "enum": ["user", "group", "wellknown"],
                                "description": "Identity type"
                            }
                        }
                    },
                    "ResumeToken": {
                        "type": "object",
                        "properties": {
                            "resume": {
                                "type": "string",
                                "description": "Token to retrieve next page of results"
                            }
                        }
                    }
                },
                "parameters": {
                    "zone": {
                        "name": "zone",
                        "in": "query",
                        "description": "Access zone name",
                        "schema": {"type": "string"}
                    },
                    "resume": {
                        "name": "resume",
                        "in": "query",
                        "description": "Resume token for pagination",
                        "schema": {"type": "string"}
                    },
                    "limit": {
                        "name": "limit",
                        "in": "query",
                        "description": "Maximum number of items to return",
                        "schema": {"type": "integer", "minimum": 1, "maximum": 1000}
                    },
                    "sort": {
                        "name": "sort",
                        "in": "query",
                        "description": "Sort field",
                        "schema": {"type": "string"}
                    },
                    "dir": {
                        "name": "dir",
                        "in": "query",
                        "description": "Sort direction",
                        "schema": {"type": "string", "enum": ["ASC", "DESC"]}
                    }
                },
                "responses": {
                    "Success": {
                        "description": "Successful operation"
                    },
                    "BadRequest": {
                        "description": "Invalid request parameters",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Error"}
                            }
                        }
                    },
                    "Unauthorized": {
                        "description": "Authentication required",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Error"}
                            }
                        }
                    },
                    "Forbidden": {
                        "description": "Insufficient permissions",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Error"}
                            }
                        }
                    },
                    "NotFound": {
                        "description": "Resource not found",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Error"}
                            }
                        }
                    },
                    "InternalError": {
                        "description": "Internal server error",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Error"}
                            }
                        }
                    }
                }
            }
        }

        # Collect tags
        all_tags = set()

        # Build paths
        for endpoint in self.endpoints:
            path = endpoint.path
            method = endpoint.method.lower()

            if path not in spec['paths']:
                spec['paths'][path] = {}

            # Generate operation ID
            clean_path = re.sub(r'\{[^}]+\}', '', path)
            parts = [p for p in clean_path.split('/') if p]
            op_id = method + ''.join(p.capitalize() for p in parts[-3:] if p)

            # Build operation
            operation = {
                'summary': endpoint.summary or f'{method.upper()} {path}',
                'description': endpoint.description,
                'operationId': op_id,
                'tags': endpoint.tags,
                'responses': endpoint.responses
            }

            if endpoint.parameters:
                operation['parameters'] = endpoint.parameters

            if endpoint.security:
                operation['security'] = endpoint.security

            for tag in endpoint.tags:
                all_tags.add(tag)

            spec['paths'][path][method] = operation

        # Sort paths
        spec['paths'] = dict(sorted(spec['paths'].items()))

        # Add tag definitions with descriptions
        tag_descriptions = {
            "Antivirus": "Antivirus scanning policies, servers, and quarantine management",
            "Api": "API version and summary information",
            "Audit": "Audit logging configuration and topic management",
            "Auth": "Authentication providers, users, groups, roles, and access control",
            "Avscan": "Antivirus scanning jobs, files, and node-level operations",
            "Catalog": "File metadata catalog fields and settings",
            "Certificate": "SSL/TLS certificate management for authority and server certificates",
            "Cloud": "CloudPools cloud tiering and data management",
            "Cluster": "Cluster configuration, nodes, identity, and health",
            "Config": "Configuration exports and imports for backup/restore",
            "Datamover": "Data movement, migration, and replication operations",
            "Debug": "Debugging and diagnostic endpoints",
            "Dedupe": "Deduplication settings and reporting",
            "Event": "Event notification, alert conditions, and channels",
            "Filefilter": "File filtering settings for protocols",
            "Filepool": "SmartPools file pool policies and templates",
            "Filesystem": "File system global settings",
            "Fsa": "File System Analytics (InsightIQ) results and settings",
            "Hardening": "Security hardening reports and settings",
            "Hardware": "Hardware inventory, FC ports, and tape devices",
            "Healthcheck": "Cluster health check definitions, schedules, and evaluations",
            "Id Resolution": "Identity mapping and resolution across zones",
            "Ipmi": "IPMI (Intelligent Platform Management Interface) configuration",
            "Job": "Job engine - job types, policies, and execution",
            "Keymanager": "Encryption key management and SED (Self-Encrypting Drive) settings",
            "Lfn": "Long File Name (LFN) settings",
            "License": "Software license management",
            "Local": "Local cluster mode management",
            "Namespace": "File system namespace operations (files, directories, ACLs)",
            "Network": "Network groupnets, subnets, pools, interfaces, and firewall",
            "Os": "Operating system security settings",
            "Papi": "Platform API settings",
            "Performance": "Performance monitoring datasets and workloads",
            "Protocols": "Protocol configuration (NFS, SMB, HDFS, HTTP, FTP, NDMP, S3, Swift)",
            "Quota": "Quota policies, reports, and notifications",
            "Remotesupport": "Remote support (ConnectEMC) configuration",
            "Security": "Security settings and checks",
            "Snapshot": "Snapshot creation, schedules, changelists, and management",
            "Statistics": "Performance statistics and metrics",
            "Storagepool": "Storage pool, node pool, nodetyped, and tier management",
            "Supportassist": "SupportAssist remote support configuration and tasks",
            "Sync": "SyncIQ replication policies, jobs, service, and reports",
            "Upgrade": "Cluster and firmware upgrade operations",
            "Worm": "SmartLock WORM compliance domains and settings",
            "Zones": "Access zone configuration and summary",
        }

        spec['tags'] = [
            {
                'name': tag,
                'description': tag_descriptions.get(tag, f'{tag} operations')
            }
            for tag in sorted(all_tags)
        ]

        return spec


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Fetch PowerScale API 9.7 endpoints in batches and generate OpenAPI spec'
    )
    parser.add_argument(
        '--batch-size', '-b',
        type=int,
        default=20,
        help='Number of endpoints per batch (default: 20)'
    )
    parser.add_argument(
        '--delay', '-d',
        type=float,
        default=0.3,
        help='Delay between requests in seconds (default: 0.3)'
    )
    parser.add_argument(
        '--output', '-o',
        default='powerscale_9.7_openapi.json',
        help='Output file path (default: powerscale_9.7_openapi.json)'
    )
    parser.add_argument(
        '--skip-fetch',
        action='store_true',
        help='Skip fetching from Dell portal, generate from known patterns only'
    )

    args = parser.parse_args()

    print("=" * 70)
    print("PowerScale API 9.7 - Batch OpenAPI Specification Generator")
    print("=" * 70)
    print()

    fetcher = PowerScaleBatchFetcher(
        batch_size=args.batch_size,
        delay=args.delay
    )

    if args.skip_fetch:
        logger.info("Generating from known endpoint patterns...")
        # Generate endpoints from patterns without fetching
        patterns = fetcher._generate_endpoint_patterns()

        for path, method in patterns:
            endpoint = EndpointInfo(
                path=path,
                method=method,
                slug="",
                summary=f"{method.upper()} {path}",
                description=f"Perform {method.upper()} operation on {path}",
                tags=fetcher._generate_tags(path),
                security=[{"basicAuth": []}],
                responses={
                    "200": {"description": "Success"},
                    "default": {
                        "description": "Error",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Error"}
                            }
                        }
                    }
                }
            )

            # Add path parameters
            path_params = re.findall(r'\{([^}]+)\}', path)
            for param_name in path_params:
                endpoint.parameters.append({
                    'name': param_name,
                    'in': 'path',
                    'required': True,
                    'schema': {'type': 'string'},
                    'description': f'{param_name} parameter'
                })

            # Add common query params for list endpoints
            if method == 'get' and path.endswith('s') and '{' not in path.split('/')[-1]:
                endpoint.parameters.extend([
                    {'name': 'limit', 'in': 'query', 'schema': {'type': 'integer'}, 'description': 'Max items'},
                    {'name': 'resume', 'in': 'query', 'schema': {'type': 'string'}, 'description': 'Resume token'},
                    {'name': 'sort', 'in': 'query', 'schema': {'type': 'string'}, 'description': 'Sort field'},
                    {'name': 'dir', 'in': 'query', 'schema': {'type': 'string', 'enum': ['ASC', 'DESC']}, 'description': 'Sort direction'},
                ])

            # Add zone parameter where applicable
            if any(x in path for x in ['/protocols/', '/auth/', '/quota/', '/snapshot/']):
                endpoint.parameters.append({
                    'name': 'zone',
                    'in': 'query',
                    'schema': {'type': 'string'},
                    'description': 'Access zone'
                })

            fetcher.endpoints.append(endpoint)

        logger.info(f"Generated {len(fetcher.endpoints)} endpoints from patterns")
    else:
        logger.info("Fetching endpoints from Dell Developer Portal...")
        fetcher.fetch_all_batches()

    # Build OpenAPI spec
    logger.info("Building OpenAPI specification...")
    spec = fetcher.build_openapi_spec()

    # Write output
    output_path = Path(args.output)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(spec, f, indent=2, ensure_ascii=False)

    # Stats
    total_paths = len(spec.get('paths', {}))
    total_operations = sum(len(m) for m in spec.get('paths', {}).values())

    print()
    print("=" * 70)
    print("✓ OpenAPI specification generated successfully!")
    print(f"  Output: {output_path.absolute()}")
    print(f"  Paths: {total_paths}")
    print(f"  Operations: {total_operations}")
    print(f"  Tags: {len(spec.get('tags', []))}")
    print("=" * 70)

    # Also generate YAML
    try:
        import yaml
        yaml_path = output_path.with_suffix('.yaml')
        with open(yaml_path, 'w', encoding='utf-8') as f:
            yaml.dump(spec, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        print(f"  YAML: {yaml_path.absolute()}")
    except ImportError:
        print("  (Install PyYAML for YAML output: pip install pyyaml)")


if __name__ == "__main__":
    main()
