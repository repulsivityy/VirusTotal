from __future__ import annotations

from datetime import timedelta

from SiemplifyDataModel import EntityTypes

INTEGRATION_IDENTIFIER = "GoogleThreatIntelligence"
INTEGRATION_DISPLAY_NAME = "Google Threat Intelligence"
INTEGRATION_PREFIX = "GTI_"

PING_SCRIPT_NAME = f"{INTEGRATION_IDENTIFIER} - Ping"
GET_GRAPH_DETAILS_SCRIPT_NAME = f"{INTEGRATION_IDENTIFIER} - Get Graph Details"
SEARCH_GRAPHS_SCRIPT_NAME = f"{INTEGRATION_IDENTIFIER} - Search Graphs"
SEARCH_ENTITY_GRAPHS_SCRIPT_NAME = f"{INTEGRATION_IDENTIFIER} - Search Entity Graphs"
UPDATE_DTM_ALERT_SCRIPT_NAME = f"{INTEGRATION_IDENTIFIER} - Update DTM Alert"
ADD_COMMENT_TO_ENTITY_SCRIPT_NAME = f"{INTEGRATION_IDENTIFIER} - Add Comment To Entity"
GET_ASM_ENTITY_DETAILS_SCRIPT_NAME = (
    f"{INTEGRATION_IDENTIFIER} - Get ASM Entity Details"
)
ADD_VOTE_TO_ENTITY_SCRIPT_NAME = f"{INTEGRATION_IDENTIFIER} - Add Vote To Entity"
SEARCH_ASM_ISSUES_SCRIPT_NAME = f"{INTEGRATION_IDENTIFIER} - Search ASM Issues"
SEARCH_ASM_ENTITIES_SCRIPT_NAME = f"{INTEGRATION_IDENTIFIER} - Search ASM Entities"
UPDATE_ASM_ISSUE_SCRIPT_NAME = f"{INTEGRATION_IDENTIFIER} - Update ASM Issue"
SET_DTM_ALERT_ANALYSIS_SCRIPT_NAME = (
    f"{INTEGRATION_IDENTIFIER} - Set DTM Alert Analysis"
)
GET_RELATED_IOCS_SCRIPT_NAME = f"{INTEGRATION_IDENTIFIER} - Get Related IOCs"
ENRICH_ENTITIES_SCRIPT_NAME = f"{INTEGRATION_IDENTIFIER} - Enrich Entities"
EXECUTE_IOC_SEARCH_SCRIPT_NAME = f"{INTEGRATION_IDENTIFIER} - Execute IOC Search"
DOWNLOAD_FILE_SCRIPT_NAME = f"{INTEGRATION_IDENTIFIER} - Download File"
ENRICH_IOCS_SCRIPT_NAME = f"{INTEGRATION_IDENTIFIER} - Enrich IOCs"
SUBMIT_FILE_SCRIPT_NAME = f"{INTEGRATION_IDENTIFIER} - Submit File"

ENDPOINTS = {
    "ping": "api/v3/ip_addresses/8.8.4.4",
    "asm_ping": "api/v3/asm/projects",
    "get_graph_details": "api/v3/graphs/{graph_id}",
    "search_graphs": "api/v3/graphs",
    "update_dtm_alert": "api/v3/dtm/alerts/{alert_id}",
    "set_dtm_alert_analysis": "api/v3/dtm/alerts/{alert_id}/analysis",
    "upload_file_to_alerts_analysis": "api/v3/dtm/alerts/{alert_id}/attachments",
    "add_comment_address": "api/v3/ip_addresses/{identifier}/comments",
    "add_comment_url": "api/v3/urls/{identifier}/comments",
    "add_comment_filehash": "api/v3/files/{identifier}/comments",
    "add_comment_hostname": "api/v3/domains/{identifier}/comments",
    "add_comment_domain": "api/v3/domains/{identifier}/comments",
    "get_dtm_alerts": "api/v3/dtm/alerts",
    "index_projects": "api/v3/asm/projects",
    "entity_full_details": "api/v3/asm/entities/{entity_id}/raw",
    "add_vote_address": "api/v3/ip_addresses/{identifier}/votes",
    "add_vote_url": "api/v3/urls/{identifier}/votes",
    "add_vote_filehash": "api/v3/files/{identifier}/votes",
    "add_vote_hostname": "api/v3/domains/{identifier}/votes",
    "add_vote_domain": "api/v3/domains/{identifier}/votes",
    "search_issues": "api/v3/asm/search/issues/{query_string}",
    "search_entities": "api/v3/asm/search/entities/{query_string}",
    "update_issue": "api/v3/asm/issues/{issue_id}/status",
    "get_issue_details": "api/v3/asm/issues/{issue_id}",
    "get_related_iocs": "api/v3/{type}/{id}/relationships/{relationship}",
    "get_iocs_for_threat_actors": "api/v3/{type}/{id}/{relationship}",
    "get_threat_actor": "api/v3/collections",
    "get_comments": "api/v3/{ioc_type}/{ioc}/comments",
    "get_ioc_details": "api/v3/{ioc_type}/{ioc}",
    "private_get_ioc_details": "api/v3/private/{ioc_type}/{ioc}",
    "vulnerability_details": "api/v3/collections/vulnerability--{vulnerability}",
    "get_widget": "api/v3/gtiwidget",
    "get_sandbox_data": "api/v3/file_behaviours/{hash}_{sandbox}",
    "get_mitre": "api/v3/files/{entity}/behaviour_mitre_trees",
    "urls": "api/v3/urls",
    "private_urls": "api/v3/private/urls",
    "submit_hash_analysis": "api/v3/files/{hash}/analyse",
    "analyses": "api/v3/analyses/{analysis_id}",
    "analyses-private": "api/v3/private/analyses/{analysis_id}",
    "search_ioc": "api/v3/intelligence/search",
    # "get_notifications": "api/v3/intelligence/hunting_notification_files",
    # [MODIFIED] - Changed endpoint to support IOC Stream API
    "get_ioc_stream": "api/v3/ioc_stream",
    "get_file": "api/v3/files/{entity_hash}/download",
    "file-upload-url": "api/v3/files/upload_url",
    "file-upload-url-private": "api/v3/private/files/upload_url",
    "generate-ai-summary": "api/v3/private/files/{hash}/generate_ai_report",
}

XTOOL_HEADER_VALUE = "GTI Google SecOps SOAR"
LIMIT_DEFAULT_VALUE = 50
GRAPHS_LIMIT_DEFAULT_VALUE = 10
SORT_FIELD_MAPPING = {
    "Name": "name",
    "Owner": "owner",
    "Creation Date": "creation_date",
    "Last Modified Date": "last_modified_date",
    "Views Count": "views_count",
    "Comments Count": "comments_count",
}
ITEMS_PER_PAGE = 40

EMAIL_REGEX = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
QUERY_JOIN_PARAMETER = " OR "
EMAIL_ENTITY_TYPE = 101

ALERT_STATUS_MAPPING = {
    "Select One": None,
    "New": "new",
    "Read": "read",
    "Resolved": "closed",
    "Escalated": "escalated",
    "In Progress": "in_progress",
    "No Action Required": "no_action_required",
    "Duplicate": "duplicate",
    "Not Relevant": "not_relevant",
    "Tracked Externally": "tracked_external",
}

COMMENT_ENDPOINTS_MAPPING = {
    EntityTypes.ADDRESS: "add_comment_address",
    EntityTypes.FILEHASH: "add_comment_filehash",
    EntityTypes.URL: "add_comment_url",
    EntityTypes.HOSTNAME: "add_comment_hostname",
    EntityTypes.DOMAIN: "add_comment_domain",
}

CASE_INSENSITIVE_ENTITIES = [
    EntityTypes.ADDRESS,
    EntityTypes.MACADDRESS,
    EntityTypes.CHILDHASH,
    EntityTypes.FILEHASH,
]

VOTE_ENDPOINTS_MAPPING = {
    EntityTypes.ADDRESS: "add_vote_address",
    EntityTypes.FILEHASH: "add_vote_filehash",
    EntityTypes.URL: "add_vote_url",
    EntityTypes.HOSTNAME: "add_vote_hostname",
    EntityTypes.DOMAIN: "add_vote_domain",
}

POSSIBLE_IOC_TYPES = ["IP", "Hash", "URL", "Domain"]

ENTITY_TYPE_MAP = {
    EntityTypes.FILEHASH: "files",
    EntityTypes.URL: "urls",
    EntityTypes.ADDRESS: "ip_addresses",
    EntityTypes.HOSTNAME: "domains",
    EntityTypes.DOMAIN: "domains",
}

RELATIONSHIP_MAP = {
    "ip_addresses": {
        "Domain": "resolutions",
        "URL": "urls",
        "Hash": "communicating_files",
        "Hash_2": "referrer_files",
    },
    "domains": {
        "IP": "resolutions",
        "Domain": "siblings",
        "URL": "urls",
        "Hash": "communicating_files",
        "Hash_2": "referrer_files",
    },
    "urls": {
        "IP": "contacted_ips",
        "Domain": "contacted_domains",
        "URL": "redirecting_urls",
        "Hash": "communicating_files",
        "Hash_2": "referrer_files",
    },
    "files": {
        "IP": "contacted_ips",
        "IP_2": "embedded_ips",
        "Domain": "contacted_domains",
        "Domain_2": "embedded_domains",
        "URL": "contacted_urls",
        "URL_2": "embedded_urls",
        "Hash": "bundled_files",
        "Hash_2": "execution_parents",
        "Hash_3": "similar_files",
    },
    "collections": {
        "IP": "ip_addresses",
        "Domain": "domains",
        "URL": "urls",
        "Hash": "files",
    },
}

MAX_SEARCH_ISSUES_LIMIT = 200
MAX_SEARCH_ENTITIES_LIMIT = 200
MAX_IOC_SEARCH_LIMIT = 200
CUSTOM_TIME = "Custom"
TIME_INTERVALS = {
    "Last Hour": timedelta(hours=1),
    "Last 6 Hours": timedelta(hours=6),
    "Last 24 Hours": timedelta(hours=24),
    "Last Week": timedelta(weeks=1),
    "Last Month": timedelta(weeks=4),
}
ASM_ISSUE_SEVERITY_MAPPING = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "informational": 5,
}
ASM_ISSUE_STATUS_MAPPING = {"Open": "open", "Closed": "closed"}
DEFAULT_PAGE_SIZE = 100

DEFAULT_ISSUE_STATUS_FILTER: str = "open"
ISSUE_STATUS_LIST: list[str, str] = [DEFAULT_ISSUE_STATUS_FILTER, "closed"]

ISSUE_STATUS_MAPPING = {
    "New": "open_new",
    "Triaged": "open_triaged",
    "In Progress": "open_in_progress",
    "Resolved": "closed_resolved",
    "Duplicate": "closed_duplicate",
    "Out Of Scope": "closed_out_of_scope",
    "Not A Security Issue (Benign)": "closed_benign",
    "Risk Accepted": "closed_risk_accepted",
    "False Positive": "closed_false_positive",
    "Unable To Reproduce": "closed_no_repro",
    "Tracked Externally": "closed_tracked_externally",
    "Mitigated": "closed",
}

CASE_WALL_LINK = "https://www.virustotal.com/gui/{entity_type}/{entity}/detection"
PRIVATE_CASE_WALL_LINK = (
    "https://www.virustotal.com/gui/private-scanning/{entity_type}/{entity}"
)
COLLECTIONS_CASE_WALL_LINK = "https://www.virustotal.com/gui/collection/{ioc}"
DATA_ENRICHMENT_PREFIX = "GTI"
IOC_MAPPING = {
    "files": "file",
    "urls": "url",
    "ip_addresses": "ip-address",
    "domains": "domain",
}
COMPLETED = "completed"

MD5_LENGTH = 32
SHA1_LENGTH = 40
SHA256_LENGTH = 64

# DTM Alerts connector
DTM_ALERTS_CONNECTOR = "Google Threat Intelligence - DTM Alerts Connector"
MAX_LIMIT = 25
SEVERITIES = ["low", "medium", "high"]
STORED_IDS_LIMIT = 10_000
DEFAULT_DEVICE_VENDOR = "Google Threat Intelligence"
DEFAULT_DEVICE_PRODUCT = "DTM Alert"
SEVERITY_MAPPING = {"low": 40, "medium": 60, "high": 80, "critical": 100}
SEVERITY_GTI_MAPPING = {
    "SEVERITY_NONE": -1,
    "SEVERITY_UNKNOWN": -1,
    "SEVERITY_INFO": -1,
    "SEVERITY_LOW": 40,
    "SEVERITY_MEDIUM": 60,
    "SEVERITY_HIGH": 80,
    "SEVERITY_CRITICAL": 100,
}
MAIN_ALERT_EVENT_TYPE = "Main Alert"
ALERT_STATUSES = ["escalated", "in_progress", "new", "read"]
EVENTS_LIMIT = 400
DTM_DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

GTI_ROOT = "https://www.virustotal.com/api/v3/"
MANDIANT_ROOT = "https://api.intelligence.mandiant.com/v4"

# ASM Issues connector
ASM_ISSUES_CONNECTOR_NAME = "Google Threat Intelligence - ASM Issues Connector"
ISSUES_POSSIBLE_SEVERITIES = ["Informational", "Low", "Medium", "High", "Critical"]
DEFAULT_ASM_DEVICE_PRODUCT = "ASM Issues"
PRIORITY_MAPPING = {1: 100, 2: 80, 3: 60, 4: 40, 5: -1}
MAX_PAGE_SIZE = 100

# Livehunt Connector
LIVEHUNT_CONNECTOR = "Google Threat Intelligence - Livehunt Connector"
DEFAULT_HOURS_BACKWARDS = 1
DEFAULT_NOTIFICATIONS_LIMIT = 40
MAX_NOTIFICATIONS_LIMIT = 40
LIVEHUNT_CONNECTOR_DEFAULT_DEVICE_PRODUCT = "Livehunt"
NOTIFICATION_ALLOWED_VERDICTS = ["VERDICT_MALICIOUS", "VERDICT_SUSPICIOUS"]
SUSPICIOUS_VERDICTS = ["VERDICT_SUSPICIOUS", "VERDICT_MALICIOUS"]

# Widget theme
WIDGET_CHRONICLE_THEME_COLORS = {
    "theme": "dark",
    "bg1": "212c44",
    "bg2": "3a4a6c"
}
