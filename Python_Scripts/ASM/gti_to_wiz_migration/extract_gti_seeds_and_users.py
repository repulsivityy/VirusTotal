#!/usr/bin/env python3
"""
Extracts Projects, Project Users, Collections, Collection Users, and Seeds
from Google Threat Intelligence (GTI) ASM.

Supports extracting:
  - Seeds only (`--extract-type seeds`)
  - Users only (`--extract-type users`)
  - Both Seeds and Users (`--extract-type both`, default)

Outputs:
1. A unified hierarchical CSV (`gti_structure_export.csv`) preserving the
   Project -> Collection -> Users / Seeds relationship both visually (`hierarchy_tree`)
   and relationally (parent project & collection columns on every row).
2. A nested JSON file (`gti_wiz_import.json`) preserving the complete hierarchy
   for creating Custom Targets and RBAC in Wiz ASM.

Requirements:
  - Python 3.8+
  - requests (`pip install requests`)
  - Environment variable `GTI_APIKEY` (or pass `-k / --api-key`)
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from datetime import datetime, timezone
import json
import logging
import os
import sys
import threading
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# --- Constants ---
ASM_BASE_URL = "https://www.virustotal.com/api/v3/asm"
PROJECTS_ENDPOINT = f"{ASM_BASE_URL}/projects"
COLLECTIONS_ENDPOINT = f"{ASM_BASE_URL}/user_collections"

CSV_FIELDNAMES = [
    "hierarchy_tree",
    "project_name",
    "project_id",
    "project_uuid",
    "scope_level",
    "collection_name",
    "collection_id",
    "collection_uuid",
    "record_type",
    "user_email",
    "user_name",
    "user_role",
    "user_id",
    "seed_type",
    "seed_value",
    "seed_id",
    "seed_status",
]

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Thread-local storage for per-thread requests.Session instances
_thread_local = threading.local()


def create_session(pool_maxsize: int = 20) -> requests.Session:
    """Creates and returns a new requests.Session with retry and backoff logic."""
    session = requests.Session()
    retry_strategy = Retry(
        total=4,
        backoff_factor=1.0,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"],
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=pool_maxsize,
        pool_maxsize=pool_maxsize,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def get_thread_session(pool_maxsize: int = 20) -> requests.Session:
    """Returns a thread-local requests.Session for thread-safe concurrent calls."""
    session = getattr(_thread_local, "session", None)
    if session is None:
        session = create_session(pool_maxsize=pool_maxsize)
        _thread_local.session = session
    return session


def parse_arguments() -> argparse.Namespace:
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Extract Projects, Collections, Users (Project & Collection level), "
            "and/or Seeds from Google Threat Intelligence (GTI) ASM."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-k",
        "--api-key",
        dest="api_key",
        help="GTI API Key (overrides GTI_APIKEY / VT_API_KEY environment variables).",
    )
    parser.add_argument(
        "-t",
        "--extract-type",
        dest="extract_type",
        choices=["seeds", "users", "both"],
        default=None,
        help=(
            "Select what to extract:\n"
            "  seeds - Extract Projects -> Collections -> Seeds only\n"
            "  users - Extract Projects -> Project Users & Collections -> Collection Users only\n"
            "  both  - Extract both Seeds and Users (default in non-interactive mode)"
        ),
    )
    parser.add_argument(
        "-i",
        "--interactive",
        dest="interactive",
        action="store_true",
        default=True,
        help="Interactively select extraction type, projects, and collections (default: True).",
    )
    parser.add_argument(
        "--non-interactive",
        dest="interactive",
        action="store_false",
        help="Run without interactive prompts (extracts all active projects and collections).",
    )
    parser.add_argument(
        "--project-filter",
        dest="project_filter",
        help=(
            "Optional comma-separated list of project names, numeric IDs, or UUIDs "
            "to filter without interactive prompts."
        ),
    )
    parser.add_argument(
        "--include-deleted",
        action="store_true",
        default=False,
        help="Include deleted collections (default: False).",
    )
    parser.add_argument(
        "--csv-out",
        default="gti_structure_export.csv",
        help="Output file path for the hierarchical GTI CSV (default: gti_structure_export.csv).",
    )
    parser.add_argument(
        "--json-out",
        default="gti_wiz_import.json",
        help="Output file path for the Wiz import JSON (default: gti_wiz_import.json).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=5,
        help="Number of concurrent threads for collection user/seed requests (default: 5).",
    )
    parser.add_argument(
        "--keep-raw",
        action="store_true",
        default=False,
        help="Include raw API objects inside the JSON output (default: False).",
    )
    parser.add_argument(
        "--print-tree",
        action="store_true",
        default=True,
        help="Print the Project -> Collection -> Seeds/Users tree in the terminal (default: True).",
    )
    parser.add_argument(
        "--no-print-tree",
        dest="print_tree",
        action="store_false",
        help="Suppress printing the full hierarchy tree to the terminal.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Enable verbose debug logging and print raw API response snippets.",
    )
    return parser.parse_args()


def resolve_extract_type(args: argparse.Namespace) -> Tuple[bool, bool, str]:
    """
    Determines whether to extract seeds, users, or both.
    Returns `(extract_seeds, extract_users, mode_label)`.
    """
    choice = args.extract_type
    if choice is None:
        if args.interactive:
            print("\n--- Select Data to Extract ---")
            print("  1. Seeds only  (Project -> Collection -> Seeds)")
            print("  2. Users only  (Project -> Project Users & Collection -> Collection Users)")
            print("  3. Both        (Seeds and Users)")
            while True:
                user_inp = input(
                    "\nEnter choice (1/2/3 or seeds/users/both) [default: 3 (both)]: "
                ).strip().lower()
                if not user_inp or user_inp in ("3", "both"):
                    choice = "both"
                    break
                if user_inp in ("1", "seeds", "seed"):
                    choice = "seeds"
                    break
                if user_inp in ("2", "users", "user"):
                    choice = "users"
                    break
                print("Invalid choice. Please enter 1, 2, or 3.")
        else:
            choice = "both"

    extract_seeds = choice in ("seeds", "both")
    extract_users = choice in ("users", "both")
    logger.info("Extraction mode selected: %s (seeds=%s, users=%s)", choice, extract_seeds, extract_users)
    return extract_seeds, extract_users, choice


def load_api_key(args: argparse.Namespace) -> str:
    """Loads the GTI API key from CLI arguments or environment variables."""
    if args.api_key:
        logger.info("Using API key provided via --api-key argument.")
        return args.api_key.strip()

    api_key = os.getenv("GTI_APIKEY") or os.getenv("VT_API_KEY")
    if not api_key:
        logger.error(
            "GTI_APIKEY environment variable is not set. "
            "Set `export GTI_APIKEY='your_key'` or pass `--api-key`."
        )
        sys.exit(1)

    logger.info("Using API key from environment variable.")
    return api_key.strip()


def _append_query_param(url: str, key: str, value: str) -> str:
    """Safely adds or updates a query parameter on a URL."""
    parsed = urlparse(url)
    query_params = dict(parse_qsl(parsed.query))
    query_params[key] = value
    new_query = urlencode(query_params)
    return urlunparse(parsed._replace(query=new_query))


def fetch_paginated_or_list(
    session: requests.Session,
    url: str,
    headers: Dict[str, str],
    debug: bool = False,
    resource_label: str = "resource",
    allow_404: bool = False,
) -> List[Dict[str, Any]]:
    """
    Fetches an ASM endpoint that may return either:
      - A flat list: `{"result": [...]}` or `{"data": [...]}`
      - A paginated dict: `{"result": {"hits": [...], "next_page_token": "..."}}`
        or `{"result": {"seeds": [...], "next_page_token": "..."}}`
    Follows `next_page_token` safely, stopping when a page returns 0 items or
    if a page token repeats.
    """
    items: List[Dict[str, Any]] = []
    current_url: Optional[str] = url
    seen_tokens: Set[str] = set()

    while current_url:
        if debug:
            logger.debug("GET %s (resource=%s)", current_url, resource_label)

        try:
            response = session.get(current_url, headers=headers, timeout=30)
            if allow_404 and response.status_code == 404:
                if debug:
                    logger.debug("404 Not Found on %s (resource=%s)", current_url, resource_label)
                break
            response.raise_for_status()
            payload = response.json()
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response is not None else "unknown"
            body = ""
            if e.response is not None:
                try:
                    body = json.dumps(e.response.json())
                except Exception:
                    body = e.response.text[:300]
            logger.warning(
                "HTTP %s fetching %s (%s): %s",
                status_code,
                resource_label,
                current_url,
                body,
            )
            break
        except (requests.exceptions.RequestException, ValueError) as e:
            logger.warning("Request error fetching %s (%s): %s", resource_label, current_url, e)
            break

        if debug:
            logger.debug(
                "Raw response for %s:\n%s",
                resource_label,
                json.dumps(payload, indent=2)[:2000],
            )

        if isinstance(payload, list):
            items.extend(payload)
            break

        if not isinstance(payload, dict):
            break

        result = payload.get("result")
        if result is None and "data" in payload:
            result = payload.get("data")

        next_token: Optional[str] = None
        page_items: List[Dict[str, Any]] = []

        if isinstance(result, list):
            page_items = result
            next_token = (
                payload.get("next_page_token")
                or (payload.get("meta") or {}).get("next_page_token")
                or (payload.get("links") or {}).get("next")
            )
        elif isinstance(result, dict):
            # Look for standard list containers inside `result`
            found_list = False
            for list_key in ("hits", "seeds", "users", "items", "collection_project_users", "data"):
                if isinstance(result.get(list_key), list):
                    page_items = result[list_key]
                    found_list = True
                    break
            if not found_list and result:
                # Single resource dict returned
                page_items = [result]

            next_token = (
                result.get("next_page_token")
                or payload.get("next_page_token")
                or (payload.get("meta") or {}).get("next_page_token")
            )
        else:
            break

        if not page_items:
            break

        items.extend(page_items)

        if next_token:
            token_str = str(next_token).strip()
            if not token_str or token_str in seen_tokens:
                if debug and token_str in seen_tokens:
                    logger.debug("Stopping pagination on repeated token for %s", resource_label)
                break
            seen_tokens.add(token_str)

            if token_str.startswith("http"):
                current_url = token_str
            else:
                current_url = _append_query_param(url, "page_token", token_str)
        else:
            current_url = None

    return items


def fetch_all_projects(
    session: requests.Session,
    api_key: str,
    keep_raw: bool = False,
    debug: bool = False,
) -> List[Dict[str, Any]]:
    """Retrieves all ASM projects accessible to the API key."""
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }
    logger.info("Fetching ASM projects...")
    raw_projects = fetch_paginated_or_list(
        session=session,
        url=PROJECTS_ENDPOINT,
        headers=headers,
        debug=debug,
        resource_label="projects",
    )

    projects = []
    for proj in raw_projects:
        entry: Dict[str, Any] = {
            "id": proj.get("id"),
            "uuid": proj.get("uuid", ""),
            "name": proj.get("name", "Unnamed Project"),
            "organization_name": proj.get("organization_name", ""),
        }
        if keep_raw or debug:
            entry["raw"] = proj
        projects.append(entry)

    logger.info("Found %d project(s).", len(projects))
    return projects


def filter_or_select_projects(
    projects: List[Dict[str, Any]],
    project_filter: Optional[str],
    interactive: bool,
) -> List[Dict[str, Any]]:
    """Filters projects via --project-filter or interactive user prompt."""
    if not projects:
        return []

    filtered = projects
    if project_filter:
        tokens = {t.strip().lower() for t in project_filter.split(",") if t.strip()}
        filtered = [
            p
            for p in projects
            if str(p.get("id", "")).lower() in tokens
            or str(p.get("uuid", "")).lower() in tokens
            or any(tok in str(p.get("name", "")).lower() for tok in tokens)
        ]
        logger.info("Filtered to %d project(s) matching --project-filter.", len(filtered))

    if not interactive:
        return filtered

    print("\n--- Available ASM Projects ---")
    for idx, proj in enumerate(filtered, start=1):
        print(f"  {idx}. {proj['name']} (ID: {proj['id']}, UUID: {proj['uuid']})")

    while True:
        choice = input(
            "\nEnter project numbers (e.g., '1,3,5'), a range (e.g., '1-5'), or 'all' [default: all]: "
        ).strip().lower()
        if not choice or choice == "all":
            return filtered

        selected_indices = set()
        valid = True
        for part in choice.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    start, end = map(int, part.split("-", 1))
                    if 1 <= start <= end <= len(filtered):
                        for i in range(start, end + 1):
                            selected_indices.add(i - 1)
                    else:
                        valid = False
                        break
                except ValueError:
                    valid = False
                    break
            else:
                try:
                    idx = int(part)
                    if 1 <= idx <= len(filtered):
                        selected_indices.add(idx - 1)
                    else:
                        valid = False
                        break
                except ValueError:
                    valid = False
                    break

        if valid and selected_indices:
            return [filtered[i] for i in sorted(selected_indices)]
        print(f"Invalid selection. Please enter numbers between 1 and {len(filtered)}, or 'all'.")


def _format_user_name(user_dict: Dict[str, Any]) -> str:
    """Extracts a human-readable user name from a GTI user object."""
    first = str(user_dict.get("first_name") or "").strip()
    last = str(user_dict.get("last_name") or "").strip()
    combined = f"{first} {last}".strip()
    if combined:
        return combined
    return str(
        user_dict.get("name")
        or user_dict.get("full_name")
        or user_dict.get("username")
        or ""
    ).strip()


def _first_non_none(*values: Any) -> Any:
    """Returns the first value that is neither None nor empty string."""
    for v in values:
        if v is not None and v != "":
            return v
    return ""


def fetch_project_users(
    session: requests.Session,
    project: Dict[str, Any],
    api_key: str,
    keep_raw: bool = False,
    debug: bool = False,
) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """
    Fetches project-level users (`GET /api/v3/asm/projects/{project_uuid}/users`).
    Returns:
      - Normalized list of project user dicts
      - Lookup map indexed by all user identifiers (`id`, `project_user_id`,
        `user_id`, `uuid`, and `email.lower()`) for enriching collection users.
    """
    project_uuid = project.get("uuid")
    project_id = project.get("id")
    if not project_uuid:
        return [], {}

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }
    if project_id is not None:
        headers["PROJECT-ID"] = str(project_id)

    url = f"{PROJECTS_ENDPOINT}/{project_uuid}/users"
    raw_users = fetch_paginated_or_list(
        session=session,
        url=url,
        headers=headers,
        debug=debug,
        resource_label=f"project_users({project['name']})",
    )

    normalized_users: List[Dict[str, Any]] = []
    user_lookup_map: Dict[str, Dict[str, Any]] = {}

    for u in raw_users:
        if not isinstance(u, dict):
            continue
        uid = _first_non_none(
            u.get("id"),
            u.get("project_user_id"),
            u.get("user_id"),
            u.get("uuid"),
        )
        email = str(u.get("email") or u.get("user_email") or "").strip()
        name = _format_user_name(u)
        role = str(u.get("role") or u.get("project_role") or "").strip()

        norm: Dict[str, Any] = {
            "user_id": uid,
            "email": email,
            "name": name,
            "role": role,
        }
        if keep_raw or debug:
            norm["raw"] = u

        normalized_users.append(norm)

        # Index by all candidate ID fields + email so collection user lookup never misses
        for key_name in ("id", "project_user_id", "user_id", "uuid"):
            val = u.get(key_name)
            if val is not None and str(val).strip() != "":
                user_lookup_map[str(val).strip()] = norm
        if email:
            user_lookup_map[email.lower()] = norm

    return normalized_users, user_lookup_map


def fetch_project_collections(
    session: requests.Session,
    project: Dict[str, Any],
    api_key: str,
    include_deleted: bool = False,
    interactive: bool = False,
    debug: bool = False,
) -> List[Dict[str, Any]]:
    """Fetches collections for a project using its numeric PROJECT-ID."""
    project_id = project.get("id")
    headers = {
        "x-apikey": api_key,
        "PROJECT-ID": str(project_id),
        "Accept": "application/json",
    }
    raw_collections = fetch_paginated_or_list(
        session=session,
        url=COLLECTIONS_ENDPOINT,
        headers=headers,
        debug=debug,
        resource_label=f"collections({project['name']})",
    )

    collections = []
    for col in raw_collections:
        if not isinstance(col, dict):
            continue
        is_deleted = bool(col.get("deleted", False))
        if is_deleted and not include_deleted:
            continue
        collections.append(
            {
                "id": col.get("id"),
                "uuid": _first_non_none(col.get("uuid"), col.get("id"), col.get("name")),
                "name": col.get("name", ""),
                "printable_name": col.get("printable_name") or col.get("name") or "Unnamed Collection",
                "workflow_name": col.get("workflow_name", ""),
                "workflow_pretty_name": col.get("workflow_pretty_name", ""),
                "deleted": is_deleted,
                "_raw_summary": col,
            }
        )

    if interactive and collections:
        print(f"\n--- Collections in Project '{project['name']}' ---")
        for idx, col in enumerate(collections, start=1):
            wf = f" [{col['workflow_pretty_name']}]" if col.get("workflow_pretty_name") else ""
            print(f"  {idx}. {col['printable_name']}{wf} (UUID: {col['uuid']})")
        sel = input(
            "Select collection numbers (e.g., '1,2'), 'all', or 'none' [default: all]: "
        ).strip().lower()
        if sel == "none":
            return []
        if sel and sel != "all":
            chosen = []
            for part in sel.split(","):
                try:
                    idx = int(part.strip())
                    if 1 <= idx <= len(collections):
                        chosen.append(collections[idx - 1])
                except ValueError:
                    pass
            if chosen:
                return chosen

    return collections


def fetch_collection_detail_fallback(
    session: requests.Session,
    collection_uuid: str,
    project_id: Any,
    api_key: str,
    debug: bool = False,
) -> Dict[str, Any]:
    """
    Fetches the single-collection detail object (`GET /api/v3/asm/user_collections/{uuid}`)
    as a fallback if sub-endpoints return empty.
    """
    headers = {
        "x-apikey": api_key,
        "PROJECT-ID": str(project_id),
        "Accept": "application/json",
    }
    url = f"{COLLECTIONS_ENDPOINT}/{collection_uuid}"
    items = fetch_paginated_or_list(
        session=session,
        url=url,
        headers=headers,
        debug=debug,
        resource_label=f"collection_detail({collection_uuid})",
        allow_404=True,
    )
    if items and isinstance(items[0], dict):
        return items[0]
    return {}


def fetch_collection_users(
    session: requests.Session,
    collection: Dict[str, Any],
    project_id: Any,
    project_user_map: Dict[str, Dict[str, Any]],
    api_key: str,
    keep_raw: bool = False,
    debug: bool = False,
    detail_cache: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Fetches collection-level users (`GET /api/v3/asm/user_collections/{uuid}/collection_project_users`)
    and enriches missing user details (email/name/project_role) using `project_user_map`.
    """
    collection_uuid = collection.get("uuid") or collection.get("name")
    if not collection_uuid:
        return []

    headers = {
        "x-apikey": api_key,
        "PROJECT-ID": str(project_id),
        "Accept": "application/json",
    }
    url = f"{COLLECTIONS_ENDPOINT}/{collection_uuid}/collection_project_users"
    raw_col_users = fetch_paginated_or_list(
        session=session,
        url=url,
        headers=headers,
        debug=debug,
        resource_label=f"collection_users({collection['printable_name']})",
        allow_404=True,
    )

    # Fallback 1: check summary object from `/user_collections`
    if not raw_col_users:
        raw_summary = collection.get("_raw_summary") or {}
        embedded = (
            raw_summary.get("collection_project_users")
            or raw_summary.get("users")
        )
        if isinstance(embedded, list):
            raw_col_users = embedded

    # Fallback 2: check `/user_collections/{uuid}` detail endpoint
    if not raw_col_users and detail_cache is not None:
        if not detail_cache:
            detail_cache.update(
                fetch_collection_detail_fallback(
                    session, str(collection_uuid), project_id, api_key, debug
                )
            )
        embedded_detail = (
            detail_cache.get("collection_project_users")
            or detail_cache.get("users")
        )
        if isinstance(embedded_detail, list):
            raw_col_users = embedded_detail

    normalized_col_users: List[Dict[str, Any]] = []
    for cu in raw_col_users:
        if not isinstance(cu, dict):
            continue

        nested_user = cu.get("user") if isinstance(cu.get("user"), dict) else {}
        project_user_id = _first_non_none(
            cu.get("project_user_id"),
            cu.get("user_id"),
            nested_user.get("id"),
            nested_user.get("user_id"),
            cu.get("id"),
        )
        email = str(
            cu.get("email")
            or cu.get("user_email")
            or nested_user.get("email")
            or ""
        ).strip()
        name = _format_user_name(cu) or _format_user_name(nested_user)
        col_role = str(
            cu.get("role")
            or cu.get("collection_role")
            or nested_user.get("role")
            or ""
        ).strip()

        # Enrich from project-level user map using any matching ID or email
        linked_proj_user: Dict[str, Any] = {}
        for candidate_id in (
            cu.get("project_user_id"),
            cu.get("user_id"),
            nested_user.get("id"),
            nested_user.get("uuid"),
            cu.get("id"),
            cu.get("uuid"),
        ):
            if candidate_id is not None and str(candidate_id).strip() in project_user_map:
                linked_proj_user = project_user_map[str(candidate_id).strip()]
                break
        if not linked_proj_user and email and email.lower() in project_user_map:
            linked_proj_user = project_user_map[email.lower()]

        if not email and linked_proj_user.get("email"):
            email = linked_proj_user["email"]
        if not name and linked_proj_user.get("name"):
            name = linked_proj_user["name"]
        project_role = linked_proj_user.get("role", "")

        entry: Dict[str, Any] = {
            "user_id": project_user_id,
            "email": email,
            "name": name,
            "role": col_role,
            "project_role": project_role,
        }
        if keep_raw or debug:
            entry["raw"] = cu
        normalized_col_users.append(entry)

    return normalized_col_users


def _extract_seed_fields(seed_obj: Any, keep_raw: bool = False, debug: bool = False) -> Dict[str, Any]:
    """Normalizes a seed / user_entity entry from GTI ASM into consistent fields."""
    if not isinstance(seed_obj, dict):
        entry: Dict[str, Any] = {
            "id": "",
            "type": "unknown",
            "value": str(seed_obj),
            "status": "active",
        }
        if keep_raw or debug:
            entry["raw"] = seed_obj
        return entry

    seed_id = str(
        _first_non_none(
            seed_obj.get("id"),
            seed_obj.get("uuid"),
            seed_obj.get("seed_id"),
        )
    ).strip()

    seed_type = str(
        _first_non_none(
            seed_obj.get("type"),
            seed_obj.get("seed_type"),
            seed_obj.get("entity_type"),
            seed_obj.get("category"),
        )
    ).strip()

    seed_value = str(
        _first_non_none(
            seed_obj.get("name"),
            seed_obj.get("value"),
            seed_obj.get("seed_value"),
            seed_obj.get("target"),
            seed_obj.get("domain"),
            seed_obj.get("ip"),
            seed_obj.get("cidr"),
            seed_obj.get("asn"),
        )
    ).strip()

    # Determine status / enabled state
    if "status" in seed_obj and seed_obj["status"] is not None:
        seed_status = str(seed_obj["status"])
    elif "state" in seed_obj and seed_obj["state"] is not None:
        seed_status = str(seed_obj["state"])
    elif "enabled" in seed_obj and seed_obj["enabled"] is not None:
        seed_status = "enabled" if bool(seed_obj["enabled"]) else "disabled"
    elif "active" in seed_obj and seed_obj["active"] is not None:
        seed_status = "active" if bool(seed_obj["active"]) else "inactive"
    elif "seed" in seed_obj and seed_obj["seed"] is not None:
        seed_status = "active" if bool(seed_obj["seed"]) else "non_seed"
    else:
        seed_status = "active"

    result: Dict[str, Any] = {
        "id": seed_id,
        "type": seed_type,
        "value": seed_value,
        "status": seed_status,
    }
    if keep_raw or debug:
        result["raw"] = seed_obj
    return result


def fetch_collection_seeds(
    session: requests.Session,
    collection: Dict[str, Any],
    project_id: Any,
    api_key: str,
    keep_raw: bool = False,
    debug: bool = False,
    detail_cache: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Fetches user entities / scan seeds for a specific collection via
    `GET /api/v3/asm/user_collections/{collection_uuid}/user_entities`
    (with fallback to `/seeds` and collection detail).
    """
    collection_uuid = collection.get("uuid") or collection.get("name")
    if not collection_uuid:
        return []

    headers = {
        "x-apikey": api_key,
        "PROJECT-ID": str(project_id),
        "Accept": "application/json",
    }

    # Primary GTI ASM v3 endpoint for collection scan seeds is `/user_entities`
    url = f"{COLLECTIONS_ENDPOINT}/{collection_uuid}/user_entities"
    raw_seeds = fetch_paginated_or_list(
        session=session,
        url=url,
        headers=headers,
        debug=debug,
        resource_label=f"user_entities({collection['printable_name']})",
        allow_404=True,
    )

    # Fallback 1: check `/seeds` endpoint if `/user_entities` returned empty
    if not raw_seeds:
        seeds_url = f"{COLLECTIONS_ENDPOINT}/{collection_uuid}/seeds"
        raw_seeds = fetch_paginated_or_list(
            session=session,
            url=seeds_url,
            headers=headers,
            debug=debug,
            resource_label=f"seeds({collection['printable_name']})",
            allow_404=True,
        )

    # Fallback 2: check summary collection dict
    if not raw_seeds:
        raw_summary = collection.get("_raw_summary") or {}
        embedded_seeds = raw_summary.get("user_entities") or raw_summary.get("seeds")
        if isinstance(embedded_seeds, list):
            raw_seeds = embedded_seeds

    # Fallback 3: check `/user_collections/{uuid}` detail endpoint
    if not raw_seeds and detail_cache is not None:
        if not detail_cache:
            detail_cache.update(
                fetch_collection_detail_fallback(
                    session, str(collection_uuid), project_id, api_key, debug
                )
            )
        embedded_detail_seeds = (
            detail_cache.get("user_entities") or detail_cache.get("seeds")
        )
        if isinstance(embedded_detail_seeds, list):
            raw_seeds = embedded_detail_seeds

    return [_extract_seed_fields(s, keep_raw=keep_raw, debug=debug) for s in raw_seeds]


def process_single_collection(
    collection: Dict[str, Any],
    project_id: Any,
    project_user_map: Dict[str, Dict[str, Any]],
    api_key: str,
    extract_seeds: bool,
    extract_users: bool,
    pool_maxsize: int = 20,
    keep_raw: bool = False,
    debug: bool = False,
) -> Dict[str, Any]:
    """
    Worker function executed per collection using a thread-local Session.
    Fetches collection users and/or seeds depending on `extract_seeds` and `extract_users`.
    """
    session = get_thread_session(pool_maxsize=pool_maxsize)
    detail_cache: Dict[str, Any] = {}

    col_users: List[Dict[str, Any]] = []
    if extract_users:
        col_users = fetch_collection_users(
            session=session,
            collection=collection,
            project_id=project_id,
            project_user_map=project_user_map,
            api_key=api_key,
            keep_raw=keep_raw,
            debug=debug,
            detail_cache=detail_cache,
        )

    col_seeds: List[Dict[str, Any]] = []
    if extract_seeds:
        col_seeds = fetch_collection_seeds(
            session=session,
            collection=collection,
            project_id=project_id,
            api_key=api_key,
            keep_raw=keep_raw,
            debug=debug,
            detail_cache=detail_cache,
        )

    col_entry: Dict[str, Any] = {
        "id": collection.get("id"),
        "uuid": collection.get("uuid"),
        "name": collection.get("name"),
        "printable_name": collection.get("printable_name"),
        "workflow_name": collection.get("workflow_name", ""),
        "workflow_pretty_name": collection.get("workflow_pretty_name", ""),
        "deleted": collection.get("deleted", False),
    }
    if extract_users:
        col_entry["users"] = col_users
    if extract_seeds:
        col_entry["seeds"] = col_seeds
    if keep_raw and collection.get("_raw_summary"):
        col_entry["raw"] = collection["_raw_summary"]

    return col_entry


def build_csv_rows(
    projects_data: List[Dict[str, Any]],
    extract_seeds: bool,
    extract_users: bool,
) -> List[Dict[str, Any]]:
    """
    Flattens the hierarchical project data into CSV rows preserving the exact
    parent-child tree relationship:
      Project 1
      -- [Project User] ...
      -- Collection 1
      ---- [Collection User] ...
      ---- [Seed] ...
    Every child row also carries its parent `project_*` and `collection_*` identifiers.
    """
    rows: List[Dict[str, Any]] = []

    for proj in projects_data:
        p_name = proj.get("name", "")
        p_id = proj.get("id", "")
        p_uuid = proj.get("uuid", "")

        # Top-level Project Header Row
        rows.append(
            {
                "hierarchy_tree": f"{p_name}",
                "project_name": p_name,
                "project_id": p_id,
                "project_uuid": p_uuid,
                "scope_level": "project",
                "collection_name": "",
                "collection_id": "",
                "collection_uuid": "",
                "record_type": "project",
                "user_email": "",
                "user_name": "",
                "user_role": "",
                "user_id": "",
                "seed_type": "",
                "seed_value": "",
                "seed_id": "",
                "seed_status": "",
            }
        )

        # 1. Project-level Users (`scope_level = 'project'`, `record_type = 'user'`)
        if extract_users:
            for p_user in proj.get("users", []):
                u_email = p_user.get("email", "")
                u_role = p_user.get("role", "")
                rows.append(
                    {
                        "hierarchy_tree": f"-- [Project User] {u_email} ({u_role})",
                        "project_name": p_name,
                        "project_id": p_id,
                        "project_uuid": p_uuid,
                        "scope_level": "project",
                        "collection_name": "",
                        "collection_id": "",
                        "collection_uuid": "",
                        "record_type": "user",
                        "user_email": u_email,
                        "user_name": p_user.get("name", ""),
                        "user_role": u_role,
                        "user_id": p_user.get("user_id", ""),
                        "seed_type": "",
                        "seed_value": "",
                        "seed_id": "",
                        "seed_status": "",
                    }
                )

        # 2. Collections (`scope_level = 'collection'`)
        for col in proj.get("collections", []):
            c_name = col.get("printable_name") or col.get("name") or ""
            c_id = col.get("id", "")
            c_uuid = col.get("uuid") or ""
            col_users = col.get("users", []) if extract_users else []
            col_seeds = col.get("seeds", []) if extract_seeds else []

            # Collection Header Row (`-- Collection 1`)
            rows.append(
                {
                    "hierarchy_tree": f"-- {c_name}",
                    "project_name": p_name,
                    "project_id": p_id,
                    "project_uuid": p_uuid,
                    "scope_level": "collection",
                    "collection_name": c_name,
                    "collection_id": c_id,
                    "collection_uuid": c_uuid,
                    "record_type": "collection",
                    "user_email": "",
                    "user_name": "",
                    "user_role": "",
                    "user_id": "",
                    "seed_type": "",
                    "seed_value": "",
                    "seed_id": "",
                    "seed_status": "",
                }
            )

            # 2a. Collection-level Users (`---- [User] ...`)
            if extract_users:
                for c_user in col_users:
                    cu_email = c_user.get("email", "")
                    cu_role = c_user.get("role", "")
                    rows.append(
                        {
                            "hierarchy_tree": f"---- [Collection User] {cu_email} ({cu_role})",
                            "project_name": p_name,
                            "project_id": p_id,
                            "project_uuid": p_uuid,
                            "scope_level": "collection",
                            "collection_name": c_name,
                            "collection_id": c_id,
                            "collection_uuid": c_uuid,
                            "record_type": "user",
                            "user_email": cu_email,
                            "user_name": c_user.get("name", ""),
                            "user_role": cu_role,
                            "user_id": c_user.get("user_id", ""),
                            "seed_type": "",
                            "seed_value": "",
                            "seed_id": "",
                            "seed_status": "",
                        }
                    )

            # 2b. Collection Seeds (`---- [Seed] ...`)
            if extract_seeds:
                for seed in col_seeds:
                    s_type = seed.get("type", "")
                    s_val = seed.get("value", "")
                    tree_label = f"---- {s_val} ({s_type})" if s_type else f"---- {s_val}"
                    rows.append(
                        {
                            "hierarchy_tree": tree_label,
                            "project_name": p_name,
                            "project_id": p_id,
                            "project_uuid": p_uuid,
                            "scope_level": "collection",
                            "collection_name": c_name,
                            "collection_id": c_id,
                            "collection_uuid": c_uuid,
                            "record_type": "seed",
                            "user_email": "",
                            "user_name": "",
                            "user_role": "",
                            "user_id": "",
                            "seed_type": s_type,
                            "seed_value": s_val,
                            "seed_id": seed.get("id", ""),
                            "seed_status": seed.get("status", ""),
                        }
                    )

    return rows


def print_hierarchy_tree(
    projects_data: List[Dict[str, Any]],
    extract_seeds: bool,
    extract_users: bool,
) -> None:
    """Prints the Project -> Collection -> Users / Seeds tree to stdout."""
    print("\n" + "=" * 80)
    print("               GTI ASM HIERARCHY TREE (Project -> Collection)")
    print("=" * 80)
    for proj in projects_data:
        p_name = proj.get("name", "Unnamed Project")
        p_id = proj.get("id", "")
        p_uuid = proj.get("uuid", "")
        print(f"\n{p_name} (ID: {p_id}, UUID: {p_uuid})")

        if extract_users:
            proj_users = proj.get("users", [])
            if proj_users:
                for p_user in proj_users:
                    u_name = p_user.get("name") or "N/A"
                    print(
                        f"-- [Project User] {p_user.get('email', 'N/A')} "
                        f"| Role: {p_user.get('role', 'N/A')} | Name: {u_name}"
                    )
            else:
                print("-- [Project Users] (none)")

        collections = proj.get("collections", [])
        if not collections:
            print("-- (No active collections)")
            continue

        for col in collections:
            c_name = col.get("printable_name") or col.get("name") or "Unnamed Collection"
            c_uuid = col.get("uuid", "")
            print(f"-- {c_name} (UUID: {c_uuid})")

            if extract_users:
                col_users = col.get("users", [])
                if col_users:
                    for c_user in col_users:
                        cu_name = c_user.get("name") or "N/A"
                        print(
                            f"---- [Collection User] {c_user.get('email', 'N/A')} "
                            f"| Role: {c_user.get('role', 'N/A')} | Name: {cu_name}"
                        )
                else:
                    print("---- [Collection Users] (none)")

            if extract_seeds:
                col_seeds = col.get("seeds", [])
                if col_seeds:
                    for seed in col_seeds:
                        s_type = seed.get("type", "")
                        s_val = seed.get("value", "")
                        s_status = seed.get("status", "")
                        meta = ", ".join(filter(None, [s_type, s_status]))
                        if meta:
                            print(f"---- [Seed] {s_val} ({meta})")
                        else:
                            print(f"---- [Seed] {s_val}")
                else:
                    wf = col.get("workflow_pretty_name") or col.get("workflow_name")
                    if wf:
                        print(f"---- [Seeds] (none - {wf})")
                    else:
                        print("---- [Seeds] (none)")
    print("\n" + "=" * 80)


def print_terminal_tables(
    projects_data: List[Dict[str, Any]],
    extract_seeds: bool,
    extract_users: bool,
) -> None:
    """Prints formatted tabular views of extracted Users and Seeds to the terminal."""
    if extract_users:
        print("\n" + "=" * 115)
        print("                                      EXTRACTED USERS TABLE")
        print("=" * 115)
        header = (
            f"{'Project':<25} | {'Scope':<10} | {'Collection':<25} | "
            f"{'Email':<32} | {'Role':<12}"
        )
        print(header)
        print("-" * 115)
        user_row_count = 0
        for proj in projects_data:
            p_name = (proj.get("name") or "")[:25]
            for u in proj.get("users", []):
                print(
                    f"{p_name:<25} | {'project':<10} | {'-':<25} | "
                    f"{(u.get('email') or 'N/A')[:32]:<32} | {(u.get('role') or 'N/A')[:12]:<12}"
                )
                user_row_count += 1
            for col in proj.get("collections", []):
                c_name = (col.get("printable_name") or col.get("name") or "")[:25]
                for cu in col.get("users", []):
                    print(
                        f"{p_name:<25} | {'collection':<10} | {c_name:<25} | "
                        f"{(cu.get('email') or 'N/A')[:32]:<32} | {(cu.get('role') or 'N/A')[:12]:<12}"
                    )
                    user_row_count += 1
        if user_row_count == 0:
            print("No users found across selected projects/collections.")
        print("=" * 115)

    if extract_seeds:
        print("\n" + "=" * 115)
        print("                                      EXTRACTED SEEDS TABLE")
        print("=" * 115)
        header = (
            f"{'Project':<25} | {'Collection':<28} | {'Seed Type':<14} | "
            f"{'Seed Value':<32} | {'Status':<10}"
        )
        print(header)
        print("-" * 115)
        seed_row_count = 0
        for proj in projects_data:
            p_name = (proj.get("name") or "")[:25]
            for col in proj.get("collections", []):
                c_name = (col.get("printable_name") or col.get("name") or "")[:28]
                for s in col.get("seeds", []):
                    print(
                        f"{p_name:<25} | {c_name:<28} | {(s.get('type') or 'N/A')[:14]:<14} | "
                        f"{(s.get('value') or 'N/A')[:32]:<32} | {(s.get('status') or 'N/A')[:10]:<10}"
                    )
                    seed_row_count += 1
        if seed_row_count == 0:
            print("No seeds found across selected projects/collections.")
        print("=" * 115)


def write_csv_output(rows: List[Dict[str, Any]], output_path: str) -> None:
    """Writes the hierarchical GTI structure CSV file."""
    with open(output_path, mode="w", encoding="utf-8", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
    logger.info("Saved %d row(s) to CSV: %s", len(rows), output_path)


def write_json_output(
    projects_data: List[Dict[str, Any]],
    output_path: str,
    extract_mode: str,
    extract_seeds: bool,
    extract_users: bool,
) -> Dict[str, Any]:
    """Writes the nested Wiz import JSON file and returns summary statistics."""
    total_projects = len(projects_data)
    total_collections = sum(len(p.get("collections", [])) for p in projects_data)
    total_project_users = (
        sum(len(p.get("users", [])) for p in projects_data) if extract_users else 0
    )
    total_collection_users = (
        sum(
            len(c.get("users", []))
            for p in projects_data
            for c in p.get("collections", [])
        )
        if extract_users
        else 0
    )
    total_seeds = (
        sum(
            len(c.get("seeds", []))
            for p in projects_data
            for c in p.get("collections", [])
        )
        if extract_seeds
        else 0
    )

    summary: Dict[str, Any] = {
        "extraction_mode": extract_mode,
        "total_projects": total_projects,
        "total_collections": total_collections,
    }
    if extract_users:
        summary["total_project_users"] = total_project_users
        summary["total_collection_users"] = total_collection_users
    if extract_seeds:
        summary["total_seeds"] = total_seeds

    export_payload = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "projects": projects_data,
    }

    with open(output_path, mode="w", encoding="utf-8") as jsonfile:
        json.dump(export_payload, jsonfile, indent=2)

    logger.info("Saved nested Wiz migration payload to JSON: %s", output_path)
    return summary


def main() -> None:
    args = parse_arguments()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    api_key = load_api_key(args)
    extract_seeds, extract_users, extract_mode = resolve_extract_type(args)

    pool_maxsize = max(10, args.workers * 2)
    main_session = get_thread_session(pool_maxsize=pool_maxsize)

    all_projects = fetch_all_projects(
        session=main_session,
        api_key=api_key,
        keep_raw=args.keep_raw,
        debug=args.debug,
    )
    selected_projects = filter_or_select_projects(
        projects=all_projects,
        project_filter=args.project_filter,
        interactive=args.interactive,
    )

    if not selected_projects:
        logger.warning("No projects selected or found. Exiting.")
        return

    projects_export: List[Dict[str, Any]] = []

    for idx, project in enumerate(selected_projects, start=1):
        p_name = project["name"]
        p_id = project["id"]
        p_uuid = project["uuid"]
        logger.info(
            "[%d/%d] Processing project '%s' (ID: %s, UUID: %s)...",
            idx,
            len(selected_projects),
            p_name,
            p_id,
            p_uuid,
        )

        # 1. Fetch Project-level Users (only if extracting users)
        project_users: List[Dict[str, Any]] = []
        project_user_map: Dict[str, Dict[str, Any]] = {}
        if extract_users:
            project_users, project_user_map = fetch_project_users(
                session=main_session,
                project=project,
                api_key=api_key,
                keep_raw=args.keep_raw,
                debug=args.debug,
            )
            logger.info("  -> Found %d project-level user(s).", len(project_users))

        # 2. Fetch Collections in Project
        collections = fetch_project_collections(
            session=main_session,
            project=project,
            api_key=api_key,
            include_deleted=args.include_deleted,
            interactive=args.interactive,
            debug=args.debug,
        )
        logger.info("  -> Found %d active collection(s).", len(collections))

        # 3. Fetch Collection Users &/or Seeds concurrently across collections
        processed_collections: List[Dict[str, Any]] = []
        if collections:
            with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
                future_to_idx = {
                    executor.submit(
                        process_single_collection,
                        col,
                        p_id,
                        project_user_map,
                        api_key,
                        extract_seeds,
                        extract_users,
                        pool_maxsize,
                        args.keep_raw,
                        args.debug,
                    ): i
                    for i, col in enumerate(collections)
                }
                results_by_idx: Dict[int, Dict[str, Any]] = {}
                for future in as_completed(future_to_idx):
                    col_idx = future_to_idx[future]
                    col_name = collections[col_idx].get("printable_name")
                    try:
                        col_data = future.result()
                        results_by_idx[col_idx] = col_data
                        details = []
                        if extract_users:
                            details.append(f"{len(col_data.get('users', []))} collection user(s)")
                        if extract_seeds:
                            details.append(f"{len(col_data.get('seeds', []))} seed(s)")
                        logger.info("     - Collection '%s': %s", col_name, ", ".join(details))
                    except Exception as e:
                        logger.error("     ! Error processing collection '%s': %s", col_name, e)

                processed_collections = [
                    results_by_idx[i] for i in sorted(results_by_idx.keys())
                ]

        proj_entry: Dict[str, Any] = {
            "id": p_id,
            "uuid": p_uuid,
            "name": p_name,
            "organization_name": project.get("organization_name", ""),
        }
        if extract_users:
            proj_entry["users"] = project_users
        proj_entry["collections"] = processed_collections
        if args.keep_raw and project.get("raw"):
            proj_entry["raw"] = project["raw"]

        projects_export.append(proj_entry)

    # Print the visual hierarchy tree and formatted tables to the terminal
    if args.print_tree:
        print_hierarchy_tree(
            projects_data=projects_export,
            extract_seeds=extract_seeds,
            extract_users=extract_users,
        )
        print_terminal_tables(
            projects_data=projects_export,
            extract_seeds=extract_seeds,
            extract_users=extract_users,
        )

    # Generate both CSV and JSON outputs
    csv_rows = build_csv_rows(
        projects_data=projects_export,
        extract_seeds=extract_seeds,
        extract_users=extract_users,
    )
    write_csv_output(csv_rows, args.csv_out)
    summary = write_json_output(
        projects_data=projects_export,
        output_path=args.json_out,
        extract_mode=extract_mode,
        extract_seeds=extract_seeds,
        extract_users=extract_users,
    )

    print("\n" + "=" * 60)
    print("               GTI ASM Extraction Summary")
    print("=" * 60)
    print(f"  Extraction Mode         : {summary['extraction_mode']}")
    print(f"  Projects Processed      : {summary['total_projects']}")
    print(f"  Active Collections      : {summary['total_collections']}")
    if extract_users:
        print(f"  Project-Level Users     : {summary['total_project_users']}")
        print(f"  Collection-Level Users  : {summary['total_collection_users']}")
    if extract_seeds:
        print(f"  Seeds Extracted         : {summary['total_seeds']}")
    print("-" * 60)
    print(f"  Unified GTI CSV Output  : {os.path.abspath(args.csv_out)}")
    print(f"  Wiz Import JSON Output  : {os.path.abspath(args.json_out)}")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
        sys.exit(0)
