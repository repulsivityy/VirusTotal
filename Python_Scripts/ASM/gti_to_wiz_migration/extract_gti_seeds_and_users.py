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
    "deleted",
    "error",
    "user_email",
    "user_name",
    "user_role",
    "user_id",
    "seed_type",
    "seed_value",
    "seed_id",
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
        # Return the final response once retries run out, so errors report the real status
        raise_on_status=False,
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
            "Optional comma-separated list of project UUIDs "
            "to filter without interactive prompts."
        ),
    )
    parser.add_argument(
        "--include-deleted",
        action="store_true",
        default=False,
        help="Include deleted projects and collections (default: False).",
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
                print("Error: Invalid choice. Please enter 1, 2, or 3.")
        else:
            choice = "both"

    extract_seeds = choice in ("seeds", "both")
    extract_users = choice in ("users", "both")
    logger.info("Extraction mode selected: %s (seeds=%s, users=%s)", choice, extract_seeds, extract_users)
    return extract_seeds, extract_users, choice


def resolve_include_deleted(args: argparse.Namespace) -> bool:
    """
    Determines whether to include deleted projects and collections.
    Respects `--include-deleted` if passed; otherwise prompts in interactive mode.
    """
    if args.include_deleted:
        logger.info("Including deleted projects and collections (--include-deleted).")
        return True

    if args.interactive:
        while True:
            ans = input(
                "\nInclude deleted projects and collections? (y/n) [default: n]: "
            ).strip().lower()
            if not ans or ans in ("n", "no"):
                return False
            if ans in ("y", "yes"):
                logger.info("Including deleted projects and collections.")
                return True
            print("Error: Invalid input. Please enter 'y' or 'n'.")

    return False


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


def validate_output_paths(csv_out: str, json_out: str) -> Tuple[str, str]:
    """
    Verifies both output files can be written before any prompts or API calls,
    so a bad path doesn't waste API quota on a full extraction run.
    Returns the resolved absolute paths; exits with code 1 on any problem.
    """
    errors: List[str] = []
    resolved: List[str] = []
    for flag, path in (("--csv-out", csv_out), ("--json-out", json_out)):
        abs_path = os.path.abspath(os.path.expanduser(path))
        parent_dir = os.path.dirname(abs_path)
        if os.path.isdir(abs_path):
            errors.append(f"{flag} '{abs_path}' is a directory, not a file.")
        elif os.path.exists(abs_path):
            # Overwriting an existing file only needs write permission on the file itself
            if not os.access(abs_path, os.W_OK):
                errors.append(f"{flag} '{abs_path}' exists but is not writable.")
        elif not os.path.isdir(parent_dir):
            errors.append(f"{flag} directory '{parent_dir}' does not exist.")
        elif not os.access(parent_dir, os.W_OK):
            errors.append(f"{flag} directory '{parent_dir}' is not writable.")
        resolved.append(abs_path)

    if resolved[0] == resolved[1]:
        errors.append("--csv-out and --json-out point to the same file.")

    if errors:
        for err in errors:
            logger.error("Invalid output path: %s", err)
        sys.exit(1)

    return resolved[0], resolved[1]


def _append_query_param(url: str, key: str, value: str) -> str:
    """Safely adds or updates a query parameter on a URL."""
    parsed = urlparse(url)
    query_params = dict(parse_qsl(parsed.query))
    query_params[key] = value
    new_query = urlencode(query_params)
    return urlunparse(parsed._replace(query=new_query))


class ASMRequestError(Exception):
    """A GTI ASM API request failed (non-2xx, network error, invalid JSON or `success: false`)."""

    def __init__(self, resource: str, url: str, status: Optional[int], message: str) -> None:
        self.resource = resource
        self.url = url
        self.status = status
        self.message = message
        status_label = f"HTTP {status}" if status is not None else "request failed"
        super().__init__(f"{status_label} fetching {resource}: {message}")


def _api_error_message(body: Any, fallback: str = "") -> str:
    """
    Extracts a readable error message from either GTI error format:
      - Gateway/auth errors: `{"error": {"code": "...", "message": "..."}}`
      - ASM errors:          `{"success": false, "message": "..."}`
    """
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            code, msg = err.get("code"), err.get("message")
            if code and msg:
                return f"{code}: {msg}"
            if code or msg:
                return str(msg or code)
        elif isinstance(err, str) and err:
            return err
        if body.get("message"):
            return str(body["message"])
    return fallback or "no error message returned"


def _error_record(resource: str, err: Exception) -> Dict[str, Any]:
    """Builds a JSON-serialisable error entry for a failed fetch."""
    if isinstance(err, ASMRequestError):
        return {"resource": resource, "status": err.status, "message": err.message}
    return {"resource": resource, "status": None, "message": f"{type(err).__name__}: {err}"}


def _format_error(err: Dict[str, Any], with_resource: bool = True) -> str:
    """Formats one error entry, e.g. 'seeds: HTTP 403 - not authorized'."""
    status = f"HTTP {err['status']}" if err.get("status") is not None else "error"
    text = f"{status} - {err.get('message', '')}"
    return f"{err.get('resource', 'request')}: {text}" if with_resource else text


def _format_errors(errors: Optional[List[Dict[str, Any]]]) -> str:
    """Joins an entity's error entries into one line (used for the CSV `error` column)."""
    return "; ".join(_format_error(e) for e in errors or [])


def _failure_reason(entity: Dict[str, Any], resource: str) -> str:
    """Short 'HTTP 403 - message' reason for a failed list, for terminal output."""
    errors = entity.get("errors") or []
    match = next((e for e in errors if e.get("resource") == resource), None)
    match = match or (errors[0] if errors else None)
    return _format_error(match, with_resource=False) if match else "unknown error"


def fetch_paginated_or_list(
    session: requests.Session,
    url: str,
    headers: Dict[str, str],
    debug: bool = False,
    resource_label: str = "resource",
) -> List[Dict[str, Any]]:
    """
    Fetches an ASM endpoint and returns its items. Handles either:
      - A flat list: `{"result": [...]}` or `{"data": [...]}` (what GTI ASM returns today)
      - A paginated dict: `{"result": {"hits": [...], "next_page_token": "..."}}`
        or `{"result": {"seeds": [...], "next_page_token": "..."}}`
    Follows `next_page_token` safely, stopping when a page returns 0 items or
    if a page token repeats.

    Raises ASMRequestError on any failure (non-2xx status, network error after retries,
    invalid JSON, `success: false`, or an unexpected response shape), so a failed fetch
    is never mistaken for an empty list.
    """
    items: List[Dict[str, Any]] = []
    current_url: Optional[str] = url
    seen_tokens: Set[str] = set()

    while current_url:
        if debug:
            logger.debug("GET %s (resource=%s)", current_url, resource_label)

        try:
            response = session.get(current_url, headers=headers, timeout=30)
        except requests.exceptions.RequestException as e:
            raise ASMRequestError(resource_label, current_url, None, str(e)) from e

        if not response.ok:
            try:
                error_body: Any = response.json()
            except ValueError:
                error_body = None
            fallback = (response.text or "").strip()[:300] or response.reason or ""
            raise ASMRequestError(
                resource_label, current_url, response.status_code,
                _api_error_message(error_body, fallback),
            )

        try:
            payload = response.json()
        except ValueError as e:
            raise ASMRequestError(
                resource_label, current_url, response.status_code, "Invalid JSON in response"
            ) from e

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
            raise ASMRequestError(
                resource_label, current_url, response.status_code,
                f"Unexpected response type: {type(payload).__name__}",
            )

        # Some APIs return HTTP 200 with `success: false`; treat that as a failure too
        if payload.get("success") is False:
            raise ASMRequestError(
                resource_label, current_url, response.status_code,
                _api_error_message(payload, "success=false"),
            )

        if "result" not in payload and "data" not in payload:
            raise ASMRequestError(
                resource_label, current_url, response.status_code,
                "Unexpected response: no 'result' field",
            )
        result = payload.get("result")
        if result is None and "data" in payload:
            result = payload.get("data")

        next_token: Optional[str] = None
        page_items: List[Dict[str, Any]] = []

        if result is None:
            # Explicit `"result": null` means no items
            break
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
            for list_key in (
                "hits",
                "seeds",
                "user_entities",
                "entities",
                "users",
                "items",
                "collection_project_users",
                "data",
            ):
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
            raise ASMRequestError(
                resource_label, current_url, response.status_code,
                f"Unexpected 'result' type: {type(result).__name__}",
            )

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
    include_deleted: bool = False,
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
        if not isinstance(proj, dict):
            continue
        is_deleted = bool(proj.get("deleted", False) or proj.get("deleted_at"))
        if is_deleted and not include_deleted:
            continue

        # Keep the name clean for CSV/JSON; `(deleted)` is added only on screen via `_display_name`
        proj_name = str(proj.get("name") or "Unnamed Project").strip()

        entry: Dict[str, Any] = {
            "id": proj.get("id"),
            "uuid": proj.get("uuid", ""),
            "name": proj_name,
            "organization_name": proj.get("organization_name", ""),
            "deleted": is_deleted,
        }
        if keep_raw:
            entry["raw"] = proj
        projects.append(entry)

    logger.info("Found %d project(s).", len(projects))
    return projects


def _parse_selection_indices(choice: str, max_len: int) -> Tuple[Optional[List[int]], Optional[str]]:
    """
    Parses a 1-based user selection string (e.g. '1,3,5' or '1-4') against `max_len`.
    Returns `(sorted_zero_based_indices, error_message)`.
    """
    selected_indices: Set[int] = set()
    for part in choice.split(","):
        part = part.strip()
        if not part:
            return None, "Empty selection item."
        if "-" in part:
            try:
                start_str, end_str = part.split("-", 1)
                start, end = int(start_str.strip()), int(end_str.strip())
                if not (1 <= start <= end <= max_len):
                    return (
                        None,
                        f"Range '{part}' is out of bounds (valid range: 1-{max_len}).",
                    )
                for i in range(start, end + 1):
                    selected_indices.add(i - 1)
            except ValueError:
                return None, f"Invalid range format '{part}' (expected e.g. '1-{max_len}')."
        else:
            try:
                idx = int(part)
                if not (1 <= idx <= max_len):
                    return (
                        None,
                        f"Number '{idx}' is out of bounds (valid numbers: 1-{max_len}).",
                    )
                selected_indices.add(idx - 1)
            except ValueError:
                return None, f"Invalid number '{part}'."

    if not selected_indices:
        return None, "No valid items selected."
    return sorted(selected_indices), None


def filter_or_select_projects(
    projects: List[Dict[str, Any]],
    project_filter: Optional[str],
    interactive: bool,
) -> List[Dict[str, Any]]:
    """Filters projects via exact UUID match (--project-filter) or interactive user prompt."""
    if not projects:
        return []

    filtered = projects
    if project_filter:
        tokens = {t.strip().lower() for t in project_filter.split(",") if t.strip()}
        filtered = [
            p
            for p in projects
            if str(p.get("uuid", "")).strip().lower() in tokens
        ]
        logger.info("Filtered to %d project(s) matching --project-filter UUID(s).", len(filtered))

    if not interactive or not filtered:
        return filtered

    print("\n--- Available ASM Projects ---")
    for idx, proj in enumerate(filtered, start=1):
        print(f"  {idx}. {_display_name(proj)} (ID: {proj['id']}, UUID: {proj['uuid']})")

    while True:
        choice = input(
            "\nEnter project numbers (e.g., '1,3,5'), a range (e.g., '1-5'), or 'all' [default: all]: "
        ).strip().lower()
        if not choice or choice == "all":
            return filtered

        indices, err = _parse_selection_indices(choice, len(filtered))
        if indices is not None:
            return [filtered[i] for i in indices]
        print(f"Error: {err} Please enter numbers between 1 and {len(filtered)}, or 'all'.")


def resolve_collection_selection_mode(interactive: bool) -> bool:
    """
    Asks once upfront whether to extract all collections across selected projects
    or prompt per project. Returns True if user wants per-project collection selection.
    """
    if not interactive:
        return False

    print("\n--- Collection Selection Mode ---")
    print("  1. All collections across selected project(s) [default]")
    print("  2. Select specific collections per project")
    while True:
        ans = input(
            "\nEnter choice (1/2 or all/select) [default: 1 (all)]: "
        ).strip().lower()
        if not ans or ans in ("1", "all"):
            return False
        if ans in ("2", "select", "choose"):
            return True
        print("Error: Invalid choice. Please enter 1 ('all') or 2 ('select').")


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


def _display_name(
    entity: Dict[str, Any], fallback: str = "", max_len: Optional[int] = None
) -> str:
    """
    Returns a project/collection name for on-screen prompts and output, suffixed with
    ' (deleted)' when the entity is deleted. CSV/JSON keep the clean name plus the
    `deleted` field instead. If `max_len` is set, the name (not the suffix) is truncated
    so the deleted marker always stays visible in fixed-width tables.
    """
    name = str(entity.get("printable_name") or entity.get("name") or fallback).strip()
    suffix = " (deleted)" if entity.get("deleted") else ""
    if max_len is not None:
        name = name[: max(0, max_len - len(suffix))]
    return f"{name}{suffix}"


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
        if keep_raw:
            norm["raw"] = u

        normalized_users.append(norm)

        # Index by typed keys so collection relationship IDs never collide with project user IDs
        for key_name in ("id", "project_user_id"):
            val = u.get(key_name)
            if val is not None and str(val).strip() != "":
                user_lookup_map[f"proj_uid:{str(val).strip()}"] = norm
        for key_name in ("uuid", "user_uuid", "user_id"):
            val = u.get(key_name)
            if val is not None and str(val).strip() != "":
                user_lookup_map[f"uuid:{str(val).strip()}"] = norm
        if email:
            user_lookup_map[f"email:{email.lower()}"] = norm

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
        is_deleted = bool(col.get("deleted", False) or col.get("deleted_at"))
        if is_deleted and not include_deleted:
            continue

        raw_name = str(col.get("name") or "").strip()
        # Keep the name clean for CSV/JSON; `(deleted)` is added only on screen via `_display_name`
        printable_name = str(
            col.get("printable_name") or raw_name or "Unnamed Collection"
        ).strip()

        collections.append(
            {
                "id": col.get("id"),
                "uuid": _first_non_none(col.get("uuid"), col.get("id"), col.get("name")),
                "name": raw_name,
                "printable_name": printable_name,
                "workflow_name": col.get("workflow_name", ""),
                "workflow_pretty_name": col.get("workflow_pretty_name", ""),
                "deleted": is_deleted,
                "_raw_summary": col,
            }
        )

    if interactive and collections:
        print(f"\n--- Collections in Project '{_display_name(project)}' ---")
        for idx, col in enumerate(collections, start=1):
            wf = f" [{col['workflow_pretty_name']}]" if col.get("workflow_pretty_name") else ""
            print(f"  {idx}. {_display_name(col)}{wf} (UUID: {col['uuid']})")
        while True:
            sel = input(
                "Select collection numbers (e.g., '1,2'), a range (e.g., '1-3'), 'all', or 'none' [default: all]: "
            ).strip().lower()
            if not sel or sel == "all":
                return collections
            if sel == "none":
                return []

            indices, err = _parse_selection_indices(sel, len(collections))
            if indices is not None:
                return [collections[i] for i in indices]
            print(
                f"Error: {err} Please enter numbers between 1 and {len(collections)}, 'all', or 'none'."
            )

    return collections


def fetch_collection_users(
    session: requests.Session,
    collection: Dict[str, Any],
    project_id: Any,
    project_user_map: Optional[Dict[str, Dict[str, Any]]],
    api_key: str,
    keep_raw: bool = False,
    debug: bool = False,
) -> List[Dict[str, Any]]:
    """
    Fetches collection-level users (`GET /api/v3/asm/user_collections/{uuid}/collection_project_users`)
    and enriches missing user details (email/name/project_role) using `project_user_map`.
    GTI returns no project-user ID here, so in practice users are linked by email.
    `project_user_map=None` means project users could not be fetched (already reported).
    Raises ASMRequestError if the request fails.
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
    )
    user_map = project_user_map or {}

    normalized_col_users: List[Dict[str, Any]] = []
    for cu in raw_col_users:
        if not isinstance(cu, dict):
            continue

        nested_user = cu.get("user") if isinstance(cu.get("user"), dict) else {}
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

        # Enrich from project-level user map without colliding collection `cu.id` with project `user.id`
        linked_proj_user: Dict[str, Any] = {}
        lookup_candidates = [
            f"proj_uid:{str(cu.get('project_user_id')).strip()}"
            if cu.get("project_user_id") is not None
            else "",
            f"proj_uid:{str(nested_user.get('id')).strip()}"
            if nested_user.get("id") is not None
            else "",
            f"uuid:{str(cu.get('user_uuid')).strip()}"
            if cu.get("user_uuid") is not None
            else "",
            f"uuid:{str(cu.get('user_id')).strip()}"
            if cu.get("user_id") is not None
            else "",
            f"uuid:{str(nested_user.get('uuid')).strip()}"
            if nested_user.get("uuid") is not None
            else "",
            f"uuid:{str(nested_user.get('user_uuid')).strip()}"
            if nested_user.get("user_uuid") is not None
            else "",
            f"email:{email.lower()}" if email else "",
        ]
        for cand_key in lookup_candidates:
            if cand_key and cand_key in user_map:
                linked_proj_user = user_map[cand_key]
                break

        if not email and linked_proj_user.get("email"):
            email = linked_proj_user["email"]
        if not name and linked_proj_user.get("name"):
            name = linked_proj_user["name"]
        project_role = linked_proj_user.get("role", "")

        # Only use IDs known to be project user IDs. Never fall back to `cu.id`, which is
        # the collection-membership ID and would not match the project-level `user_id`.
        resolved_user_id = _first_non_none(
            linked_proj_user.get("user_id"),
            cu.get("project_user_id"),
        )
        # Skip the warning when project users couldn't be fetched (already reported as an error)
        if not linked_proj_user and project_user_map is not None:
            logger.warning(
                "Collection '%s': user '%s' not found in project users (user_id=%s).",
                collection.get("printable_name"),
                email or name or "<unknown>",
                resolved_user_id or "blank",
            )

        entry: Dict[str, Any] = {
            "user_id": resolved_user_id,
            "email": email,
            "name": name,
            "role": col_role,
            "project_role": project_role,
        }
        if keep_raw:
            entry["raw"] = cu
        normalized_col_users.append(entry)

    return normalized_col_users


def _extract_seed_fields(seed_obj: Any, keep_raw: bool = False) -> Dict[str, Any]:
    """Normalizes a seed / user_entity entry from GTI ASM into consistent fields."""
    if not isinstance(seed_obj, dict):
        entry: Dict[str, Any] = {
            "id": "",
            "type": "unknown",
            "value": str(seed_obj),
        }
        if keep_raw:
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

    # GTI `/user_entities` returns no status field, so no seed status is exported
    result: Dict[str, Any] = {
        "id": seed_id,
        "type": seed_type,
        "value": seed_value,
    }
    if keep_raw:
        result["raw"] = seed_obj
    return result


def fetch_collection_seeds(
    session: requests.Session,
    collection: Dict[str, Any],
    project_id: Any,
    api_key: str,
    keep_raw: bool = False,
    debug: bool = False,
) -> List[Dict[str, Any]]:
    """
    Fetches scan seeds for a specific collection via
    `GET /api/v3/asm/user_collections/{collection_uuid}/user_entities`.
    Entities explicitly marked `seed: false` are skipped, with a warning showing the count.
    Raises ASMRequestError if the request fails.
    """
    collection_uuid = collection.get("uuid") or collection.get("name")
    if not collection_uuid:
        return []

    headers = {
        "x-apikey": api_key,
        "PROJECT-ID": str(project_id),
        "Accept": "application/json",
    }

    url = f"{COLLECTIONS_ENDPOINT}/{collection_uuid}/user_entities"
    raw_seeds = fetch_paginated_or_list(
        session=session,
        url=url,
        headers=headers,
        debug=debug,
        resource_label=f"user_entities({collection['printable_name']})",
    )

    # Keep only original seeds; never drop non-seed entities silently
    seeds = [s for s in raw_seeds if not (isinstance(s, dict) and s.get("seed") is False)]
    skipped = len(raw_seeds) - len(seeds)
    if skipped:
        logger.warning(
            "Collection '%s': skipped %d non-seed entit%s (seed=false).",
            _display_name(collection),
            skipped,
            "y" if skipped == 1 else "ies",
        )
    return [_extract_seed_fields(s, keep_raw=keep_raw) for s in seeds]


def process_single_collection(
    collection: Dict[str, Any],
    project_id: Any,
    project_user_map: Optional[Dict[str, Dict[str, Any]]],
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
    Each fetch fails independently: a failed list is set to None and its error recorded
    under `errors`, while the other list is still extracted.
    """
    session = get_thread_session(pool_maxsize=pool_maxsize)
    col_entry = _base_collection_entry(collection)
    errors: List[Dict[str, Any]] = []

    if extract_users:
        try:
            col_entry["users"] = fetch_collection_users(
                session=session,
                collection=collection,
                project_id=project_id,
                project_user_map=project_user_map,
                api_key=api_key,
                keep_raw=keep_raw,
                debug=debug,
            )
        except ASMRequestError as e:
            logger.error("Collection '%s': failed to fetch users: %s", _display_name(collection), e)
            col_entry["users"] = None
            errors.append(_error_record("collection_users", e))

    if extract_seeds:
        try:
            col_entry["seeds"] = fetch_collection_seeds(
                session=session,
                collection=collection,
                project_id=project_id,
                api_key=api_key,
                keep_raw=keep_raw,
                debug=debug,
            )
        except ASMRequestError as e:
            logger.error("Collection '%s': failed to fetch seeds: %s", _display_name(collection), e)
            col_entry["seeds"] = None
            errors.append(_error_record("seeds", e))

    if errors:
        col_entry["errors"] = errors
    if keep_raw and collection.get("_raw_summary"):
        col_entry["raw"] = collection["_raw_summary"]

    return col_entry


def _base_collection_entry(collection: Dict[str, Any]) -> Dict[str, Any]:
    """Collection fields shared by every output entry (successful or failed)."""
    return {
        "id": collection.get("id"),
        "uuid": collection.get("uuid"),
        "name": collection.get("name"),
        "printable_name": collection.get("printable_name"),
        "workflow_name": collection.get("workflow_name", ""),
        "workflow_pretty_name": collection.get("workflow_pretty_name", ""),
        "deleted": collection.get("deleted", False),
    }


def _failed_collection_entry(
    collection: Dict[str, Any],
    err: Exception,
    extract_seeds: bool,
    extract_users: bool,
    keep_raw: bool = False,
) -> Dict[str, Any]:
    """Output entry for a collection whose worker crashed: kept in the export, lists marked failed."""
    col_entry = _base_collection_entry(collection)
    if extract_users:
        col_entry["users"] = None
    if extract_seeds:
        col_entry["seeds"] = None
    col_entry["errors"] = [_error_record("collection", err)]
    if keep_raw and collection.get("_raw_summary"):
        col_entry["raw"] = collection["_raw_summary"]
    return col_entry


def build_csv_rows(
    projects_data: List[Dict[str, Any]],
    extract_seeds: bool,
    extract_users: bool,
) -> List[Dict[str, Any]]:
    """
    Flattens the hierarchical project data into CSV rows preserving the
    parent-child tree order without leading formula characters (`--` / `----`).
    Every child row also carries its parent `project_*` and `collection_*` identifiers.
    `deleted` reflects the row's scope (project or collection), matching the JSON.
    `error` is set on the project/collection row whose users, collections or seeds
    failed to fetch (those lists are `null` in the JSON).
    """
    rows: List[Dict[str, Any]] = []

    def _csv_row(**fields: Any) -> Dict[str, Any]:
        # Every column starts blank, so each row only sets the fields it needs
        row = {name: "" for name in CSV_FIELDNAMES}
        row.update(fields)
        return row

    for proj in projects_data:
        p_name = proj.get("name", "")
        p_deleted = proj.get("deleted", False)
        project_fields = {
            "project_name": p_name,
            "project_id": proj.get("id", ""),
            "project_uuid": proj.get("uuid", ""),
        }

        # Top-level Project Header Row
        rows.append(
            _csv_row(
                hierarchy_tree=f"{p_name}",
                scope_level="project",
                record_type="project",
                deleted=p_deleted,
                error=_format_errors(proj.get("errors")),
                **project_fields,
            )
        )

        # 1. Project-level Users (`scope_level = 'project'`, `record_type = 'user'`)
        if extract_users:
            for p_user in proj.get("users") or []:
                u_email = p_user.get("email", "")
                u_role = p_user.get("role", "")
                rows.append(
                    _csv_row(
                        hierarchy_tree=f"[Project User] {u_email} ({u_role})",
                        scope_level="project",
                        record_type="user",
                        deleted=p_deleted,
                        user_email=u_email,
                        user_name=p_user.get("name", ""),
                        user_role=u_role,
                        user_id=p_user.get("user_id", ""),
                        **project_fields,
                    )
                )

        # 2. Collections (`scope_level = 'collection'`)
        for col in proj.get("collections") or []:
            c_name = col.get("printable_name") or col.get("name") or ""
            c_deleted = col.get("deleted", False)
            collection_fields = {
                "collection_name": c_name,
                "collection_id": col.get("id", ""),
                "collection_uuid": col.get("uuid") or "",
            }

            # Collection Header Row
            rows.append(
                _csv_row(
                    hierarchy_tree=f"{c_name}",
                    scope_level="collection",
                    record_type="collection",
                    deleted=c_deleted,
                    error=_format_errors(col.get("errors")),
                    **project_fields,
                    **collection_fields,
                )
            )

            # 2a. Collection-level Users
            if extract_users:
                for c_user in col.get("users") or []:
                    cu_email = c_user.get("email", "")
                    cu_role = c_user.get("role", "")
                    rows.append(
                        _csv_row(
                            hierarchy_tree=f"[Collection User] {cu_email} ({cu_role})",
                            scope_level="collection",
                            record_type="user",
                            deleted=c_deleted,
                            user_email=cu_email,
                            user_name=c_user.get("name", ""),
                            user_role=cu_role,
                            user_id=c_user.get("user_id", ""),
                            **project_fields,
                            **collection_fields,
                        )
                    )

            # 2b. Collection Seeds
            if extract_seeds:
                for seed in col.get("seeds") or []:
                    s_type = seed.get("type", "")
                    s_val = seed.get("value", "")
                    rows.append(
                        _csv_row(
                            hierarchy_tree=f"{s_val} ({s_type})" if s_type else f"{s_val}",
                            scope_level="collection",
                            record_type="seed",
                            deleted=c_deleted,
                            seed_type=s_type,
                            seed_value=s_val,
                            seed_id=seed.get("id", ""),
                            **project_fields,
                            **collection_fields,
                        )
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
        p_name = _display_name(proj, fallback="Unnamed Project")
        p_id = proj.get("id", "")
        p_uuid = proj.get("uuid", "")
        print(f"\n{p_name} (ID: {p_id}, UUID: {p_uuid})")

        if extract_users:
            proj_users = proj.get("users")
            if proj_users is None:
                print(f"-- [Project Users] FAILED: {_failure_reason(proj, 'project_users')}")
            elif proj_users:
                for p_user in proj_users:
                    u_name = p_user.get("name") or "N/A"
                    print(
                        f"-- [Project User] {p_user.get('email', 'N/A')} "
                        f"| Role: {p_user.get('role', 'N/A')} | Name: {u_name}"
                    )
            else:
                print("-- [Project Users] (none)")

        collections = proj.get("collections")
        if collections is None:
            print(f"-- [Collections] FAILED: {_failure_reason(proj, 'collections')}")
            continue
        if not collections:
            print("-- (No collections)")
            continue

        for col in collections:
            c_name = _display_name(col, fallback="Unnamed Collection")
            c_uuid = col.get("uuid", "")
            print(f"-- {c_name} (UUID: {c_uuid})")

            if extract_users:
                col_users = col.get("users")
                if col_users is None:
                    print(f"---- [Collection Users] FAILED: {_failure_reason(col, 'collection_users')}")
                elif col_users:
                    for c_user in col_users:
                        cu_name = c_user.get("name") or "N/A"
                        print(
                            f"---- [Collection User] {c_user.get('email', 'N/A')} "
                            f"| Role: {c_user.get('role', 'N/A')} | Name: {cu_name}"
                        )
                else:
                    print("---- [Collection Users] (none)")

            if extract_seeds:
                col_seeds = col.get("seeds")
                if col_seeds is None:
                    print(f"---- [Seeds] FAILED: {_failure_reason(col, 'seeds')}")
                elif col_seeds:
                    for seed in col_seeds:
                        s_type = seed.get("type", "")
                        s_val = seed.get("value", "")
                        if s_type:
                            print(f"---- [Seed] {s_val} ({s_type})")
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
            p_name = _display_name(proj, max_len=25)
            for u in proj.get("users") or []:
                print(
                    f"{p_name:<25} | {'project':<10} | {'-':<25} | "
                    f"{(u.get('email') or 'N/A')[:32]:<32} | {(u.get('role') or 'N/A')[:12]:<12}"
                )
                user_row_count += 1
            for col in proj.get("collections") or []:
                c_name = _display_name(col, max_len=25)
                for cu in col.get("users") or []:
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
            f"{'Seed Value':<45}"
        )
        print(header)
        print("-" * 115)
        seed_row_count = 0
        for proj in projects_data:
            p_name = _display_name(proj, max_len=25)
            for col in proj.get("collections") or []:
                c_name = _display_name(col, max_len=28)
                for s in col.get("seeds") or []:
                    print(
                        f"{p_name:<25} | {c_name:<28} | {(s.get('type') or 'N/A')[:14]:<14} | "
                        f"{(s.get('value') or 'N/A')[:45]:<45}"
                    )
                    seed_row_count += 1
        if seed_row_count == 0:
            print("No seeds found across selected projects/collections.")
        print("=" * 115)


def collect_errors(projects_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flattens project- and collection-level errors into one list, each with its context."""
    flat: List[Dict[str, Any]] = []
    for proj in projects_data:
        project_ctx = {
            "project_name": proj.get("name", ""),
            "project_uuid": proj.get("uuid", ""),
        }
        for err in proj.get("errors") or []:
            flat.append({**project_ctx, "collection_name": "", "collection_uuid": "", **err})
        for col in proj.get("collections") or []:
            for err in col.get("errors") or []:
                flat.append(
                    {
                        **project_ctx,
                        "collection_name": col.get("printable_name") or col.get("name") or "",
                        "collection_uuid": col.get("uuid") or "",
                        **err,
                    }
                )
    return flat


def print_error_report(errors: List[Dict[str, Any]]) -> None:
    """Prints every recorded failure last, so an incomplete export can't go unnoticed."""
    print("\n" + "!" * 60)
    print(f"  {len(errors)} ERROR(S) - this export is INCOMPLETE")
    print("!" * 60)
    for err in errors:
        scope = err.get("project_name", "")
        if err.get("collection_name"):
            scope = f"{scope} / {err['collection_name']}"
        print(f"  - [{scope}] {_format_error(err)}")
    print("  Failed lists are null in the JSON and flagged in the CSV 'error' column.")
    print("!" * 60)


def write_csv_output(rows: List[Dict[str, Any]], output_path: str) -> None:
    """Writes the hierarchical GTI structure CSV file."""
    # `utf-8-sig` writes a BOM so Excel detects UTF-8 and renders non-ASCII names correctly
    with open(output_path, mode="w", encoding="utf-8-sig", newline="") as csvfile:
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
    errors: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Writes the nested Wiz import JSON file and returns summary statistics.
    Lists that failed to fetch are `null` (vs `[]` for genuinely empty), and every
    failure is listed in the top-level `errors` array with its project/collection.
    """
    errors = errors or []
    total_projects = len(projects_data)
    total_collections = sum(len(p.get("collections") or []) for p in projects_data)
    total_project_users = (
        sum(len(p.get("users") or []) for p in projects_data) if extract_users else 0
    )
    total_collection_users = (
        sum(
            len(c.get("users") or [])
            for p in projects_data
            for c in p.get("collections") or []
        )
        if extract_users
        else 0
    )
    total_seeds = (
        sum(
            len(c.get("seeds") or [])
            for p in projects_data
            for c in p.get("collections") or []
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
    summary["total_errors"] = len(errors)

    export_payload = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "errors": errors,
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

    # Fail fast on bad output paths before any prompts or API calls
    args.csv_out, args.json_out = validate_output_paths(args.csv_out, args.json_out)

    api_key = load_api_key(args)
    extract_seeds, extract_users, extract_mode = resolve_extract_type(args)
    include_deleted = resolve_include_deleted(args)

    pool_maxsize = max(10, args.workers * 2)
    main_session = get_thread_session(pool_maxsize=pool_maxsize)

    # Listing projects is the only fatal failure: nothing else can run without it
    try:
        all_projects = fetch_all_projects(
            session=main_session,
            api_key=api_key,
            include_deleted=include_deleted,
            keep_raw=args.keep_raw,
            debug=args.debug,
        )
    except ASMRequestError as e:
        logger.error("Cannot list ASM projects, aborting: %s", e)
        sys.exit(1)

    selected_projects = filter_or_select_projects(
        projects=all_projects,
        project_filter=args.project_filter,
        interactive=args.interactive,
    )

    if not selected_projects:
        logger.warning("No projects selected or found. Exiting.")
        return

    # Ask once upfront whether to extract all collections or select per project.
    # A failed collection listing is recorded against its project (collections = None).
    select_collections_per_project = resolve_collection_selection_mode(args.interactive)
    collections_by_project_idx: Dict[int, Optional[List[Dict[str, Any]]]] = {}
    project_errors_by_idx: Dict[int, List[Dict[str, Any]]] = {}
    for idx, project in enumerate(selected_projects):
        project_errors_by_idx[idx] = []
        try:
            collections_by_project_idx[idx] = fetch_project_collections(
                session=main_session,
                project=project,
                api_key=api_key,
                include_deleted=include_deleted,
                interactive=select_collections_per_project,
                debug=args.debug,
            )
        except ASMRequestError as e:
            logger.error("Project '%s': failed to list collections: %s", _display_name(project), e)
            collections_by_project_idx[idx] = None
            project_errors_by_idx[idx].append(_error_record("collections", e))

    projects_export: List[Dict[str, Any]] = []

    for idx, project in enumerate(selected_projects, start=1):
        p_name = project["name"]
        p_id = project["id"]
        p_uuid = project["uuid"]
        proj_errors = project_errors_by_idx[idx - 1]
        logger.info(
            "[%d/%d] Processing project '%s' (ID: %s, UUID: %s)...",
            idx,
            len(selected_projects),
            _display_name(project),
            p_id,
            p_uuid,
        )

        # 1. Fetch Project-level Users (only if extracting users); None = fetch failed
        project_users: Optional[List[Dict[str, Any]]] = []
        project_user_map: Optional[Dict[str, Dict[str, Any]]] = {}
        if extract_users:
            try:
                project_users, project_user_map = fetch_project_users(
                    session=main_session,
                    project=project,
                    api_key=api_key,
                    keep_raw=args.keep_raw,
                    debug=args.debug,
                )
                logger.info("  -> Found %d project-level user(s).", len(project_users))
            except ASMRequestError as e:
                logger.error("  ! Failed to fetch project users: %s", e)
                project_users, project_user_map = None, None
                proj_errors.append(_error_record("project_users", e))

        # 2. Use pre-fetched/selected Collections in Project (None = listing failed)
        collections = collections_by_project_idx.get(idx - 1)
        processed_collections: Optional[List[Dict[str, Any]]] = None
        if collections is not None:
            logger.info("  -> Processing %d selected collection(s).", len(collections))
            processed_collections = []

        # 3. Fetch Collection Users &/or Seeds concurrently across collections
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
                    col_name = _display_name(collections[col_idx])
                    try:
                        col_data = future.result()
                    except Exception as e:
                        # Keep the collection in the output, marked as failed, instead of dropping it
                        logger.error("     ! Error processing collection '%s': %s", col_name, e)
                        col_data = _failed_collection_entry(
                            collections[col_idx], e, extract_seeds, extract_users, args.keep_raw
                        )
                    results_by_idx[col_idx] = col_data
                    details = []
                    if extract_users:
                        col_users = col_data.get("users")
                        details.append(
                            "users FAILED" if col_users is None else f"{len(col_users)} collection user(s)"
                        )
                    if extract_seeds:
                        col_seeds = col_data.get("seeds")
                        details.append(
                            "seeds FAILED" if col_seeds is None else f"{len(col_seeds)} seed(s)"
                        )
                    logger.info("     - Collection '%s': %s", col_name, ", ".join(details))

                processed_collections = [
                    results_by_idx[i] for i in sorted(results_by_idx.keys())
                ]

        proj_entry: Dict[str, Any] = {
            "id": p_id,
            "uuid": p_uuid,
            "name": p_name,
            "organization_name": project.get("organization_name", ""),
            "deleted": project.get("deleted", False),
        }
        if extract_users:
            proj_entry["users"] = project_users
        proj_entry["collections"] = processed_collections
        if proj_errors:
            proj_entry["errors"] = proj_errors
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
    errors = collect_errors(projects_export)
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
        errors=errors,
    )

    print("\n" + "=" * 60)
    print("               GTI ASM Extraction Summary")
    print("=" * 60)
    print(f"  Extraction Mode         : {summary['extraction_mode']}")
    print(f"  Projects Processed      : {summary['total_projects']}")
    print(f"  Collections Processed   : {summary['total_collections']}")
    if extract_users:
        print(f"  Project-Level Users     : {summary['total_project_users']}")
        print(f"  Collection-Level Users  : {summary['total_collection_users']}")
    if extract_seeds:
        print(f"  Seeds Extracted         : {summary['total_seeds']}")
    print(f"  Errors                  : {summary['total_errors']}")
    print("-" * 60)
    print(f"  Unified GTI CSV Output  : {os.path.abspath(args.csv_out)}")
    print(f"  Wiz Import JSON Output  : {os.path.abspath(args.json_out)}")
    print("=" * 60)

    if errors:
        print_error_report(errors)
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
        sys.exit(0)
