from __future__ import annotations

import base64
import os
import re
from datetime import datetime, timedelta

import data_models
from constants import EMAIL_ENTITY_TYPE, EMAIL_REGEX
from data_models import ThreatActor
from exceptions import GoogleThreatIntelligenceExceptions, PathNotExistException
from requests.structures import CaseInsensitiveDict
from SiemplifyDataModel import EntityTypes
from TIPCommon.types import Entity
from TIPCommon.utils import get_entity_original_identifier

SEVERITY_DICT = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "UNKNOWN": 0}


def get_entity_type(entity: Entity) -> str:
    """Helper function to get entity type

    Args:
        entity (Entity): entity to get type from

    Returns:
        str: entity type

    """
    if (
        re.search(EMAIL_REGEX, get_entity_original_identifier(entity))
        and entity.entity_type == EntityTypes.USER
    ):
        return EMAIL_ENTITY_TYPE

    return entity.entity_type


def prepare_hash_identifier(identifier: str) -> str:
    """Normalized the given identifier by converting it to lowercase.

    Args:
        identifier: The input identifier string.

    Returns:
        str: The normalized lowercase identifier.

    """
    return identifier.lower()


def prepare_entity_for_manager(entity: Entity) -> str:
    """Prepare an entity's identifier for the manager based on its type.

    Args:
        entity: The Entity object.

    Results:
        str: A processed entity identifier string.

    """
    identifier = get_entity_original_identifier(entity)

    if entity.entity_type == EntityTypes.URL:
        return encode_url(identifier)

    if entity.entity_type == EntityTypes.FILEHASH:
        return prepare_hash_identifier(identifier)

    return identifier


def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def get_next_page_url(headers: CaseInsensitiveDict[str]) -> str:
    """Get next page url from response headers

    Args:
        headers (CaseInsensitiveDict[str]): response headers

    Returns:
        str: next page url

    """
    # extract next page url from response link header
    matches = re.findall(r"<(.*?)>", headers.get("link", ""))
    return matches[0] if matches else None


def adjust_time(time_str: str) -> datetime:
    """Adjusts the given time by adding 6 hours.
    If the result is greater than the current time, return the current time.

    Args:
        time_str (str): Input time in format 'YYYY-MM-DDTHH:MM:SSZ'

    Returns:
        datetime: Adjusted time as a datetime object

    """
    given_time = datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%SZ")
    updated_time = given_time + timedelta(hours=6)
    now_time = datetime.utcnow()

    return min(updated_time, now_time)


def get_threat_actor_id_by_origin(threat_actors: list[ThreatActor]) -> str:
    """Returns the ID of the first object with origin "Google Threat Intelligence".

    If not found, returns the first object with origin "Partner".
    If neither exists, returns the ID of the first object in the list.
    """
    id_from_gti = None
    community_id = None

    for threat_actor in threat_actors:
        if threat_actor.origin == "Google Threat Intelligence":
            return threat_actor.id
        if threat_actor.origin == "Partner" and community_id is None:
            community_id = threat_actor.id
        if id_from_gti is None:
            id_from_gti = threat_actor.id

    return community_id if community_id is not None else id_from_gti


def get_threat_actor_by_origin(threat_actors: list[ThreatActor]) -> ThreatActor:
    """Returns the object with origin "Google Threat Intelligence".

    If not found, returns the first object with origin "Partner".
    If neither exists, returns the object in the list.

    Args:
        threat_actors: List of ThreatActor objects.

    Returns:
        ThreatActor: The ThreatActor object based on the specified logic.

    """
    from_gti = None
    community = None

    for threat_actor in threat_actors:
        if threat_actor.origin == "Google Threat Intelligence":
            return threat_actor
        if threat_actor.origin == "Partner" and community is None:
            community = threat_actor
        if from_gti is None:
            from_gti = threat_actor

    return community if community is not None else from_gti


def prepare_cached_widget(html_content: str) -> str:
    """Stripping the excessive data from html.

    Args:
        html_content: the widget content to be stripped

    Returns:
        str: Modified html content

    """
    tags_to_strip = [
        r"<nav>.*?</nav>",
        r"<section rel=\"iocs\".*?</section>",
        r"<section rel=\"graph\".*?</section>",
        r"<section rel=\"attribution\".*?</section>",
        r"<script.*?</script>",
    ]
    for tag in tags_to_strip:
        html_content = re.sub(tag, "", html_content, flags=re.DOTALL)

    return "".join(html_content.replace("VT Augment by", "Cached Widget").splitlines())


def get_highest_severity(signature_list) -> str:
    """Get the Highest Severity available in mitre technique.

    Args:
        signature_list: It takes signature list in mitre technique

    Returns:
        str: Return Highest severity in signature list in mitre technique

    """
    for p in SEVERITY_DICT:
        if p in signature_list:
            return p
    return " ".join([str(elem) for elem in list(SEVERITY_DICT)[-1:]])


def compare_severity(technique_severity: str, lowest_mitre_technique: str):
    """Check the item severity should be greater than lowest mitre technique.

    Args:
        lowest_mitre_technique: It takes severity input as a parameter
        technique_severity: sealing severity value of mitre technique
    Returns:
        bool: Return true if item severity is higher or equal else return false

    """
    return SEVERITY_DICT[technique_severity] >= SEVERITY_DICT[lowest_mitre_technique]


def remove_duplicate_mitre(json_data: list[dict]) -> list[dict]:
    """Remove duplicate items from the json response.

    Args:
        It takes Json response and filter out duplicate items
    Returns:
        list: Returns list of unique mitre technique

    """
    unique_identifier = set()
    unique_data = []

    for data in json_data:
        identifier = (data["id"], data["severity"])
        if identifier not in unique_identifier:
            unique_identifier.add(identifier)
            unique_data.append(data)
    sorted_data = sorted(
        unique_data, key=lambda d: SEVERITY_DICT[d["severity"]] + 1, reverse=True
    )
    return sorted_data


def fetch_mitre_data(raw_data, lowest_mitre_technique_severity):
    """Extracts MITRE tactics/techniques, filtering by severity."""
    related_mitre_tactics = []
    related_mitre_techniques = []
    mitre_date = {}
    try:
        raw_data = raw_data.get("data")

        tactics_unique_identifier = set()
        my_tactics = []
        my_techniques = []

        for key in raw_data:
            my_tactics.extend(raw_data.get(key, {}).get("tactics", []))

        # Fetching mitre tactics
        for tactic in my_tactics:
            tactics_json = {
                "id": tactic.get("id", ""),
                "name": tactic.get("name", ""),
            }
            identifier = tactics_json["id"]
            if identifier not in tactics_unique_identifier:
                tactics_unique_identifier.add(identifier)
                related_mitre_tactics.append(tactics_json)
            my_techniques.extend(tactic.get("techniques", []))

        # Fetching mitre techniques
        for technique in my_techniques:
            signature = technique.get("signatures", [])
            severities = [
                severity_value.get("severity", {}) for severity_value in signature
            ]
            highest_severity = get_highest_severity(severities)
            if compare_severity(highest_severity, lowest_mitre_technique_severity):
                techniques_json = {
                    "id": technique.get("id", ""),
                    "name": technique.get("name", ""),
                    "severity": highest_severity,
                }
                related_mitre_techniques.append(techniques_json)
        related_mitre_techniques = remove_duplicate_mitre(related_mitre_techniques)
        status = "completed"
        mitre_date = {
            "raw_data": raw_data,
            "status": status,
            "mitre_tactics": related_mitre_tactics,
            "mitre_techniques": related_mitre_techniques,
        }
    except (AttributeError, TypeError):
        status = "failed"
        mitre_date = {
            "raw_data": raw_data,
            "status": status,
            "mitre_tactics": related_mitre_tactics,
            "mitre_techniques": related_mitre_techniques,
        }

    return mitre_date


def convert_days_to_milliseconds(days: int) -> int:
    """Convert days to milliseconds.

    Args:
        days: {int} days to convert
    Returns:
        int: converted milliseconds

    """
    return days * 24 * 60 * 60 * 1000


def save_file(path, name: str, content: str) -> str:
    """Saves file content to a local file.

    Args:
        path: The directory path where the file should be saved.
        name: The filename to use.
        content: The file content to write.

    Returns:
        str: The full local path to the saved file.

    Raises:
        PathNotExistException: If the specified directory path does not exist.

    """
    if not os.path.exists(path):
        raise PathNotExistException(f"Folder {path} not found.")

    local_path = os.path.join(path, name)
    with open(local_path, "wb") as file:
        file.write(content.encode(encoding="UTF-8"))

    return local_path


def prepare_ioc_for_manager(ioc, ioc_type) -> str:
    """Prepares an Indicator of Compromise (IOC) for a manager.

    Transforms IOCs based on their type, such as URL encoding.

    Args:
        ioc (str): The IOC string.
        ioc_type (str): The type of the IOC (e.g., "URL").

    Returns:
        str: The transformed IOC string.

    """
    if ioc_type == "URL":
        return encode_url(ioc)

    return ioc


class Enricher:
    def __init__(self, api_client, logger):
        self.api_client = api_client
        self.logger = logger

    def get_sandbox_response(
        self,
        entity_identifier: str,
        sandboxes: list,
    ) -> dict[str, data_models.Sandbox | None]:
        """Retrieve sandbox response data for a given entity from list of sandboxes.

        Args:
            entity_identifier: The identifier of the entity.
            sandboxes: A list of sandbox names.

        Returns:
            Dict[str, Optional[datamodels.Sandbox]]:A mapping of
            sandbox names to data or None on error.

        """
        sandboxes_data = {}
        for sandbox in sandboxes:
            try:
                sandboxes_data[sandbox] = self.api_client.get_sandbox_data(
                    entity_identifier, sandbox, show_entity_status=True
                )
            except GoogleThreatIntelligenceExceptions as err:
                self.logger.error(
                    f"Error retrieving sandbox data for {entity_identifier} "
                    f"and sandbox {sandbox}: {err}"
                )
                sandboxes_data[sandbox] = None
        return sandboxes_data

    def get_mitre_response(
        self,
        entity_identifier: str,
        lowest_mitre_severity: str,
    ) -> data_models.Mitre | None:
        """Get MITRE response for a given entity identifier.

        Args:
            entity_identifier: The identifier of the entity.
            lowest_mitre_severity: The lowest severity level
            to use when querying MITRE data.

        Returns:
           Optional[datamodels.Mitre]: MITRE response data or None if an error occurs.

        """
        try:
            return self.api_client.get_mitre(
                file_hash=entity_identifier,
                show_entity_status=True,
                lowest_mitre_severity=lowest_mitre_severity,
            )
        except GoogleThreatIntelligenceExceptions as err:
            self.logger.error(
                f"Error retrieving MITRE data for {entity_identifier}: {err}"
            )
            return None

    def get_ai_summary_data(self, entity_identifier: str) -> dict | None:
        """Retrieve AI summary data for a given entity identifier.

        Args:
            entity_identifier: The identifier of the entity.

        Returns:
            Optional[Dict]: AI summary data or None if an error occurs.

        """
        try:
            return self.api_client.get_ai_summary(
                file_hash=entity_identifier,
            )
        except GoogleThreatIntelligenceExceptions as err:
            self.logger.error(
                f"Error retrieving AI Summary data for {entity_identifier}: {err}"
            )
            return None
