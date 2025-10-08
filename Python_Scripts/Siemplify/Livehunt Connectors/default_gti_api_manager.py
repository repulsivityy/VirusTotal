from __future__ import annotations

import contextlib
import os

from typing import Any

import api_data_parser as parser
import requests
from requests import Session
import data_models
from SiemplifyConnectors import SiemplifyConnectorExecution
from TIPCommon.base.utils import NewLineLogger
from TIPCommon.filters import filter_old_alerts
from TIPCommon.smp_time import is_approaching_timeout
from TIPCommon.types import Entity
from api_utils import (
    build_asm_entity_query_string,
    build_query_for_single_params,
    build_query_string,
    get_full_url,
    get_project_id,
    validate_response,
    validate_gti_response,
)
from constants import (
    ALERT_STATUSES,
    COMMENT_ENDPOINTS_MAPPING,
    DEFAULT_PAGE_SIZE,
    GTI_ROOT,
    ITEMS_PER_PAGE,
    MANDIANT_ROOT,
    MAX_LIMIT,
    MAX_NOTIFICATIONS_LIMIT,
    SEVERITIES,
    VOTE_ENDPOINTS_MAPPING,
    WIDGET_CHRONICLE_THEME_COLORS,
)
from data_models import (
    ASMEntity,
    ASMIssue,
    DTMAlert,
    Graph,
    GraphDetails,
    IOCSearchResult,
    ThreatActor,
)
from exceptions import (
    FileSubmissionError,
    GoogleThreatIntelligenceExceptions,
    ProjectNotFoundError,
)
from utils import (
    WidgetComponentPreprocessor,
    adjust_time,
    fetch_mitre_data,
    get_next_page_url,
    prepare_entity_for_manager,
    prepare_hash_identifier,
)


class ApiManager:
    def __init__(
        self,
        api_root: str,
        session: Session,
        asm_project_name: str,
        logger: NewLineLogger,
    ) -> None:
        """Manager for handling API interactions

        Args:
            api_root (str): API root URL
            session (Session): initialized session object to be used in API session
            asm_project_name (str): ASM project name
            logger (NewLineLogger): logger object

        """
        self.api_root = api_root + "/" if not api_root.endswith("/") else api_root
        self.session = session
        self.asm_project_name = asm_project_name
        self.logger = logger
        self.project_id = None

    def test_connectivity(self) -> None:
        """Test connectivity."""
        try:
            response = self.session.get(
                get_full_url(
                    self.api_root,
                    "asm_ping" if self.asm_project_name else "ping",
                )
            )
        except UnicodeEncodeError as exc:
            raise ValueError(
                "API key contains unsupported unicode characters."
            ) from exc

        validate_response(response)

        if self.asm_project_name:
            project_id = get_project_id(
                response.json()["result"],
                self.asm_project_name,
            )

            if not project_id:
                raise ProjectNotFoundError(
                    f"the following ASM Project wasn't found: {self.asm_project_name}."
                    "Please check the integration configuration."
                )

    def set_project_id(self, project_name) -> None:
        """Set Project ID from project name.

        Args:
            project_name: {str} The name of the Project

        """
        project_name = project_name or self.asm_project_name

        url = get_full_url(self.api_root, "index_projects")
        if not project_name:
            self.project_id = None
            return

        response = self.session.get(url)
        validate_response(response)
        projects = response.json()["result"]
        project_id = get_project_id(projects, project_name)

        if not project_id:
            raise ProjectNotFoundError(
                f"the following ASM Project wasn't found: {project_name}."
            )

        self.project_id = project_id

    def get_graph_details(self, graph_id: str, links_limit: int) -> GraphDetails:
        """Get graph details by graph id

        Args:
            graph_id (str): graph id
            links_limit (int): maximum links amount to return

        Returns:
            GraphDetails: GraphDetails object

        """
        response = self.session.get(
            get_full_url(self.api_root, "get_graph_details", graph_id=graph_id)
        )

        validate_response(response)
        return parser.build_graph_details_object(
            response.json(), links_limit=links_limit
        )

    def search_graphs(self, query: str, sort_field: str, graphs_limit: int) -> [Graph]:
        """Search graphs

        Args:
            query (str): query filter to search for graphs
            sort_field (str): sort field for the graphs
            graphs_limit (int): maximum graphs amount to return

        Returns:
            [Graphs]: list of Graphs object

        """
        url = get_full_url(self.api_root, "search_graphs")
        params = {
            "filter": query,
            "order": sort_field,
            "limit": graphs_limit,
            "attributes": "graph_data",
        }

        return self.paginate_results(
            url=url,
            limit=graphs_limit,
            parser_method="build_graph_objects",
            params=params,
        )

    def paginate_results(
        self,
        url: str,
        limit: int,
        parser_method: str,
        params: dict[str, Any] | None = None,
        show_entity_status: bool = False,
    ) -> list[Any]:
        """Paginate results

        Args:
            url: url to send request to.
            limit: limit for the results.
            parser_method: parser method to build the result.
            params: request query params, defaults to None.
            show_entity_status: Return error message for entity.

        Returns:
            list[Any]: list of results

        """
        params = params or {}
        results = []
        response = None
        params["limit"] = min(limit, ITEMS_PER_PAGE)

        while True:
            url = parser.get_next_page_url(response.json()) if response else url

            if len(results) >= limit or not url:
                break

            params = {} if response else params
            response = self.session.get(url, params=params)
            validate_response(response, show_entity_status=show_entity_status)
            results.extend(
                getattr(parser, parser_method)(
                    parser.get_results_from_raw_data(response.json())
                )
            )

        return results[:limit]

    def update_alert(self, alert_id: str, status: str) -> DTMAlert:
        """Update alert status

        Args:
            alert_id (str): Alert id
            status (str): Status to update

        Returns:
            DTMAlert: DTMAlert object

        """
        url = get_full_url(self.api_root, "update_dtm_alert", alert_id=alert_id)

        payload = {"status": status}
        response = self.session.patch(url, json=payload)
        validate_response(response)

        return parser.build_dtm_alert_object(response.json())

    def update_analysis_text_on_alert(self, alert_id: str, text: str) -> None:
        """Updates the analysis text on an alert object

        Args:
            alert_id (str): Alert id
            text (str): Text of the analysis

        Returns:
            None

        """
        response = self.session.put(
            url=get_full_url(
                api_root=self.api_root,
                endpoint_id="set_dtm_alert_analysis",
                alert_id=alert_id
            ),
            json={"analysis": text}
        )
        validate_response(response)

    def upload_file_to_alerts_analysis(
        self,
        alert_id: str,
        file_paths: list[str]
    ) -> None:
        """Uploads files to alert`s analysis

        Uses `contextlib.ExitStack` to guarantee that a dynamic number of
        successfully opened files are all properly closed.

        Args:
            alert_id (str): Alert id
            file_paths (list): List of the absolute file paths

        Returns:
            None
        """
        if not file_paths:
            return

        with contextlib.ExitStack() as stack:
            files = tuple(
                (
                    "files",
                    (
                        os.path.basename(file_path),
                        stack.enter_context(open(file_path, "rb")),
                        "application/octet-stream"
                    )
                ) for file_path in file_paths
            )

            response = self.session.post(
                get_full_url(
                    api_root=self.api_root,
                    endpoint_id="upload_file_to_alerts_analysis",
                    alert_id=alert_id
                ),
                files=files
            )
            validate_gti_response(response)

    def add_comment_to_entity(self, entity: Entity, comment: str):
        """Add vote to entity
        Args:
            entity: Siemplify entity
            comment: comment to add to entities
        return:
            Bool(True/False)
        """
        identifier = prepare_entity_for_manager(entity)
        endpoint_id = COMMENT_ENDPOINTS_MAPPING.get(entity.entity_type)
        if endpoint_id:
            url = get_full_url(self.api_root, endpoint_id, identifier=identifier)
        else:
            raise GoogleThreatIntelligenceExceptions("Not supported entity type")

        payload = {"data": {"type": "comment", "attributes": {"text": comment}}}
        response = self.session.post(url=url, json=payload)
        if response.status_code == 409:  # duplicate entries considered as success
            return True
        validate_response(response)

        return True

    def get_dtm_alerts(
        self,
        timestamp: str,
        limit: int,
        siemplify: SiemplifyConnectorExecution,
        lowest_severity: str = "",
        monitor_ids: list[str] | None = None,
        alert_types: list[str] | None = None,
        existing_ids: list[str] | None = None,
    ) -> list[DTMAlert]:
        """Get alerts

        Args:
            timestamp (str): timestamp filter to get alert from
            limit (int): limit for results
            siemplify (SiemplifyConnectorExecution): SiemplifyConnectorExecution object
            lowest_severity (str): lowest severity filter
            monitor_ids (list[str] | None ): list of monitor ids filters
            alert_types (list[str] | None ): list of alert type filters
            existing_ids (list[str] | None ): list of ids to filter

        Returns:
            [DTMAlert]: list of DTMAlert dataclasses

        """
        url = get_full_url(self.api_root, "get_dtm_alerts")

        params = {
            "since": timestamp,
            "size": max(limit, MAX_LIMIT),
            "severity": (
                SEVERITIES[SEVERITIES.index(lowest_severity.lower()) :]
                if lowest_severity
                else SEVERITIES
            ),
            "monitor_id": monitor_ids,
            "alert_type": alert_types,
            "order": "asc",
            "refs": "true",
            "monitor_name": "true",
            "status": ALERT_STATUSES,
        }

        return self._paginate_results(url, limit, siemplify, existing_ids, params)

    def add_vote_to_entity(self, entity: Entity, vote: str):
        """Add vote to entity
        Args:
            entity: Siemplify entity
            vote: str
        return:
            Bool(True/False)
        """
        identifier = prepare_entity_for_manager(entity)
        endpoint_id = VOTE_ENDPOINTS_MAPPING.get(entity.entity_type)
        if endpoint_id:
            url = get_full_url(self.api_root, endpoint_id, identifier=identifier)
        else:
            raise GoogleThreatIntelligenceExceptions("Not supported entity type")

        payload = {"data": {"type": "vote", "attributes": {"verdict": vote.lower()}}}
        response = self.session.post(url=url, json=payload)
        # Action returns 409 when duplicate entries (considered as success)
        if response.status_code == 409:
            return True
        validate_response(response)
        return True

    def _paginate_results(
        self,
        full_url: str,
        limit: int,
        siemplify: SiemplifyConnectorExecution,
        existing_ids: [str] = None,
        params: dict | None = None,
    ) -> list[DTMAlert]:
        """Paginate the results

        Args:
            full_url (str): full url to send request to
            limit (int): limit for the results to fetch
            existing_ids ([str]): list of ids to filter
            params (dict): request params dict
            siemplify (SiemplifyConnectorExecution): SiemplifyConnectorExecution object

        Returns:
            [DTMAlert]: list of DTMAlert dataclasses

        """
        results, next_page_link, response = [], None, None

        while True:
            if response:
                if not next_page_link or (limit is not None and len(results) >= limit):
                    break

                full_url = next_page_link
                params = {}

            response = self.session.get(full_url, params=params)

            current_link = response.headers.get("link", "")
            if self.api_root not in current_link:
                updated_link = current_link.replace(MANDIANT_ROOT, GTI_ROOT)
                response.headers.update({"link": updated_link})

            validate_response(response)
            next_page_link = get_next_page_url(response.headers)

            results.extend(
                filter_old_alerts(
                    siemplify,
                    alerts=parser.build_dtm_alert_objects(response.json()),
                    existing_ids=set(existing_ids) if existing_ids else [],
                    id_key="alert_id",
                )
            )

        return results[:limit] if limit else results

    def get_asm_entity_by_id(self, entity_id) -> ASMEntity:
        """Fetches details of a given entity id.

        Args:
            entity_id: {str} entity id to fetch details of

        Returns:
            ASMEntity: ASMEntity object

        """
        url = get_full_url(self.api_root, "entity_full_details", entity_id=entity_id)

        response = self.session.get(url)
        validate_response(response)
        response_json = response.json()

        if not response_json["success"]:
            raise GoogleThreatIntelligenceExceptions(response_json["message"])

        return parser.build_asm_entity_object(response_json)

    def search_issues(
        self,
        limit: int,
        script_starting_time: int,
        execution_deadline: int,
        **kwargs,
    ) -> list[ASMIssue]:
        """Searches issues that match specified criteria up to limit.

        Args:
            limit: {int} Limitation of how much issues to fetch
            script_starting_time: {int} Script starting time
            execution_deadline: {int} Execution deadline
            kwargs: {Dict[str, Any]} the dictionary that contains all kwargs params
                                    specified for filtering, check
                                    build_query_string for details.

        Returns:
            [Issue]: list of Issue dataclasses

        """
        page_number = 0
        filtered_issues = []

        query_string = build_query_string(
            entity_name=kwargs.get("entity_name"),
            issue_ids=kwargs.get("issue_ids"),
            entity_ids=kwargs.get("entity_ids"),
            tags=kwargs.get("tags"),
            time_parameter=kwargs.get("time_parameter"),
            start_time=kwargs.get("start_time"),
            end_time=kwargs.get("end_time"),
            status=kwargs.get("status"),
            lowest_severity=kwargs.get("lowest_severity"),
        )

        url = get_full_url(
            api_root=self.api_root,
            endpoint_id="search_issues",
            query_string=query_string,
        )

        while True:
            if is_approaching_timeout(script_starting_time, execution_deadline):
                self.logger.info("Timeout is approaching. Action will gracefully exit")
                break

            issues, more_pages = self.search_issues_by_page(
                url=url,
                page_number=page_number,
                parser_method=parser.build_issue_objects,
            )
            filtered_issues.extend(issues)

            if len(filtered_issues) >= limit or not more_pages:
                self.logger.info(
                    f"Reached Maximum count of entities to process of {limit} !"
                )
                break

            page_number += 1

        return filtered_issues[:limit]

    def search_asm_entities(
        self,
        limit: int,
        script_starting_time: int,
        execution_deadline: int,
        **kwargs,
    ) -> list[ASMEntity]:
        """Searches ASM entities that match specified criteria up to limit.

        Args:
            limit: {int} Limitation of how much issues to fetch
            script_starting_time: {int} Script starting time
            execution_deadline: {int} Execution deadline
            kwargs: {Dict[str, Any]} the dictionary that contains all kwargs params
                    specified for filtering, check build_query_string for details.

        Returns:
            [ASMEntity]: list of Issue dataclasses

        """
        page_number = 0
        filtered_issues = []

        names = kwargs.get("entity_name", [])
        query_string = build_asm_entity_query_string(
            names=names,
            critical_or_high=kwargs.get("critical_or_high"),
            tags=kwargs.get("tags"),
            minimum_vulns=kwargs.get("vuln_count_gte"),
            minimum_issues=kwargs.get("issue_count_gte"),
        )

        url = get_full_url(
            api_root=self.api_root,
            endpoint_id="search_entities",
            query_string=query_string,
        )

        while True:
            if is_approaching_timeout(script_starting_time, execution_deadline):
                self.logger.info("Timeout is approaching. Action will gracefully exit")
                break

            issues, more_pages = self.search_issues_by_page(
                url=url,
                page_number=page_number,
                parser_method=parser.build_asm_entity_objects,
            )
            filtered_issues.extend(issues)

            if len(filtered_issues) >= limit or not more_pages:
                self.logger.info(
                    f"Reached Maximum count of entities to process of {limit} !"
                )
                break

            page_number += 1

        return filtered_issues[:limit]

    def search_issues_by_page(self, url, page_number, parser_method, limit=None):
        """Searches issues that match query string criteria and returns
        specified page results.
        If the provided limit is less than the default page size,
        the default page size will be used instead.

        Params:
            url: {str} the url to fetch.
            page_number: {str} result page_number to fetch.

        Returns:
            Tuple(Hits {List[obj]}, More {bool})

        """
        if self.project_id:
            self.session.headers.update({"PROJECT-ID": self.project_id})
        page_size = max(DEFAULT_PAGE_SIZE, limit) if limit else DEFAULT_PAGE_SIZE
        params = {"page_size": page_size, "page": page_number}

        response = self.session.get(url, params=params)
        validate_response(response)

        response_json = response.json()
        if response_json["success"]:
            return (
                parser_method(response_json["result"]["hits"]),
                response_json["result"]["more"],
            )

        self.logger.error(f"Failed to fetch data - {response_json['message']}")

        return [], False

    def update_issue(self, issue_id: str, status: str) -> dict:
        """Updates issue in ASM with new status.

        Args:
            issue_id: issue id to update in ASM
            status: new issue status

        Returns:
            the updated issue data

        """
        data = {"status": status}
        url = get_full_url(
            api_root=self.api_root, endpoint_id="update_issue", issue_id=issue_id
        )

        response = self.session.post(url, json=data)
        validate_response(response)
        response_json = response.json()

        if not response_json["success"]:
            raise GoogleThreatIntelligenceExceptions(response_json["message"])

        return response_json

    def get_issues(
        self,
        severity: int,
        limit: int,
        last_seen_after: str,
        status_filter: list[str],
        siemplify: SiemplifyConnectorExecution = None,
        existing_ids: list[str] | None = None,
    ) -> list[ASMIssue]:
        """Fetches a list of issues from ASM.

        Args:
            severity: lowest severity to fetch
            limit: max issues to fetch
            last_seen_after: reference time to fetch events
            status_filter (list[str]): Statuses to filter by.
            siemplify (SiemplifyConnectorExecution): SiemplifyConnectorExecution object
            existing_ids (list[str] | None): list of ids to filter

        Returns:
            List of ASMIssue objects

        """
        last_seen_before = adjust_time(last_seen_after)
        last_seen_before_str = last_seen_before.strftime("%Y-%m-%dT%H:%M:%SZ")

        page_number = 0
        filtered_issues = []
        query_string = build_query_for_single_params(
            last_seen_after=last_seen_after,
            last_seen_before=last_seen_before_str,
            severity_lte=severity,
        )
        status_query_list = (f"status_new:{status.lower()}" for status in status_filter)
        query_string += " ".join(status_query_list)

        url = get_full_url(
            api_root=self.api_root,
            endpoint_id="search_issues",
            query_string=query_string,
        )

        while True:
            issues, more_pages = self.search_issues_by_page(
                url=url,
                page_number=page_number,
                parser_method=parser.build_issue_objects,
                limit=limit,
            )

            filtered_issues.extend(
                filter_old_alerts(
                    siemplify,
                    alerts=issues,
                    existing_ids=set(existing_ids) if existing_ids else [],
                    id_key="issue_id",
                )
            )
            if not more_pages:
                break
            page_number += 1

        return sorted(filtered_issues, key=lambda alert: alert.last_seen_ms)[:limit]

    def get_issue_details(self, issue_id: str) -> data_models.ASMIssue:
        """Fetches details of a given issue id

        Args:
            issue_id: issue id to fetch details of

        Returns:
            datamodels.ASMIssue object

        """
        if self.project_id:
            self.session.headers.update({"PROJECT-ID": self.project_id})
        url = get_full_url(
            api_root=self.api_root, endpoint_id="get_issue_details", issue_id=issue_id
        )
        response = self.session.get(url)
        validate_response(response)

        response_json = response.json()
        if not response_json["success"]:
            raise GoogleThreatIntelligenceExceptions(
                f"Failed to fetch details of issue "
                f"{issue_id} - {response_json['message']}"
            )

        return parser.build_asm_issue_object(response_json.get("result", {}))

    def get_related_iocs(self, ioc_type, identifier, relationship, limit):
        """Fetches related iocs for entity
        Args:
            ioc_type: entity type
            identifier: entity identifier
            relationship: entity relationship
            limit: max iocs to fetch
        Returns:
            [RelatedIOC]: list of DTMAlert RelatedIOC
        """
        endpoint_id = (
            "get_iocs_for_threat_actors"
            if ioc_type == "collections"
            else "get_related_iocs"
        )

        url = get_full_url(
            api_root=self.api_root,
            endpoint_id=endpoint_id,
            type=ioc_type,
            id=identifier,
            relationship=relationship,
        )
        return self.paginate_results(
            url,
            limit or ITEMS_PER_PAGE,
            "build_related_ioc_objects",
        )

    def get_threat_actor(self, name: str) -> list[ThreatActor]:
        """Fetches a list of Threat Actors.

        Args:
            name: threat actor name

        Returns:
            List of ThreatActor objects

        """
        url = get_full_url(
            api_root=self.api_root,
            endpoint_id="get_threat_actor",
        )
        params = {
            "filter": f'collection_type:threat-actor name: "{name}"',
        }

        return self.paginate_results(
            url,
            ITEMS_PER_PAGE,
            "build_threat_actor_objects",
            params=params,
        )

    def retrieve_ioc(
        self, ioc: str, ioc_type: str, is_private_submission=False
    ) -> requests.Response:
        """Retrieves information about an IOC from the appropriate endpoint."""
        request_endpoint = "get_ioc_details"
        if is_private_submission:
            request_endpoint = "private_get_ioc_details"

        url = get_full_url(
            api_root=self.api_root,
            endpoint_id=request_endpoint,
            ioc_type=ioc_type,
            ioc=ioc,
        )
        response = self.session.get(url)
        return response

    def get_ioc_details(
        self,
        ioc: str,
        ioc_type: str,
        show_entity_status: bool = False,
        is_private_submission=False,
    ):
        """Retrieves detailed information about a specific IOC.

        Args:
            ioc (str): The value of the IOC.
            ioc_type (str): The type of the IOC .
            show_entity_status (bool, optional): Return error message for entity
            is_private_submission (bool): Whether the file submission is private.

        Returns:
            IOC: IOC object

        """
        response = self.retrieve_ioc(
            ioc=ioc,
            ioc_type=ioc_type,
            is_private_submission=is_private_submission,
        )
        validate_response(response, show_entity_status=show_entity_status)
        return parser.build_ioc_object(response.json(), ioc_type=ioc_type, ioc=ioc)

    def check_file_exists_by_hash(
        self,
        file_hash: str,
        ioc_type: str,
        is_private_submission=False,
    ):
        """Check if a file with the given hash exists in the system.

        Args:
            file_hash: Hash of the file(e.g. SHA-256)
            ioc_type: Type of the IOC.
            is_private_submission: Whether to check in private submissions.

        Returns:
            bool: True if file exists (status 200), False otherwise.s

        """
        response = self.retrieve_ioc(
            ioc=file_hash,
            ioc_type=ioc_type,
            is_private_submission=is_private_submission,
        )
        return response.status_code == 200

    def get_comments(
        self,
        ioc_type: str,
        ioc: str,
        limit: int,
        show_entity_status: bool = False,
    ):
        """Retrieves comments for a given entity.

        Args:
            ioc_type: The type of indicator of compromise (IOC).
            ioc: The indicator of compromise value.
            limit: The maximum number of comments to return.
            show_entity_status: Whether to include error messages related to
                                the entity's status.

        Returns:
            A list of Comment instances.

        """
        url = get_full_url(
            api_root=self.api_root,
            endpoint_id="get_comments",
            ioc_type=ioc_type,
            ioc=ioc,
        )
        return self.paginate_results(
            url=url,
            limit=limit,
            parser_method="build_comment_objects",
            show_entity_status=show_entity_status,
        )

    def get_vulnerability_details(
        self,
        entity_identifier: str,
    ) -> data_models.Vulnerability:
        """Get Actor details
        Args:
            entity_identifier: The identifier
        Returns:
            datamodels.Vulnerability object
        """
        url = get_full_url(
            api_root=self.api_root,
            endpoint_id="vulnerability_details",
            vulnerability=entity_identifier,
        )
        response = self.session.get(
            url,
            params={"rating_types": "predicted,analyst,unrated"},
        )
        validate_response(response)

        return parser.build_vulnerability_obj(response.json())

    def get_widget(self, entity: str, show_entity_status: bool = False):
        """Get Widget for given entity
        Args:
            entity {str}: entity identifier
            show_entity_status {bool}:  Return error message for entity
        Return
            {str}: widget for given entity
        """
        url = get_full_url(self.api_root, "get_widget")
        params = {"query": entity, **WIDGET_CHRONICLE_THEME_COLORS}

        response = self.session.get(url, params=params)
        validate_response(response, show_entity_status=show_entity_status)
        response_json = response.json()

        widget_link = response_json.get("data", {}).get("url")
        widget_link += "/summary"
        if response_json.get("data", {}).get("found"):
            return widget_link, WidgetComponentPreprocessor(
                widget_link, self.session
            ).prepare_cached_widget()
        return None, None

    def get_sandbox_data(
        self,
        file_hash: str,
        sandbox: str,
        show_entity_status: bool = False,
    ):
        """Get sandbox data
        Args:
            hash {str}:  hash
            sandbox {str}:  sandbox name
            show_entity_status {bool}: {bool} return error message for entity
        Return
            Sandbox: Sandbox dataclasses
        """
        identifier = prepare_hash_identifier(file_hash)
        url = get_full_url(
            api_root=self.api_root,
            endpoint_id="get_sandbox_data",
            hash=identifier,
            sandbox=sandbox,
        )
        response = self.session.get(url)
        validate_response(response, show_entity_status=show_entity_status)
        return parser.build_sandbox_object(response.json())

    def get_mitre(
        self,
        file_hash: str,
        show_entity_status: bool = False,
        lowest_mitre_severity: str = "INFO",
    ):
        """Get Mitre for given entity
        Args:
            file_hash {str}:  hash
            show_entity_status {bool}: {bool} Return error message for entity
            lowest_mitre_severity {str}: {str} lowest mitre severity
        Return
            Mitre: Mitre dataclasses
        """
        identifier = prepare_hash_identifier(file_hash)
        url = get_full_url(
            api_root=self.api_root,
            endpoint_id="get_mitre",
            entity=identifier,
        )
        response = self.session.get(url)
        validate_response(response, show_entity_status=show_entity_status)
        mitre_data = fetch_mitre_data(response.json(), lowest_mitre_severity)
        return parser.build_mitre_object(mitre_data)

    def submit_url_for_analysis(
        self,
        url: str,
        show_entity_status: bool = False,
        private_submission: bool = False,
    ) -> str:
        """Submits a URL for analysis.

        Args:
            url: The URL to analyze.
            show_entity_status: Whether to return an error message for the entity.
            private_submission: if submitted url is private

        Returns:
            The analysis ID.

        """
        endpoint_id = "urls"
        if private_submission:
            endpoint_id = "private_urls"
        response = self.session.post(
            get_full_url(
                api_root=self.api_root,
                endpoint_id=endpoint_id,
            ),
            data={"url": url},
        )
        validate_response(response, show_entity_status=show_entity_status)
        return parser.get_analysis_id(response.json())

    @staticmethod
    def get_file_content(file_path: str) -> bytes | None:
        """Reads and returns the binary content of the file.

        Args:
            file_path: Path to the file.

        Returns:
            bytes: File content in binary mode.

        Raises:
            FileSubmissionError: If the file cannot be opened or read.

        """
        try:
            with open(file_path, "rb") as file_handler:
                return file_handler.read()
        except OSError as e:
            raise FileSubmissionError(f"Failed to open file '{file_path}': {e}") from e

    def submit_file_for_analysis(
        self,
        url: str,
        file_bytes: bytes,
        zip_password: str | None = None,
    ) -> str:
        """Get File Analysis ID

        Args:
            url: The url for sending the request.
            file_bytes: byte representation of a file
            zip_password:Password for the ZIP file, if required.

        Returns:
            The analysis ID.

        """
        files = {"file": file_bytes}
        data = {"password": zip_password} if zip_password else None

        response = self.session.post(url, files=files, data=data)
        validate_response(response=response, show_entity_status=True)

        return parser.get_analysis_id(response.json())

    def get_upload_url(self, is_private_submission: bool = False):
        """Retrieve the URL for uploading file.

        Args:
            is_private_submission: Whether the file submission is private.

        Result:
            The parser upload URL from the API response.

        """
        complete_url = get_full_url(
            api_root=self.api_root, endpoint_id="file-upload-url"
        )

        if is_private_submission:
            complete_url = get_full_url(
                api_root=self.api_root, endpoint_id="file-upload-url-private"
            )
        response = self.session.get(complete_url)
        validate_response(response=response, show_entity_status=True)
        return parser.get_upload_url(response.json())

    def submit_hash_for_analysis(
        self,
        file_hash: data_models.Hash,
        show_entity_status: bool = False,
    ) -> str:
        """Submits a hash for analysis.

        Args:
            file_hash: The hash to analyze.
            show_entity_status: Whether to return an error message for the entity.

        Returns:
            The analysis ID.

        """
        identifier = prepare_hash_identifier(file_hash)
        url = get_full_url(
            api_root=self.api_root,
            endpoint_id="submit_hash_analysis",
            hash=identifier,
        )
        response = self.session.post(url)
        validate_response(response, show_entity_status=show_entity_status)
        return parser.get_analysis_id(response.json())

    def download_file_from_url(self, url: str) -> bytes:
        """Download a file from url."""
        response = self.session.get(url=url)
        validate_response(response)
        return response.content

    def get_ai_summary(self, file_hash: str):
        """Get AI Summary for given entity.

        Args:
            file_hash: File hash

        Returns:
            AISummary: instance

        """
        request_url = get_full_url(
            api_root=self.api_root,
            endpoint_id="generate-ai-summary",
            hash=file_hash,
        )
        response = self.session.get(request_url)
        validate_response(response)

        return parser.get_ai_generated_summary(response.json())

    def check_analysis_status(
        self,
        analysis_id: str,
        show_entity_status: bool = False,
        is_private_submission: bool = False,
        get_file_hash: bool = False,
    ):
        """Checks the status of an analysis.

        Args:
            analysis_id (str): The ID of the analysis.
            show_entity_status (bool): Whether to return error messages related to
                                the entity's status.
            is_private_submission (bool): Whether the file submission is private.
            get_file_hash (bool): Whether to include the file hash in the request.

        Returns:
            str:The analysis ID.

        """
        url = get_full_url(
            api_root=self.api_root,
            endpoint_id="analyses",
            analysis_id=analysis_id,
        )
        if is_private_submission:
            url = get_full_url(
                api_root=self.api_root,
                endpoint_id="analyses-private",
                analysis_id=analysis_id,
            )

        response = self.session.get(url)
        validate_response(response, show_entity_status=show_entity_status)

        result = response.json()
        if get_file_hash:
            return parser.get_analysis_status(
                raw_data=result
            ), parser.get_hash_from_file_analysis(raw_data=result)

        return parser.get_analysis_status(raw_data=result)

    def search_iocs(self, query: str, limit: int) -> list[IOCSearchResult]:
        """Search IOCs.

        Args:
            query: search query to execute.
            limit: maximum amount of results to return.

        Returns:
            list[IOCSearchResult]: list of IOCSearchResult objects.

        """
        url = get_full_url(self.api_root, "search_ioc")
        params = {
            "query": query,
            "limit": limit,
        }

        response = self.session.get(url, params=params)
        validate_response(response)
        return parser.build_ioc_search_result_objects(response.json())

    def get_notifications(
        self,
        timestamp: int,
        limit: int,
        siemplify: SiemplifyConnectorExecution = None,
        existing_ids: list[str] | None = None,
    ):
        """Get notifications

        Args:
            timestamp (int): timestamp filter to get notifications from
            limit (int): limit for results
            siemplify (SiemplifyConnectorExecution): SiemplifyConnectorExecution object
            existing_ids (list[str] | None): list of ids to filter

        Returns:
            list[Notification]: list of Notification objects

        """
        url = get_full_url(self.api_root, "get_notifications", timestamp=timestamp)

        params = {
            "limit": MAX_NOTIFICATIONS_LIMIT,
            "order": "date+",
            "filter": f"date:{timestamp}+",
        }

        return self._paginate_results_by_next_page_link(
            full_url=url,
            limit=limit,
            siemplify=siemplify,
            parser_method="build_notification_objects",
            existing_ids=existing_ids,
            params=params,
        )

    def _paginate_results_by_next_page_link(
        self,
        full_url: str,
        limit: int,
        siemplify: SiemplifyConnectorExecution,
        parser_method: str,
        existing_ids: list[str] | None = None,
        params: dict | None = None,
    ) -> list[Any]:
        """Paginate the results

        Args:
            full_url (str): full url to send request to
            limit (int): limit for the results to fetch
            siemplify (SiemplifyConnectorExecution): SiemplifyConnectorExecution object
            parser_method (str): parser method to convert json to dataclass
            existing_ids (list[str] | None): list of ids to filter
            params (dict | None): request params dict

        Returns:
            list[Any]: list of any dataclasses

        """
        results, next_page_link, response = [], None, None
        existing_ids_set = set(existing_ids) if existing_ids else set()

        while True:
            if response:
                if not next_page_link or (limit is not None and len(results) >= limit):
                    break

                full_url = next_page_link
                params = {}

            response = self.session.get(full_url, params=params)
            validate_response(response)
            next_page_link = response.json().get("links", {}).get("next", "")
            alerts = getattr(parser, parser_method)(response.json())
            filtered_alerts = [
                alert
                for alert in alerts
                if not hasattr(alert, "pass_filter") or alert.pass_filter()
            ]

            results.extend(
                filter_old_alerts(
                    siemplify,
                    alerts=filtered_alerts,
                    existing_ids=existing_ids_set,
                    id_key="alert_id",
                )
            )

        return results[:limit] if limit else results

    def get_file(self, entity_hash: str) -> str:
        """Downloads a file based on its hash.

        Args:
            entity_hash (str): The hash of the file to download.

        Returns:
            str: The text content of the downloaded file.

        """
        url = get_full_url(self.api_root, "get_file", entity_hash=entity_hash)
        response = self.session.get(url)
        validate_response(response)
        return response.text
