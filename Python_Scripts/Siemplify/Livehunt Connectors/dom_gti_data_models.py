from __future__ import annotations

import dataclasses
from typing import Any, Optional

# [MODIFIED] - Imports updated to use new dom_gti modules
from dom_gti_constants import (
    CASE_WALL_LINK,
    COLLECTIONS_CASE_WALL_LINK,
    DATA_ENRICHMENT_PREFIX,
    NOTIFICATION_ALLOWED_VERDICTS,
    PRIVATE_CASE_WALL_LINK,
    SEVERITY_GTI_MAPPING,
)
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import convert_string_to_unix_time
from TIPCommon.transformation import add_prefix_to_dict, dict_to_flat
from TIPCommon.types import SingleJson


@dataclasses.dataclass(frozen=True)
class BaseModel:
    raw_data: SingleJson

    def to_json(self) -> SingleJson:
        return dataclasses.asdict(self)

    def to_flat(self) -> dict[str, Any]:
        return dict_to_flat(self.to_json()["raw_data"])


@dataclasses.dataclass(frozen=True)
class BaseObject(BaseModel):
    """Class to create data model for Base Object"""

    @classmethod
    def from_json(cls, raw_data: SingleJson) -> BaseObject:
        """Create a BaseObject object from JSON data.

        Args:
            raw_data (SingleJson): raw data to create BaseObject from

        Returns:
            BaseObject: Base object

        """
        return cls(raw_data=raw_data)


@dataclasses.dataclass(frozen=True)
class GraphDetails(BaseModel):
    """Class to create data model for GraphDetails object"""

    graph_id: str
    links: [Link]

    @classmethod
    def from_json(cls, raw_data: dict, links: [Link]) -> GraphDetails:
        """Create GraphDetails object from raw json data.

        Args:
            raw_data (dict): raw data of graph details
            links ([Link]): list of Link objects

        Returns:
            GraphDetails: GraphDetails object

        """
        return cls(
            raw_data=raw_data,
            graph_id=raw_data.get("id"),
            links=links,
        )


@dataclasses.dataclass(frozen=True)
class Link(BaseModel):
    """Class to create data model for Link object"""

    source: str
    target: str
    connection_type: str

    @classmethod
    def from_json(cls, raw_data: dict) -> Link:
        """Create Link object from raw json data.

        Args:
            raw_data (dict): raw data of link

        Returns:
            Link: Link object

        """
        return cls(
            raw_data=raw_data,
            source=raw_data.get("source"),
            target=raw_data.get("target"),
            connection_type=raw_data.get("connection_type"),
        )

    def to_csv(self):
        return {
            "Source": self.source,
            "Target": self.target,
            "Connection Type": self.connection_type,
        }


@dataclasses.dataclass(frozen=True)
class Graph(BaseModel):
    """Class to create data model for Graph object"""

    @classmethod
    def from_json(cls, raw_data: dict) -> Graph:
        """Create Graph object from raw json data.

        Args:
            raw_data (dict): raw data of graph

        Returns:
            Graph: Graph object

        """
        return cls(raw_data=raw_data)

    def to_json_shorten(self) -> SingleJson:
        """Prepare shorten json data from raw data

        Returns:
            SingleJson: SingleJson data

        """
        return {
            "attributes": self.raw_data.get("attributes", {}),
            "id": self.raw_data.get("id"),
        }


@dataclasses.dataclass(frozen=True)
class DTMAlert(BaseModel):
    """Class to create data model for DTM Alert object"""

    raw_flat_data: dict
    alert_id: str
    status: str
    title: str
    created_at: str
    severity: int
    alert_type: str
    alert_summary: str
    aggregated_under_id: str
    monitor_name: str
    topics: [Topic]

    @classmethod
    def from_json(cls, raw_data: dict, topics: [Topic]) -> DTMAlert:
        """Create DTMAlert object from raw json data.

        Args:
            raw_data (dict): raw data of graph
            topics ([Topic]): list of Topic objects

        Returns:
            DTMAlert: DTMAlert object

        """
        return cls(
            raw_data=raw_data,
            raw_flat_data=dict_to_flat(raw_data),
            alert_id=raw_data.get("id"),
            status=raw_data.get("status"),
            title=raw_data.get("title"),
            created_at=convert_string_to_unix_time(raw_data.get("created_at")),
            severity=raw_data.get("severity"),
            alert_type=raw_data.get("alert_type"),
            alert_summary=raw_data.get("alert_summary"),
            aggregated_under_id=raw_data.get("aggregated_under_id"),
            monitor_name=raw_data.get("monitor_name"),
            topics=topics,
        )


@dataclasses.dataclass(frozen=True)
class Topic(BaseModel):
    """Class to create data model for Topic object"""

    @classmethod
    def from_json(cls, raw_data: dict) -> Topic:
        """Create Topic object from raw json data.

        Args:
            raw_data (dict): raw data of alert

        Returns:
            Topic: Topic object

        """
        return cls(raw_data=raw_data)


@dataclasses.dataclass(frozen=True)
class ASMEntity(BaseModel):
    """Class to create data model for ASMEntity object"""

    name: str

    @classmethod
    def from_json(cls, raw_data: dict) -> ASMEntity:
        """Create ASMEntity object from raw json data.

        Args:
            raw_data (dict): raw data of alert

        Returns:
            ASMEntity: ASMEntity object

        """
        return cls(raw_data=raw_data, name=raw_data.get("name"))


@dataclasses.dataclass(frozen=True)
class ASMIssue(BaseModel):
    """Class to create data model for ASM Issues object"""

    alert_id: str
    raw_flat_data: dict
    issue_id: str
    pretty_name: str
    proof: str
    description: str
    severity: int
    category: str
    first_seen: str
    last_seen: str
    last_seen_ms: str
    first_seen_ms: str

    @staticmethod
    def extract_category(raw_data: dict) -> Optional[str]:
        """Extract category from the raw data."""
        return raw_data.get("category") or raw_data.get("summary", {}).get("category")

    @classmethod
    def from_json(cls, raw_data: dict) -> ASMIssue:
        """Create ASMIssues object from raw json data.

        Args:
            raw_data (dict): raw data of issue
        Returns:
            ASMIssues: ASMIssues object

        """
        return cls(
            raw_data=raw_data,
            alert_id=raw_data.get("id") or raw_data.get("uid"),
            raw_flat_data=dict_to_flat(raw_data),
            issue_id=raw_data.get("id") or raw_data.get("uid"),
            pretty_name=raw_data.get("pretty_name"),
            proof=raw_data.get("details", {}).get("proof"),
            description=raw_data.get("description"),
            severity=raw_data.get("severity"),
            category=cls.extract_category(raw_data),
            first_seen=raw_data.get("first_seen"),
            last_seen=raw_data.get("last_seen"),
            last_seen_ms=convert_string_to_unix_time(raw_data.get("last_seen")),
            first_seen_ms=convert_string_to_unix_time(raw_data.get("first_seen")),
        )


@dataclasses.dataclass(frozen=True)
class RelatedIOC(BaseModel):
    """Class to create data model for RelatedIOC object"""

    id: str
    type: str
    url: str

    @classmethod
    def from_json(cls, raw_data: dict) -> RelatedIOC:
        """Create RelatedIOC object from raw json data.

        Args:
            raw_data (dict): raw data of alert

        Returns:
            Issue: RelatedIOC object

        """
        return cls(
            raw_data=raw_data,
            id=raw_data.get("id"),
            type=raw_data.get("type"),
            url=raw_data.get("context_attributes", {}).get("url", ""),
        )


@dataclasses.dataclass(frozen=True)
class IOC(BaseModel):
    last_analysis_results: dict

    def to_json_shorten(
        self,
        entity_type: str | None = None,
        comments: list[Comment] | None = None,
        widget_link: str | None = None,
        cached_html_widget: str | None = None,
        sandboxes_data: dict[str, Sandbox] | None = None,
        mitre_response: Mitre | None = None,
        ai_summary_response=None,
    ) -> SingleJson:
        """Prepare shorten json data from raw data

        Returns:
            SingleJson: SingleJson data

        """
        if comments:
            self.raw_data["comments"] = [comment.raw_data for comment in comments]
        if sandboxes_data:
            self.raw_data["sandboxes_data"] = {
                key: value.raw_data if value else None
                for key, value in sandboxes_data.items()
            }
        if mitre_response:
            if mitre_response.mitre_tactics:
                self.raw_data["related_mitre_tactics"] = mitre_response.mitre_tactics
            if mitre_response.mitre_techniques:
                self.raw_data["related_mitre_techniques"] = (
                    mitre_response.mitre_techniques
                )

        if ai_summary_response:
            self.raw_data["generated_ai_summary"] = ai_summary_response
        if widget_link:
            self.raw_data["widget_link"] = widget_link
        if cached_html_widget:
            self.raw_data["widget_html"] = cached_html_widget
        if entity_type in [EntityTypes.THREATACTOR, EntityTypes.CVE]:
            attributes = self.raw_data.get("attributes", {})
            if entity_type == EntityTypes.THREATACTOR:
                if "aggregations" in attributes:
                    attributes.pop("aggregations")
                attributes["threat_actor_id"] = self.raw_data.get("id", "")
            return attributes

        return self.raw_data

    def get_enrichment_data(self):
        raise NotImplementedError

    def to_enrichment_data(self, widget_link=None):
        """Returns cleaned and prefixed enrichment data,
        optionally with a widget link.
        """
        clean_enrichment_data = {
            k: v for k, v in self.get_enrichment_data().items() if v
        }

        if widget_link:
            clean_enrichment_data["widget_link"] = widget_link

        return add_prefix_to_dict(clean_enrichment_data, DATA_ENRICHMENT_PREFIX)

    def to_csv(self) -> list[dict]:
        """Converts last analysis results to a list of dictionaries s
           uitable for CSV export.

        Transforms the 'last_analysis_results' dictionary into a list of dictionaries,
        where each dictionary represents an engine's analysis results with keys
        "Name", "Category", "Method", and "Result".

        Returns:
            list: A list of dictionaries, each representing an engine's analysis
                  results.

        """
        engine_csvs = []
        for key, engine in self.last_analysis_results.items():
            engine_csvs.append({
                "Name": key,
                "Category": engine.get("category", ""),
                "Method": engine.get("method", ""),
                "Result": engine.get("result", ""),
            })

        return engine_csvs


@dataclasses.dataclass(frozen=True)
class ThreatActor(IOC):
    """Class to create data model for RelatedIOC object"""

    id: str
    type: str
    name: str
    origin: str
    motivations: dict
    aliases: list
    industries: list
    malware: list
    source_region: list
    target_region: list
    description: str
    last_activity_time: str
    report_link: str

    @classmethod
    def from_json(cls, raw_data: dict) -> ThreatActor:
        """Create ThreatActor object from raw json data.

        Args:
            raw_data (dict): raw data

        Returns:
            ThreatActor: ThreatActor object

        """
        return cls(
            raw_data=raw_data,
            last_analysis_results=raw_data.get("attributes", {}).get(
                "last_analysis_results", {}
            ),
            id=raw_data.get("id"),
            type=raw_data.get("type"),
            name=raw_data.get("attributes", {}).get("name", ""),
            origin=raw_data.get("attributes", {}).get("origin", ""),
            motivations=raw_data.get("attributes", {}).get("motivations", {}),
            aliases=raw_data.get("attributes", {}).get("alt_names_details", []),
            industries=raw_data.get("attributes", {}).get("targeted_industries", []),
            malware=raw_data.get("attributes", {}).get("malware", []),
            source_region=raw_data.get("attributes", {}).get(
                "source_regions_hierarchy", []
            ),
            target_region=raw_data.get("attributes", {}).get(
                "targeted_regions_hierarchy", []
            ),
            description=raw_data.get("attributes", {}).get("description", ""),
            last_activity_time=raw_data.get("attributes", {}).get(
                "last_activity_time", ""
            ),
            report_link=COLLECTIONS_CASE_WALL_LINK.format(ioc=raw_data.get("id")),
        )

    def get_enrichment_data(self):
        enrichment_data = {
            "motivations": ", ".join([
                motivation.get("value", "")
                for motivation in self.motivations
                if motivation.get("value") is not None
            ]),
            "aliases": ", ".join([
                alias.get("value", "")
                for alias in self.aliases
                if alias.get("value") is not None
            ]),
            "industries": ", ".join(self.industries),
            "malware": ", ".join([
                malware.get("name", "")
                for malware in self.malware
                if malware.get("name") is not None
            ]),
            "source_region": ", ".join([
                source.get("country", "")
                for source in self.source_region
                if source.get("country") is not None
            ]),
            "target_region": ", ".join([
                target.get("country", "")
                for target in self.target_region
                if target.get("country") is not None
            ]),
            "origin": self.origin,
            "description": self.description,
            "last_activity_time": self.last_activity_time,
            "report_link": self.report_link,
        }

        return enrichment_data


@dataclasses.dataclass(frozen=True)
class IP(IOC):
    """Class to create data model for IP object"""

    ioc_type: str
    ioc: str
    entity_id: str
    as_owner: str
    asn: str
    continent: str
    country: str
    last_analysis_stats: dict
    harmless: int
    malicious: int
    suspicious: int
    undetected: int
    not_after: str
    not_before: str
    reputation: int
    tags: list
    total_votes_harmless: int
    total_votes_malicious: int
    report_link: str
    threat_score: int
    severity: str
    normalised_categories: list
    verdict: str
    description: str

    @classmethod
    def from_json(cls, raw_data: dict, ioc_type: str, ioc: str) -> IP:
        """Create IP object from raw json data.

        Args:
            raw_data (dict): raw data of IP
            ioc_type (str): ioc type
            ioc (str): ioc identifier

        Returns:
            IP: IP object

        """
        return cls(
            raw_data=raw_data,
            last_analysis_results=raw_data.get("attributes", {}).get(
                "last_analysis_results", {}
            ),
            ioc_type=ioc_type,
            ioc=ioc,
            entity_id=raw_data.get("id", ""),
            as_owner=raw_data.get("attributes", {}).get("as_owner", ""),
            asn=raw_data.get("attributes", {}).get("asn", ""),
            continent=raw_data.get("attributes", {}).get("continent", ""),
            country=raw_data.get("attributes", {}).get("country", ""),
            last_analysis_stats=raw_data.get("attributes", {}).get(
                "last_analysis_stats", {}
            ),
            harmless=raw_data.get("attributes", {})
            .get("last_analysis_stats", {})
            .get("harmless", 0),
            malicious=raw_data.get("attributes", {})
            .get("last_analysis_stats", {})
            .get("malicious", 0),
            suspicious=raw_data.get("attributes", {})
            .get("last_analysis_stats", {})
            .get("suspicious", 0),
            undetected=raw_data.get("attributes", {})
            .get("last_analysis_stats", {})
            .get("undetected", 0),
            not_after=raw_data.get("attributes", {})
            .get("last_https_certificate", {})
            .get("validity", {})
            .get("not_after", ""),
            not_before=raw_data.get("attributes", {})
            .get("last_https_certificate", {})
            .get("validity", {})
            .get("not_before", ""),
            reputation=raw_data.get("attributes", {}).get("reputation", 0),
            tags=raw_data.get("attributes", {}).get("tags", []),
            total_votes_harmless=raw_data.get("attributes", {})
            .get("total_votes", {})
            .get("harmless", 0),
            total_votes_malicious=raw_data.get("attributes", {})
            .get("total_votes", {})
            .get("malicious", 0),
            report_link=CASE_WALL_LINK.format(entity_type=ioc_type, entity=ioc),
            threat_score=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("threat_score", {})
            .get("value", 0),
            severity=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("severity", {})
            .get("value", ""),
            normalised_categories=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("contributing_factors", {})
            .get("normalised_categories", []),
            verdict=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("verdict", {})
            .get("value", ""),
            description=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("description", ""),
        )

    def get_enrichment_data(self):
        enrichment_data = {
            "id": self.entity_id,
            "owner": self.as_owner,
            "asn": self.asn,
            "continent": self.continent,
            "country": self.country,
            "harmless_count": self.harmless,
            "malicious_count": self.malicious,
            "suspicious_count": self.suspicious,
            "undetected_count": self.undetected,
            "certificate_valid_not_after": self.not_after,
            "certificate_valid_not_before": self.not_before,
            "reputation": self.reputation,
            "tags": ", ".join(self.tags),
            "malicious_vote_count": self.total_votes_malicious,
            "harmless_vote_count": self.total_votes_harmless,
            "report_link": self.report_link,
            "threat_score": self.threat_score,
            "severity": self.severity,
            "normalised_categories": ", ".join(self.normalised_categories),
            "verdict": self.verdict,
            "description": self.description,
        }

        return enrichment_data


@dataclasses.dataclass(frozen=True)
class URL(IOC):
    """Class to create data model for URL object"""

    ioc_type: str
    ioc: str
    entity_id: str
    title: str
    categories: dict
    last_http_response_code: str
    last_http_response_content_length: str
    threat_names: list
    last_analysis_stats: dict
    harmless: int
    malicious: int
    suspicious: int
    undetected: int
    reputation: int
    tags: list
    total_votes_harmless: int
    total_votes_malicious: int
    report_link: str
    last_analysis_date: int
    threat_score: int
    severity: str
    normalised_categories: list
    verdict: str
    description: str

    @classmethod
    def from_json(cls, raw_data: dict, ioc_type: str, ioc: str) -> URL:
        """Create URL object from raw json data.

        Args:
            raw_data (dict): raw data of URL
            ioc_type (str): ioc type
            ioc (str): ioc identifier

        Returns:
            URL: URL object

        """
        return cls(
            raw_data=raw_data,
            last_analysis_results=raw_data.get("attributes", {}).get(
                "last_analysis_results", {}
            ),
            ioc_type=ioc_type,
            ioc=ioc,
            entity_id=raw_data.get("id", ""),
            title=raw_data.get("attributes", {}).get("title", ""),
            categories=raw_data.get("attributes", {}).get("categories", {}),
            last_http_response_code=raw_data.get("attributes", {}).get(
                "last_http_response_code", ""
            ),
            last_http_response_content_length=raw_data.get("attributes", {}).get(
                "last_http_response_content_length", ""
            ),
            threat_names=raw_data.get("attributes", {}).get("threat_names", []),
            last_analysis_stats=raw_data.get("attributes", {}).get(
                "last_analysis_stats", {}
            ),
            harmless=raw_data.get("attributes", {})
            .get("last_analysis_stats", {})
            .get("harmless", 0),
            malicious=raw_data.get("attributes", {})
            .get("last_analysis_stats", {})
            .get("malicious", 0),
            suspicious=raw_data.get("attributes", {})
            .get("last_analysis_stats", {})
            .get("suspicious", 0),
            undetected=raw_data.get("attributes", {})
            .get("last_analysis_stats", {})
            .get("undetected", 0),
            reputation=raw_data.get("attributes", {}).get("reputation", 0),
            tags=raw_data.get("attributes", {}).get("tags", []),
            total_votes_harmless=raw_data.get("attributes", {})
            .get("total_votes", {})
            .get("harmless", 0),
            total_votes_malicious=raw_data.get("attributes", {})
            .get("total_votes", {})
            .get("malicious", 0),
            report_link=CASE_WALL_LINK.format(entity_type=ioc_type, entity=ioc),
            last_analysis_date=raw_data.get("attributes", {}).get(
                "last_analysis_date", 0
            ),
            threat_score=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("threat_score", {})
            .get("value", 0),
            severity=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("severity", {})
            .get("value", ""),
            normalised_categories=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("contributing_factors", {})
            .get("normalised_categories", []),
            verdict=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("verdict", {})
            .get("value", ""),
            description=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("description", ""),
        )

    def get_enrichment_data(self):
        enrichment_data = {
            "id": self.entity_id,
            "title": self.title,
            "last_http_response_code": self.last_http_response_code,
            "last_http_response_content_length": self.last_http_response_content_length,
            "threat_names": ", ".join(self.threat_names),
            "harmless_count": self.harmless,
            "malicious_count": self.malicious,
            "suspicious_count": self.suspicious,
            "undetected_count": self.undetected,
            "reputation": self.reputation,
            "tags": ", ".join(self.tags),
            "malicious_vote_count": self.total_votes_malicious,
            "harmless_vote_count": self.total_votes_harmless,
            "report_link": self.report_link,
            "threat_score": self.threat_score,
            "severity": self.severity,
            "normalised_categories": ", ".join(self.normalised_categories),
            "verdict": self.verdict,
            "description": self.description,
        }
        for key, value in self.categories.items():
            enrichment_data[f"category_{key}"] = value

        return enrichment_data


@dataclasses.dataclass(frozen=True)
class Hash(IOC):
    """Class to create data model for Hash object"""
    raw_data: SingleJson
    last_analysis_results: dict
    ioc_type: str
    ioc: str
    entity_id: str
    magic: str
    md5: str
    sha1: str
    sha256: str
    ssdeep: str
    tlsh: str
    vhash: str
    meaningful_name: str
    names: list
    harmless: int
    malicious: int
    suspicious: int
    undetected: int
    reputation: int
    tags: list
    total_votes_harmless: int
    total_votes_malicious: int
    report_link: str
    private_report_link: str
    exiftool: dict
    threat_score: int
    severity: str
    normalised_categories: list
    verdict: str
    description: str
    last_analysis_date: int

    @classmethod
    def from_json(cls, raw_data: dict, ioc_type: str, ioc: str) -> Hash:
        """Create Hash object from raw json data.

        Args:
            raw_data (dict): raw data of Hash
            ioc_type (str): ioc type
            ioc (str): ioc identifier

        Returns:
            Hash: Hash object

        """
        return cls(
            raw_data=raw_data,
            last_analysis_results=raw_data.get("attributes", {}).get(
                "last_analysis_results", {}
            ),
            ioc_type=ioc_type,
            ioc=ioc,
            entity_id=raw_data.get("id", ""),
            magic=raw_data.get("attributes", {}).get("magic", ""),
            md5=raw_data.get("attributes", {}).get("md5", ""),
            sha1=raw_data.get("attributes", {}).get("sha1", ""),
            sha256=raw_data.get("attributes", {}).get("sha256", ""),
            ssdeep=raw_data.get("attributes", {}).get("ssdeep", ""),
            tlsh=raw_data.get("attributes", {}).get("tlsh", ""),
            vhash=raw_data.get("attributes", {}).get("vhash", ""),
            meaningful_name=raw_data.get("attributes", {}).get("meaningful_name", ""),
            names=raw_data.get("attributes", {}).get("names", []),
            harmless=raw_data.get("attributes", {})
            .get("last_analysis_stats", {})
            .get("harmless", 0),
            malicious=raw_data.get("attributes", {})
            .get("last_analysis_stats", {})
            .get("malicious", 0),
            suspicious=raw_data.get("attributes", {})
            .get("last_analysis_stats", {})
            .get("suspicious", 0),
            undetected=raw_data.get("attributes", {})
            .get("last_analysis_stats", {})
            .get("undetected", 0),
            reputation=raw_data.get("attributes", {}).get("reputation", 0),
            tags=raw_data.get("attributes", {}).get("tags", []),
            total_votes_harmless=raw_data.get("attributes", {})
            .get("total_votes", {})
            .get("harmless", 0),
            total_votes_malicious=raw_data.get("attributes", {})
            .get("total_votes", {})
            .get("malicious", 0),
            report_link=CASE_WALL_LINK.format(entity_type=ioc_type, entity=ioc),
            private_report_link=PRIVATE_CASE_WALL_LINK.format(
                entity_type=ioc_type, entity=ioc
            ),
            exiftool=raw_data.get("attributes", {}).get("exiftool", {}),
            threat_score=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("threat_score", {})
            .get("value", 0),
            severity=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("severity", {})
            .get("value", ""),
            normalised_categories=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("contributing_factors", {})
            .get("normalised_categories", []),
            verdict=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("verdict", {})
            .get("value", ""),
            description=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("description", ""),
            last_analysis_date=raw_data.get("attributes", {}).get(
                "last_analysis_date", 0
            ),
        )

    def get_enrichment_data(self):
        enrichment_data = {
            "id": self.entity_id,
            "magic": self.magic,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "ssdeep": self.ssdeep,
            "tlsh": self.tlsh,
            "vhash": self.vhash,
            "meaningful_name": self.meaningful_name,
            "names": ", ".join(self.names),
            "harmless_count": self.harmless,
            "malicious_count": self.malicious,
            "suspicious_count": self.suspicious,
            "undetected_count": self.undetected,
            "reputation": self.reputation,
            "tags": ", ".join(self.tags),
            "malicious_vote_count": self.total_votes_malicious,
            "harmless_vote_count": self.total_votes_harmless,
            "report_link": self.report_link,
            "threat_score": self.threat_score,
            "severity": self.severity,
            "normalised_categories": ", ".join(self.normalised_categories),
            "verdict": self.verdict,
            "description": self.description,
        }
        enrichment_data.update(self.exiftool)

        return enrichment_data


@dataclasses.dataclass(frozen=True)
class Domain(IOC):
    """Class to create data model for Domain object"""

    ioc_type: str
    ioc: str
    entity_id: str
    tags: list
    categories: dict
    last_analysis_stats: dict
    harmless: int
    malicious: int
    suspicious: int
    undetected: int
    reputation: int
    total_votes_harmless: int
    total_votes_malicious: int
    report_link: str
    threat_score: int
    severity: str
    normalised_categories: list
    verdict: str
    description: str

    @classmethod
    def from_json(cls, raw_data: dict, ioc_type: str, ioc: str) -> Domain:
        """Create Domain object from raw json data.

        Args:
            raw_data (dict): raw data of Domain
            ioc_type (str): ioc type
            ioc (str): ioc identifier

        Returns:
            Domain: Domain object

        """
        return cls(
            raw_data=raw_data,
            last_analysis_results=raw_data.get("attributes", {}).get(
                "last_analysis_results", {}
            ),
            ioc_type=ioc_type,
            ioc=ioc,
            entity_id=raw_data.get("id", ""),
            categories=raw_data.get("attributes", {}).get("categories", {}),
            tags=raw_data.get("attributes", {}).get("tags", []),
            last_analysis_stats=raw_data.get("attributes", {}).get(
                "last_analysis_stats", {}
            ),
            harmless=raw_data.get("attributes", {})
            .get("last_analysis_stats", {})
            .get("harmless", 0),
            malicious=raw_data.get("attributes", {})
            .get("last_analysis_stats", {})
            .get("malicious", 0),
            suspicious=raw_data.get("attributes", {})
            .get("last_analysis_stats", {})
            .get("suspicious", 0),
            undetected=raw_data.get("attributes", {})
            .get("last_analysis_stats", {})
            .get("undetected", 0),
            reputation=raw_data.get("attributes", {}).get("reputation", 0),
            total_votes_harmless=raw_data.get("attributes", {})
            .get("total_votes", {})
            .get("harmless", 0),
            total_votes_malicious=raw_data.get("attributes", {})
            .get("total_votes", {})
            .get("malicious", 0),
            report_link=CASE_WALL_LINK.format(entity_type=ioc_type, entity=ioc),
            threat_score=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("threat_score", {})
            .get("value", 0),
            severity=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("severity", {})
            .get("value", ""),
            normalised_categories=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("contributing_factors", {})
            .get("normalised_categories", []),
            verdict=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("verdict", {})
            .get("value", ""),
            description=raw_data.get("attributes", {})
            .get("gti_assessment", {})
            .get("description", ""),
        )

    def get_enrichment_data(self):
        enrichment_data = {
            "id": self.entity_id,
            "harmless_count": self.harmless,
            "malicious_count": self.malicious,
            "suspicious_count": self.suspicious,
            "undetected_count": self.undetected,
            "reputation": self.reputation,
            "tags": ", ".join(self.tags),
            "malicious_vote_count": self.total_votes_malicious,
            "harmless_vote_count": self.total_votes_harmless,
            "report_link": self.report_link,
            "threat_score": self.threat_score,
            "severity": self.severity,
            "normalised_categories": ", ".join(self.normalised_categories),
            "verdict": self.verdict,
            "description": self.description,
        }
        for key, value in self.categories.items():
            enrichment_data[f"category_{key}"] = value

        return enrichment_data


@dataclasses.dataclass(frozen=True)
class Comment(BaseModel):
    """Class to create data model for Comment object"""

    comment_id: str
    comment: str
    date: str
    abuse_votes: int
    positive_votes: dict
    negative_votes: dict

    @classmethod
    def from_json(cls, raw_data: dict) -> Comment:
        """Create Comment object from raw json data.

        Args:
            raw_data (dict): raw data

        Returns:
            Comment: Comment object

        """
        return cls(
            raw_data=raw_data,
            comment_id=raw_data.get("id", ""),
            comment=raw_data.get("attributes", {}).get("text", ""),
            date=raw_data.get("attributes", {}).get("date", ""),
            abuse_votes=raw_data.get("attributes", {}).get("votes", {}).get("abuse", 0),
            positive_votes=raw_data.get("attributes", {}),
            negative_votes=raw_data.get("attributes", {})
            .get("votes", {})
            .get("negative", 0),
        )

    def to_csv(self):
        return {
            "Date": self.date,
            "Comment": self.comment,
            "Abuse Votes": self.abuse_votes,
            "Negative Votes": self.negative_votes,
            "Positive Votes": self.positive_votes,
            "ID": self.comment_id,
        }


@dataclasses.dataclass(frozen=True)
class Vulnerability(IOC):
    """Class to create data model for Vulnerability object"""

    sources: list
    exploitation_state: str
    date_of_disclosure: str
    vendor_fix_references: list
    exploitation_vectors: list
    description: str
    risk_rating: str
    available_mitigation: list
    exploitation_consequence: str
    report_link: str

    @classmethod
    def from_json(cls, raw_data: dict) -> Vulnerability:
        """Create Vulnerability object from raw json data.

        Args:
            raw_data (dict): raw data of Vulnerability

        Returns:
            Vulnerability: Vulnerability object

        """
        return cls(
            raw_data=raw_data,
            last_analysis_results=raw_data.get("attributes", {}).get(
                "last_analysis_results", {}
            ),
            sources=raw_data.get("attributes", {}).get("sources", []),
            exploitation_state=raw_data.get("attributes", {}).get(
                "exploitation_state", ""
            ),
            date_of_disclosure=raw_data.get("attributes", {}).get(
                "date_of_disclosure", ""
            ),
            vendor_fix_references=raw_data.get("attributes", {}).get(
                "vendor_fix_references", []
            ),
            exploitation_vectors=raw_data.get("attributes", {}).get(
                "exploitation_vectors", []
            ),
            description=raw_data.get("attributes", {}).get("description", ""),
            risk_rating=raw_data.get("attributes", {}).get("risk_rating", ""),
            available_mitigation=raw_data.get("attributes", {}).get(
                "available_mitigation", []
            ),
            exploitation_consequence=raw_data.get("attributes", {}).get(
                "exploitation_consequence", ""
            ),
            report_link=COLLECTIONS_CASE_WALL_LINK.format(
                ioc=raw_data.get("attributes", {}).get("id", "")
            ),
        )

    def get_enrichment_data(self):
        enrichment_data = {
            "sources": ", ".join([
                source.get("name")
                for source in self.sources
                if source.get("name") is not None
            ]),
            "exploitation_state": self.exploitation_state,
            "date_of_disclosure": self.date_of_disclosure,
            "vendor_fix_references": ", ".join([
                vendor.get("url", "")
                for vendor in self.vendor_fix_references
                if vendor.get("url") is not None
            ]),
            "exploitation_vectors": ", ".join(self.exploitation_vectors),
            "description": self.description,
            "risk_rating": self.risk_rating,
            "available_mitigation": ", ".join(self.available_mitigation),
            "exploitation_consequence": self.exploitation_consequence,
            "report_link": self.report_link,
        }

        return enrichment_data


@dataclasses.dataclass(frozen=True)
class Sandbox(BaseModel):
    """Class to create data model for Sandbox object"""

    @classmethod
    def from_json(cls, raw_data: dict) -> Sandbox:
        """Create Sandbox object from raw json data.

        Args:
            raw_data (dict): raw data

        Returns:
            Sandbox: Sandbox object

        """
        return cls(raw_data=raw_data)


@dataclasses.dataclass(frozen=True)
class Mitre(BaseModel):
    """Class to create data model for Sandbox object"""

    status: str
    mitre_tactics: list[dict]
    mitre_techniques: list[dict]

    @classmethod
    def from_json(cls, mitre_data: dict) -> Mitre:
        """Create Mitre object from raw json data.

        Args:
            mitre_data (dict): mitre data

        Returns:
            Mitre: Sandbox object

        """
        return cls(
            raw_data=mitre_data.get("raw_data", {}),
            status=mitre_data.get("status", ""),
            mitre_tactics=mitre_data.get("mitre_tactics", []),
            mitre_techniques=mitre_data.get("mitre_techniques", []),
        )


@dataclasses.dataclass(frozen=True)
class IOCSearchResult(BaseModel):
    """Class to create data model for IOCSearchResult object."""

    @classmethod
    def from_json(cls, raw_data: dict) -> IOCSearchResult:
        """Create IOCSearchResult object from raw json data.

        Args:
            raw_data: Parsed JSON input to construct the object.

        Returns:
            IOCSearchResult: The resulting search result object.

        """
        return cls(raw_data=raw_data)

    def to_json_shorten(self) -> SingleJson:
        return self.raw_data


# @dataclasses.dataclass(frozen=True)
# class Notification(BaseModel):
#     """Class to create data model for Notification object"""
#
#     raw_flat_data: dict
#     alert_id: str
#     meaningful_name: str
#     malicious: int
#     suspicious: int
#     rule_name: str
#     timestamp: int
#     verdict: str
#     severity: str
#
#     @classmethod
#     def from_json(cls, raw_data: dict) -> Notification:
#         """Create Notification object from raw json data
#
#         Args:
#             raw_data (dict): raw data of notification
#
#         Returns:
#             Notification: Notification object
#
#         """
#         context_attributes = raw_data.get("context_attributes", {})
#         attributes = raw_data.get("attributes", {})
#
#         return cls(
#             raw_data=raw_data,
#             raw_flat_data=dict_to_flat(raw_data),
#             alert_id=context_attributes.get("notification_id", ""),
#             meaningful_name=attributes.get("meaningful_name", ""),
#             malicious=attributes.get("last_analysis_stats", {}).get("malicious", 0),
#             suspicious=attributes.get("last_analysis_stats", {}).get("suspicious", 0),
#             rule_name=context_attributes.get("rule_name", ""),
#             timestamp=context_attributes.get("notification_date", 0) * 1000,
#             verdict=(
#                 attributes.get("gti_assessment", {}).get("verdict", {}).get("value")
#             ),
#             severity=(
#                 attributes.get("gti_assessment", {}).get("severity", {}).get("value")
#             ),
#         )
#
#     def get_severity(self):
#         """Get the severity value based on gti_assessment severity values
#
#         Returns:
#             int: severity value
#
#         """
#         return SEVERITY_GTI_MAPPING.get(self.severity, -1)
#
#     def pass_filter(self):
#         """Check if filtering is passed
#
#         Returns:
#             bool: True if filtering is passed, False otherwise
#
#         """
#         return self.verdict in NOTIFICATION_ALLOWED_VERDICTS

# [MODIFIED] - Generalized Notification model for ioc_stream
@dataclasses.dataclass(frozen=True)
class Notification(BaseModel):
    """Class to create data model for Notification object"""

    raw_flat_data: dict
    alert_id: str
    id: str
    type: str
    rule_name: str
    timestamp: int
    verdict: str
    severity: str
    origin: str
    sources: list
    tags: list
    file_size: int
    file_type: str


    @classmethod
    def from_json(cls, raw_data: dict) -> Notification:
        """Create Notification object from raw json data

        Args:
            raw_data (dict): raw data of notification

        Returns:
            Notification: Notification object

        """
        context_attributes = raw_data.get("context_attributes", {})
        attributes = raw_data.get("attributes", {})
        # [MODIFIED] - Safely access hunting_info
        hunting_info = context_attributes.get("hunting_info")

        return cls(
            raw_data=raw_data,
            raw_flat_data=dict_to_flat(raw_data),
            alert_id=context_attributes.get("notification_id", ""),
            id=raw_data.get("id"),
            type=raw_data.get("type"),
            # [MODIFIED] - Check if hunting_info exists before getting rule_name
            rule_name=hunting_info.get("rule_name", "") if hunting_info else "",
            timestamp=context_attributes.get("notification_date", 0) * 1000,
            verdict=(
                attributes.get("gti_assessment", {}).get("verdict", {}).get("value")
            ),
            severity=(
                attributes.get("gti_assessment", {}).get("severity", {}).get("value")
            ),
            origin=context_attributes.get("origin"),
            sources=context_attributes.get("sources", []),
            tags=context_attributes.get("tags", []),
            # [MODIFIED] - Provide default values for file-specific fields
            file_size=attributes.get("size", 0),
            file_type=attributes.get("type_description", ""),
        )

    def get_severity(self):
        """Get the severity value based on gti_assessment severity values

        Returns:
            int: severity value

        """
        # [MODIFIED] - Add check for None before dictionary lookup
        if self.severity:
            return SEVERITY_GTI_MAPPING.get(self.severity, -1)
        return -1

    def pass_filter(self):
        """Check if filtering is passed

        Returns:
            bool: True if filtering is passed, False otherwise

        """
        return self.verdict in NOTIFICATION_ALLOWED_VERDICTS


@dataclasses.dataclass(frozen=True)
class FileHashExistence:
    """Data class to represent the existence of a file hash
    in public and private submissions.

    Attributes:
        exists_public (bool): Whether the file hash exists in public submissions.
        exists_private (bool): Whether the file hash exists in private submissions.
        file_hash (str): The file hash.

    """

    exists_public: bool
    exists_private: bool
    file_hash: str
