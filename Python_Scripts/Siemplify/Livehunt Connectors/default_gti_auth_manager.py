from __future__ import annotations

import dataclasses

from constants import INTEGRATION_IDENTIFIER, XTOOL_HEADER_VALUE
from exceptions import GoogleThreatIntelligenceExceptions
from requests import Session
from SiemplifyAction import SiemplifyAction
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyJob import SiemplifyJob
from TIPCommon.base.interfaces import Logger
from TIPCommon.base.utils import CreateSession
from TIPCommon.extraction import extract_script_param
from TIPCommon.types import ChronicleSOAR


def build_auth_headers(api_key: str) -> dict:
    return {"x-apikey": api_key, "x-tool": XTOOL_HEADER_VALUE}


def build_auth_manager_params(chronicle_soar: ChronicleSOAR) -> AuthManagerParams:
    """Extract auth params for Auth manager

    Args:
         chronicle_soar: ChronicleSOAR SDK object

    Returns:
        AuthManagerParams: AuthManagerParams object

    """
    if isinstance(chronicle_soar, SiemplifyAction):
        input_dictionary = chronicle_soar.get_configuration(INTEGRATION_IDENTIFIER)
    elif isinstance(chronicle_soar, (SiemplifyConnectorExecution, SiemplifyJob)):
        input_dictionary = chronicle_soar.parameters
    else:
        raise GoogleThreatIntelligenceExceptions(
            "Provided SOAR instance is not supported."
        )

    api_root = extract_script_param(
        chronicle_soar,
        input_dictionary=input_dictionary,
        param_name="API Root",
        is_mandatory=True,
        print_value=True,
    )
    api_key = extract_script_param(
        chronicle_soar,
        input_dictionary=input_dictionary,
        param_name="API Key",
        is_mandatory=True,
        remove_whitespaces=False,
    )
    asm_project_name = extract_script_param(
        chronicle_soar,
        input_dictionary=input_dictionary,
        param_name="ASM Project Name",
        print_value=True,
    )
    verify_ssl = extract_script_param(
        chronicle_soar,
        input_dictionary=input_dictionary,
        param_name="Verify SSL",
        input_type=bool,
        is_mandatory=True,
        print_value=True,
    )

    return AuthManagerParams(
        api_root=api_root,
        api_key=api_key,
        asm_project_name=asm_project_name,
        verify_ssl=verify_ssl,
    )


@dataclasses.dataclass(frozen=True)
class AuthManagerParams:
    api_root: str
    api_key: str
    asm_project_name: str | None
    verify_ssl: bool


class AuthManager:
    def __init__(
        self,
        params: AuthManagerParams,
        logger: Logger | None = None,
    ):
        self.api_root = params.api_root
        self.api_key = params.api_key
        self.asm_project_name = params.asm_project_name
        self.verify_ssl = params.verify_ssl
        self.logger = logger

    def prepare_session(self) -> Session:
        """Preparse session object to be used in API session."""
        session = CreateSession.create_session()
        session.verify = self.verify_ssl
        session.headers.update(build_auth_headers(api_key=self.api_key))
        return session
