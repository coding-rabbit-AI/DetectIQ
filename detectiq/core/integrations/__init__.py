from importlib.util import find_spec
from typing import Dict, Type

from detectiq.core.integrations.base import BaseSIEMIntegration
from detectiq.core.utils.logging import get_logger

# Configure logging
logger = get_logger(__name__)

# Dictionary to track available integrations
AVAILABLE_INTEGRATIONS: Dict[str, Type[BaseSIEMIntegration]] = {}


def _register_integration(name: str, import_func) -> None:
    """Helper function to register an integration with error handling."""
    try:
        import_func()
        logger.debug(f"Successfully registered {name} integration")
    except Exception as e:
        logger.warning(f"Failed to register {name} integration: {str(e)}")


def _register_splunk():
    """Register Splunk integration if dependencies are available."""
    if find_spec("splunklib"):
        from detectiq.core.integrations.splunk import SplunkIntegration

        AVAILABLE_INTEGRATIONS["splunk"] = SplunkIntegration
    else:
        logger.debug("Splunk integration not available: splunklib not installed")


def _register_elastic():
    """Register Elasticsearch integration if dependencies are available."""
    if find_spec("elasticsearch"):
        from detectiq.core.integrations.elastic import ElasticIntegration

        AVAILABLE_INTEGRATIONS["elastic"] = ElasticIntegration
    else:
        logger.debug("Elasticsearch integration not available: elasticsearch not installed")


def _register_microsoft():
    """Register Microsoft XDR integration if dependencies are available."""
    if find_spec("msal"):
        from detectiq.core.integrations.microsoft_xdr import MicrosoftXDRIntegration

        AVAILABLE_INTEGRATIONS["microsoft_xdr"] = MicrosoftXDRIntegration
    else:
        logger.debug("Microsoft XDR integration not available: msal not installed")


# Register available integrations with error handling
_register_integration("Splunk", _register_splunk)
_register_integration("Elasticsearch", _register_elastic)
_register_integration("Microsoft XDR", _register_microsoft)


def get_available_integrations() -> Dict[str, Type[BaseSIEMIntegration]]:
    """Get dictionary of available integrations."""
    if not AVAILABLE_INTEGRATIONS:
        logger.warning("No SIEM integrations are currently available")
    return AVAILABLE_INTEGRATIONS.copy()


def get_integration(name: str) -> Type[BaseSIEMIntegration]:
    """Get a specific integration by name."""
    if name not in AVAILABLE_INTEGRATIONS:
        raise ValueError(
            f"Integration '{name}' not found. Available integrations: " f"{list(AVAILABLE_INTEGRATIONS.keys())}"
        )
    return AVAILABLE_INTEGRATIONS[name]
