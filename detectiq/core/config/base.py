import json
import os
from pathlib import Path
from typing import Any, Optional

import keyring
from pydantic import BaseModel, Field, SecretStr

from detectiq.core.integrations.elastic import ElasticCredentials
from detectiq.core.integrations.microsoft_xdr import MicrosoftXDRCredentials
from detectiq.core.integrations.splunk import SplunkCredentials
from detectiq.core.utils.logging import get_logger
from detectiq.globals import DEFAULT_DIRS

logger = get_logger(__name__)


class IntegrationCredentials(BaseModel):
    """Base integration credentials model."""

    hostname: str = Field(default="")
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    tenant_id: Optional[str] = None
    cloud_id: Optional[str] = None
    verify_ssl: bool = True
    enabled: bool = False

    class Config:
        extra = "allow"


class Integrations(BaseModel):
    """Integration configuration model."""

    splunk: Optional[SplunkCredentials] = None
    elastic: Optional[ElasticCredentials] = None
    microsoft_xdr: Optional[MicrosoftXDRCredentials] = None

    class Config:
        arbitrary_types_allowed = True


class DetectIQConfig(BaseModel):
    """Main configuration model."""

    openai_api_key: str = Field(default="")
    rule_directories: dict = Field(
        default_factory=lambda: {
            "sigma": str(DEFAULT_DIRS.SIGMA_RULE_DIR),
            "yara": str(DEFAULT_DIRS.YARA_RULE_DIR),
            "snort": str(DEFAULT_DIRS.SNORT_RULE_DIR),
        }
    )
    vector_store_directories: dict = Field(
        default_factory=lambda: {
            "sigma": str(DEFAULT_DIRS.SIGMA_VECTOR_STORE_DIR),
            "yara": str(DEFAULT_DIRS.YARA_VECTOR_STORE_DIR),
            "snort": str(DEFAULT_DIRS.SNORT_VECTOR_STORE_DIR),
        }
    )
    log_level: str = Field(default="INFO")
    model: str = Field(default="gpt-4o")
    integrations: Integrations = Field(default_factory=Integrations)

    @property
    def RULE_DIRS(self):
        return self.rule_directories

    @property
    def VECTOR_STORE_DIRS(self):
        return self.vector_store_directories

    class Config:
        extra = "allow"


class ConfigManager:
    APP_NAME = "detectiq"
    PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
    CONFIG_FILE = PROJECT_ROOT / "config.json"

    def __init__(self):
        logger.debug(f"Initializing ConfigManager. Config file: {self.CONFIG_FILE}")
        self.config = self._load_config()
        if not self.CONFIG_FILE.exists():
            self.save_config()

    def _load_config(self) -> DetectIQConfig:
        config_dict = self._get_default_config()
        if self.CONFIG_FILE.exists():
            self._update_from_file(config_dict)
        return DetectIQConfig(**config_dict)

    def _get_default_config(self) -> dict:
        return {
            "openai_api_key": keyring.get_password(self.APP_NAME, "openai_api_key") or os.getenv("OPENAI_API_KEY", ""),
            "rule_directories": {
                "sigma": str(DEFAULT_DIRS.SIGMA_RULE_DIR),
                "yara": str(DEFAULT_DIRS.YARA_RULE_DIR),
                "snort": str(DEFAULT_DIRS.SNORT_RULE_DIR),
            },
            "vector_store_directories": {
                "sigma": str(DEFAULT_DIRS.SIGMA_VECTOR_STORE_DIR),
                "yara": str(DEFAULT_DIRS.YARA_VECTOR_STORE_DIR),
                "snort": str(DEFAULT_DIRS.SNORT_VECTOR_STORE_DIR),
            },
            "log_level": os.getenv("DETECTIQ_LOG_LEVEL", "INFO"),
            "model": os.getenv("DETECTIQ_MODEL", "gpt-4"),
            "integrations": {},
        }

    def save_config(self):
        config_dict = self.config.model_dump(exclude_none=True)
        with open(self.CONFIG_FILE, "w") as f:
            json.dump(config_dict, f, indent=2, default=str)

    def update_config(self, **kwargs):
        config_dict = self.config.model_dump()
        config_dict.update(kwargs)
        self.config = DetectIQConfig(**config_dict)
        self.save_config()

    def _update_from_file(self, config_dict: dict) -> None:
        with open(self.CONFIG_FILE) as f:
            file_config = json.load(f)
            config_dict.update(file_config)


async def get_config(user: Optional[Any] = None) -> ConfigManager:
    """Get config manager instance."""
    return ConfigManager()
