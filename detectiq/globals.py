import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Load environment variables at module import
load_dotenv()


def get_env_path(env_var: str, default: str) -> Path:
    """Get path from environment variable or default."""
    path_str = os.getenv(env_var, default)
    path = Path(path_str)
    path.mkdir(parents=True, exist_ok=True)
    return path


class DEFAULT_DIRS:
    """Default directories for DetectIQ."""

    # Base directories
    BASE_DIR = Path(__file__).parent.parent
    DATA_DIR = get_env_path("DETECTIQ_DATA_DIR", str(BASE_DIR / "data"))

    # Rule directories
    RULE_DIR = get_env_path("DETECTIQ_RULE_DIR", str(DATA_DIR / "rules"))
    YARA_RULE_DIR = get_env_path("DETECTIQ_YARA_RULE_DIR", str(RULE_DIR / "yara"))
    SIGMA_RULE_DIR = get_env_path("DETECTIQ_SIGMA_RULE_DIR", str(RULE_DIR / "sigma"))
    SNORT_RULE_DIR = get_env_path("DETECTIQ_SNORT_RULE_DIR", str(RULE_DIR / "snort"))
    GENERATED_RULE_DIR = get_env_path("DETECTIQ_GENERATED_RULE_DIR", str(RULE_DIR / "generated"))

    # Vector store directories
    VECTOR_STORE_DIR = get_env_path("DETECTIQ_VECTOR_STORE_DIR", str(DATA_DIR / "vector_stores"))
    YARA_VECTOR_STORE_DIR = VECTOR_STORE_DIR / "yara"
    SIGMA_VECTOR_STORE_DIR = VECTOR_STORE_DIR / "sigma"
    SNORT_VECTOR_STORE_DIR = VECTOR_STORE_DIR / "snort"

    # Log directory
    LOG_DIR = get_env_path("DETECTIQ_LOG_DIR", str(DATA_DIR / "logs"))

    # Temp directory for file analysis
    TEMP_DIR = get_env_path("DETECTIQ_TEMP_DIR", str(DATA_DIR / "temp"))


class Config:
    """Configuration settings for DetectIQ."""

    # OpenAI settings
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    OPENAI_MODEL: str = os.getenv("DETECTIQ_MODEL", "gpt-4o")

    # Logging settings
    LOG_LEVEL: str = os.getenv("DETECTIQ_LOG_LEVEL", "INFO")

    # Rule update settings
    AUTO_UPDATE_RULES: bool = os.getenv("DETECTIQ_AUTO_UPDATE_RULES", "true").lower() == "true"
    UPDATE_CHECK_INTERVAL: int = int(os.getenv("DETECTIQ_UPDATE_CHECK_INTERVAL", "86400"))  # 24 hours

    # Vector store settings
    VECTOR_STORE_TYPE: str = os.getenv("DETECTIQ_VECTOR_STORE_TYPE", "faiss")
    EMBEDDING_MODEL: str = os.getenv("DETECTIQ_EMBEDDING_MODEL", "text-embedding-3-small")

    @classmethod
    def validate(cls) -> None:
        """Validate required configuration."""
        if not cls.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY environment variable is required")


# Validate configuration at import
Config.validate()

# Create all directories
for directory in [
    DEFAULT_DIRS.DATA_DIR,
    DEFAULT_DIRS.YARA_RULE_DIR,
    DEFAULT_DIRS.SIGMA_RULE_DIR,
    DEFAULT_DIRS.SNORT_RULE_DIR,
    DEFAULT_DIRS.VECTOR_STORE_DIR,
    DEFAULT_DIRS.YARA_VECTOR_STORE_DIR,
    DEFAULT_DIRS.SIGMA_VECTOR_STORE_DIR,
    DEFAULT_DIRS.SNORT_VECTOR_STORE_DIR,
    DEFAULT_DIRS.LOG_DIR,
    DEFAULT_DIRS.TEMP_DIR,
]:
    directory.mkdir(parents=True, exist_ok=True)
