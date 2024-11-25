import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiofiles
import yaml

from detectiq.core.utils.logging import get_logger
from detectiq.webapp.backend.api.models import StoredRule

logger = get_logger(__name__)


class RuleFileStorage:
    """Service for managing rule files on disk"""

    def __init__(self, base_path: Optional[str] = None):
        """Initialize storage service.

        Args:
            base_path: Optional base path for rule storage
        """
        logger.info("Initializing RuleFileStorage")
        self.base_path = Path(base_path or os.getenv("RULE_STORAGE_PATH", "rules"))
        self._ensure_directories()

    def _ensure_directories(self) -> None:
        """Ensure required directories exist."""
        for rule_type in ["sigma", "yara", "snort"]:
            (self.base_path / rule_type).mkdir(parents=True, exist_ok=True)

    def save_rule_file(self, rule_type: str, name: str, content: str) -> Path:
        """Save rule to appropriate directory with proper extension.

        Args:
            rule_type: Type of rule (sigma, yara, snort)
            name: Name of the rule
            content: Rule content

        Returns:
            Path: Path to saved rule file
        """
        extensions = {"sigma": ".yml", "yara": ".yar", "snort": ".rules"}

        file_path = self.base_path / rule_type / f"{name}{extensions[rule_type]}"
        file_path.write_text(content)
        return file_path

    def load_rule_file(self, rule_type: str, name: str) -> Optional[str]:
        """Load rule content from file.

        Args:
            rule_type: Type of rule (sigma, yara, snort)
            name: Name of the rule

        Returns:
            Optional[str]: Rule content if found, None otherwise
        """
        extensions = {"sigma": ".yml", "yara": ".yar", "snort": ".rules"}

        file_path = self.base_path / rule_type / f"{name}{extensions[rule_type]}"
        if file_path.exists():
            return file_path.read_text()
        return None

    def export_rules(self, rules: List[StoredRule], export_path: Path) -> None:
        """Export rules to filesystem in organized structure.

        Args:
            rules: List of rules to export
            export_path: Path to export directory
        """
        try:
            for rule in rules:
                # Get rule attributes safely with defaults
                rule_type = getattr(rule, "type", "unknown")
                rule_name = getattr(rule, "title", "unnamed")  # Using title instead of name
                content = getattr(rule, "content", "")
                metadata = getattr(rule, "metadata", {})
                version = getattr(rule, "version", "1.0.0")
                source = getattr(rule, "source", "unknown")

                # Create rule path
                rule_path = export_path / rule_type / f"{rule_name}.yml"
                rule_path.parent.mkdir(parents=True, exist_ok=True)

                # Export rule with metadata
                try:
                    rule_content = yaml.safe_load(content) if content else {}
                except yaml.YAMLError:
                    logger.warning(f"Failed to parse YAML content for rule: {rule_name}")
                    rule_content = {"content": content}

                rule_data = {
                    "rule": rule_content,
                    "metadata": metadata,
                    "version": version,
                    "source": source,
                }

                # Write rule data
                with rule_path.open("w") as f:
                    yaml.dump(rule_data, f, default_flow_style=False)

                logger.debug(f"Exported rule: {rule_name} to {rule_path}")

        except Exception as e:
            logger.error(f"Error exporting rules: {e}")
            raise

    async def store_rule(self, rule_data: Dict[str, Any], file_path: Path) -> None:
        """Store rule data to file asynchronously."""
        try:
            logger.info(f"Storing rule to {file_path}")
            async with aiofiles.open(file_path, mode="w") as f:
                await f.write(rule_data["content"])
            logger.debug(f"Successfully stored rule: {rule_data.get('metadata', {}).get('name', 'unnamed')}")
        except Exception as e:
            logger.error(f"Error storing rule: {e}")
            raise
