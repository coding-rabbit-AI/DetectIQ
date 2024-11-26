import os
import shutil
import zipfile
from datetime import datetime
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
from ruamel.yaml import YAML

from detectiq.core.utils.logging import get_logger
from detectiq.globals import DEFAULT_DIRS

logger = get_logger(__name__)


class SigmaRuleUpdater:
    """Download/update Sigma rules from the official SigmaHQ release packages."""

    GITHUB_API_LATEST = "https://api.github.com/repos/SigmaHQ/sigma/releases/latest"
    BASE_URL = "https://github.com/SigmaHQ/sigma/releases/latest/download"
    RULE_PACKAGES = {
        "core": "sigma_core.zip",
        "core+": "sigma_core+.zip",
        "core++": "sigma_core++.zip",
        "emerging_threats": "sigma_emerging_threats_addon.zip",
        "all": "sigma_all_rules.zip",
    }

    def __init__(self, rule_dir: Optional[str] = None, package_type: str = "core"):
        """Initialize SigmaRuleUpdater.

        Args:
            rule_dir: Directory to store rules. Defaults to DEFAULT_DIRS.SIGMA_RULE_DIR
            package_type: Type of rule package to download ("core", "core+", "core++", etc.)
        """
        self.rule_dir = Path(rule_dir) if rule_dir else DEFAULT_DIRS.SIGMA_RULE_DIR
        self.rule_dir.mkdir(parents=True, exist_ok=True)

        if package_type not in self.RULE_PACKAGES:
            raise ValueError(f"Invalid package type. Must be one of: {list(self.RULE_PACKAGES.keys())}")
        self.package_type = package_type

        # Store individual rules in a subdirectory
        self.individual_rules_dir = self.rule_dir / "individual_rules"
        self.individual_rules_dir.mkdir(parents=True, exist_ok=True)

        self.installed_version = None

        # Initialize YAML parser with roundtrip mode
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        self.yaml.indent(mapping=2, sequence=4, offset=2)
        self.yaml.width = 4096  # Prevent line wrapping

    async def check_for_updates(self) -> Tuple[bool, Optional[str]]:
        """Check if updates are available."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.GITHUB_API_LATEST) as response:
                    response.raise_for_status()
                    latest_release = await response.json()
                    latest_version = latest_release["tag_name"]

                    if not self.installed_version or self.installed_version != latest_version:
                        return True, latest_version

                    return False, latest_version

        except Exception as e:
            raise RuntimeError(f"Failed to check for updates: {str(e)}")

    async def update_rules(self, force: bool = False) -> None:
        """Download and update rules."""
        try:
            updates_available, latest_version = await self.check_for_updates()

            if not updates_available and not force:
                logger.info("No updates available")
                return

            # Clean existing rules directory
            if self.rule_dir.exists():
                logger.info("Cleaning rule directory")
                try:
                    # Remove directory and all its contents recursively
                    shutil.rmtree(self.rule_dir)
                    # Recreate empty directories
                    self.rule_dir.mkdir(parents=True, exist_ok=True)
                    self.individual_rules_dir.mkdir(parents=True, exist_ok=True)
                    logger.info("Successfully cleaned rule directory")
                except Exception as e:
                    logger.error(f"Error cleaning rule directory: {e}")
                    raise

            # Download and extract rules
            zip_url = f"{self.BASE_URL}/{self.RULE_PACKAGES[self.package_type]}"

            async with aiohttp.ClientSession() as session:
                async with session.get(zip_url) as response:
                    response.raise_for_status()
                    content = await response.read()

            # Extract rules
            with zipfile.ZipFile(BytesIO(content)) as zf:
                # Extract all YAML files
                for file_info in zf.filelist:
                    if file_info.filename.endswith(".yml"):
                        zf.extract(file_info, self.rule_dir)

            # Parse and save individual rules
            await self._save_individual_rules()

            # Update installed version
            self.installed_version = latest_version
            logger.info(f"Updated to version {latest_version}")

        except Exception as e:
            raise RuntimeError(f"Failed to update rules: {str(e)}")

    async def _save_individual_rules(self) -> None:
        """Parse and save individual rules with preserved ordering."""
        try:
            self.individual_rules_dir.mkdir(parents=True, exist_ok=True)

            # Process each YAML file
            for rule_file in self.rule_dir.glob("**/*.yml"):
                if rule_file.is_file():
                    try:
                        with open(rule_file) as f:
                            rule_data = self.yaml.load(f)

                            # Skip non-rule files
                            if not isinstance(rule_data, dict) or "detection" not in rule_data:
                                continue

                            # Save individual rule
                            rule_name = rule_data.get("title", "").replace(" ", "_")
                            if rule_name:
                                output_path = self.individual_rules_dir / f"{rule_name}.yml"
                                output_path.parent.mkdir(parents=True, exist_ok=True)
                                
                                with open(output_path, "w") as out_f:
                                    self.yaml.dump(rule_data, out_f)

                    except Exception as e:
                        logger.warning(f"Failed to process rule file {rule_file}: {e}")
                        continue

            logger.info(f"Saved individual rules to {self.individual_rules_dir}")

        except Exception as e:
            raise RuntimeError(f"Failed to save individual rules: {str(e)}")

    async def load_rules(self) -> List[Dict[str, Any]]:
        """Load rules for vectorstore creation with preserved ordering."""
        rules = []

        try:
            if not self.individual_rules_dir.exists():
                logger.warning("Individual rules directory does not exist")
                return rules

            for rule_file in self.individual_rules_dir.glob("*.yml"):
                try:
                    with open(rule_file) as f:
                        rule_data = self.yaml.load(f)

                        # Skip non-rule files
                        if not isinstance(rule_data, dict) or "detection" not in rule_data:
                            continue

                        # Extract metadata
                        metadata = {
                            "title": rule_data.get("title", ""),
                            "id": rule_data.get("id", ""),
                            "status": rule_data.get("status", ""),
                            "description": rule_data.get("description", ""),
                            "author": rule_data.get("author", ""),
                            "rule_type": "sigma",
                            "package_type": self.package_type,
                            "version": self.installed_version,
                        }

                        if "tags" in rule_data:
                            metadata["tags"] = rule_data["tags"]

                        if "logsource" in rule_data:
                            metadata["logsource"] = rule_data["logsource"]

                        severity = rule_data.get("level", "medium")

                        # Convert to string using ruamel.yaml
                        string_buffer = StringIO()
                        self.yaml.dump(rule_data, string_buffer)
                        rule_content = string_buffer.getvalue()

                        rules.append({
                            "content": rule_content,
                            "metadata": metadata,
                            "severity": severity
                        })

                except Exception as e:
                    logger.warning(f"Failed to process rule {rule_file}: {e}")
                    continue

            logger.info(f"Loaded {len(rules)} rules")

        except Exception as e:
            raise RuntimeError(f"Failed to load rules: {str(e)}")

        return rules
