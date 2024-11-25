import asyncio
import os
import re
import shutil
import zipfile
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiofiles
import aiohttp
import plyara
from plyara.utils import rebuild_yara_rule

from detectiq.core.utils.logging import get_logger
from detectiq.globals import DEFAULT_DIRS

logger = get_logger(__name__)


def map_severity_score(score: Optional[str | int]) -> str:
    """Map numerical or string severity score to string severity level.

    Args:
        score: Severity score (0-100) or string severity level

    Returns:
        String severity level
    """
    if score is None:
        return "medium"

    # Handle string severity values
    if isinstance(score, str):
        score_lower = score.lower()
        valid_severities = {"critical", "high", "medium", "low", "informational"}
        if score_lower in valid_severities:
            return score_lower

    # Handle numerical values
    try:
        numeric_score = int(score)
        if not 0 <= numeric_score <= 100:
            logger.warning(f"Invalid severity score: {score}, defaulting to medium")
            return "medium"

        if numeric_score >= 90:
            return "critical"
        elif numeric_score >= 70:
            return "high"
        elif numeric_score >= 40:
            return "medium"
        elif numeric_score >= 10:
            return "low"
        else:
            return "informational"
    except (ValueError, TypeError):
        logger.warning(f"Invalid severity score format: {score}, defaulting to medium")
        return "medium"


class YaraRuleUpdater:
    """Download/update YARA rules from YARA-Forge releases."""

    GITHUB_API_LATEST = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
    BASE_URL = "https://github.com/YARAHQ/yara-forge/releases/latest/download"
    RULE_PACKAGES = {
        "core": "yara-forge-rules-core.zip",
        "extended": "yara-forge-rules-extended.zip",
        "full": "yara-forge-rules-full.zip",
    }

    def __init__(self, rule_dir: Optional[str] = None, package_type: str = "core"):
        """Initialize YaraRuleUpdater."""
        self.rule_dir = Path(rule_dir) if rule_dir else DEFAULT_DIRS.YARA_RULE_DIR

        if package_type not in self.RULE_PACKAGES:
            raise ValueError(f"Invalid package type. Must be one of: {list(self.RULE_PACKAGES.keys())}")
        self.package_type = package_type
        self.installed_version = None

    async def update_rules(self, force: bool = False) -> None:
        """Download and update rules."""
        try:
            updates_available, latest_version = await self.check_for_updates()

            if not updates_available and not force:
                logger.info("No updates available")
                return

            # Ensure rule directory exists
            self.rule_dir.mkdir(parents=True, exist_ok=True)

            # Clean existing rules directory
            logger.info("Cleaning rule directory")
            for item in self.rule_dir.glob("*"):
                if item.is_file():
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item)

            # Create individual rules directory
            individual_rules_dir = self.rule_dir / "individual_rules"
            individual_rules_dir.mkdir(parents=True, exist_ok=True)

            # Download and extract rules
            zip_url = f"{self.BASE_URL}/{self.RULE_PACKAGES[self.package_type]}"
            logger.info(f"Downloading rules from {zip_url}")

            async with aiohttp.ClientSession() as session:
                async with session.get(zip_url) as response:
                    response.raise_for_status()
                    content = await response.read()

            # Extract rules and license
            with zipfile.ZipFile(BytesIO(content)) as zf:
                # Extract main rule file
                package_dir = f"packages/{self.package_type}"
                rule_file = f"{package_dir}/yara-rules-{self.package_type}.yar"
                zf.extract(rule_file, self.rule_dir)

                # Extract license from rule file
                await self._extract_and_save_license(self.rule_dir / rule_file)

                # Move to root of rule dir
                shutil.move(self.rule_dir / rule_file, self.rule_dir / f"yara-rules-{self.package_type}.yar")

                # Cleanup package dir if it exists
                package_path = self.rule_dir / "packages"
                if package_path.exists():
                    shutil.rmtree(package_path)

            # Parse and save individual rules
            await self._save_individual_rules()

            # Update installed version
            self.installed_version = latest_version
            logger.info(f"Updated to version {latest_version}")

        except Exception as e:
            raise RuntimeError(f"Failed to update rules: {str(e)}")

    async def _save_individual_rules(self) -> None:
        """Parse main rule file and save individual rules."""
        try:
            individual_rules_dir = self.rule_dir / "individual_rules"
            individual_rules_dir.mkdir(parents=True, exist_ok=True)

            parser = plyara.Plyara()
            rule_file = self.rule_dir / f"yara-rules-{self.package_type}.yar"

            if not rule_file.exists():
                raise FileNotFoundError(f"Main rule file not found: {rule_file}")

            # Process rules in chunks to improve memory usage
            chunk_size = 1000  # Adjust based on available memory
            rules_processed = 0

            with open(rule_file) as f:
                # Read file content once
                rule_content = f.read()

            try:
                # Parse all rules at once - more efficient than parsing individually
                all_rules = parser.parse_string(rule_content)
                total_rules = len(all_rules)

                # Process rules in chunks
                for i in range(0, total_rules, chunk_size):
                    chunk = all_rules[i : i + chunk_size]

                    # Process chunk of rules concurrently
                    tasks = []
                    for rule in chunk:
                        if "rule_name" not in rule:
                            logger.warning("Skipping rule without name")
                            continue

                        try:
                            rule_name = rule["rule_name"]
                            rule_string = rebuild_yara_rule(rule)

                            if not rule_string or "condition:" not in rule_string:
                                logger.warning(f"Skipping invalid rule: {rule_name}")
                                continue

                            rule_path = individual_rules_dir / f"{rule_name}.yar"
                            tasks.append(self._save_rule_file(rule_path, rule_string))

                        except Exception as e:
                            logger.warning(f"Failed to process rule: {e}")
                            continue

                    # Save chunk of rules concurrently
                    if tasks:
                        await asyncio.gather(*tasks)
                        rules_processed += len(tasks)

                    # Log progress
                    if (i + chunk_size) % 5000 == 0:
                        logger.info(f"Processed {i + chunk_size}/{total_rules} rules")

                logger.info(f"Successfully saved {rules_processed} valid individual rules")

            except Exception as e:
                logger.error(f"Failed to parse rules: {e}")
                raise

        except Exception as e:
            raise RuntimeError(f"Failed to save individual rules: {str(e)}")

    async def _save_rule_file(self, path: Path, content: str) -> None:
        """Save rule to file asynchronously."""
        async with aiofiles.open(path, "w") as f:
            await f.write(content)

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

    def _parse_rule_metadata(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Parse metadata from a YARA rule.

        Args:
            rule: Dictionary containing parsed YARA rule

        Returns:
            Dictionary containing extracted metadata
        """
        metadata = {
            "title": "",
            "description": "",
            "author": "",
            "reference": "",
            "date": "",
            "hash": "",
            "severity": "medium",  # Default severity
            "type": "",
            "tags": [],
        }

        # Extract metadata fields
        if "metadata" in rule:
            rule_metadata = rule["metadata"]
            # Handle both list and dict metadata formats
            if isinstance(rule_metadata, dict):
                for key, value in rule_metadata.items():
                    if key == "severity" or key == "score":
                        metadata["severity"] = map_severity_score(value)
                    else:
                        metadata[key] = value
            elif isinstance(rule_metadata, list):
                # Convert list metadata to dict
                for item in rule_metadata:
                    if isinstance(item, dict) and len(item) == 1:
                        key, value = next(iter(item.items()))
                        if key == "severity" or key == "score":
                            metadata["severity"] = map_severity_score(value)
                        else:
                            metadata[key] = value

        # Set title from rule name if not in metadata
        if not metadata["title"] and "rule_name" in rule:
            metadata["title"] = rule["rule_name"]

        # Extract tags
        if "tags" in rule:
            metadata["tags"] = rule["tags"]

        return metadata

    async def load_rules(self) -> List[Dict[str, Any]]:
        """Load YARA rules from the rules directory."""
        rules = []
        try:
            for rule_file in self.rule_dir.glob("**/*.yar"):
                if rule_file.is_file():
                    try:
                        with open(rule_file) as f:
                            content = f.read()

                        title = rule_file.stem.replace("_", " ").title()

                        # Create rule dictionary
                        rule_dict = {
                            "title": title,
                            "content": content,
                            "type": "yara",
                            "severity": "medium",  # Default severity
                            "metadata": {
                                "file_path": str(rule_file),
                                "description": f"YARA rule for {title}",
                                "title": title,
                            },
                        }
                        rules.append(rule_dict)
                        logger.debug(f"Loaded YARA rule: {title}")

                    except Exception as e:
                        logger.warning(f"Failed to load YARA rule {rule_file}: {e}")
                        continue

            logger.info(f"Loaded {len(rules)} YARA rules")
            return rules

        except Exception as e:
            logger.error(f"Failed to load YARA rules: {str(e)}")
            raise RuntimeError(f"Failed to load YARA rules: {str(e)}")

    async def _extract_and_save_license(self, rule_file: Path) -> None:
        """Extract license from rule file and save it."""
        try:
            async with aiofiles.open(rule_file, "r") as f:
                content = await f.read()

            # Find the first occurrence of 'rule' or 'import' at the start of a line
            pattern = re.compile(r"^(rule|import)", re.MULTILINE)
            match = pattern.search(content)

            if match:
                license_text = content[: match.start()].strip()

                # Create licenses directory if it doesn't exist
                license_dir = Path("licenses/yara")
                license_dir.mkdir(parents=True, exist_ok=True)

                # Save license
                async with aiofiles.open(license_dir / "yaraforge.txt", "w") as f:
                    await f.write(license_text)

                logger.info("YARA license extracted and saved successfully")
            else:
                logger.warning("Could not find license text in YARA rules file")

        except Exception as e:
            logger.error(f"Failed to extract and save YARA license: {e}")


if __name__ == "__main__":
    updater = YaraRuleUpdater()
    rules = asyncio.run(updater.load_rules())
    print(rules)
