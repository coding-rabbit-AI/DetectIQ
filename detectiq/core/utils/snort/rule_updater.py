import asyncio
import shutil
import tarfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import aiofiles
import aiohttp
from aiofiles import open as aio_open
from idstools.rule import parse as parse_rule

from detectiq.core.utils.logging import get_logger
from detectiq.globals import DEFAULT_DIRS

logger = get_logger(__name__)


class SnortRuleUpdater:
    """Class for updating Snort rules."""

    SNORT_RULES_URL = "https://www.snort.org/downloads/community/snort3-community-rules.tar.gz"

    def __init__(self, rule_dir: Optional[str] = None):
        """Initialize SnortRuleUpdater."""
        self.rule_dir = Path(rule_dir or DEFAULT_DIRS.SNORT_RULE_DIR)
        self.rule_dir.mkdir(parents=True, exist_ok=True)
        self.rules_file = self.rule_dir / "snort3-community-rules.tar.gz"

    async def _extract_and_save_licenses(self, tar_file) -> None:
        """Extract and save license files from Snort rules tarball."""
        try:
            # Create licenses directory if it doesn't exist
            license_dir = Path("licenses/snort")
            license_dir.mkdir(parents=True, exist_ok=True)

            # List of license files to extract with their new names
            license_files = {
                "snort3-community-rules/LICENSE": "LICENSE.txt",
                "snort3-community-rules/AUTHORS": "AUTHORS.txt",
                "snort3-community-rules/VRT-License.txt": "VRT-License.txt",
            }

            for src_path, dest_name in license_files.items():
                try:
                    license_file = tar_file.extractfile(src_path)
                    if license_file:
                        content = license_file.read().decode("utf-8")
                        dest_path = license_dir / dest_name
                        async with aiofiles.open(dest_path, "w") as f:
                            await f.write(content)
                        logger.info(f"Saved {dest_name} to licenses/snort/")
                    else:
                        logger.warning(f"License file not found in archive: {src_path}")
                except KeyError:
                    logger.warning(f"License file not found in archive: {src_path}")
                except Exception as e:
                    logger.error(f"Error extracting license file {src_path}: {e}")

        except Exception as e:
            logger.error(f"Failed to extract and save Snort license files: {e}")
            raise

    async def update_rules(self, force: bool = False) -> None:
        """Update Snort rules."""
        try:
            # Download rules if they don't exist or force update
            if force or not self.rules_file.exists():
                async with aiohttp.ClientSession() as session:
                    async with session.get(self.SNORT_RULES_URL) as response:
                        response.raise_for_status()
                        content = await response.read()

                        # Save the downloaded content
                        self.rules_file.write_bytes(content)

            # Extract rules and licenses
            with tarfile.open(self.rules_file, "r:gz") as tar:
                # Extract license files first
                await self._extract_and_save_licenses(tar)

                # Extract rules
                tar.extractall(path=self.rule_dir)

            logger.info("Successfully updated Snort rules")

        except Exception as e:
            logger.error(f"Failed to update Snort rules: {e}")
            raise

    async def load_rules(self) -> List[Dict[str, str]]:
        """Load Snort rules from files.

        Returns:
            List of dictionaries containing rule content and metadata
        """
        rules = []
        try:
            rules_path = self.rule_dir / "snort3-community-rules"
            for file in rules_path.glob("*.rules"):
                async with aio_open(file, "r") as f:
                    content = await f.read()

                    # Split content into individual rules
                    individual_rules = [
                        rule.strip()
                        for rule in content.split("\n")
                        if rule.strip() and not rule.strip().startswith("#")
                    ]

                    # Process each rule
                    for rule in individual_rules:
                        try:
                            # Extract basic metadata from the rule
                            metadata = self._parse_rule_metadata(rule)
                            if not metadata:  # Skip invalid/incomplete rules
                                continue

                            rules.append(
                                {
                                    "content": rule,
                                    "metadata": {
                                        "file_name": file.name,
                                        "rule_type": "snort",
                                        "path": str(file),
                                        **metadata,
                                    },
                                }
                            )
                        except Exception as e:
                            logger.warning(f"Failed to process rule: {rule[:100]}... Error: {e}")
                            continue

            logger.info(f"Loaded {len(rules)} valid Snort rules")
            return rules
        except Exception as e:
            logger.error(f"Failed to load rules: {str(e)}")
            raise

    def _parse_msg_parts(self, msg: str) -> Tuple[str, str, str]:
        """Parse category, subcategory and name from msg field.

        Args:
            msg: Rule message string (e.g., "MALWARE-CNC HttpBrowser User-Agent outbound communication attmept")

        Returns:
            Tuple of (category, subcategory, name)
        """
        parts = msg.split(" ", 1)  # Split only on first space
        if len(parts) >= 2 and "-" in parts[0]:
            category_parts = parts[0].split("-")
            if len(category_parts) == 2:
                category = category_parts[0].title()
                subcategory = category_parts[1].title()
                name = parts[1]  # Keep everything after the first space as name
                return category, subcategory, name
            else:
                # Handle case where there's only category
                category = parts[0].title()
                name = parts[1]
                return category, "", name

        # If no category/subcategory format found
        return "", "", msg

    def _get_severity_from_classtype(self, classtype: str) -> str:
        """Determine severity based on classtype.

        Args:
            classtype: Rule classtype string

        Returns:
            Severity level string
        """
        severity_map = {
            "high": ["exploit", "trojan", "backdoor", "rootkit", "malware"],
            "critical": ["attack", "shell", "admin", "escalation", "compromise"],
            "low": ["policy", "info", "scan", "suspicious"],
        }

        classtype_lower = classtype.lower()
        for severity, keywords in severity_map.items():
            if any(keyword in classtype_lower for keyword in keywords):
                return severity
        return "medium"  # Default severity

    def _parse_rule_metadata(self, rule_text: str) -> Dict[str, str]:
        """Parse metadata from a Snort rule."""
        # First check if rule has required components
        header_parts = rule_text.split("(")[0].strip().split()
        if len(header_parts) < 5:  # action proto src_ip src_port direction dst_ip dst_port
            logger.debug(f"Skipping incomplete rule: {rule_text[:100]}...")
            return {}  # Return empty dict to indicate invalid rule

        metadata = {
            "severity": "medium",
            "description": "",
            "msg": "",
            "sid": "",
            "rev": "",
            "category": "",
            "subcategory": "",
            "name": "",
            "classtype": "",
            "reference": [],
            "gid": "",
            "metadata": {},
        }

        try:
            # Split header and options
            if "(" not in rule_text:
                return metadata

            header, options = rule_text.split("(", 1)
            options = options.strip().rstrip(")")

            # Parse options
            current_option = ""
            in_quotes = False
            options_dict = {}

            for char in options:
                if char == '"':
                    in_quotes = not in_quotes
                    current_option += char
                elif char == ";" and not in_quotes:
                    if ":" in current_option:
                        key, value = current_option.split(":", 1)
                        options_dict[key.strip()] = value.strip().strip('"')
                    else:
                        options_dict[current_option.strip()] = ""
                    current_option = ""
                else:
                    current_option += char

            # Extract key metadata
            if "msg" in options_dict:
                msg = options_dict["msg"]
                metadata.update(
                    {
                        "msg": msg,
                        "description": msg,
                        "name": msg,
                        "title": msg,
                        "category": msg.split("-")[0].title() if "-" in msg.split()[0] else "",
                        "subcategory": msg.split("-")[1].split()[0].title() if "-" in msg.split()[0] else "",
                    }
                )

            if "sid" in options_dict:
                metadata["sid"] = options_dict["sid"]

            if "rev" in options_dict:
                metadata["rev"] = options_dict["rev"]

            if "gid" in options_dict:
                metadata["gid"] = options_dict["gid"]

            if "classtype" in options_dict:
                metadata["classtype"] = options_dict["classtype"]
                metadata["severity"] = self._get_severity_from_classtype(options_dict["classtype"])

            if "reference" in options_dict:
                metadata["reference"] = [r.strip() for r in options_dict["reference"].split(",")]

            if "metadata" in options_dict:
                metadata["metadata"] = dict(
                    item.split(" ", 1) for item in options_dict["metadata"].split(",") if " " in item
                )
                # Check for impact_flag red in metadata
                if metadata["metadata"].get("impact_flag") == "red":
                    metadata["severity"] = "critical"

            # Fallback to classtype-based severity if not critical
            if metadata["severity"] != "critical" and "classtype" in options_dict:
                metadata["severity"] = self._get_severity_from_classtype(options_dict["classtype"])

            # Parse header for rule type
            header_parts = header.strip().split()
            if len(header_parts) > 0:
                if header_parts[0] == "file_id":
                    metadata["rule_type"] = "file_identification"
                elif len(header_parts) > 1 and header_parts[1] == "file":
                    metadata["rule_type"] = "file"
                else:
                    metadata["rule_type"] = "traditional"

        except Exception as e:
            logger.warning(f"Error parsing rule metadata: {e}")
            if not metadata["msg"]:
                metadata["title"] = f"Snort Rule {metadata['sid']}"

        return metadata

    def _rules_exist(self) -> bool:
        """Check if rules already exist."""
        rules_path = self.rule_dir / "snort3-community-rules"
        return rules_path.exists() and any(rules_path.glob("*.rules"))

    async def _download_rules(self) -> None:
        """Download Snort rules from snort.org."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.SNORT_RULES_URL) as response:
                    if response.status != 200:
                        raise Exception(f"Failed to download rules: HTTP {response.status}")

                    async with aio_open(self.rules_file, "wb") as f:
                        await f.write(await response.read())

            logger.info("Successfully downloaded Snort rules")
        except Exception as e:
            logger.error(f"Failed to download rules: {str(e)}")
            raise

    async def _extract_rules(self) -> None:
        """Extract downloaded rules."""
        try:
            # Run extraction in a thread pool since tarfile is blocking
            await asyncio.get_event_loop().run_in_executor(None, self._extract_tar_gz)
            logger.info("Successfully extracted Snort rules")
        except Exception as e:
            logger.error(f"Failed to extract rules: {str(e)}")
            raise

    def _extract_tar_gz(self) -> None:
        """Extract tar.gz file synchronously."""
        with tarfile.open(self.rules_file, "r:gz") as tar:
            tar.extractall(path=self.rule_dir)

    async def _save_license_files(self, extracted_path: Path) -> None:
        """Save Snort license files to the licenses directory."""
        try:
            license_dir = Path("licenses/snort")
            license_dir.mkdir(parents=True, exist_ok=True)

            # List of files to copy with their new names
            license_files = {"LICENSE": "LICENSE.txt", "AUTHORS": "AUTHORS.txt", "VRT-License": "VRT-License.txt"}

            for src_name, dst_name in license_files.items():
                src_path = extracted_path / src_name
                if src_path.exists():
                    shutil.copy2(src_path, license_dir / dst_name)
                    logger.info(f"Copied {src_name} to licenses/snort/{dst_name}")
                else:
                    logger.warning(f"License file not found: {src_name}")

        except Exception as e:
            logger.error(f"Failed to save Snort license files: {e}")
