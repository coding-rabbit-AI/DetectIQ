import asyncio
import shutil
import tarfile
from io import BytesIO
from pathlib import Path
from typing import Optional, Tuple

import aiofiles
import aiohttp

from detectiq.core.utils.logging import get_logger
from detectiq.globals import DEFAULT_DIRS

logger = get_logger(__name__)


class SnortRuleUpdater:
    """Class for updating Snort rules."""

    SNORT_RULES_URL = "https://www.snort.org/downloads/community/snort3-community-rules.tar.gz"
    MD5_URL = "https://www.snort.org/downloads/community/md5s"

    def __init__(self, rule_dir: Optional[str] = None):
        """Initialize SnortRuleUpdater."""
        self.rule_dir = Path(rule_dir or DEFAULT_DIRS.SNORT_RULE_DIR)
        self.rule_dir.mkdir(parents=True, exist_ok=True)
        self.rules_file = self.rule_dir / "snort3-community-rules.tar.gz"
        self.version_file = self.rule_dir / "version.txt"
        self.installed_version = self._read_installed_version()

        # Store individual rules in a subdirectory (consistent with other updaters)
        self.individual_rules_dir = self.rule_dir / "individual_rules"
        self.individual_rules_dir.mkdir(parents=True, exist_ok=True)

    def _read_installed_version(self) -> Optional[str]:
        if self.version_file.exists():
            with open(self.version_file, "r") as f:
                return f.read().strip()
        return None

    async def check_for_updates(self) -> Tuple[bool, Optional[str]]:
        """Check if updates are available."""
        try:
            remote_md5 = await self._fetch_remote_md5()
            if not self.installed_version or remote_md5 != self.installed_version:
                return True, remote_md5
            return False, remote_md5
        except Exception as e:
            raise RuntimeError(f"Failed to check for updates: {str(e)}")

    async def update_rules(self, force: bool = False) -> None:
        """Update Snort rules."""
        try:
            updates_available, latest_version = await self.check_for_updates()

            if not updates_available and not force:
                logger.info("No updates available")
                return

            # Clean existing rules directory (consistent with other updaters)
            if self.rule_dir.exists():
                logger.info("Cleaning rule directory")
                try:
                    shutil.rmtree(self.rule_dir)
                    self.rule_dir.mkdir(parents=True, exist_ok=True)
                    self.individual_rules_dir.mkdir(parents=True, exist_ok=True)
                    logger.info("Successfully cleaned rule directory")
                except Exception as e:
                    logger.error(f"Error cleaning rule directory: {e}")
                    raise

            # Download and extract rules
            await self._download_rules()
            await self._extract_rules()

            # Save individual rules (consistent with other updaters)
            await self._save_individual_rules()

            # Update installed version
            self.installed_version = latest_version
            with open(self.version_file, "w") as f:
                f.write(latest_version)
            logger.info(f"Updated to version {latest_version}")

        except Exception as e:
            raise RuntimeError(f"Failed to update rules: {str(e)}")

    async def _fetch_remote_md5(self) -> Optional[str]:
        """Fetch the MD5 hash of the latest Snort rules from the Snort website."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.MD5_URL) as response:
                    response.raise_for_status()
                    content = await response.text()
                    for line in content.splitlines():
                        if "snort3-community-rules.tar.gz" in line:
                            return line.split()[0]
        except Exception as e:
            logger.error(f"Failed to fetch remote MD5 hash: {e}")
        return None

    async def _download_rules(self) -> None:
        """Download Snort rules from snort.org."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.SNORT_RULES_URL) as response:
                    response.raise_for_status()
                    async with aiofiles.open(self.rules_file, "wb") as f:
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

    async def _save_individual_rules(self) -> None:
        """Parse and save individual rules."""
        # Implement rule parsing and saving logic here
        pass
