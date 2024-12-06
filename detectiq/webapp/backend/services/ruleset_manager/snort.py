import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional

from langchain.embeddings.base import Embeddings
from langchain_openai import OpenAIEmbeddings

from detectiq.core.config import config
from detectiq.core.llm.snort_rules import SnortLLM
from detectiq.core.llm.tools.snort.create_snort_rule import CreateSnortRuleTool
from detectiq.core.utils.logging import get_logger
from detectiq.core.utils.snort.rule_updater import SnortRuleUpdater
from detectiq.webapp.backend.services.rule_service import DjangoRuleRepository

logger = get_logger(__name__)


class SnortRulesetManager:
    def __init__(
        self,
        rule_dir: Optional[str] = None,
        vector_store_dir: Optional[str] = None,
        package_type: Optional[str] = None,
        embedding_model: Optional[Embeddings] = None,
    ):
        """Initialize the Snort ruleset manager."""
        self.rule_dir = Path(rule_dir or config.rule_directories["snort"])
        self.vector_store_dir = Path(vector_store_dir or config.vector_store_directories["snort"])
        self.rule_repository = DjangoRuleRepository()
        self.package_type = package_type or config.yara_package_type or "core"
        self.embedding_model = (
            embedding_model if embedding_model is not None else OpenAIEmbeddings(model=config.embedding_model)
        )

        # Initialize rule updater
        self.updater = SnortRuleUpdater(rule_dir=str(self.rule_dir))

        # Initialize LLM handler
        self.llm = SnortLLM(
            rule_dir=str(self.rule_dir),
            auto_update=False,
            vector_store_dir=str(self.vector_store_dir),
            embedding_model=self.embedding_model,
        )

    async def verify_rule(self, rule_content: str, pcap_content: bytes):
        """Verify a Snort rule against PCAP content."""
        try:
            # Implementation of rule verification
            pass
        except Exception as e:
            logger.error(f"Error verifying Snort rule: {e}")
            raise

    async def update_rules(self, force: bool = False) -> List[Dict[str, Any]]:
        """Update Snort rules and return loaded rules."""
        try:
            logger.info("Updating Snort rules...")

            # Clean rule directory if it exists
            if self.rule_dir.exists():
                await self._clean_rule_directory()

            # Update and load rules
            await self.updater.update_rules(force=force)
            #
            rules = await self.updater.load_rules()

            logger.info(f"Successfully updated and loaded {len(rules)} Snort rules")
            return rules
        except Exception as e:
            logger.error(f"Error updating Snort rules: {e}")
            raise

    async def _clean_rule_directory(self):
        """Clean the rule directory."""
        try:
            import shutil

            shutil.rmtree(self.rule_dir)
            self.rule_dir.mkdir(parents=True, exist_ok=True)
            logger.info("Successfully cleaned Snort rule directory")
        except Exception as e:
            logger.error(f"Error cleaning Snort rule directory: {e}")
            raise

    async def create_vector_store(self) -> None:
        """Create vector store for Snort rules."""
        try:
            await self.llm.create_vectordb()
            logger.info("Successfully created Snort vector store")
        except Exception as e:
            logger.error(f"Error creating Snort vector store: {e}")
            raise
