import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional

from langchain_openai import OpenAIEmbeddings

from detectiq.core.config import config
from detectiq.core.llm.sigma_rules import SigmaLLM
from detectiq.core.utils.logging import get_logger
from detectiq.core.utils.sigma.rule_updater import SigmaRuleUpdater
from detectiq.webapp.backend.services.rule_service import DjangoRuleRepository

logger = get_logger(__name__)


class SigmaRulesetManager:
    def __init__(
        self,
        rule_dir: Optional[str] = None,
        vector_store_dir: Optional[str] = None,
        package_type: Optional[str] = None,
        embedding_model: Optional[str] = None,
    ):
        """Initialize the Sigma ruleset manager."""
        self.rule_dir = Path(rule_dir or config.rule_directories.get("sigma"))
        self.vector_store_dir = Path(vector_store_dir or config.vector_store_directories.get("sigma"))
        self.rule_repository = DjangoRuleRepository()
        self.package_type = package_type or config.sigma_package_type or "core"
        self.embedding_model = embedding_model or OpenAIEmbeddings(model=config.embedding_model)
        # Initialize rule updater
        self.updater = SigmaRuleUpdater(rule_dir=str(self.rule_dir), package_type=self.package_type)

        # Initialize LLM handler
        try:
            self.llm = SigmaLLM(
                rule_dir=str(self.rule_dir),
                auto_update=False,
                vector_store_dir=str(self.vector_store_dir),
                embedding_model=self.embedding_model,
            )
        except Exception as e:
            logger.error(f"Error initializing SigmaLLM: {e}")

    async def update_rules(self, force: bool = False) -> List[Dict[str, Any]]:
        """Update Sigma rules and return loaded rules."""
        try:
            logger.info("Updating Sigma rules...")

            # Clean rule directory if it exists
            if self.rule_dir.exists():
                await self._clean_rule_directory()

            # Update and load rules
            await self.updater.update_rules(force=force)
            rules = await self.updater.load_rules()

            logger.info(f"Successfully updated and loaded {len(rules)} Sigma rules")
            return rules
        except Exception as e:
            logger.error(f"Error updating Sigma rules: {e}")
            raise

    async def _clean_rule_directory(self):
        """Clean the rule directory."""
        try:
            import shutil

            shutil.rmtree(self.rule_dir)
            self.rule_dir.mkdir(parents=True, exist_ok=True)
            logger.info("Successfully cleaned Sigma rule directory")
        except Exception as e:
            logger.error(f"Error cleaning Sigma rule directory: {e}")
            raise

    async def create_vector_store(self) -> None:
        """Create vector store for Sigma rules."""
        try:
            await self.llm.create_vectordb()
            logger.info("Successfully created Sigma vector store")
        except Exception as e:
            logger.error(f"Error creating Sigma vector store: {e}")
            raise
