import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from django.conf import settings
from langchain_openai import OpenAIEmbeddings

from detectiq.core.llm.sigma_rules import SigmaLLM
from detectiq.core.llm.tools.sigma.create_sigma_rule import CreateSigmaRuleTool
from detectiq.core.utils.logging import get_logger
from detectiq.core.utils.sigma.rule_updater import SigmaRuleUpdater
from detectiq.webapp.backend.services.rule_service import DjangoRuleRepository

logger = get_logger(__name__)


class SigmaRulesetManager:
    def __init__(self):
        """Initialize the Sigma ruleset manager."""
        self.rule_dir = settings.RULE_DIRS["sigma"]
        self.vector_store_dir = settings.VECTOR_STORE_DIRS["sigma"]
        self.rule_repository = DjangoRuleRepository()

        # Initialize rule updater
        self.updater = SigmaRuleUpdater(rule_dir=str(self.rule_dir))

        # Initialize LLM handler
        self.llm = SigmaLLM(
            rule_dir=str(self.rule_dir),
            auto_update=False,
            vector_store_dir=str(self.vector_store_dir),
            embedding_model=OpenAIEmbeddings(model="text-embedding-3-small"),
        )

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
