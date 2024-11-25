import asyncio
import os
from typing import List

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.management.base import BaseCommand

from detectiq.core.utils.logging import get_logger
from detectiq.webapp.backend.services.ruleset_manager.ruleset_manager import RulesetManager

logger = get_logger(__name__)


class Command(BaseCommand):
    help = "Initialize rulesets and optionally create vector stores for Sigma, YARA, and Snort rules"

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Force redownload of all rules",
        )
        parser.add_argument(
            "--create_vectorstores",
            action="store_true",
            help="Create vector stores for rules (requires OpenAI API key)",
        )
        parser.add_argument(
            "--rule_types",
            nargs="+",
            type=str,
            choices=["sigma", "yara", "snort", "all"],
            default=["all"],
            help="Specify which rule types to initialize (sigma, yara, snort, or all)",
        )

    async def ainit_rulesets(
        self, force: bool = False, create_vectorstores: bool = False, rule_types: List[str] = ["all"]
    ):
        """Async initialization of rulesets."""
        try:
            # Only verify OpenAI API key if creating vector stores
            if create_vectorstores:
                if not settings.OPENAI_API_KEY:
                    raise ImproperlyConfigured("OPENAI_API_KEY must be set to create vector stores")

            # Verify rule directories are configured
            if not all(dir_path for dir_path in settings.RULE_DIRS.values()):
                raise ImproperlyConfigured("Rule directories not properly configured")

            logger.info("Starting async ruleset initialization")
            manager = RulesetManager()

            # Determine which rule types to initialize
            if "all" in rule_types:
                types_to_init = ["sigma", "yara", "snort"]
            else:
                types_to_init = rule_types

            logger.info(f"Initializing rule types: {', '.join(types_to_init)}")

            # Create rule directories if they don't exist
            for rule_type in types_to_init:
                directory = settings.RULE_DIRS.get(rule_type)
                if directory:
                    os.makedirs(directory, exist_ok=True)

            # Initialize rulesets with vector store option
            await manager.initialize_rulesets(create_vectorstores=create_vectorstores, rule_types=types_to_init)
            logger.info(f"Successfully initialized rulesets for: {', '.join(types_to_init)}")

        except Exception as e:
            logger.error(f"Error initializing rulesets: {e}")
            raise

    def handle(self, *args, **options):
        force = options.get("force", False)
        create_vectorstores = options.get("create_vectorstores", False)
        rule_types = options.get("rule_types", ["all"])

        try:
            self.stdout.write("Starting ruleset initialization...")

            # Debug prints
            if create_vectorstores:
                self.stdout.write(f"OpenAI API Key configured: {bool(settings.OPENAI_API_KEY)}")
            self.stdout.write(f"Rule directories configured: {settings.RULE_DIRS}")
            self.stdout.write(f"Rule types to initialize: {', '.join(rule_types)}")

            # Run initialization
            asyncio.run(
                self.ainit_rulesets(force=force, create_vectorstores=create_vectorstores, rule_types=rule_types)
            )

            success_msg = f"Successfully initialized rulesets for: {', '.join(rule_types)}"
            if create_vectorstores:
                success_msg += " and created vector stores"
            self.stdout.write(self.style.SUCCESS(success_msg))

        except ImproperlyConfigured as e:
            self.stdout.write(self.style.ERROR(f"Configuration error: {str(e)}"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error initializing rulesets: {str(e)}"))
