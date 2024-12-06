from typing import Any, Dict, List, Optional

import yaml
from django.db import transaction
from django.db.models import QuerySet
from idstools.rule import parse as parse_snort_rule
from plyara import Plyara

from detectiq.core.utils.logging import get_logger
from detectiq.webapp.backend.rules.models import StoredRule as Rule
from detectiq.webapp.backend.utils.mitre_utils import extract_mitre_info

logger = get_logger(__name__)


class DjangoRuleRepository:
    """Repository for managing rules in Django ORM."""

    def __init__(self, user_id: Optional[str] = None):
        """Initialize repository."""
        self.user_id = user_id
        logger.info("Initializing DjangoRuleRepository")

    def get_rules(self, filters: Optional[Dict[str, Any]] = None) -> QuerySet[Rule]:
        """Get rules with optional filters."""
        queryset = Rule.objects.all()

        if not filters:
            return queryset

        # Handle direct field filters
        filter_kwargs = {}
        for key, value in filters.items():
            if value is not None and key != "pagination":
                filter_kwargs[key] = value

        if filter_kwargs:
            queryset = queryset.filter(**filter_kwargs)
            logger.debug(f"Applied filters: {filter_kwargs}, resulting count: {queryset.count()}")

        return queryset.order_by("-created_at")

    async def get_rules_count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Get total count of rules matching filters."""
        queryset = Rule.objects.all()

        if filters:
            if "enabled" in filters:
                queryset = queryset.filter(enabled=filters["enabled"])
            if "type" in filters:
                queryset = queryset.filter(type=filters["type"])
            if "severity" in filters:
                queryset = queryset.filter(severity=filters["severity"])
            if "integration" in filters:
                queryset = queryset.filter(integration=filters["integration"])

        return await queryset.acount()

    @transaction.atomic
    async def sync_rules(self, integration_name: str, rules: List[Dict[str, Any]]) -> None:
        """Sync rules with atomic transaction."""
        try:
            logger.info(f"Starting rule sync for {integration_name}")

            # Disable existing rules from this integration
            await Rule.objects.filter(integration=integration_name, user_id=self.user_id).aupdate(enabled=False)

            # Create or update rules
            for rule in rules:
                await Rule.objects.aupdate_or_create(
                    title=rule["title"],
                    integration=integration_name,
                    user_id=self.user_id,
                    defaults={
                        "content": rule["content"],
                        "type": rule.get("type", "sigma"),
                        "severity": rule.get("severity", "medium"),
                        "description": rule.get("description", ""),
                        "enabled": True,
                    },
                )

            logger.info(f"Successfully synced {len(rules)} rules for {integration_name}")

        except Exception as e:
            logger.error(f"Error syncing rules: {e}")
            raise

    async def save_rules(self, rules: List[Dict[str, Any]], source: str) -> None:
        """Save rules to database."""

        for rule_data in rules:
            await Rule.objects.acreate(
                title=rule_data["title"],
                content=rule_data["content"],
                type=rule_data.get("type", "sigma"),
                severity=rule_data.get("severity", "medium"),
                integration=source,
                enabled=rule_data.get("enabled", True),
                description=rule_data.get("description", ""),
                user_id=self.user_id,
                source=rule_data.get("source", "DetectIQ"),
                metadata=rule_data.get("metadata", {}),
                package_type=rule_data.get("package_type", ""),
                mitre_tactics=rule_data.get("mitre_tactics", []),
                mitre_techniques=rule_data.get("mitre_techniques", []),
            )

    async def create_rule(self, rule_data: Dict[str, Any]) -> Rule:
        """Create rule asynchronously."""
        logger.info(f"Creating {rule_data.get('type', 'sigma')} rule from description")

        try:
            content = rule_data.get("content", "")
            rule_type = rule_data.get("type")

            if rule_type == "sigma":
                yaml_content = yaml.safe_load(content)
                if yaml_content and "description" in yaml_content:
                    rule_data["description"] = yaml_content["description"]
                mitre_tactics, mitre_techniques = extract_mitre_info(rule_type, rule_data)
                rule_data["mitre_tactics"] = mitre_tactics
                rule_data["mitre_techniques"] = mitre_techniques
            elif rule_type == "yara":
                parser = Plyara()
                parsed_rules = parser.parse_string(content)
                if parsed_rules:
                    rule = parsed_rules[0]  # Get first rule
                    # Extract description from metadata
                    if "metadata" in rule:
                        metadata = rule["metadata"]
                        if isinstance(metadata, dict):
                            rule_data["description"] = metadata.get("description", "")
                        elif isinstance(metadata, list):
                            for item in metadata:
                                if isinstance(item, dict) and "description" in item:
                                    rule_data["description"] = item["description"]
                                    break
            elif rule_type == "snort":
                parsed_rule = parse_snort_rule(content)
                if parsed_rule and parsed_rule.msg and not rule_data.get("description"):
                    rule_data["description"] = parsed_rule.msg

        except Exception as e:
            logger.error(f"Error extracting description from content: {e}")

        # Remove the flag before saving
        rule_data.pop("use_description_from_content", None)

        return await Rule.objects.acreate(**rule_data)

    def update_rule(self, rule_id: int, rule_data: Dict[str, Any]) -> Optional[Rule]:
        try:
            rule = Rule.objects.get(id=rule_id)
            for key, value in rule_data.items():
                setattr(rule, key, value)
            rule.save()
            return rule
        except Rule.DoesNotExist:
            return None

    def delete_rule(self, rule_id: int) -> bool:
        try:
            rule = Rule.objects.get(id=rule_id)
            rule.delete()
            return True
        except Rule.DoesNotExist:
            return False

    async def delete_rules_by_type(self, rule_type: str) -> None:
        """Delete all rules of a specific type."""
        try:
            await Rule.objects.filter(type=rule_type).adelete()
            logger.info(f"Deleted all rules of type {rule_type}")
        except Exception as e:
            logger.error(f"Error deleting rules of type {rule_type}: {e}")
            raise

    async def delete_all_rules(self) -> None:
        """Delete all rules from the database."""
        try:
            await Rule.objects.all().adelete()
            logger.info("Deleted all rules from database")
        except Exception as e:
            logger.error(f"Error deleting all rules: {e}")
            raise

    def create_rule_sync(self, rule_data: Dict[str, Any]) -> Rule:
        """Create rule synchronously."""
        logger.info(f"Creating {rule_data.get('type', 'sigma')} rule from description")
        return Rule.objects.create(**rule_data)

    async def delete_rules_by_type_and_source(self, rule_type: str, source: str) -> None:
        """Delete all rules of a specific type and source from the database."""
        try:
            await Rule.objects.filter(type=rule_type, source=source).adelete()
            logger.info(f"Successfully deleted all {rule_type} rules from source {source}")
        except Exception as e:
            logger.error(f"Error deleting {rule_type} rules from source {source}: {e}")
            raise

    async def bulk_save_rules(self, rules: List[Dict[str, Any]]) -> None:
        """Save multiple rules to the database using bulk create."""
        try:
            rule_objects = [
                Rule(
                    title=rule["title"],
                    content=rule["content"],
                    type=rule["type"],
                    severity=rule["severity"],
                    enabled=rule["enabled"],
                    description=rule["description"],
                    metadata=rule["metadata"],
                    source=rule["source"],
                    package_type=rule.get("package_type", ""),
                    mitre_tactics=rule.get("mitre_tactics", []),
                    mitre_techniques=rule.get("mitre_techniques", []),
                )
                for rule in rules
            ]

            await Rule.objects.abulk_create(rule_objects)
            logger.info(f"Successfully saved {len(rules)} rules to database")

        except Exception as e:
            logger.error(f"Error saving rules to database: {e}")
            raise
