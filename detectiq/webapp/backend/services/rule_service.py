from typing import Any, Dict, List, Optional

import yaml
from django.db import transaction
from django.db.models import QuerySet
from idstools.rule import parse as parse_snort_rule
from plyara import Plyara

from detectiq.core.utils.logging import get_logger
from detectiq.webapp.backend.api.models import RuleVersion, StoredRule

logger = get_logger(__name__)


class DjangoRuleRepository:
    """Repository for managing rules in Django ORM."""

    def __init__(self, user_id: Optional[str] = None):
        """Initialize repository."""
        self.user_id = user_id
        logger.info("Initializing DjangoRuleRepository")

    def get_rules(self, filters: Optional[Dict[str, Any]] = None) -> QuerySet[StoredRule]:
        """Get rules with optional filters."""
        queryset = StoredRule.objects.all()

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
        queryset = StoredRule.objects.all()

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
            await StoredRule.objects.filter(integration=integration_name, user_id=self.user_id).aupdate(enabled=False)

            # Create or update rules
            for rule in rules:
                await StoredRule.objects.aupdate_or_create(
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
        source_mapping = {
            'sigma': 'SigmaHQ',
            'yara': 'YARA-Forge',
            'snort': 'Snort3 Community'
        }

        for rule_data in rules:
            rule_type = rule_data.get("type", "sigma")
            # Use the source mapping based on rule type
            rule_source = source_mapping.get(rule_type, 'DetectIQ')
            
            await StoredRule.objects.acreate(
                title=rule_data["title"],
                content=rule_data["content"],
                type=rule_data.get("type", "sigma"),
                severity=rule_data.get("severity", "medium"),
                integration=source,
                enabled=rule_data.get("enabled", True),
                description=rule_data.get("description", ""),
                user_id=self.user_id,
                source=rule_source  # Add the source field
            )

    async def create_rule(self, rule_data: Dict[str, Any]) -> StoredRule:
        """Create rule asynchronously."""
        logger.info(f"Creating {rule_data.get('type', 'sigma')} rule from description")

        try:
            content = rule_data.get("content", "")
            rule_type = rule_data.get("type")

            if rule_type == "sigma":
                yaml_content = yaml.safe_load(content)
                if yaml_content and "description" in yaml_content:
                    rule_data["description"] = yaml_content["description"]
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

        return await StoredRule.objects.acreate(**rule_data)

    def update_rule(self, rule_id: int, rule_data: Dict[str, Any]) -> Optional[StoredRule]:
        try:
            rule = StoredRule.objects.get(id=rule_id)
            for key, value in rule_data.items():
                setattr(rule, key, value)
            rule.save()
            return rule
        except StoredRule.DoesNotExist:
            return None

    def delete_rule(self, rule_id: int) -> bool:
        try:
            rule = StoredRule.objects.get(id=rule_id)
            rule.delete()
            return True
        except StoredRule.DoesNotExist:
            return False

    async def delete_rules_by_type(self, rule_type: str) -> None:
        """Delete all rules of a specific type."""
        try:
            await StoredRule.objects.filter(type=rule_type).adelete()
            logger.info(f"Deleted all rules of type {rule_type}")
        except Exception as e:
            logger.error(f"Error deleting rules of type {rule_type}: {e}")
            raise

    async def delete_all_rules(self) -> None:
        """Delete all rules from the database."""
        try:
            await StoredRule.objects.all().adelete()
            logger.info("Deleted all rules from database")
        except Exception as e:
            logger.error(f"Error deleting all rules: {e}")
            raise

    def create_rule_sync(self, rule_data: Dict[str, Any]) -> StoredRule:
        """Create rule synchronously."""
        logger.info(f"Creating {rule_data.get('type', 'sigma')} rule from description")
        return StoredRule.objects.create(**rule_data)
