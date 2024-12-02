import yaml
from django.core.management.base import BaseCommand
from django.db import transaction

from detectiq.webapp.backend.rules.models import StoredRule


class Command(BaseCommand):
    help = "Normalize severity values and sources for existing rules in the database"

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be updated without making changes",
        )

    def normalize_severity(self, severity: str) -> str:
        """Normalize severity value."""
        valid_severities = ["informational", "low", "medium", "high", "critical"]
        normalized = severity.lower()
        return normalized if normalized in valid_severities else "medium"

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        updated_count = 0
        error_count = 0

        source_mapping = {"sigma": "SigmaHQ", "yara": "YARA-Forge", "snort": "Snort3 Community"}

        with transaction.atomic():
            # Get all rules
            rules = StoredRule.objects.all()
            total_rules = rules.count()

            self.stdout.write(f"Processing {total_rules} rules...")

            for rule in rules:
                try:
                    updates_made = False

                    # Source normalization
                    if not rule.source:
                        new_source = source_mapping.get(rule.type.lower(), "DetectIQ")
                        if not dry_run:
                            rule.source = new_source
                            updates_made = True
                            self.stdout.write(f"Rule '{rule.title}': Added source -> {new_source}")

                    # Severity normalization (only for Sigma rules)
                    if rule.type.lower() == "sigma":
                        yaml_content = yaml.safe_load(rule.content)
                        if yaml_content:
                            yaml_severity = yaml_content.get("level", "medium")
                            new_severity = self.normalize_severity(yaml_severity)

                            if rule.severity != new_severity:
                                if not dry_run:
                                    rule.severity = new_severity
                                    updates_made = True
                                self.stdout.write(f"Rule '{rule.title}': {rule.severity} -> {new_severity}")

                    if updates_made and not dry_run:
                        rule.save()
                        updated_count += 1

                except yaml.YAMLError as e:
                    error_count += 1
                    self.stdout.write(self.style.ERROR(f"Error parsing YAML for rule '{rule.title}': {str(e)}"))
                except Exception as e:
                    error_count += 1
                    self.stdout.write(self.style.ERROR(f"Error processing rule '{rule.title}': {str(e)}"))

        action = "Would update" if dry_run else "Updated"
        self.stdout.write(
            self.style.SUCCESS(
                f"\nCompleted! {action} {updated_count} rules. "
                f"Encountered {error_count} errors. "
                f"Total rules processed: {total_rules}"
            )
        )
