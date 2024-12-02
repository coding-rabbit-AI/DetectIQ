from django.core.management.base import BaseCommand
from django.db import transaction

from detectiq.core.utils.logging import get_logger
from detectiq.webapp.backend.rules.models import StoredRule

logger = get_logger(__name__)


class Command(BaseCommand):
    help = "Delete all rules from the database"

    def add_arguments(self, parser):
        parser.add_argument(
            "--rule-type",
            type=str,
            choices=["sigma", "yara", "snort"],
            help="Optionally specify a rule type to delete only those rules",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be deleted without actually deleting",
        )

    def handle(self, *args, **options):
        rule_type = options["rule_type"]
        dry_run = options["dry_run"]

        try:
            with transaction.atomic():
                # Build the queryset based on rule type
                queryset = StoredRule.objects.all()
                if rule_type:
                    queryset = queryset.filter(type=rule_type)
                    type_msg = f"{rule_type} rules"
                else:
                    type_msg = "rules"

                # Get count before deletion
                count = queryset.count()

                if dry_run:
                    self.stdout.write(self.style.WARNING(f"Would delete {count} {type_msg} (dry run)"))
                else:
                    # Delete the rules
                    queryset.delete()
                    self.stdout.write(self.style.SUCCESS(f"Successfully deleted {count} {type_msg}"))

                logger.info(f"{'Would delete' if dry_run else 'Deleted'} {count} {type_msg}")

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error deleting rules: {str(e)}"))
            logger.error(f"Error in delete_all_rules command: {str(e)}")
            raise
