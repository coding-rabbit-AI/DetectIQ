from django.core.management.base import BaseCommand

from detectiq.webapp.backend.api.models import StoredRule


class Command(BaseCommand):
    help = "Deletes all LLM-generated rules from the database"

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be deleted without actually deleting",
        )

    def handle(self, *args, **options):
        # Query for LLM-generated rules
        llm_rules = StoredRule.objects.filter(integration__startswith="llm_")
        count = llm_rules.count()

        if options["dry_run"]:
            self.stdout.write(self.style.WARNING(f"Would delete {count} LLM-generated rules"))
            for rule in llm_rules:
                self.stdout.write(f"- {rule.title} (ID: {rule.pk})")
        else:
            llm_rules.delete()
            self.stdout.write(self.style.SUCCESS(f"Successfully deleted {count} LLM-generated rules"))
