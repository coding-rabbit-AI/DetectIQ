from django.core.management.base import BaseCommand

from detectiq.webapp.backend.rules.models import StoredRule


class Command(BaseCommand):
    help = "Check rules in the database"

    def handle(self, *args, **options):
        rules = StoredRule.objects.all()
        count = rules.count()

        self.stdout.write(f"Total rules in database: {count}")

        if count > 0:
            self.stdout.write("\nSample of rules:")
            for rule in rules[:5]:
                self.stdout.write(f"\nRule ID: {str(rule.pk)}")
                self.stdout.write(f"Title: {rule.title}")
                self.stdout.write(f"Type: {rule.type}")
                self.stdout.write(f"Enabled: {rule.enabled}")
                self.stdout.write("-" * 40)
                self.stdout.write(f"Source: {rule.source}")
