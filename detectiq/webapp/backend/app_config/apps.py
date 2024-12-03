from django.apps import AppConfig


class AppConfigConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "detectiq.webapp.backend.app_config"
    label = "app_config"
