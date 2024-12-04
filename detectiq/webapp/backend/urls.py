from django.urls import include, path

urlpatterns = [
    path("", include("detectiq.webapp.backend.rules.urls")),
    path("app-config/", include("detectiq.webapp.backend.app_config.urls")),
    path("rule-creator/", include("detectiq.webapp.backend.rule_creator.urls")),
]
