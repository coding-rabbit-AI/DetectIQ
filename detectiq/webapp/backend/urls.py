from django.urls import include, path
from rest_framework.routers import DefaultRouter

from detectiq.webapp.backend.rules.views import RuleViewSet

# Initialize the router
router = DefaultRouter()
router.register(r"rules", RuleViewSet, basename="rule")

urlpatterns = [
    path("", include(router.urls)),  # Remove 'api/' prefix
    path("settings/", include("detectiq.webapp.backend.api.urls")),  # Update to settings module
]
