from django.contrib import admin
from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .api.views import RuleViewSet, SettingsViewSet

router = DefaultRouter()
router.register(r"rules", RuleViewSet, basename="rule")
router.register(r"settings", SettingsViewSet, basename="settings")

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include(router.urls)),
    path("api/rules/status/<str:request_id>/", RuleViewSet.as_view({"get": "status"}), name="rule-status"),
    path("api/rules/last-request/", RuleViewSet.as_view({"get": "last_request"}), name="last-request"),
]
