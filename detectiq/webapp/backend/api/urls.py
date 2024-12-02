from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import SettingsViewSet

router = DefaultRouter()
router.register(r"settings", SettingsViewSet, basename="settings")

urlpatterns = [
    path("", include(router.urls)),
]
