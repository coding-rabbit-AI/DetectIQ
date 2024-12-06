from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import RuleViewSet

router = DefaultRouter()
router.register("rules", RuleViewSet, basename="rules")  # Remove 'api/' prefix

urlpatterns = router.urls
