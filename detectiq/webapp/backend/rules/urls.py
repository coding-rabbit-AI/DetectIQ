from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import RuleViewSet

router = DefaultRouter()
router.register("", RuleViewSet, basename="rules")

urlpatterns = router.urls
