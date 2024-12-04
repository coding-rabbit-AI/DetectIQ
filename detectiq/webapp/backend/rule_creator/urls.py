from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import RuleCreatorViewSet

router = DefaultRouter()
router.register("", RuleCreatorViewSet, basename="rule-creator")

urlpatterns = [
    path("create-with-llm/", RuleCreatorViewSet.as_view({"post": "create_with_llm"}), name="create-with-llm"),
] + router.urls
