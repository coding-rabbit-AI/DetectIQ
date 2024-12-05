from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import AppConfigViewSet

router = DefaultRouter()
router.register("", AppConfigViewSet, basename="app-config")

urlpatterns = [
    path("get-config/", AppConfigViewSet.as_view({"get": "get_config"}), name="get-config"),
    path("update-config/", AppConfigViewSet.as_view({"post": "update_config"}), name="update-config"),
    path("test-integration/", AppConfigViewSet.as_view({"post": "test_integration"}), name="test-integration"),
    path("check-vectorstores/", AppConfigViewSet.as_view({"get": "check_vectorstores"}), name="check-vectorstores"),
    path("create-vectorstore/", AppConfigViewSet.as_view({"post": "create_vectorstore"}), name="create-vectorstore"),
    path("check-rule-packages/", AppConfigViewSet.as_view({"get": "check_rule_packages"}), name="check-rule-packages"),
    path("update-rule-package/", AppConfigViewSet.as_view({"post": "update_rule_package"}), name="update-rule-package"),
] + router.urls
