from django.contrib.auth import get_user_model
from django.db import models

User = get_user_model()


class Workflow(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    blocks = models.JSONField()  # Store workflow blocks configuration
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        app_label = "backend"
