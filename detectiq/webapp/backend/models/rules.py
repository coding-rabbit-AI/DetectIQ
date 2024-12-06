from typing import Any, Dict, List, Optional, Tuple

import yaml
from django.contrib.auth import get_user_model
from django.db import models

User = get_user_model()

# Define types for rule choices
SeverityChoices = List[Tuple[str, str]]
SEVERITY_CHOICES: SeverityChoices = [
    ("informational", "Informational"),
    ("low", "Low"),
    ("medium", "Medium"),
    ("high", "High"),
    ("critical", "Critical"),
]
