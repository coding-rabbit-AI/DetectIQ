import re
from typing import Dict, List, Tuple

from detectiq.webapp.backend.rules.models import StoredRule


def extract_mitre_info(rule_type: str, rule: Dict) -> Tuple[List[str], List[str]]:
    """Extract MITRE tactics and techniques from rule."""
    tactics = []
    techniques = []

    if rule_type == "sigma":
        # Get tags from metadata
        metadata = rule.get("metadata", {})
        tags = metadata.get("tags", [])

        if not isinstance(tags, list):
            return [], []

        for tag in tags:
            if not isinstance(tag, str):
                continue

            if tag.startswith("attack."):
                tag_value = tag.replace("attack.", "").lower().replace("-", "_")

                # Handle techniques (check first as some tactics might start with t)
                if re.match(r"^t\d{4}(?:\.\d{3})?$", tag_value, re.IGNORECASE):
                    techniques.append(tag_value.upper())
                # Handle tactics
                elif tag_value in StoredRule.MITRE_TACTICS:
                    tactics.append(StoredRule.MITRE_TACTICS[tag_value])

    return tactics, techniques
