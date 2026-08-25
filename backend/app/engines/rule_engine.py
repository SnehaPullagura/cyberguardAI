import re
import yaml
import logging
from typing import Dict, Any, List, Optional
from app.models.event import SecurityEvent
from app.schemas.event import SecurityEventCreate

logger = logging.getLogger(__name__)


class RuleEngine:
    """Evaluates rule conditions against normalized security events."""

    @staticmethod
    def parse_yaml_rule(yaml_str: str) -> Dict[str, Any]:
        """Parse raw YAML Sigma/CyberGuard rule string into rule structure."""
        return yaml.safe_load(yaml_str)

    def evaluate_event(
        self, event: SecurityEventCreate, rule_condition: Dict[str, Any]
    ) -> bool:
        """Evaluate if an event satisfies the rule condition dict."""
        try:
            # Check category matching
            req_category = rule_condition.get("category")
            if req_category and req_category != "any" and req_category != event.category:
                return False

            # Check match_all conditions
            match_all = rule_condition.get("match_all", {})
            for field_path, expected_val in match_all.items():
                val = self._get_field_value(event, field_path)
                if not self._compare_value(val, expected_val):
                    return False

            # Check match_any conditions
            match_any = rule_condition.get("match_any", {})
            if match_any:
                any_matched = False
                for field_path, expected_val in match_any.items():
                    val = self._get_field_value(event, field_path)
                    if self._compare_value(val, expected_val):
                        any_matched = True
                        break
                if not any_matched:
                    return False

            return True
        except Exception as e:
            logger.error(f"Error evaluating rule condition: {e}")
            return False

    def _get_field_value(
        self, event: SecurityEventCreate, field_path: str
    ) -> Optional[Any]:
        """Extract value from event schema by field path string."""
        if field_path == "action":
            return event.action
        elif field_path == "category":
            return event.category
        elif field_path == "source_type":
            return event.source_type
        elif field_path == "severity":
            return event.severity
        elif field_path.startswith("source.") and event.source:
            sub_key = field_path.split(".", 1)[1]
            return getattr(event.source, sub_key, None)
        elif field_path.startswith("destination.") and event.destination:
            sub_key = field_path.split(".", 1)[1]
            return getattr(event.destination, sub_key, None)
        elif field_path.startswith("process.") and event.process:
            sub_key = field_path.split(".", 1)[1]
            return getattr(event.process, sub_key, None)
        elif field_path.startswith("observer.") and event.observer:
            sub_key = field_path.split(".", 1)[1]
            return getattr(event.observer, sub_key, None)
        elif field_path == "raw_payload":
            return event.raw_payload

        # Check in normalized payload
        if event.normalized_payload and field_path in event.normalized_payload:
            return event.normalized_payload.get(field_path)

        return None

    def _compare_value(self, actual: Any, expected: Any) -> bool:
        """Compare actual event value with rule expected value (supports list, regex, wildcard)."""
        if actual is None:
            return False

        if isinstance(expected, list):
            return any(self._compare_value(actual, item) for item in expected)

        actual_str = str(actual).lower()
        expected_str = str(expected).lower()

        if expected_str.startswith("regex:"):
            pattern = expected_str[6:]
            return bool(re.search(pattern, actual_str, re.IGNORECASE))
        elif expected_str.startswith("*") or expected_str.endswith("*"):
            pattern = expected_str.replace("*", ".*")
            return bool(re.match(f"^{pattern}$", actual_str, re.IGNORECASE))

        return actual_str == expected_str


rule_engine = RuleEngine()
