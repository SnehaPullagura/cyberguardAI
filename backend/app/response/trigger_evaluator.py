import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class TriggerEvaluator:
    """Safe evaluator for structured playbook trigger conditions without dynamic code execution."""

    SUPPORTED_OPERATORS = {
        "eq": lambda a, b: a == b,
        "ne": lambda a, b: a != b,
        "gt": lambda a, b: float(a) > float(b),
        "gte": lambda a, b: float(a) >= float(b),
        "lt": lambda a, b: float(a) < float(b),
        "lte": lambda a, b: float(a) <= float(b),
        "contains": lambda a, b: str(b).lower() in str(a).lower() if a is not None else False,
        "in": lambda a, b: a in b if isinstance(b, (list, tuple, set)) else str(a) in str(b),
    }

    @staticmethod
    def get_field_value(context: Dict[str, Any], field_path: str) -> Any:
        """Safely extract nested field from context dictionary using dot-notation."""
        if not field_path:
            return None
        parts = field_path.split(".")
        current = context
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif hasattr(current, part):
                current = getattr(current, part)
            else:
                return None
        return current

    def evaluate_single_condition(self, condition: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Evaluates a single condition dictionary against context."""
        field = condition.get("field")
        op = str(condition.get("operator", "eq")).lower()
        target_value = condition.get("value")

        if not field or op not in self.SUPPORTED_OPERATORS:
            logger.warning(f"Invalid condition specification: {condition}")
            return False

        actual_value = self.get_field_value(context, field)
        if actual_value is None:
            return False

        try:
            eval_fn = self.SUPPORTED_OPERATORS[op]
            return bool(eval_fn(actual_value, target_value))
        except (ValueError, TypeError) as e:
            logger.debug(f"Type error evaluating condition {field} {op} {target_value}: {e}")
            return False

    def evaluate_all(self, conditions: List[Dict[str, Any]], context: Dict[str, Any]) -> bool:
        """Evaluates all conditions with logical AND. Returns True if all conditions pass or if conditions list is empty."""
        if not conditions:
            return True

        for cond in conditions:
            if not self.evaluate_single_condition(cond, context):
                return False
        return True


trigger_evaluator = TriggerEvaluator()
