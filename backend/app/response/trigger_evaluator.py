import logging
from typing import Dict, Any, List, Union

logger = logging.getLogger(__name__)


class TriggerEvaluator:
    """Safe structured condition evaluator supporting allowlisted comparison operators without eval() or exec()."""

    ALLOWED_OPERATORS = ["gte", "gt", "lte", "lt", "eq", "ne", "in", "contains"]

    def evaluate_condition(self, condition: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Evaluate a single structured condition against event/alert/incident context."""
        field = condition.get("field")
        op = condition.get("operator")
        target_val = condition.get("value")

        if not field or not op or op not in self.ALLOWED_OPERATORS:
            return False

        # Extract field value from context dictionary
        actual_val = self._extract_nested_value(context, field)
        if actual_val is None:
            return False

        try:
            if op == "gte":
                return float(actual_val) >= float(target_val)
            elif op == "gt":
                return float(actual_val) > float(target_val)
            elif op == "lte":
                return float(actual_val) <= float(target_val)
            elif op == "lt":
                return float(actual_val) < float(target_val)
            elif op == "eq":
                return str(actual_val).lower() == str(target_val).lower()
            elif op == "ne":
                return str(actual_val).lower() != str(target_val).lower()
            elif op == "in":
                if isinstance(target_val, list):
                    return str(actual_val) in [str(x) for x in target_val]
                return str(actual_val) in str(target_val)
            elif op == "contains":
                return str(target_val).lower() in str(actual_val).lower()
        except (ValueError, TypeError) as e:
            logger.warning(f"Error evaluating condition {condition}: {e}")
            return False

        return False

    def evaluate_all_conditions(self, conditions: List[Dict[str, Any]], context: Dict[str, Any]) -> bool:
        """Evaluate list of conditions; all must evaluate to True (AND logic)."""
        if not conditions:
            return True
        for cond in conditions:
            if not self.evaluate_condition(cond, context):
                return False
        return True

    def _extract_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        parts = path.split(".")
        curr = data
        for p in parts:
            if isinstance(curr, dict) and p in curr:
                curr = curr[p]
            else:
                return None
        return curr


trigger_evaluator = TriggerEvaluator()
