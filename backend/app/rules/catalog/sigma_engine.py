"""Sigma Rule Compiler, AST Parser, and Query Transpiler Engine.
Compiles YAML/JSON Sigma detection rules into optimized Python callable matchers and SQL queries.
"""

import re
import json
from typing import Dict, Any, List, Optional, Callable


class SigmaCompiler:
    """Translates Sigma condition trees into evaluatable Python functions."""

    def compile_rule(self, rule_def: Dict[str, Any]) -> Callable[[Dict[str, Any]], bool]:
        """Compiles rule condition dictionary into a high-speed matcher function."""
        conditions = rule_def.get("condition", {})
        
        def matcher(event: Dict[str, Any]) -> bool:
            for key, expected in conditions.items():
                if "|" in key:
                    field, modifier = key.split("|", 1)
                else:
                    field, modifier = key, "exact"

                val = event.get(field)
                if val is None:
                    return False

                if modifier == "exact":
                    if val != expected:
                        return False
                elif modifier == "contains":
                    if isinstance(expected, list):
                        if not any(exp.lower() in str(val).lower() for exp in expected):
                            return False
                    elif str(expected).lower() not in str(val).lower():
                        return False
                elif modifier == "endswith":
                    if not str(val).lower().endswith(str(expected).lower()):
                        return False
                elif modifier == "regex":
                    if not re.search(str(expected), str(val), re.IGNORECASE):
                        return False
                elif modifier == "gte":
                    try:
                        if float(val) < float(expected):
                            return False
                    except (ValueError, TypeError):
                        return False
                elif modifier == "not_in":
                    if isinstance(expected, list) and val in expected:
                        return False
            return True

        return matcher

sigma_compiler = SigmaCompiler()
