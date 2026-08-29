"""Threat Hunting Execution Engine & Job Coordinator."""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.hunting.kql_translator import kql_translator, spl_translator
from app.hunting.hunting_playbooks import THREAT_HUNTING_PLAYBOOKS, get_hunting_playbook_by_id

logger = logging.getLogger(__name__)


class ThreatHuntingEngine:
    """Coordinates retroactive threat hunts, KQL execution, and anomaly investigations."""

    def __init__(self):
        self.playbooks = THREAT_HUNTING_PLAYBOOKS

    def execute_hunt_query(
        self,
        db: Session,
        query: str,
        query_type: str = "kql",
        max_results: int = 100
    ) -> Dict[str, Any]:
        """Executes a KQL or SPL threat hunting query against the security event database."""
        start_time = datetime.now(timezone.utc)

        try:
            if query_type.lower() == "kql":
                sql_query = kql_translator.translate(query)
            elif query_type.lower() == "spl":
                sql_query = spl_translator.translate(query)
            else:
                sql_query = query

            logger.info("Executing translated threat hunt SQL: %s", sql_query)
            result_proxy = db.execute(text(sql_query))
            rows = result_proxy.fetchall()
            columns = list(result_proxy.keys()) if hasattr(result_proxy, "keys") else []

            results = []
            for row in rows[:max_results]:
                row_dict = {}
                for idx, col in enumerate(columns):
                    val = row[idx]
                    if isinstance(val, datetime):
                        val = val.isoformat()
                    row_dict[col] = val
                results.append(row_dict)

            execution_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

            return {
                "status": "success",
                "query": query,
                "query_type": query_type,
                "sql_executed": sql_query,
                "total_matches": len(results),
                "execution_time_ms": round(execution_ms, 2),
                "columns": columns,
                "results": results,
            }

        except Exception as e:
            logger.error("Threat hunt query execution failed: %s", e)
            execution_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            return {
                "status": "error",
                "query": query,
                "query_type": query_type,
                "error_message": str(e),
                "execution_time_ms": round(execution_ms, 2),
                "results": [],
            }

    def run_playbook_hunt(self, db: Session, hunt_id: str) -> Dict[str, Any]:
        """Executes a pre-defined threat hunt playbook by ID."""
        playbook = get_hunting_playbook_by_id(hunt_id)
        if not playbook:
            return {"status": "not_found", "message": f"Hunt playbook {hunt_id} not found."}

        kql = playbook.get("kql_query", "")
        hunt_results = self.execute_hunt_query(db, query=kql, query_type="kql")

        return {
            "hunt_id": hunt_id,
            "playbook_title": playbook.get("title"),
            "hypothesis": playbook.get("hypothesis"),
            "mitre_tactic": playbook.get("mitre_tactic"),
            "mitre_technique": playbook.get("mitre_technique"),
            "severity": playbook.get("severity"),
            "hunt_execution": hunt_results,
            "analysis_steps": playbook.get("analysis_steps"),
            "remediation_recommendation": playbook.get("remediation_recommendation"),
        }

    def list_playbooks(self, tactic: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns catalog of threat hunting playbooks filtered by MITRE tactic."""
        if not tactic:
            return self.playbooks
        return [p for p in self.playbooks if p.get("mitre_tactic", "").lower() == tactic.lower()]


hunting_engine = ThreatHuntingEngine()
