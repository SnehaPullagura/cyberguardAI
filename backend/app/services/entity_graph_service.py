import logging
from typing import Dict, Any, List, Set, Optional
from sqlalchemy.orm import Session

from app.models.investigation import InvestigationCase, CaseEvidence
from app.models.incident import Incident
from app.models.alert import Alert

logger = logging.getLogger(__name__)


class EntityGraphService:
    """Builds multi-hop Entity Relationship Graphs for Cases and Incidents."""

    def build_case_graph(self, db: Session, case_id: str) -> Dict[str, Any]:
        """Constructs a network graph of all connected entities, alerts, and evidence in a case."""
        case = db.query(InvestigationCase).filter(
            (InvestigationCase.id == case_id) | (InvestigationCase.case_id == case_id)
        ).first()

        if not case:
            return {
                "case_id": case_id,
                "nodes": [],
                "edges": [],
                "nodes_count": 0,
                "edges_count": 0,
            }

        nodes_map: Dict[str, Dict[str, Any]] = {}
        edges: List[Dict[str, Any]] = []
        seen_edges: Set[str] = set()

        def add_node(node_id: str, label: str, node_type: str, props: Optional[Dict[str, Any]] = None):
            if node_id not in nodes_map:
                nodes_map[node_id] = {
                    "id": node_id,
                    "label": label,
                    "type": node_type,
                    "properties": props or {},
                }

        def add_edge(source: str, target: str, relationship: str):
            edge_key = f"{source}->{target}:{relationship}"
            if edge_key not in seen_edges and source in nodes_map and target in nodes_map:
                seen_edges.add(edge_key)
                edges.append({
                    "source": source,
                    "target": target,
                    "relationship": relationship,
                })

        # 1. Root Case Node
        case_node_id = f"case:{case.id}"
        add_node(case_node_id, case.title, "case", {
            "case_id": case.case_id,
            "status": case.status,
            "priority": case.priority,
            "severity": case.severity,
        })

        # 2. Linked Incident and its Alerts
        if case.incident_id:
            incident = db.query(Incident).filter(Incident.id == case.incident_id).first()
            if incident:
                inc_node_id = f"incident:{incident.id}"
                add_node(inc_node_id, incident.title, "incident", {
                    "incident_id": incident.incident_id,
                    "severity": incident.severity,
                })
                add_edge(case_node_id, inc_node_id, "investigates_incident")

                # Linked Alerts
                for inc_alert in incident.alerts:
                    alert = inc_alert.alert
                    if alert:
                        alert_node_id = f"alert:{alert.id}"
                        add_node(alert_node_id, alert.title, "alert", {
                            "severity": alert.severity,
                            "risk_score": alert.risk_score,
                        })
                        add_edge(inc_node_id, alert_node_id, "triggered_by")

                        # Extract entities from alert
                        if alert.source_entity:
                            s_node = f"entity:{alert.source_entity}"
                            add_node(s_node, alert.source_entity, "entity")
                            add_edge(alert_node_id, s_node, "source_entity")

                        if alert.target_entity:
                            t_node = f"entity:{alert.target_entity}"
                            add_node(t_node, alert.target_entity, "entity")
                            add_edge(alert_node_id, t_node, "target_entity")

        # 3. Evidence Items
        for ev in case.evidence_items:
            ev_node_id = f"evidence:{ev.id}"
            add_node(ev_node_id, ev.title, "evidence", {"type": ev.evidence_type})
            add_edge(case_node_id, ev_node_id, "contains_evidence")

            # Link evidence internal entities
            if isinstance(ev.data, dict):
                if "source_ip" in ev.data and ev.data["source_ip"]:
                    sip = ev.data["source_ip"]
                    ip_id = f"ip:{sip}"
                    add_node(ip_id, sip, "ip")
                    add_edge(ev_node_id, ip_id, "references_ip")

                if "user" in ev.data and ev.data["user"]:
                    u_name = ev.data["user"]
                    u_id = f"user:{u_name}"
                    add_node(u_id, u_name, "user")
                    add_edge(ev_node_id, u_id, "references_user")

                if "hash" in ev.data and ev.data["hash"]:
                    h_val = ev.data["hash"]
                    h_id = f"hash:{h_val[:12]}..."
                    add_node(h_id, h_val[:16], "file_hash", {"full_hash": h_val})
                    add_edge(ev_node_id, h_id, "references_hash")

        return {
            "case_id": case.case_id,
            "nodes": list(nodes_map.values()),
            "edges": edges,
            "nodes_count": len(nodes_map),
            "edges_count": len(edges),
        }


entity_graph_service = EntityGraphService()
