"""KQL (Kusto Query Language) and Splunk SPL Query Transpiler for CyberGuard AI SIEM.
Translates enterprise security queries into optimized PostgreSQL / TimescaleDB SQL.
"""

import re
from typing import Dict, Any, List, Optional, Tuple


class QueryTranspilerError(Exception):
    """Raised when query syntax cannot be parsed or mapped."""
    pass


class KQLTranslator:
    """Translates Kusto Query Language (KQL) expressions to SQL queries."""

    TABLE_MAPPINGS = {
        "SecurityEvent": "events",
        "DeviceProcessEvents": "events",
        "DeviceNetworkEvents": "events",
        "DeviceLogonEvents": "events",
        "SigninLogs": "events",
        "AuditLogs": "events",
        "Alerts": "security_alerts",
        "Incidents": "incidents",
    }

    COLUMN_MAPPINGS = {
        "TimeGenerated": "timestamp",
        "Timestamp": "timestamp",
        "Account": "source_user",
        "AccountName": "source_user",
        "User": "source_user",
        "IPAddress": "source_ip",
        "SourceIP": "source_ip",
        "DestinationIP": "destination_ip",
        "DestIP": "destination_ip",
        "Action": "action",
        "Activity": "action",
        "EventID": "event_type",
        "Category": "category",
        "Severity": "severity",
        "RiskScore": "risk_score",
        "AnomalyScore": "anomaly_score",
        "ProcessCommandLine": "details",
        "CommandLine": "details",
    }

    def translate(self, kql_query: str) -> str:
        """Transpiles a multi-pipe KQL query string into ANSI/Postgres SQL."""
        if not kql_query or not kql_query.strip():
            raise QueryTranspilerError("Empty KQL query provided.")

        pipes = [p.strip() for p in kql_query.split("|") if p.strip()]
        if not pipes:
            raise QueryTranspilerError("Invalid KQL query structure.")

        # First pipe is the table identifier
        source_table_raw = pipes[0]
        source_table = self.TABLE_MAPPINGS.get(source_table_raw, "security_events")

        where_clauses: List[str] = []
        select_columns: List[str] = ["*"]
        order_by_clause: Optional[str] = None
        limit_clause: str = "LIMIT 100"
        aggregations: List[str] = []
        group_by_cols: List[str] = []

        for pipe in pipes[1:]:
            parts = pipe.split(maxsplit=1)
            operator = parts[0].lower()
            args = parts[1].strip() if len(parts) > 1 else ""

            if operator == "where":
                sql_cond = self._parse_where_clause(args)
                if sql_cond:
                    where_clauses.append(sql_cond)
            elif operator == "project":
                cols = [c.strip() for c in args.split(",")]
                select_columns = [self.COLUMN_MAPPINGS.get(c, c) for c in cols]
            elif operator in ("take", "limit"):
                try:
                    num = int(args)
                    limit_clause = f"LIMIT {num}"
                except ValueError:
                    limit_clause = "LIMIT 100"
            elif operator == "sort" or operator == "order":
                order_by_clause = self._parse_sort_clause(args)
            elif operator == "summarize":
                agg_select, grp_by = self._parse_summarize_clause(args)
                aggregations.extend(agg_select)
                group_by_cols.extend(grp_by)

        if aggregations:
            sel_str = ", ".join(aggregations + group_by_cols)
        else:
            sel_str = ", ".join(select_columns)

        sql = f"SELECT {sel_str} FROM {source_table}"

        if where_clauses:
            sql += " WHERE " + " AND ".join(where_clauses)

        if group_by_cols:
            sql += " GROUP BY " + ", ".join(group_by_cols)

        if order_by_clause:
            sql += f" {order_by_clause}"
        elif not aggregations:
            sql += " ORDER BY timestamp DESC"

        sql += f" {limit_clause}"
        return sql

    def _parse_where_clause(self, clause: str) -> str:
        """Parses KQL where condition operators."""
        # Replace contains
        clause = re.sub(
            r'(\w+)\s+contains\s+[\'"]([^\'"]+)[\'"]',
            lambda m: f"{self.COLUMN_MAPPINGS.get(m.group(1), m.group(1))} ILIKE '%{m.group(2)}%'",
            clause,
            flags=re.IGNORECASE
        )
        # Replace startswith
        clause = re.sub(
            r'(\w+)\s+startswith\s+[\'"]([^\'"]+)[\'"]',
            lambda m: f"{self.COLUMN_MAPPINGS.get(m.group(1), m.group(1))} ILIKE '{m.group(2)}%'",
            clause,
            flags=re.IGNORECASE
        )
        # Replace endswith
        clause = re.sub(
            r'(\w+)\s+endswith\s+[\'"]([^\'"]+)[\'"]',
            lambda m: f"{self.COLUMN_MAPPINGS.get(m.group(1), m.group(1))} ILIKE '%{m.group(2)}'",
            clause,
            flags=re.IGNORECASE
        )
        # Replace ==
        clause = re.sub(
            r'(\w+)\s*==\s*[\'"]([^\'"]+)[\'"]',
            lambda m: f"{self.COLUMN_MAPPINGS.get(m.group(1), m.group(1))} = '{m.group(2)}'",
            clause
        )
        # Replace !=
        clause = re.sub(
            r'(\w+)\s*!=\s*[\'"]([^\'"]+)[\'"]',
            lambda m: f"{self.COLUMN_MAPPINGS.get(m.group(1), m.group(1))} != '{m.group(2)}'",
            clause
        )
        # Replace in (list)
        clause = re.sub(
            r'(\w+)\s+in\s*\(([^)]+)\)',
            lambda m: f"{self.COLUMN_MAPPINGS.get(m.group(1), m.group(1))} IN ({m.group(2)})",
            clause,
            flags=re.IGNORECASE
        )
        # Replace and / or
        clause = re.sub(r'\band\b', 'AND', clause, flags=re.IGNORECASE)
        clause = re.sub(r'\bor\b', 'OR', clause, flags=re.IGNORECASE)
        return clause

    def _parse_sort_clause(self, args: str) -> str:
        """Parses sort by TimeGenerated desc."""
        parts = args.replace("by", "").strip().split()
        if not parts:
            return "ORDER BY timestamp DESC"
        col = self.COLUMN_MAPPINGS.get(parts[0], parts[0])
        direction = "ASC" if len(parts) > 1 and parts[1].lower() == "asc" else "DESC"
        return f"ORDER BY {col} {direction}"

    def _parse_summarize_clause(self, args: str) -> Tuple[List[str], List[str]]:
        """Parses summarize count() by Account, Category."""
        if "by" in args:
            agg_part, grp_part = args.split("by", 1)
        else:
            agg_part, grp_part = args, ""

        aggs: List[str] = []
        for a in agg_part.split(","):
            a = a.strip()
            if "count()" in a.lower():
                aggs.append("COUNT(*) AS count")
            elif "avg(" in a.lower():
                m = re.search(r'avg\((\w+)\)', a, re.IGNORECASE)
                if m:
                    col = self.COLUMN_MAPPINGS.get(m.group(1), m.group(1))
                    aggs.append(f"AVG({col}) AS avg_{col}")
            elif "sum(" in a.lower():
                m = re.search(r'sum\((\w+)\)', a, re.IGNORECASE)
                if m:
                    col = self.COLUMN_MAPPINGS.get(m.group(1), m.group(1))
                    aggs.append(f"SUM({col}) AS sum_{col}")

        grp_cols = [self.COLUMN_MAPPINGS.get(c.strip(), c.strip()) for c in grp_part.split(",") if c.strip()]
        return aggs, grp_cols


class SplunkSPLTranslator:
    """Translates Splunk Search Processing Language (SPL) into SQL."""

    def translate(self, spl_query: str) -> str:
        """Transpiles a Splunk SPL search pipeline to PostgreSQL SQL."""
        if not spl_query or not spl_query.strip():
            raise QueryTranspilerError("Empty SPL query provided.")

        pipes = [p.strip() for p in spl_query.split("|") if p.strip()]
        search_pipe = pipes[0] if pipes else ""

        # Extract search keywords
        where_clauses: List[str] = []
        if search_pipe.lower().startswith("search "):
            search_pipe = search_pipe[7:].strip()

        # Parse key=value pairs
        kv_pairs = re.findall(r'(\w+)=[\'"]?([^\s\'"]+)[\'"]?', search_pipe)
        for k, v in kv_pairs:
            col = KQLTranslator.COLUMN_MAPPINGS.get(k, k)
            if "*" in v:
                like_val = v.replace("*", "%")
                where_clauses.append(f"{col} ILIKE '{like_val}'")
            else:
                where_clauses.append(f"{col} = '{v}'")

        select_cols = ["*"]
        limit = 100

        for pipe in pipes[1:]:
            cmd = pipe.split(maxsplit=1)
            op = cmd[0].lower()
            args = cmd[1].strip() if len(cmd) > 1 else ""

            if op in ("head", "limit"):
                try:
                    limit = int(args)
                except ValueError:
                    limit = 100
            elif op == "fields":
                cols = [c.strip() for c in args.split(",") if not c.strip().startswith("-")]
                select_cols = [KQLTranslator.COLUMN_MAPPINGS.get(c, c) for c in cols if c]

        sql = f"SELECT {', '.join(select_cols)} FROM events"
        if where_clauses:
            sql += " WHERE " + " AND ".join(where_clauses)
        sql += f" ORDER BY timestamp DESC LIMIT {limit}"
        return sql


kql_translator = KQLTranslator()
spl_translator = SplunkSPLTranslator()
