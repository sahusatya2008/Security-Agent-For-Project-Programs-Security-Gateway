from __future__ import annotations

import networkx as nx

from core.schemas import VulnerabilityFinding


class SecurityKnowledgeGraph:
    def __init__(self) -> None:
        self.graph = nx.DiGraph()

    def add_finding(self, finding: VulnerabilityFinding) -> None:
        vuln = finding.vulnerability_type
        sev = finding.severity
        self.graph.add_node(vuln, kind="vulnerability")
        self.graph.add_node(sev, kind="severity")
        self.graph.add_edge(vuln, sev, relation="classified_as")

    def summary(self) -> dict:
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
        }
