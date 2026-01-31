"""
causal_graph.py - Causal security graph implementation

Implements the main causal graph structure with:
- DAG management and cycle detection
- Dijkstra variant for maximum probability paths
- Simplified belief propagation
- Vulnerability inference from anomalies
"""

import logging
import heapq
import time
import numpy as np
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from .causal_node import CausalNode, NodeType
from .causal_edge import CausalEdge, CausalityType

logger = logging.getLogger('security_suite.causal_graph')


@dataclass
class PathResult:
    """Result of path finding."""
    path: List[str]
    probability: float
    edges: List[CausalEdge]


@dataclass
class InferenceResult:
    """Result of vulnerability inference."""
    source_nodes: List[str]
    confidence: float
    path: List[str]
    explanation: str


class CausalSecurityGraph:
    """
    Directed Acyclic Graph for causal security analysis.

    Implements:
    - Node and edge management with DAG constraints
    - Modified Dijkstra for maximum probability paths
    - Backward DFS for vulnerability inference
    - Belief propagation (simplified Pearl's algorithm)

    Complexity:
    - add_node: O(1)
    - add_edge: O(d) where d = depth limit for cycle detection
    - find_max_probability_path: O((V+E) log V)
    - infer_vulnerability_from_anomaly: O(V+E)
    """

    # Configuration
    MAX_CYCLE_DETECTION_DEPTH = 100
    DEFAULT_EDGE_STRENGTH = 0.5
    PROPAGATION_DECAY = 0.9

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize causal security graph.

        Args:
            config: Optional configuration overrides
        """
        self._nodes: Dict[str, CausalNode] = {}
        self._edges: Dict[str, CausalEdge] = {}

        # Adjacency lists for efficient traversal
        self._outgoing: Dict[str, Set[str]] = defaultdict(set)
        self._incoming: Dict[str, Set[str]] = defaultdict(set)

        # Configuration
        config = config or {}
        self._max_cycle_depth = config.get('max_cycle_depth', self.MAX_CYCLE_DETECTION_DEPTH)
        self._default_strength = config.get('default_edge_strength', self.DEFAULT_EDGE_STRENGTH)
        self._propagation_decay = config.get('propagation_decay', self.PROPAGATION_DECAY)

        logger.debug("Created CausalSecurityGraph")

    @property
    def node_count(self) -> int:
        """Number of nodes in graph."""
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        """Number of edges in graph."""
        return len(self._edges)

    def add_node(
        self,
        node_id: str,
        node_type: NodeType,
        name: str = '',
        metadata: Optional[Dict[str, Any]] = None
    ) -> CausalNode:
        """
        Add a node to the graph.

        Args:
            node_id: Unique identifier
            node_type: Type of node
            name: Human-readable name
            metadata: Additional metadata

        Returns:
            The created or existing node

        Complexity: O(1)
        """
        if node_id in self._nodes:
            logger.debug(f"Node {node_id} already exists")
            return self._nodes[node_id]

        node = CausalNode(
            node_id=node_id,
            node_type=node_type,
            name=name,
            metadata=metadata
        )

        self._nodes[node_id] = node
        logger.debug(f"Added node: {node_id}")

        return node

    def get_node(self, node_id: str) -> Optional[CausalNode]:
        """Get a node by ID."""
        return self._nodes.get(node_id)

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        causality_type: CausalityType = CausalityType.DIRECT,
        strength: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[CausalEdge]:
        """
        Add an edge between two nodes.

        Args:
            source_id: Source node ID (cause)
            target_id: Target node ID (effect)
            causality_type: Type of causal relationship
            strength: Initial causality strength
            metadata: Additional metadata

        Returns:
            The created edge, or None if would create cycle

        Raises:
            ValueError: If source or target node doesn't exist

        Complexity: O(d) where d = max cycle detection depth
        """
        # Validate nodes exist
        if source_id not in self._nodes:
            raise ValueError(f"Source node not found: {source_id}")
        if target_id not in self._nodes:
            raise ValueError(f"Target node not found: {target_id}")

        # Check for existing edge
        edge_id = f"{source_id}->{target_id}"
        if edge_id in self._edges:
            logger.debug(f"Edge {edge_id} already exists")
            return self._edges[edge_id]

        # Check for cycle
        if self._would_create_cycle(source_id, target_id):
            logger.warning(f"Edge {edge_id} would create cycle, rejected")
            return None

        # Create edge
        strength = strength if strength is not None else self._default_strength

        try:
            edge = CausalEdge(
                source_id=source_id,
                target_id=target_id,
                causality_type=causality_type,
                initial_strength=strength,
                metadata=metadata
            )
        except ValueError as e:
            logger.error(f"Failed to create edge: {e}")
            return None

        self._edges[edge_id] = edge
        self._outgoing[source_id].add(target_id)
        self._incoming[target_id].add(source_id)

        logger.debug(f"Added edge: {edge_id}")
        return edge

    def get_edge(self, source_id: str, target_id: str) -> Optional[CausalEdge]:
        """Get an edge by source and target IDs."""
        edge_id = f"{source_id}->{target_id}"
        return self._edges.get(edge_id)

    def _would_create_cycle(self, source_id: str, target_id: str) -> bool:
        """
        Check if adding edge source->target would create a cycle.

        Uses depth-limited DFS from target to check if we can reach source.

        Args:
            source_id: Proposed edge source
            target_id: Proposed edge target

        Returns:
            True if would create cycle, False otherwise

        Complexity: O(d) where d = max depth
        """
        if source_id == target_id:
            return True

        # DFS from target to see if we can reach source
        visited = set()
        stack = [(target_id, 0)]

        while stack:
            node_id, depth = stack.pop()

            if depth > self._max_cycle_depth:
                # Depth limit reached, assume no cycle
                continue

            if node_id == source_id:
                return True

            if node_id in visited:
                continue

            visited.add(node_id)

            for neighbor in self._outgoing.get(node_id, set()):
                if neighbor not in visited:
                    stack.append((neighbor, depth + 1))

        return False

    def find_max_probability_path(
        self,
        source_id: str,
        target_id: str
    ) -> Optional[PathResult]:
        """
        Find the path with maximum probability from source to target.

        Uses modified Dijkstra's algorithm where:
        - Edge weights are -log(strength) for shortest path = highest probability
        - Path probability is product of edge strengths

        Args:
            source_id: Starting node ID
            target_id: Destination node ID

        Returns:
            PathResult with path and probability, or None if no path

        Complexity: O((V+E) log V)
        """
        if source_id not in self._nodes or target_id not in self._nodes:
            return None

        # Distance = -log(probability), so min distance = max probability
        distances: Dict[str, float] = {source_id: 0.0}
        predecessors: Dict[str, Optional[str]] = {source_id: None}

        # Priority queue: (distance, node_id)
        pq = [(0.0, source_id)]
        visited = set()

        while pq:
            dist, node_id = heapq.heappop(pq)

            if node_id in visited:
                continue
            visited.add(node_id)

            if node_id == target_id:
                break

            for neighbor in self._outgoing.get(node_id, set()):
                if neighbor in visited:
                    continue

                edge = self.get_edge(node_id, neighbor)
                if edge is None or edge.strength <= 0:
                    continue

                # Convert probability to distance
                edge_dist = -np.log(edge.strength)
                new_dist = dist + edge_dist

                if neighbor not in distances or new_dist < distances[neighbor]:
                    distances[neighbor] = new_dist
                    predecessors[neighbor] = node_id
                    heapq.heappush(pq, (new_dist, neighbor))

        # Reconstruct path
        if target_id not in predecessors:
            return None

        path = []
        current = target_id
        while current is not None:
            path.append(current)
            current = predecessors.get(current)
        path.reverse()

        # Calculate total probability and collect edges
        probability = 1.0
        edges = []
        for i in range(len(path) - 1):
            edge = self.get_edge(path[i], path[i + 1])
            if edge:
                probability *= edge.strength
                edges.append(edge)

        return PathResult(path=path, probability=probability, edges=edges)

    def infer_vulnerability_from_anomaly(
        self,
        anomaly_node_id: str,
        min_strength: float = 0.3
    ) -> List[InferenceResult]:
        """
        Infer potential vulnerability sources from an anomaly.

        Uses backward DFS to find nodes that could have caused the anomaly.

        Args:
            anomaly_node_id: Node where anomaly was detected
            min_strength: Minimum edge strength to consider

        Returns:
            List of potential sources with confidence scores

        Complexity: O(V+E)
        """
        if anomaly_node_id not in self._nodes:
            return []

        results = []
        visited = set()

        def backward_dfs(
            node_id: str,
            path: List[str],
            cumulative_strength: float
        ) -> None:
            """Recursive backward DFS."""
            if node_id in visited:
                return
            visited.add(node_id)

            current_path = path + [node_id]

            # Check if this could be a source (has few or no incoming edges)
            incoming = self._incoming.get(node_id, set())
            is_potential_source = len(incoming) <= 1

            if is_potential_source and len(current_path) > 1:
                # Found potential source
                node = self._nodes.get(node_id)
                explanation = self._generate_explanation(current_path)

                results.append(InferenceResult(
                    source_nodes=[node_id],
                    confidence=cumulative_strength,
                    path=list(reversed(current_path)),
                    explanation=explanation
                ))

            # Continue backward traversal
            for predecessor_id in incoming:
                edge = self.get_edge(predecessor_id, node_id)
                if edge and edge.strength >= min_strength:
                    new_strength = cumulative_strength * edge.strength * self._propagation_decay
                    if new_strength >= min_strength * 0.1:  # Threshold for continuing
                        backward_dfs(predecessor_id, current_path, new_strength)

        # Start backward DFS
        backward_dfs(anomaly_node_id, [], 1.0)

        # Sort by confidence
        results.sort(key=lambda r: r.confidence, reverse=True)

        return results

    def _generate_explanation(self, path: List[str]) -> str:
        """Generate human-readable explanation for inferred path."""
        if len(path) < 2:
            return "Direct anomaly source"

        parts = []
        for i in range(len(path) - 1):
            source = self._nodes.get(path[i])
            target = self._nodes.get(path[i + 1])
            edge = self.get_edge(path[i], path[i + 1])

            if source and target and edge:
                parts.append(
                    f"{source.name} causes {target.name} "
                    f"(strength: {edge.strength:.2f})"
                )

        return " -> ".join(parts)

    def propagate_beliefs(
        self,
        evidence: Dict[str, float],
        max_iterations: int = 100,
        convergence_threshold: float = 1e-6
    ) -> Dict[str, float]:
        """
        Propagate beliefs through the graph (simplified belief propagation).

        Args:
            evidence: Dict mapping node_id to observed value/belief
            max_iterations: Maximum iterations
            convergence_threshold: Stop when max change < threshold

        Returns:
            Dict mapping node_id to updated belief

        Complexity: O(iterations * E)
        """
        # Initialize beliefs
        beliefs = {node_id: 0.5 for node_id in self._nodes}
        beliefs.update(evidence)

        for iteration in range(max_iterations):
            max_change = 0.0
            new_beliefs = beliefs.copy()

            for node_id in self._nodes:
                if node_id in evidence:
                    continue  # Don't update evidence nodes

                # Collect messages from parents
                incoming_messages = []
                for parent_id in self._incoming.get(node_id, set()):
                    edge = self.get_edge(parent_id, node_id)
                    if edge:
                        message = beliefs[parent_id] * edge.strength
                        incoming_messages.append(message)

                # Update belief
                if incoming_messages:
                    new_belief = np.mean(incoming_messages)
                    change = abs(new_belief - beliefs[node_id])
                    max_change = max(max_change, change)
                    new_beliefs[node_id] = new_belief

            beliefs = new_beliefs

            if max_change < convergence_threshold:
                logger.debug(f"Belief propagation converged at iteration {iteration}")
                break

        return beliefs

    def get_subgraph(
        self,
        node_ids: Set[str],
        include_edges: bool = True
    ) -> 'CausalSecurityGraph':
        """
        Extract subgraph containing specified nodes.

        Args:
            node_ids: Set of node IDs to include
            include_edges: Whether to include edges between nodes

        Returns:
            New CausalSecurityGraph with subset of nodes/edges
        """
        subgraph = CausalSecurityGraph()

        # Add nodes
        for node_id in node_ids:
            node = self._nodes.get(node_id)
            if node:
                subgraph._nodes[node_id] = node

        # Add edges
        if include_edges:
            for edge_id, edge in self._edges.items():
                if edge.source_id in node_ids and edge.target_id in node_ids:
                    subgraph._edges[edge_id] = edge
                    subgraph._outgoing[edge.source_id].add(edge.target_id)
                    subgraph._incoming[edge.target_id].add(edge.source_id)

        return subgraph

    def get_descendants(self, node_id: str) -> Set[str]:
        """Get all nodes reachable from given node."""
        descendants = set()
        stack = list(self._outgoing.get(node_id, set()))

        while stack:
            current = stack.pop()
            if current not in descendants:
                descendants.add(current)
                stack.extend(self._outgoing.get(current, set()))

        return descendants

    def get_ancestors(self, node_id: str) -> Set[str]:
        """Get all nodes that can reach given node."""
        ancestors = set()
        stack = list(self._incoming.get(node_id, set()))

        while stack:
            current = stack.pop()
            if current not in ancestors:
                ancestors.add(current)
                stack.extend(self._incoming.get(current, set()))

        return ancestors

    def topological_sort(self) -> List[str]:
        """
        Return nodes in topological order.

        Returns:
            List of node IDs in topological order

        Raises:
            ValueError: If graph has cycles
        """
        in_degree = {node_id: len(self._incoming.get(node_id, set()))
                     for node_id in self._nodes}

        queue = [node_id for node_id, degree in in_degree.items() if degree == 0]
        result = []

        while queue:
            node_id = queue.pop(0)
            result.append(node_id)

            for neighbor in self._outgoing.get(node_id, set()):
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        if len(result) != len(self._nodes):
            raise ValueError("Graph contains cycles")

        return result

    def to_dict(self) -> Dict[str, Any]:
        """Serialize graph to dictionary."""
        return {
            'nodes': {
                node_id: node.to_dict()
                for node_id, node in self._nodes.items()
            },
            'edges': {
                edge_id: edge.to_dict()
                for edge_id, edge in self._edges.items()
            },
            'config': {
                'max_cycle_depth': self._max_cycle_depth,
                'default_strength': self._default_strength,
                'propagation_decay': self._propagation_decay
            }
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CausalSecurityGraph':
        """Deserialize graph from dictionary."""
        graph = cls(config=data.get('config', {}))

        # Restore nodes
        for node_id, node_data in data.get('nodes', {}).items():
            node = CausalNode.from_dict(node_data)
            graph._nodes[node_id] = node

        # Restore edges
        for edge_id, edge_data in data.get('edges', {}).items():
            edge = CausalEdge.from_dict(edge_data)
            graph._edges[edge_id] = edge
            graph._outgoing[edge.source_id].add(edge.target_id)
            graph._incoming[edge.target_id].add(edge.source_id)

        return graph

    def __repr__(self) -> str:
        return f"CausalSecurityGraph(nodes={self.node_count}, edges={self.edge_count})"
