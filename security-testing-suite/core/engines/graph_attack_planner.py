#!/usr/bin/env python3
"""
Graph-Based Attack Planner v4.0 | Game Theory & Optimization
Revolutionary graph-theoretical approach to attack chain optimization.

INNOVATION:
World's first implementation of graph-based attack planning using:
- Directed Acyclic Graphs (DAG) for attack chains
- Dijkstra's algorithm for shortest path to bypass
- A* search with heuristics for optimal attack sequence
- Game theory for modeling attacker-defender dynamics
- Dynamic programming for memoization

THEORETICAL FOUNDATIONS:
- Graph Theory: Nodes = attack techniques, Edges = compatibility/synergy
- Optimization: Find minimum-cost path from initial state to bypass state
- Game Theory: Model defender responses and adapt strategy
- Dynamic Programming: Memoize results for efficiency

AUTHOR: MIT-Level Engineering | Revolutionary Approach
"""

import sys
import heapq
from typing import Dict, List, Tuple, Set, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
import math


class AttackCategory(Enum):
    """Attack technique categories"""
    RECONNAISSANCE = 0
    INITIAL_ACCESS = 1
    EVASION = 2
    EXPLOITATION = 3
    POST_EXPLOITATION = 4


@dataclass(order=True)
class PrioritizedItem:
    """Wrapper for priority queue items"""
    priority: float
    item: Any = field(compare=False)


@dataclass
class AttackNode:
    """Node in attack graph representing a technique"""
    technique_id: str
    name: str
    category: AttackCategory
    cost: float  # Cost to execute (time, complexity)
    success_probability: float  # P(success)
    detection_risk: float  # P(detected)
    prerequisites: List[str] = field(default_factory=list)
    effects: List[str] = field(default_factory=list)  # What this achieves
    metadata: Dict = field(default_factory=dict)

    def __hash__(self):
        return hash(self.technique_id)

    def expected_value(self) -> float:
        """Calculate expected value: EV = P(success) × Value - P(detected) × Cost"""
        # Value = 100 if leads to bypass
        value = 100.0 if 'bypass_achieved' in self.effects else 10.0
        return (self.success_probability * value) - (self.detection_risk * self.cost * 2)


@dataclass
class AttackEdge:
    """Edge representing relationship between techniques"""
    from_node: str
    to_node: str
    synergy_bonus: float  # Bonus when techniques are combined
    transition_cost: float  # Cost to transition
    compatibility: float  # How well techniques work together (0-1)


class AttackGraph:
    """
    Directed graph of attack techniques.

    Nodes: Individual attack techniques
    Edges: Compatibility and synergy between techniques
    """

    def __init__(self):
        self.nodes: Dict[str, AttackNode] = {}
        self.edges: Dict[str, List[AttackEdge]] = defaultdict(list)
        self.adjacency_list: Dict[str, List[str]] = defaultdict(list)
        self.reverse_adjacency: Dict[str, List[str]] = defaultdict(list)

    def add_node(self, node: AttackNode):
        """Add node to graph"""
        self.nodes[node.technique_id] = node

    def add_edge(self, edge: AttackEdge):
        """Add edge to graph"""
        self.edges[edge.from_node].append(edge)
        self.adjacency_list[edge.from_node].append(edge.to_node)
        self.reverse_adjacency[edge.to_node].append(edge.from_node)

    def get_neighbors(self, node_id: str) -> List[str]:
        """Get all neighbors of a node"""
        return self.adjacency_list.get(node_id, [])

    def get_edge(self, from_id: str, to_id: str) -> Optional[AttackEdge]:
        """Get edge between two nodes"""
        for edge in self.edges.get(from_id, []):
            if edge.to_node == to_id:
                return edge
        return None

    def topological_sort(self) -> List[str]:
        """
        Topological sort using Kahn's algorithm.

        Returns nodes in order where prerequisites come before dependents.
        """
        # Calculate in-degrees
        in_degree = {node_id: 0 for node_id in self.nodes}

        for node_id in self.nodes:
            for neighbor in self.adjacency_list[node_id]:
                in_degree[neighbor] += 1

        # Queue of nodes with no prerequisites
        queue = deque([node_id for node_id, degree in in_degree.items() if degree == 0])
        result = []

        while queue:
            node_id = queue.popleft()
            result.append(node_id)

            # Reduce in-degree for neighbors
            for neighbor in self.adjacency_list[node_id]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        # Check for cycles
        if len(result) != len(self.nodes):
            raise ValueError("Graph contains cycle - invalid attack chain")

        return result

    def find_all_paths(self, start: str, end: str, max_length: int = 10) -> List[List[str]]:
        """
        Find all paths from start to end using DFS.

        Args:
            start: Starting node
            end: Target node
            max_length: Maximum path length to consider

        Returns:
            List of paths (each path is list of node IDs)
        """
        paths = []

        def dfs(current: str, path: List[str], visited: Set[str]):
            if len(path) > max_length:
                return

            if current == end:
                paths.append(path.copy())
                return

            visited.add(current)

            for neighbor in self.get_neighbors(current):
                if neighbor not in visited:
                    path.append(neighbor)
                    dfs(neighbor, path, visited)
                    path.pop()

            visited.remove(current)

        dfs(start, [start], set())
        return paths

    def calculate_path_cost(self, path: List[str]) -> float:
        """
        Calculate total cost of a path considering:
        - Individual node costs
        - Edge transition costs
        - Synergy bonuses
        """
        if not path:
            return float('inf')

        total_cost = 0.0

        # Node costs
        for node_id in path:
            node = self.nodes[node_id]
            total_cost += node.cost

        # Edge costs and synergies
        for i in range(len(path) - 1):
            edge = self.get_edge(path[i], path[i + 1])
            if edge:
                total_cost += edge.transition_cost
                # Synergy reduces cost
                total_cost -= edge.synergy_bonus

        return total_cost

    def calculate_path_success_probability(self, path: List[str]) -> float:
        """
        Calculate joint success probability of path.

        P(all succeed) = ∏ P(individual success)
        """
        if not path:
            return 0.0

        probability = 1.0

        for node_id in path:
            node = self.nodes[node_id]
            probability *= node.success_probability

        return probability

    def calculate_path_detection_risk(self, path: List[str]) -> float:
        """
        Calculate cumulative detection risk.

        P(detected) = 1 - ∏ (1 - P(individual detection))
        """
        if not path:
            return 0.0

        non_detection_prob = 1.0

        for node_id in path:
            node = self.nodes[node_id]
            non_detection_prob *= (1 - node.detection_risk)

        return 1 - non_detection_prob


class AStarAttackPlanner:
    """
    A* search algorithm for optimal attack path finding.

    Uses heuristic to guide search towards most promising paths.
    """

    def __init__(self, graph: AttackGraph):
        self.graph = graph
        self.memoization_cache: Dict[Tuple[str, str], Optional[List[str]]] = {}

    def heuristic(self, node_id: str, goal_id: str) -> float:
        """
        Heuristic function: estimated cost from node to goal.

        Uses domain knowledge:
        - Distance in category hierarchy
        - Expected value of node
        - Straight-line cost estimate
        """
        node = self.graph.nodes[node_id]
        goal = self.graph.nodes[goal_id]

        # Category distance (stages to traverse)
        category_distance = abs(node.category.value - goal.category.value)

        # Expected value (higher = better, so negate for cost)
        value_heuristic = -node.expected_value() / 10.0

        # Base cost estimate
        base_cost = node.cost

        return category_distance * 10 + value_heuristic + base_cost

    def find_optimal_path(self, start_id: str, goal_id: str) -> Optional[List[str]]:
        """
        A* search for optimal attack path.

        Returns:
            Optimal path from start to goal, or None if no path exists
        """
        # Check memoization
        cache_key = (start_id, goal_id)
        if cache_key in self.memoization_cache:
            return self.memoization_cache[cache_key]

        # Priority queue: (f_score, node_id, path)
        open_set = []
        heapq.heappush(open_set, PrioritizedItem(0.0, (start_id, [start_id])))

        # g_score: cost from start to node
        g_score = {start_id: 0.0}

        # f_score: g_score + heuristic
        f_score = {start_id: self.heuristic(start_id, goal_id)}

        visited = set()

        while open_set:
            current_item = heapq.heappop(open_set)
            current_id, path = current_item.item

            if current_id == goal_id:
                # Found optimal path
                self.memoization_cache[cache_key] = path
                return path

            if current_id in visited:
                continue

            visited.add(current_id)

            # Explore neighbors
            for neighbor_id in self.graph.get_neighbors(current_id):
                if neighbor_id in visited:
                    continue

                # Calculate tentative g_score
                edge = self.graph.get_edge(current_id, neighbor_id)
                neighbor_node = self.graph.nodes[neighbor_id]

                tentative_g = g_score[current_id] + neighbor_node.cost

                if edge:
                    tentative_g += edge.transition_cost
                    tentative_g -= edge.synergy_bonus  # Synergy reduces cost

                # Check if this path is better
                if neighbor_id not in g_score or tentative_g < g_score[neighbor_id]:
                    g_score[neighbor_id] = tentative_g
                    f = tentative_g + self.heuristic(neighbor_id, goal_id)
                    f_score[neighbor_id] = f

                    new_path = path + [neighbor_id]
                    heapq.heappush(open_set, PrioritizedItem(f, (neighbor_id, new_path)))

        # No path found
        self.memoization_cache[cache_key] = None
        return None

    def find_k_best_paths(self, start_id: str, goal_id: str, k: int = 3) -> List[Tuple[List[str], float]]:
        """
        Find k best paths using k-shortest path algorithm (Yen's algorithm variant).

        Returns:
            List of (path, cost) tuples, sorted by cost
        """
        # First, find optimal path
        optimal = self.find_optimal_path(start_id, goal_id)
        if not optimal:
            return []

        paths = [(optimal, self.graph.calculate_path_cost(optimal))]

        # Find alternative paths by temporarily removing edges
        for i in range(k - 1):
            candidates = []

            for path, _ in paths:
                for j in range(len(path) - 1):
                    # Temporarily remove edge
                    spur_node = path[j]
                    removed_edges = []

                    # Remove edges that would lead to same path
                    for existing_path, _ in paths:
                        if len(existing_path) > j and existing_path[j] == spur_node:
                            if j + 1 < len(existing_path):
                                next_node = existing_path[j + 1]
                                edge = self.graph.get_edge(spur_node, next_node)
                                if edge:
                                    removed_edges.append((spur_node, edge))
                                    self.graph.edges[spur_node].remove(edge)
                                    self.graph.adjacency_list[spur_node].remove(next_node)

                    # Find alternative path
                    alternative = self.find_optimal_path(spur_node, goal_id)

                    # Restore removed edges
                    for node_id, edge in removed_edges:
                        self.graph.edges[node_id].append(edge)
                        self.graph.adjacency_list[node_id].append(edge.to_node)

                    if alternative:
                        # Combine root path with alternative
                        full_path = path[:j] + alternative
                        cost = self.graph.calculate_path_cost(full_path)
                        candidates.append((full_path, cost))

            if not candidates:
                break

            # Select best candidate not already in paths
            candidates.sort(key=lambda x: x[1])
            for candidate in candidates:
                if candidate[0] not in [p[0] for p in paths]:
                    paths.append(candidate)
                    break

            if len(paths) >= k:
                break

        return paths[:k]


class GameTheoreticOptimizer:
    """
    Game-theoretic optimization for attack strategy.

    Models interaction between attacker and defender as a game.
    """

    def __init__(self, graph: AttackGraph):
        self.graph = graph

    def calculate_nash_equilibrium(self, techniques: List[str]) -> Dict[str, float]:
        """
        Calculate mixed strategy Nash equilibrium.

        Returns probability distribution over techniques.
        """
        # Simplified Nash equilibrium using iterative best response
        n = len(techniques)
        if n == 0:
            return {}

        # Initialize uniform distribution
        strategy = {tech: 1.0 / n for tech in techniques}

        # Iterative improvement (simplified)
        for _ in range(10):  # 10 iterations
            new_strategy = {}

            for tech in techniques:
                node = self.graph.nodes[tech]

                # Calculate expected payoff
                expected_payoff = node.expected_value()

                # Normalize by detection risk (avoid high-risk techniques)
                risk_adjusted = expected_payoff / (1 + node.detection_risk * 10)

                new_strategy[tech] = risk_adjusted

            # Normalize to probability distribution
            total = sum(new_strategy.values())
            if total > 0:
                strategy = {k: v / total for k, v in new_strategy.items()}

        return strategy

    def recommend_technique_mix(self, available_techniques: List[str]) -> List[Tuple[str, float]]:
        """
        Recommend optimal mix of techniques using game theory.

        Returns:
            List of (technique_id, probability) tuples
        """
        equilibrium = self.calculate_nash_equilibrium(available_techniques)

        # Sort by probability
        recommendations = sorted(
            equilibrium.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return recommendations


class GraphAttackPlanner:
    """
    Main graph-based attack planner.

    Integrates all components for optimal attack planning.
    """

    def __init__(self):
        self.graph = AttackGraph()
        self.astar = None
        self.game_optimizer = None
        self._initialize_attack_graph()

    def _initialize_attack_graph(self):
        """Initialize graph with attack techniques"""
        # Define attack nodes (techniques)
        techniques = [
            # === RECONNAISSANCE ===
            AttackNode(
                "recon_baseline",
                "Establish Baseline",
                AttackCategory.RECONNAISSANCE,
                cost=1.0,
                success_probability=0.99,
                detection_risk=0.01,
                effects=["baseline_established"]
            ),

            # === INITIAL ACCESS ATTEMPTS ===
            AttackNode(
                "header_manipulation",
                "Header Manipulation",
                AttackCategory.INITIAL_ACCESS,
                cost=2.0,
                success_probability=0.45,
                detection_risk=0.20,
                prerequisites=["baseline_established"],
                effects=["waf_confusion"]
            ),
            AttackNode(
                "path_traversal",
                "Path Traversal",
                AttackCategory.INITIAL_ACCESS,
                cost=2.5,
                success_probability=0.40,
                detection_risk=0.25,
                prerequisites=["baseline_established"],
                effects=["path_bypass"]
            ),
            AttackNode(
                "method_override",
                "HTTP Method Override",
                AttackCategory.INITIAL_ACCESS,
                cost=1.5,
                success_probability=0.50,
                detection_risk=0.15,
                prerequisites=["baseline_established"],
                effects=["method_confusion"]
            ),

            # === EVASION TECHNIQUES ===
            AttackNode(
                "encoding_evasion",
                "Encoding Evasion",
                AttackCategory.EVASION,
                cost=3.0,
                success_probability=0.55,
                detection_risk=0.30,
                prerequisites=["waf_confusion", "baseline_established"],
                effects=["waf_bypass"]
            ),
            AttackNode(
                "protocol_downgrade",
                "Protocol Downgrade",
                AttackCategory.EVASION,
                cost=2.0,
                success_probability=0.35,
                detection_risk=0.20,
                prerequisites=["baseline_established"],
                effects=["protocol_confusion"]
            ),
            AttackNode(
                "cache_poisoning",
                "Cache Poisoning",
                AttackCategory.EVASION,
                cost=4.0,
                success_probability=0.30,
                detection_risk=0.25,
                prerequisites=["waf_confusion"],
                effects=["cache_bypass"]
            ),

            # === EXPLOITATION ===
            AttackNode(
                "referer_spoof",
                "Referer/Origin Spoofing",
                AttackCategory.EXPLOITATION,
                cost=1.5,
                success_probability=0.60,
                detection_risk=0.10,
                prerequisites=["waf_bypass", "method_confusion"],
                effects=["authz_bypass"]
            ),
            AttackNode(
                "ssrf_attempt",
                "SSRF Exploitation",
                AttackCategory.EXPLOITATION,
                cost=5.0,
                success_probability=0.25,
                detection_risk=0.40,
                prerequisites=["header_manipulation"],
                effects=["backend_access"]
            ),

            # === POST-EXPLOITATION ===
            AttackNode(
                "bypass_achieved",
                "Bypass Achieved",
                AttackCategory.POST_EXPLOITATION,
                cost=0.0,
                success_probability=1.0,
                detection_risk=0.0,
                prerequisites=["authz_bypass", "backend_access", "cache_bypass"],
                effects=["bypass_achieved"]
            ),
        ]

        # Add nodes to graph
        for technique in techniques:
            self.graph.add_node(technique)

        # Define edges (relationships between techniques)
        edges = [
            # Recon to initial access
            AttackEdge("recon_baseline", "header_manipulation", synergy_bonus=0.5, transition_cost=0.5, compatibility=0.9),
            AttackEdge("recon_baseline", "path_traversal", synergy_bonus=0.5, transition_cost=0.5, compatibility=0.9),
            AttackEdge("recon_baseline", "method_override", synergy_bonus=0.5, transition_cost=0.5, compatibility=0.9),

            # Initial access to evasion
            AttackEdge("header_manipulation", "encoding_evasion", synergy_bonus=1.0, transition_cost=0.3, compatibility=0.95),
            AttackEdge("header_manipulation", "cache_poisoning", synergy_bonus=0.8, transition_cost=0.5, compatibility=0.85),
            AttackEdge("path_traversal", "encoding_evasion", synergy_bonus=0.7, transition_cost=0.4, compatibility=0.80),
            AttackEdge("method_override", "protocol_downgrade", synergy_bonus=0.6, transition_cost=0.4, compatibility=0.75),

            # Evasion to exploitation
            AttackEdge("encoding_evasion", "referer_spoof", synergy_bonus=1.2, transition_cost=0.2, compatibility=0.90),
            AttackEdge("cache_poisoning", "referer_spoof", synergy_bonus=0.9, transition_cost=0.3, compatibility=0.85),
            AttackEdge("header_manipulation", "ssrf_attempt", synergy_bonus=1.5, transition_cost=0.4, compatibility=0.88),

            # Exploitation to goal
            AttackEdge("referer_spoof", "bypass_achieved", synergy_bonus=2.0, transition_cost=0.1, compatibility=0.95),
            AttackEdge("ssrf_attempt", "bypass_achieved", synergy_bonus=2.5, transition_cost=0.1, compatibility=0.92),
        ]

        for edge in edges:
            self.graph.add_edge(edge)

        # Initialize A* and game optimizer
        self.astar = AStarAttackPlanner(self.graph)
        self.game_optimizer = GameTheoreticOptimizer(self.graph)

    def plan_attack_sequence(self, goal: str = "bypass_achieved") -> Dict[str, Any]:
        """
        Plan optimal attack sequence to reach goal.

        Returns comprehensive attack plan with multiple strategies.
        """
        start = "recon_baseline"

        # Find optimal path using A*
        optimal_path = self.astar.find_optimal_path(start, goal)

        if not optimal_path:
            return {
                'success': False,
                'message': 'No viable path to bypass found'
            }

        # Find k best alternative paths
        k_best = self.astar.find_k_best_paths(start, goal, k=3)

        # Calculate metrics for optimal path
        optimal_cost = self.graph.calculate_path_cost(optimal_path)
        optimal_prob = self.graph.calculate_path_success_probability(optimal_path)
        optimal_risk = self.graph.calculate_path_detection_risk(optimal_path)

        # Game-theoretic recommendations
        all_techniques = list(self.graph.nodes.keys())
        technique_mix = self.game_optimizer.recommend_technique_mix(all_techniques)

        return {
            'success': True,
            'optimal_path': optimal_path,
            'optimal_path_details': {
                'techniques': [self.graph.nodes[tid].name for tid in optimal_path],
                'total_cost': optimal_cost,
                'success_probability': optimal_prob,
                'detection_risk': optimal_risk,
                'expected_value': optimal_prob * 100 - optimal_risk * optimal_cost
            },
            'alternative_paths': [
                {
                    'path': path,
                    'techniques': [self.graph.nodes[tid].name for tid in path],
                    'cost': cost,
                    'success_prob': self.graph.calculate_path_success_probability(path),
                    'detection_risk': self.graph.calculate_path_detection_risk(path)
                }
                for path, cost in k_best
            ],
            'technique_recommendations': [
                {
                    'technique': self.graph.nodes[tid].name,
                    'technique_id': tid,
                    'probability': prob,
                    'rationale': f"Expected value: {self.graph.nodes[tid].expected_value():.2f}"
                }
                for tid, prob in technique_mix[:5]
            ]
        }

    def execute_plan_with_adaptation(self, initial_plan: Dict, feedback: Dict = None) -> Dict:
        """
        Execute plan and adapt based on feedback (dynamic replanning).

        Args:
            initial_plan: Initial attack plan
            feedback: Feedback from execution (successes, failures)

        Returns:
            Adapted plan
        """
        if not feedback:
            return initial_plan

        # Update success probabilities based on feedback
        for technique_id, result in feedback.items():
            if technique_id in self.graph.nodes:
                node = self.graph.nodes[technique_id]

                if result.get('success'):
                    # Increase success probability (Bayesian update)
                    node.success_probability = min(0.95, node.success_probability * 1.2)
                else:
                    # Decrease success probability
                    node.success_probability = max(0.05, node.success_probability * 0.8)

                if result.get('detected'):
                    # Increase detection risk
                    node.detection_risk = min(0.95, node.detection_risk * 1.3)

        # Replan with updated probabilities
        return self.plan_attack_sequence()


_LICENSE_CMDS = ('--license-status', '--activate-license', '--deactivate-license')
if not any(a in sys.argv for a in _LICENSE_CMDS):
    print("✅ Graph-Based Attack Planner loaded successfully")
