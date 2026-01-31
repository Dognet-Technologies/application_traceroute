"""
adaptive_taxonomy.py - Self-learning vulnerability taxonomy

Implements adaptive categorization using:
- HDBSCAN clustering for vulnerability grouping
- Auto-naming based on cluster characteristics
- Hierarchical taxonomy management
- Pattern learning from observations
"""

import logging
import time
import re
import numpy as np
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import hdbscan
    HDBSCAN_AVAILABLE = True
except ImportError:
    HDBSCAN_AVAILABLE = False

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger('security_suite.adaptive_taxonomy')


class TaxonomyLevel(Enum):
    """Hierarchy levels in taxonomy."""
    CATEGORY = 'category'      # Top level (e.g., "Injection")
    SUBCATEGORY = 'subcategory'  # Middle level (e.g., "SQL Injection")
    VARIANT = 'variant'        # Specific variant (e.g., "Union-based SQLi")


@dataclass
class TaxonomyNode:
    """
    Node in the taxonomy hierarchy.

    Attributes:
        node_id: Unique identifier
        name: Human-readable name
        level: Hierarchy level
        parent_id: Parent node ID
        children: Child node IDs
        patterns: Characteristic patterns
        examples: Example instances
        confidence: Confidence in this category
    """
    node_id: str
    name: str
    level: TaxonomyLevel
    parent_id: Optional[str] = None
    children: Set[str] = field(default_factory=set)
    patterns: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    confidence: float = 0.5
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_example(self, example: str) -> None:
        """Add an example instance."""
        if example not in self.examples:
            self.examples.append(example)
            self.updated_at = time.time()

    def add_pattern(self, pattern: str) -> None:
        """Add a characteristic pattern."""
        if pattern not in self.patterns:
            self.patterns.append(pattern)
            self.updated_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'node_id': self.node_id,
            'name': self.name,
            'level': self.level.value,
            'parent_id': self.parent_id,
            'children': list(self.children),
            'patterns': self.patterns,
            'example_count': len(self.examples),
            'keywords': self.keywords,
            'confidence': self.confidence
        }


@dataclass
class ClassificationResult:
    """Result of classifying a vulnerability."""
    node_id: str
    node_name: str
    confidence: float
    path: List[str]  # Path from root to node
    alternative_matches: List[Tuple[str, float]] = field(default_factory=list)


class SelfLearningTaxonomy:
    """
    Self-learning vulnerability taxonomy.

    Implements:
    - HDBSCAN/DBSCAN clustering for grouping
    - TF-IDF vectorization for text features
    - Auto-naming based on keywords
    - Hierarchical structure with inheritance

    Performance targets:
    - Clustering: O(n log n) with HDBSCAN
    - Classification: O(k) where k = taxonomy size
    """

    # Configuration
    MIN_CLUSTER_SIZE = 3
    MIN_SAMPLES = 2
    SIMILARITY_THRESHOLD = 0.5
    MAX_KEYWORDS = 5

    # Known vulnerability patterns for seeding
    SEED_PATTERNS = {
        'sqli': [r'union.*select', r'or\s+1\s*=\s*1', r'--\s*$', r"'\s*or\s*'"],
        'xss': [r'<script', r'javascript:', r'onerror\s*=', r'onload\s*='],
        'path_traversal': [r'\.\./', r'\.\.\\', r'/etc/passwd', r'%2e%2e'],
        'command_injection': [r';\s*\w+', r'\|\s*\w+', r'`[^`]+`', r'\$\([^)]+\)'],
        'ssrf': [r'localhost', r'127\.0\.0\.1', r'0\.0\.0\.0', r'169\.254'],
        'xxe': [r'<!ENTITY', r'<!DOCTYPE', r'SYSTEM\s+"', r'file://'],
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize taxonomy.

        Args:
            config: Optional configuration overrides
        """
        config = config or {}

        self.min_cluster_size = config.get('min_cluster_size', self.MIN_CLUSTER_SIZE)
        self.min_samples = config.get('min_samples', self.MIN_SAMPLES)
        self.similarity_threshold = config.get('similarity_threshold', self.SIMILARITY_THRESHOLD)
        self.max_keywords = config.get('max_keywords', self.MAX_KEYWORDS)

        # Storage
        self._nodes: Dict[str, TaxonomyNode] = {}
        self._root_nodes: Set[str] = set()
        self._vectorizer: Optional[TfidfVectorizer] = None
        self._vectors: Optional[np.ndarray] = None
        self._observation_texts: List[str] = []
        self._observation_labels: List[str] = []

        # Precompile patterns
        self._compiled_patterns: Dict[str, List[re.Pattern]] = {}
        for category, patterns in self.SEED_PATTERNS.items():
            self._compiled_patterns[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

        # Initialize with seed taxonomy
        self._initialize_seed_taxonomy()

        logger.debug("Initialized SelfLearningTaxonomy")

    def _initialize_seed_taxonomy(self) -> None:
        """Initialize taxonomy with known vulnerability categories."""
        seed_categories = [
            ('injection', 'Injection', ['sqli', 'command_injection', 'ldap_injection']),
            ('client_side', 'Client-Side', ['xss', 'csrf', 'open_redirect']),
            ('path_manipulation', 'Path Manipulation', ['path_traversal', 'lfi', 'rfi']),
            ('xml_attacks', 'XML Attacks', ['xxe', 'xpath_injection']),
            ('server_side', 'Server-Side', ['ssrf', 'ssti', 'deserialization']),
            ('authentication', 'Authentication', ['broken_auth', 'session_fixation']),
            ('access_control', 'Access Control', ['idor', 'privilege_escalation']),
        ]

        for cat_id, cat_name, subcats in seed_categories:
            # Create category node
            category_node = TaxonomyNode(
                node_id=cat_id,
                name=cat_name,
                level=TaxonomyLevel.CATEGORY,
                confidence=0.9
            )
            self._nodes[cat_id] = category_node
            self._root_nodes.add(cat_id)

            # Create subcategory nodes
            for subcat_id in subcats:
                subcat_name = subcat_id.replace('_', ' ').title()
                subcat_node = TaxonomyNode(
                    node_id=subcat_id,
                    name=subcat_name,
                    level=TaxonomyLevel.SUBCATEGORY,
                    parent_id=cat_id,
                    patterns=self.SEED_PATTERNS.get(subcat_id, []),
                    confidence=0.8
                )
                self._nodes[subcat_id] = subcat_node
                category_node.children.add(subcat_id)

    def add_node(
        self,
        node_id: str,
        name: str,
        level: TaxonomyLevel,
        parent_id: Optional[str] = None,
        patterns: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None
    ) -> TaxonomyNode:
        """
        Add a node to the taxonomy.

        Args:
            node_id: Unique identifier
            name: Human-readable name
            level: Hierarchy level
            parent_id: Parent node ID
            patterns: Characteristic patterns
            keywords: Associated keywords

        Returns:
            The created TaxonomyNode
        """
        node = TaxonomyNode(
            node_id=node_id,
            name=name,
            level=level,
            parent_id=parent_id,
            patterns=patterns or [],
            keywords=keywords or []
        )

        self._nodes[node_id] = node

        if parent_id and parent_id in self._nodes:
            self._nodes[parent_id].children.add(node_id)
        elif level == TaxonomyLevel.CATEGORY:
            self._root_nodes.add(node_id)

        # Compile patterns
        if patterns:
            self._compiled_patterns[node_id] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

        logger.debug(f"Added taxonomy node: {node_id}")
        return node

    def classify(self, text: str, context: Optional[Dict[str, Any]] = None) -> ClassificationResult:
        """
        Classify a vulnerability text.

        Args:
            text: Vulnerability description or payload
            context: Additional context

        Returns:
            ClassificationResult with best match

        Complexity: O(k * p) where k = nodes, p = patterns per node
        """
        scores: Dict[str, float] = {}

        # Pattern matching
        for node_id, patterns in self._compiled_patterns.items():
            match_count = sum(1 for p in patterns if p.search(text))
            if match_count > 0:
                scores[node_id] = match_count / len(patterns)

        # TF-IDF similarity if vectorizer is trained
        if self._vectorizer is not None and self._vectors is not None:
            tfidf_scores = self._compute_tfidf_similarity(text)
            for node_id, score in tfidf_scores.items():
                if node_id in scores:
                    scores[node_id] = (scores[node_id] + score) / 2
                else:
                    scores[node_id] = score * 0.5

        # Keyword matching
        text_lower = text.lower()
        for node_id, node in self._nodes.items():
            keyword_matches = sum(1 for kw in node.keywords if kw.lower() in text_lower)
            if keyword_matches > 0:
                kw_score = min(keyword_matches / max(len(node.keywords), 1), 1.0)
                if node_id in scores:
                    scores[node_id] = (scores[node_id] + kw_score) / 2
                else:
                    scores[node_id] = kw_score * 0.3

        if not scores:
            # Default to unknown
            return ClassificationResult(
                node_id='unknown',
                node_name='Unknown',
                confidence=0.0,
                path=['unknown'],
                alternative_matches=[]
            )

        # Find best match
        best_id = max(scores, key=scores.get)
        best_score = scores[best_id]

        # Get alternatives
        alternatives = sorted(
            [(nid, score) for nid, score in scores.items() if nid != best_id],
            key=lambda x: x[1],
            reverse=True
        )[:3]

        # Build path
        path = self._get_path_to_root(best_id)
        path.reverse()

        node = self._nodes.get(best_id)
        node_name = node.name if node else best_id

        return ClassificationResult(
            node_id=best_id,
            node_name=node_name,
            confidence=best_score,
            path=path,
            alternative_matches=alternatives
        )

    def _get_path_to_root(self, node_id: str) -> List[str]:
        """Get path from node to root."""
        path = [node_id]
        current = self._nodes.get(node_id)

        while current and current.parent_id:
            path.append(current.parent_id)
            current = self._nodes.get(current.parent_id)

        return path

    def _compute_tfidf_similarity(self, text: str) -> Dict[str, float]:
        """Compute TF-IDF similarity with known examples."""
        if self._vectorizer is None or self._vectors is None:
            return {}

        try:
            text_vector = self._vectorizer.transform([text])
            similarities = cosine_similarity(text_vector, self._vectors)[0]

            # Map to node IDs
            scores: Dict[str, List[float]] = defaultdict(list)
            for idx, sim in enumerate(similarities):
                if idx < len(self._observation_labels):
                    label = self._observation_labels[idx]
                    scores[label].append(sim)

            # Average scores per node
            return {
                node_id: np.mean(sims)
                for node_id, sims in scores.items()
                if sims
            }

        except Exception as e:
            logger.debug(f"TF-IDF similarity failed: {e}")
            return {}

    def learn_from_observations(
        self,
        observations: List[Tuple[str, str]]
    ) -> int:
        """
        Learn from labeled observations.

        Args:
            observations: List of (text, label) tuples

        Returns:
            Number of new clusters/categories discovered

        Complexity: O(n log n) for clustering
        """
        if not observations:
            return 0

        texts, labels = zip(*observations)
        texts = list(texts)
        labels = list(labels)

        # Update observations
        self._observation_texts.extend(texts)
        self._observation_labels.extend(labels)

        # Train/update vectorizer
        self._vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 2),
            stop_words='english'
        )
        self._vectors = self._vectorizer.fit_transform(self._observation_texts)

        # Add examples to nodes
        for text, label in observations:
            if label in self._nodes:
                self._nodes[label].add_example(text)

        # Cluster unlabeled or uncertain observations
        new_clusters = self._discover_new_clusters(texts, labels)

        logger.info(f"Learned from {len(observations)} observations, discovered {new_clusters} new clusters")
        return new_clusters

    def _discover_new_clusters(
        self,
        texts: List[str],
        labels: List[str]
    ) -> int:
        """Discover new clusters using HDBSCAN or DBSCAN."""
        if len(texts) < self.min_cluster_size:
            return 0

        # Get vectors for texts
        vectors = self._vectorizer.transform(texts)

        # Cluster
        if HDBSCAN_AVAILABLE:
            clusterer = hdbscan.HDBSCAN(
                min_cluster_size=self.min_cluster_size,
                min_samples=self.min_samples,
                metric='euclidean'
            )
        else:
            clusterer = DBSCAN(
                eps=0.5,
                min_samples=self.min_samples,
                metric='cosine'
            )

        try:
            cluster_labels = clusterer.fit_predict(vectors.toarray())
        except Exception as e:
            logger.debug(f"Clustering failed: {e}")
            return 0

        # Analyze clusters
        unique_clusters = set(cluster_labels) - {-1}  # Exclude noise
        new_count = 0

        for cluster_id in unique_clusters:
            cluster_mask = cluster_labels == cluster_id
            cluster_texts = [t for t, m in zip(texts, cluster_mask) if m]
            cluster_existing_labels = [l for l, m in zip(labels, cluster_mask) if m]

            # Check if this cluster maps to existing category
            label_counts = defaultdict(int)
            for label in cluster_existing_labels:
                label_counts[label] += 1

            if label_counts:
                dominant_label = max(label_counts, key=label_counts.get)
                # Add examples to existing node
                if dominant_label in self._nodes:
                    for text in cluster_texts:
                        self._nodes[dominant_label].add_example(text)
            else:
                # Potentially new category
                keywords = self._extract_keywords(cluster_texts)
                if keywords:
                    new_name = self._generate_name(keywords)
                    new_id = f"auto_{int(time.time())}_{cluster_id}"

                    self.add_node(
                        node_id=new_id,
                        name=new_name,
                        level=TaxonomyLevel.VARIANT,
                        keywords=keywords
                    )

                    for text in cluster_texts:
                        self._nodes[new_id].add_example(text)

                    new_count += 1

        return new_count

    def _extract_keywords(self, texts: List[str], max_keywords: int = 5) -> List[str]:
        """Extract keywords from texts using TF-IDF."""
        if not texts or self._vectorizer is None:
            return []

        try:
            vectors = self._vectorizer.transform(texts)
            # Sum TF-IDF scores
            scores = np.array(vectors.sum(axis=0)).flatten()

            # Get feature names
            feature_names = self._vectorizer.get_feature_names_out()

            # Top keywords
            top_indices = scores.argsort()[-max_keywords:][::-1]
            keywords = [feature_names[i] for i in top_indices if scores[i] > 0]

            return keywords

        except Exception as e:
            logger.debug(f"Keyword extraction failed: {e}")
            return []

    def _generate_name(self, keywords: List[str]) -> str:
        """Generate a name from keywords."""
        if not keywords:
            return "Unknown Pattern"

        # Capitalize and join
        name_parts = [kw.replace('_', ' ').title() for kw in keywords[:3]]
        return ' '.join(name_parts)

    def get_taxonomy_tree(self) -> Dict[str, Any]:
        """Get full taxonomy as nested structure."""
        def build_tree(node_id: str) -> Dict[str, Any]:
            node = self._nodes.get(node_id)
            if not node:
                return {}

            tree = {
                'id': node.node_id,
                'name': node.name,
                'level': node.level.value,
                'example_count': len(node.examples),
                'confidence': node.confidence,
                'children': []
            }

            for child_id in node.children:
                child_tree = build_tree(child_id)
                if child_tree:
                    tree['children'].append(child_tree)

            return tree

        return {
            'roots': [build_tree(root_id) for root_id in self._root_nodes],
            'total_nodes': len(self._nodes)
        }

    def get_node(self, node_id: str) -> Optional[TaxonomyNode]:
        """Get a node by ID."""
        return self._nodes.get(node_id)

    def get_all_categories(self) -> List[TaxonomyNode]:
        """Get all category-level nodes."""
        return [
            node for node in self._nodes.values()
            if node.level == TaxonomyLevel.CATEGORY
        ]

    def get_children(self, node_id: str) -> List[TaxonomyNode]:
        """Get children of a node."""
        node = self._nodes.get(node_id)
        if not node:
            return []

        return [
            self._nodes[child_id]
            for child_id in node.children
            if child_id in self._nodes
        ]

    def export(self) -> Dict[str, Any]:
        """Export taxonomy to dictionary."""
        return {
            'nodes': {
                node_id: node.to_dict()
                for node_id, node in self._nodes.items()
            },
            'root_nodes': list(self._root_nodes),
            'total_observations': len(self._observation_texts)
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SelfLearningTaxonomy':
        """Import taxonomy from dictionary."""
        taxonomy = cls()
        taxonomy._nodes.clear()
        taxonomy._root_nodes.clear()

        for node_id, node_data in data.get('nodes', {}).items():
            node = TaxonomyNode(
                node_id=node_data['node_id'],
                name=node_data['name'],
                level=TaxonomyLevel(node_data['level']),
                parent_id=node_data.get('parent_id'),
                children=set(node_data.get('children', [])),
                patterns=node_data.get('patterns', []),
                keywords=node_data.get('keywords', []),
                confidence=node_data.get('confidence', 0.5)
            )
            taxonomy._nodes[node_id] = node

            if node_data.get('patterns'):
                taxonomy._compiled_patterns[node_id] = [
                    re.compile(p, re.IGNORECASE) for p in node_data['patterns']
                ]

        taxonomy._root_nodes = set(data.get('root_nodes', []))

        return taxonomy
