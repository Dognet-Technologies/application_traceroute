# 📋 MODULO 3: Self-Learning Taxonomy

**File**: `extensions/taxonomy/adaptive_taxonomy.py`  
**Righe**: ~800  
**Dipendenze**: numpy, scikit-learn, hdbscan  

---

## 🎯 OBIETTIVO

Sistema auto-apprendimento che:
1. Clusterizza anomalie/vulnerabilità trovate
2. Identifica pattern comuni automaticamente
3. Genera nomi descrittivi per nuove classi di vulnerabilità
4. Impara da risultati per migliorare detection futura

---

## 🧠 TEORIA

### **HDBSCAN Clustering**

```
ALGORITMO:

[1] FEATURE EXTRACTION (9-dimensional vector)
├─> perturbation_type_id: 0-4
├─> deviation_metric_id: 0-2  
├─> kl_divergence: normalized
├─> severity: 0-1
├─> num_affected_layers: count
├─> layer_type_indicators: [waf, proxy, backend]
└─> response_time: normalized

[2] HDBSCAN CLUSTERING
├─> Hierarchical density-based clustering
├─> Auto-detect number of clusters
├─> Noise points labeled as -1
└─> min_cluster_size: 5 (configurable)

[3] CLUSTER CHARACTERIZATION
├─> Extract common patterns
├─> Calculate signature:
│   ├─> Typical perturbation types
│   ├─> Affected layer combinations
│   └─> Severity statistics
└─> Generate descriptive name

[4] LEARNING FROM RESULTS
├─> Track success/failure per cluster
├─> Adjust priorities based on success rate
└─> Generate more of winning patterns
```

### **Auto-Naming Algorithm**

```python
Template: [Layer-info] [Causal-pattern] [Severity-level]

Examples:
- "Cross-Layer Timing-Dependent State Confusion (HIGH)"
- "WAF Parser Discrepancy (MEDIUM)"
- "Backend Encoding-Based Anomaly (CRITICAL)"

Components:
├─> Layer: "WAF", "Backend", "Cross-Layer"
├─> Pattern: From perturbation types
└─> Severity: From severity_mean
```

---

## 💻 IMPLEMENTAZIONE COMPLETA

```python
"""
extensions/taxonomy/adaptive_taxonomy.py

Self-learning vulnerability taxonomy using HDBSCAN clustering
"""

import numpy as np
import time
import json
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from collections import Counter

try:
    import hdbscan
    from sklearn.preprocessing import StandardScaler
    HDBSCAN_AVAILABLE = True
except ImportError:
    HDBSCAN_AVAILABLE = False
    print("⚠️  hdbscan not installed. Install: pip install hdbscan scikit-learn")


@dataclass
class ClusterSignature:
    """
    Signature of a vulnerability cluster
    
    Characterizes common patterns among anomalies in same cluster
    """
    common_causal_patterns: List[str]
    typical_perturbation_types: Set[str]
    affected_layer_combination: Set[str]
    severity_mean: float
    severity_std: float
    cluster_size: int
    success_rate: float = 0.0  # NEW: Track success rate
    
    def to_dict(self) -> Dict:
        """Serialize"""
        return {
            'common_causal_patterns': self.common_causal_patterns,
            'typical_perturbation_types': list(self.typical_perturbation_types),
            'affected_layer_combination': list(self.affected_layer_combination),
            'severity_mean': float(self.severity_mean),
            'severity_std': float(self.severity_std),
            'cluster_size': self.cluster_size,
            'success_rate': self.success_rate
        }
    
    def similarity(self, other: 'ClusterSignature') -> float:
        """
        Calculate Jaccard similarity between signatures
        
        Returns:
            Similarity score [0, 1]
        """
        # Jaccard on layers
        layers_union = self.affected_layer_combination | other.affected_layer_combination
        layers_intersection = self.affected_layer_combination & other.affected_layer_combination
        
        jaccard_layers = len(layers_intersection) / len(layers_union) if layers_union else 0.0
        
        # Jaccard on perturbations
        perturb_union = self.typical_perturbation_types | other.typical_perturbation_types
        perturb_intersection = self.typical_perturbation_types & other.typical_perturbation_types
        
        jaccard_perturb = len(perturb_intersection) / len(perturb_union) if perturb_union else 0.0
        
        # Average
        return (jaccard_layers + jaccard_perturb) / 2


@dataclass
class VulnerabilityClass:
    """
    Auto-learned vulnerability class
    """
    id: str
    name: str
    signature: ClusterSignature
    examples: List[Dict] = field(default_factory=list)
    discovery_timestamp: float = field(default_factory=time.time)
    confidence: float = 0.0
    
    # NEW: Learning metrics
    total_attempts: int = 0
    successful_attempts: int = 0
    
    def record_attempt(self, success: bool):
        """Record exploitation attempt"""
        self.total_attempts += 1
        if success:
            self.successful_attempts += 1
        
        # Update success rate
        if self.total_attempts > 0:
            self.signature.success_rate = self.successful_attempts / self.total_attempts
    
    def get_priority_score(self) -> float:
        """
        Calculate priority score for this vulnerability class
        
        Higher score = should focus more on this type
        """
        # Factors:
        # - Success rate (most important)
        # - Severity
        # - Confidence
        
        success_weight = 0.6
        severity_weight = 0.3
        confidence_weight = 0.1
        
        score = (
            self.signature.success_rate * success_weight +
            self.signature.severity_mean * severity_weight +
            self.confidence * confidence_weight
        )
        
        return score
    
    def to_dict(self) -> Dict:
        """Serialize"""
        return {
            'id': self.id,
            'name': self.name,
            'signature': self.signature.to_dict(),
            'examples': self.examples[:10],  # First 10 only
            'discovery_timestamp': self.discovery_timestamp,
            'confidence': self.confidence,
            'total_attempts': self.total_attempts,
            'successful_attempts': self.successful_attempts,
            'priority_score': self.get_priority_score()
        }


class SelfLearningTaxonomy:
    """
    Self-learning vulnerability taxonomy
    
    Features:
    1. HDBSCAN clustering of anomalies
    2. Auto-characterization of clusters
    3. Auto-naming of vulnerability classes
    4. Learning from exploitation results
    5. Priority adjustment based on success
    """
    
    def __init__(
        self,
        min_cluster_size: int = 5,
        min_samples: int = 3,
        recluster_threshold: int = 20
    ):
        if not HDBSCAN_AVAILABLE:
            raise ImportError("hdbscan required. Install: pip install hdbscan scikit-learn")
        
        self.min_cluster_size = min_cluster_size
        self.min_samples = min_samples
        self.recluster_threshold = recluster_threshold
        
        # Clustering model
        self.cluster_model = hdbscan.HDBSCAN(
            min_cluster_size=min_cluster_size,
            min_samples=min_samples,
            metric='euclidean'
        )
        
        # Scaler for features
        self.scaler = StandardScaler()
        
        # Anomalies observed
        self.anomalies: List[Tuple[Dict, np.ndarray]] = []  # (anomaly, features)
        
        # Vulnerability classes identified
        self.vulnerability_clusters: Dict[int, VulnerabilityClass] = {}
        
        # Counter for re-clustering
        self.anomalies_since_last_cluster = 0
        
        # Metadata
        self.last_cluster_time = None
    
    def learn_from_anomaly(self, anomaly: Dict) -> None:
        """
        Add anomaly and potentially re-cluster
        
        Args:
            anomaly: Dict with anomaly info (from DifferentialAnalyzer or other)
        """
        # Extract features
        features = self.extract_features(anomaly)
        
        # Store
        self.anomalies.append((anomaly, features))
        self.anomalies_since_last_cluster += 1
        
        # Re-cluster if threshold reached
        if self.anomalies_since_last_cluster >= self.recluster_threshold:
            print(f"[+] Re-clustering taxonomy ({len(self.anomalies)} total anomalies)...")
            self.recluster()
            self.anomalies_since_last_cluster = 0
    
    def record_exploitation_result(
        self,
        anomaly_or_vuln: Dict,
        success: bool
    ) -> None:
        """
        Record result of exploitation attempt
        
        Updates success rates for learning
        """
        # Find matching cluster
        features = self.extract_features(anomaly_or_vuln)
        
        if not self.anomalies:
            return
        
        # Find closest cluster
        X = np.array([f for _, f in self.anomalies])
        if len(X) < self.min_cluster_size:
            return
        
        # Predict cluster
        labels = self.cluster_model.fit_predict(X)
        
        # Find label for this anomaly
        distances = np.linalg.norm(X - features, axis=1)
        closest_idx = np.argmin(distances)
        label = labels[closest_idx]
        
        if label != -1 and label in self.vulnerability_clusters:
            # Record attempt
            self.vulnerability_clusters[label].record_attempt(success)
            print(f"[📊] Updated {self.vulnerability_clusters[label].name}: "
                  f"success rate = {self.vulnerability_clusters[label].signature.success_rate:.1%}")
    
    def extract_features(self, anomaly: Dict) -> np.ndarray:
        """
        Feature engineering for anomalies
        
        Features (9-dimensional):
        [0] perturbation_type_id (0-4)
        [1] deviation_metric_id (0-2)
        [2] kl_divergence (normalized)
        [3] severity (0-1)
        [4] num_affected_layers
        [5-7] layer_type_indicators (waf, proxy, backend)
        [8] response_time (normalized)
        
        Returns:
            Feature vector np.ndarray
        """
        # Encodings
        perturbation_encoding = {
            'single_char': 0, 'boundary': 1, 'type_confusion': 2,
            'encoding': 3, 'parser_state': 4
        }
        
        metric_encoding = {
            'response_time': 0, 'response_size': 1, 'response_code': 2
        }
        
        # Extract
        perturb_type = anomaly.get('perturbation_type', 'single_char')
        deviation_metric = anomaly.get('deviation_metric', 'response_time')
        kl_div = anomaly.get('kl_divergence', 0.0)
        severity = anomaly.get('severity', 0.5)
        affected_layers = anomaly.get('affected_layers', [])
        
        # Build feature vector
        features = np.array([
            # Categorical
            perturbation_encoding.get(perturb_type, 0),
            metric_encoding.get(deviation_metric, 0),
            
            # Continuous
            min(kl_div, 10.0) / 10.0,  # Normalize KL
            severity,
            len(affected_layers),
            
            # Layer indicators (binary)
            1 if any('waf' in str(l).lower() for l in affected_layers) else 0,
            1 if any('proxy' in str(l).lower() for l in affected_layers) else 0,
            1 if any('backend' in str(l).lower() for l in affected_layers) else 0,
            
            # Timing
            min(anomaly.get('response_time', 0.0), 10.0) / 10.0
        ], dtype=float)
        
        return features
    
    def recluster(self) -> None:
        """
        Execute clustering on all anomalies
        
        Identifies new clusters and converts to VulnerabilityClass
        """
        if len(self.anomalies) < self.min_cluster_size:
            print(f"[!] Not enough anomalies for clustering "
                  f"({len(self.anomalies)} < {self.min_cluster_size})")
            return
        
        # Feature matrix
        X = np.array([features for _, features in self.anomalies])
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # HDBSCAN clustering
        labels = self.cluster_model.fit_predict(X_scaled)
        
        # Identify clusters (ignore -1 = noise)
        unique_labels = set(labels)
        unique_labels.discard(-1)
        
        print(f"[+] Found {len(unique_labels)} clusters")
        
        # For each cluster
        for label in unique_labels:
            # Anomalies in this cluster
            cluster_indices = [i for i, l in enumerate(labels) if l == label]
            cluster_anomalies = [self.anomalies[i][0] for i in cluster_indices]
            
            # Characterize cluster
            signature = self.characterize_cluster(cluster_anomalies)
            
            # If cluster new, create VulnerabilityClass
            if label not in self.vulnerability_clusters:
                vuln_name = self.generate_vulnerability_name(signature)
                
                vuln_class = VulnerabilityClass(
                    id=f"vuln-cluster-{label}",
                    name=vuln_name,
                    signature=signature,
                    examples=cluster_anomalies,
                    confidence=self._calculate_cluster_confidence(cluster_anomalies)
                )
                
                self.vulnerability_clusters[label] = vuln_class
                
                print(f"  [NEW] Cluster {label}: {vuln_name} ({len(cluster_anomalies)} anomalies)")
            
            else:
                # Update existing
                self.vulnerability_clusters[label].examples = cluster_anomalies
                self.vulnerability_clusters[label].signature = signature
                self.vulnerability_clusters[label].confidence = self._calculate_cluster_confidence(cluster_anomalies)
        
        self.last_cluster_time = time.time()
    
    def characterize_cluster(self, anomalies: List[Dict]) -> ClusterSignature:
        """
        Extract common characteristics of cluster
        
        Args:
            anomalies: List of anomalies in cluster
        
        Returns:
            ClusterSignature
        """
        # Perturbation types
        perturb_types = set()
        for a in anomalies:
            ptype = a.get('perturbation_type', 'unknown')
            perturb_types.add(ptype)
        
        # Affected layers
        all_layers = set()
        for a in anomalies:
            layers = a.get('affected_layers', [])
            all_layers.update(layers)
        
        # Severity stats
        severities = [a.get('severity', 0.5) for a in anomalies]
        severity_mean = np.mean(severities)
        severity_std = np.std(severities)
        
        return ClusterSignature(
            common_causal_patterns=[],  # TODO: Pattern mining
            typical_perturbation_types=perturb_types,
            affected_layer_combination=all_layers,
            severity_mean=severity_mean,
            severity_std=severity_std,
            cluster_size=len(anomalies)
        )
    
    def _calculate_cluster_confidence(self, anomalies: List[Dict]) -> float:
        """
        Calculate confidence of cluster
        
        Based on:
        - Cluster size (larger = more confident)
        - Severity consistency (low std = more confident)
        
        Returns:
            Confidence [0, 1]
        """
        size_score = min(len(anomalies) / 20.0, 1.0)  # Max at 20
        
        severities = [a.get('severity', 0.5) for a in anomalies]
        consistency_score = 1.0 - min(np.std(severities), 1.0)
        
        return (size_score + consistency_score) / 2
    
    def generate_vulnerability_name(self, signature: ClusterSignature) -> str:
        """
        Generate descriptive name for vulnerability class
        
        Template: [Layer-info] [Causal-pattern] [Severity-level]
        
        Examples:
        - "Cross-Layer Timing-Dependent State Confusion (HIGH)"
        - "WAF Parser Discrepancy (MEDIUM)"
        - "Backend Critical Anomaly (CRITICAL)"
        
        Returns:
            Vulnerability name
        """
        components = []
        
        # Layer information
        layers = signature.affected_layer_combination
        if len(layers) > 1:
            components.append("Cross-Layer")
        elif layers:
            layer_name = list(layers)[0]
            components.append(layer_name)
        
        # Perturbation/Causal pattern
        perturb_types = signature.typical_perturbation_types
        
        if 'type_confusion' in perturb_types:
            components.append("Type-Confusion")
        elif 'boundary' in perturb_types:
            components.append("Boundary-Condition")
        elif 'encoding' in perturb_types:
            components.append("Encoding-Based")
        elif 'parser_state' in perturb_types:
            components.append("Parser-State")
        else:
            components.append("Anomaly-Pattern")
        
        # Severity level
        severity = signature.severity_mean
        if severity > 0.8:
            severity_label = "CRITICAL"
        elif severity > 0.6:
            severity_label = "HIGH"
        elif severity > 0.4:
            severity_label = "MEDIUM"
        else:
            severity_label = "LOW"
        
        # Combine
        name = " ".join(components) if components else "Unknown Vulnerability"
        name += f" ({severity_label})"
        
        return name
    
    def get_top_priority_classes(self, n: int = 5) -> List[VulnerabilityClass]:
        """
        Get top N vulnerability classes by priority score
        
        Priority based on success rate + severity
        """
        classes = list(self.vulnerability_clusters.values())
        classes.sort(key=lambda c: c.get_priority_score(), reverse=True)
        return classes[:n]
    
    def export_taxonomy(self) -> Dict:
        """
        Export complete taxonomy
        
        Returns:
            Dict serializable to JSON
        """
        return {
            'metadata': {
                'total_anomalies': len(self.anomalies),
                'num_clusters': len(self.vulnerability_clusters),
                'last_cluster_time': self.last_cluster_time,
                'min_cluster_size': self.min_cluster_size
            },
            'vulnerability_classes': [
                vuln_class.to_dict()
                for vuln_class in self.vulnerability_clusters.values()
            ],
            'top_priorities': [
                {
                    'name': vc.name,
                    'priority_score': vc.get_priority_score(),
                    'success_rate': vc.signature.success_rate
                }
                for vc in self.get_top_priority_classes(5)
            ]
        }
    
    def save_to_json(
        self,
        filepath: Optional[Path] = None,
        domain: Optional[str] = None
    ) -> None:
        """
        Save taxonomy to JSON
        
        Args:
            filepath: Custom path (default: results/taxonomy_$timestamp.json)
            domain: Domain name for filename
        """
        if filepath is None:
            timestamp = int(time.time())
            
            if domain:
                taxonomy_dir = Path(f"results/{domain}_{timestamp}")
            else:
                taxonomy_dir = Path("results/taxonomy")
            
            taxonomy_dir.mkdir(parents=True, exist_ok=True)
            filepath = taxonomy_dir / f"learned_taxonomy_{timestamp}.json"
        
        # Export
        data = self.export_taxonomy()
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[+] Taxonomy saved to {filepath}")
    
    @classmethod
    def load_from_json(cls, filepath: Path) -> 'SelfLearningTaxonomy':
        """
        Load taxonomy from JSON
        
        Args:
            filepath: Path to JSON file
        
        Returns:
            SelfLearningTaxonomy instance
        """
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        # Create instance
        metadata = data['metadata']
        taxonomy = cls(min_cluster_size=metadata['min_cluster_size'])
        
        # Reconstruct vulnerability classes
        for vuln_data in data['vulnerability_classes']:
            signature = ClusterSignature(
                common_causal_patterns=vuln_data['signature']['common_causal_patterns'],
                typical_perturbation_types=set(vuln_data['signature']['typical_perturbation_types']),
                affected_layer_combination=set(vuln_data['signature']['affected_layer_combination']),
                severity_mean=vuln_data['signature']['severity_mean'],
                severity_std=vuln_data['signature']['severity_std'],
                cluster_size=vuln_data['signature']['cluster_size'],
                success_rate=vuln_data['signature'].get('success_rate', 0.0)
            )
            
            vuln_class = VulnerabilityClass(
                id=vuln_data['id'],
                name=vuln_data['name'],
                signature=signature,
                examples=vuln_data.get('examples', []),
                discovery_timestamp=vuln_data['discovery_timestamp'],
                confidence=vuln_data['confidence'],
                total_attempts=vuln_data.get('total_attempts', 0),
                successful_attempts=vuln_data.get('successful_attempts', 0)
            )
            
            # Extract cluster ID
            cluster_id = int(vuln_data['id'].split('-')[-1])
            taxonomy.vulnerability_clusters[cluster_id] = vuln_class
        
        return taxonomy


# ============================================================================
# USAGE EXAMPLE
# ============================================================================

def example_usage():
    """
    Example of how to use SelfLearningTaxonomy
    
    WORKFLOW:
    
    1. Create taxonomy
    2. Feed anomalies as they're discovered
    3. Taxonomy automatically clusters and learns
    4. Record exploitation results
    5. Get top priority vulnerability types
    6. Generate more of winning types
    7. Export learned taxonomy
    """
    
    taxonomy = SelfLearningTaxonomy(min_cluster_size=5)
    
    # Step 1: Feed anomalies
    for anomaly in discovered_anomalies:
        taxonomy.learn_from_anomaly(anomaly)
    
    # Step 2: After clustering, try to exploit
    for vuln_class in taxonomy.vulnerability_clusters.values():
        # Generate bypasses of this type
        bypasses = generate_bypasses_from_pattern(vuln_class.signature)
        
        # Try exploiting
        for bypass in bypasses:
            success = try_exploit(bypass)
            
            # Record result
            taxonomy.record_exploitation_result(
                vuln_class.examples[0],  # Representative anomaly
                success=success
            )
    
    # Step 3: Get top priorities
    top_classes = taxonomy.get_top_priority_classes(5)
    
    print("\n[📊] Top Priority Vulnerability Classes:")
    for i, vc in enumerate(top_classes, 1):
        print(f"{i}. {vc.name}")
        print(f"   Priority Score: {vc.get_priority_score():.2f}")
        print(f"   Success Rate: {vc.signature.success_rate:.1%}")
        print(f"   Attempts: {vc.successful_attempts}/{vc.total_attempts}")
    
    # Step 4: Focus on winning patterns
    if top_classes:
        winning_class = top_classes[0]
        print(f"\n[🎯] Focus on: {winning_class.name}")
        print(f"    Generate more variations of this pattern!")
    
    # Step 5: Export
    taxonomy.save_to_json(domain="example.com")


if __name__ == "__main__":
    if not HDBSCAN_AVAILABLE:
        print("[!] hdbscan not installed. Install: pip install hdbscan scikit-learn")
    else:
        print("""
        SelfLearningTaxonomy - Auto-Discovery of Vulnerability Patterns
        
        Features:
        - HDBSCAN clustering
        - Auto-naming
        - Success rate tracking
        - Priority scoring
        - Learning from results
        
        See example_usage() for integration
        """)
```

---

## ✅ CHECKLIST IMPLEMENTAZIONE

- [ ] Creare directory `extensions/taxonomy/`
- [ ] Implementare `adaptive_taxonomy.py`
- [ ] Creare `__init__.py`
- [ ] Testare clustering su dati simulati
- [ ] Integrare con application_traceroute
- [ ] Integrare con smart_crawler
- [ ] Test su anomalie reali
- [ ] Validare auto-naming

---

## 📊 BENEFICI

**Auto-Discovery**:
- Identifica nuove classi di vulnerabilità automaticamente
- Nomi descrittivi generati automaticamente

**Learning**:
- Traccia success rate per ogni tipo
- Prioritizza tipi con successo alto
- Genera più varianti dei pattern vincenti

**Export**:
- JSON esportabile per sharing community
- Taxonomy riutilizzabile tra scan

