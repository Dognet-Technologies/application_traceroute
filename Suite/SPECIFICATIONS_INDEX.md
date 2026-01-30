# Specifications Index

This document maps each module to its complete specification in the conversation history.

## Core Modules

### 1. CausalNode (core/graph/causal_node.py)
- **Specification Location**: Part 3, Section 3.1
- **Lines of Code**: ~500
- **Dependencies**: numpy, scipy
- **Key Features**:
  - KDE-based behavior distribution
  - Entropy calculation
  - Anomaly detection via CDF
  - Observation tracking

**Key Classes**:
- `NodeType(Enum)` - 4 types: STACK_LAYER, DATA_FLOW, STATE, TIME
- `ObservationData(dataclass)` - Single observation
- `CausalNode(class)` - Main node implementation

**Critical Methods**:
- `add_observation()` - O(1)
- `update_distribution()` - O(n log n)
- `calculate_entropy()` - O(k) where k=integration points
- `is_anomalous()` - O(n) for CDF calculation

**Corrections Applied**:
- ✅ Fixed CDF calculation in `is_anomalous()`
- ✅ Added edge case handling for entropy
- ✅ Improved numeric stability

---

### 2. CausalEdge (core/graph/causal_edge.py)
- **Specification Location**: Part 3, Section 3.2
- **Lines of Code**: ~300
- **Dependencies**: numpy
- **Key Features**:
  - Causality strength tracking
  - Evidence accumulation
  - Conditional probability
  - Bayesian updates

**Key Classes**:
- `CausalityType(Enum)` - DIRECT, INDIRECT, CONDITIONAL
- `CausalEvidence(dataclass)` - Evidence for causation
- `CausalEdge(class)` - Main edge implementation

**Critical Methods**:
- `add_evidence()` - O(1)
- `update_strength()` - Exponential moving average
- `get_conditional_probability()` - Conditional on other nodes

**Corrections Applied**:
- ✅ Added input validation (no self-loops, strength [0,1])
- ✅ Improved documentation

---

### 3. CausalSecurityGraph (core/graph/causal_graph.py)
- **Specification Location**: Part 3, Section 3.3
- **Lines of Code**: ~800
- **Dependencies**: numpy, networkx (optional)
- **Key Features**:
  - DAG management
  - Dijkstra variant for max probability paths
  - Belief propagation (simplified)
  - Vulnerability inference

**Key Classes**:
- `CausalSecurityGraph(class)` - Main graph

**Critical Methods**:
- `add_node()`, `add_edge()` - O(1)
- `find_max_probability_path()` - O((V+E) log V)
- `infer_vulnerability_from_anomaly()` - Backward DFS
- `_would_create_cycle()` - DFS with depth limit

**Corrections Applied**:
- ✅ Added depth limit to cycle detection (prevents infinite recursion)
- ✅ Improved adjacency list management
- ✅ Better error messages

---

### 4. DifferentialCausalAnalyzer (core/behavioral/differential_analyzer.py)
- **Specification Location**: Part 4, Section 3.4
- **Lines of Code**: ~900
- **Dependencies**: numpy, scipy, requests
- **Key Features**:
  - 75 minimal perturbations
  - KL-divergence anomaly detection
  - Baseline distribution estimation
  - Affected layer inference

**Key Classes**:
- `PerturbationType(Enum)` - 5 types
- `Perturbation(ABC)` - Base class
- `SingleCharPerturbation`, `BoundaryPerturbation`, etc. - Concrete types
- `DifferentialCausalAnalyzer(class)` - Main analyzer

**Critical Methods**:
- `analyze()` - Main entry point, respects 60s timeout
- `_establish_baseline()` - 50 samples, KDE estimation
- `_generate_perturbations()` - Returns exactly 75 perturbations
- `_detect_anomalies()` - KL-divergence > threshold

**Corrections Applied**:
- ✅ Added UUID to results_dir for uniqueness
- ✅ Better timeout handling
- ✅ Improved KL-divergence calculation

---

### 5. HybridCorrelationEngine (core/correlation/hybrid_correlator.py)
- **Specification Location**: Part 4, Section 3.5
- **Lines of Code**: ~600
- **Dependencies**: numpy
- **Key Features**:
  - Graph-based causal reasoning
  - Feature vector similarity (cosine)
  - Bayesian combination of scores
  - Batch correlation

**Key Classes**:
- `Bypass(dataclass)` - Bypass technique representation
- `ForbiddenEndpoint(dataclass)` - Blocked endpoint
- `BypassEndpointCorrelation(dataclass)` - Result
- `FeatureVectorizer(class)` - Vectorization
- `HybridCorrelationEngine(class)` - Main correlator

**Critical Methods**:
- `correlate()` - Single bypass-endpoint
- `graph_based_reasoning()` - Uses causal paths
- `feature_vector_similarity()` - Cosine similarity
- `bayesian_combination()` - Weighted average
- `batch_correlate()` - O(B × E)

**Corrections Applied**:
- ✅ Ensured numpy import
- ✅ Better error handling

---

### 6. BayesianBypassValidator (core/validation/bayesian_validator.py)
- **Specification Location**: Part 5, Section 3.6
- **Lines of Code**: ~700
- **Dependencies**: numpy, scipy, requests
- **Key Features**:
  - Thompson Sampling
  - UCB algorithm
  - Beta distribution priors
  - PoC generation

**Key Classes**:
- `ValidationStatus(Enum)` - SUCCESS, FAILED, ERROR, TIMEOUT
- `BypassTestResult(dataclass)` - Test result
- `BayesianPrior(dataclass)` - Beta(α, β) distribution
- `BayesianBypassValidator(class)` - Main validator

**Critical Methods**:
- `validate()` - Main loop with convergence
- `select_next_bypass()` - UCB selection
- `test_bypass()` - Single test execution
- `update_posterior()` - Beta update
- `has_converged()` - Convergence check

**Corrections Applied**:
- ✅ Protected division by zero in UCB
- ✅ Better convergence criteria
- ✅ Improved PoC generation

---

### 7. SelfLearningTaxonomy (modules/taxonomy/adaptive_taxonomy.py)
- **Specification Location**: Part 5, Section 3.7
- **Lines of Code**: ~800
- **Dependencies**: numpy, hdbscan, scikit-learn
- **Key Features**:
  - HDBSCAN clustering
  - Auto-naming vulnerability classes
  - Cluster signature characterization
  - JSON export/import

**Key Classes**:
- `ClusterSignature(dataclass)` - Cluster characteristics
- `VulnerabilityClass(dataclass)` - Learned vulnerability
- `SelfLearningTaxonomy(class)` - Main taxonomy

**Critical Methods**:
- `learn_from_anomaly()` - Incremental learning
- `extract_features()` - 9-dimensional feature vector
- `recluster()` - HDBSCAN clustering
- `characterize_cluster()` - Extract signature
- `generate_vulnerability_name()` - Auto-naming
- `save_to_json()` - Export

**Corrections Applied**:
- ✅ Better feature engineering
- ✅ Robust clustering handling
- ✅ Improved naming algorithm

---

### 8. SecuritySuiteOrchestrator (cli/orchestrator.py)
- **Specification Location**: Part 5, Section 3.8
- **Lines of Code**: ~1000
- **Dependencies**: rich, all core modules
- **Key Features**:
  - 8-phase workflow
  - Interactive TUI with Rich
  - Progress bars and tables
  - Markdown report generation
  - Checkpoint support

**Key Classes**:
- `SecuritySuiteOrchestrator(class)` - Main orchestrator

**Critical Methods**:
- `run()` - Main workflow
- `_phase_1_stack_analysis()` - Phase 1
- ... (8 phases total)
- `_generate_markdown_report()` - Report generation
- `_save_partial_results()` - Interrupt handling

**Corrections Applied**:
- ✅ Better phase coordination
- ✅ Improved error handling
- ✅ Rich TUI integration

---

## Utility Modules

### 9. Config (utils/config.py)
- **Specification Location**: Refinements section
- **Lines of Code**: ~150
- **Features**: JSON config, defaults, deep merge

### 10. Logging (utils/logging_config.py)
- **Specification Location**: Refinements section
- **Lines of Code**: ~80
- **Features**: File + console logging, formatters

### 11. Validators (utils/validators.py)
- **Specification Location**: Refinements section
- **Lines of Code**: ~100
- **Features**: URL, domain, port validation

### 12. Checkpoint (utils/checkpoint.py)
- **Specification Location**: Refinements section
- **Lines of Code**: ~80
- **Features**: Progress save/resume

---

## Total Statistics

- **Total Modules**: 12 core + 4 utils = 16
- **Total Lines of Code**: ~6,500 (core) + ~500 (utils) = ~7,000
- **Total Classes**: 35+
- **Total Methods**: 150+
- **Total Test Cases**: 30+

---

## Implementation Checklist

- [ ] utils/config.py
- [ ] utils/logging_config.py
- [ ] utils/validators.py
- [ ] utils/checkpoint.py
- [ ] core/graph/causal_node.py
- [ ] core/graph/causal_edge.py
- [ ] core/graph/causal_graph.py
- [ ] core/behavioral/differential_analyzer.py
- [ ] core/correlation/hybrid_correlator.py
- [ ] core/validation/bayesian_validator.py
- [ ] modules/taxonomy/adaptive_taxonomy.py
- [ ] cli/orchestrator.py
- [ ] tests/test_causal_node.py
- [ ] tests/test_causal_graph.py
- [ ] tests/test_integration.py

---

All specifications are COMPLETE and READY for implementation.

