# MODULO 1: Causal Response Analyzer - Specifiche Complete per ClaudeCode

**File**: `extensions/response/causal_response_analyzer.py`  
**Righe**: ~1,500  
**Dipendenze**: numpy, scipy, requests, advanced_bypass_engine  

---

## 🎯 OBIETTIVO

Migliorare la **response verification** in application_traceroute per ridurre falsi positivi.

### Problema Attuale

```python
# application_traceroute (linea 2643)
if status not in [400, 401, 403, 429]:
    # BYPASS TROVATO!
    discrepancy = {'type': 'bypass', 'severity': 'CRITICAL'}
```

**Limite**: Rileva solo status code change, ma NON verifica se:
- Il bypass ha REALMENTE raggiunto contenuto protetto
- La risposta è solo un'error page diversa
- Il backend è stato effettivamente raggiunto

### Soluzione

Multi-level analysis con **causal inference** per verificare:
1. ✅ Content type transition (error → protected)
2. ✅ Protected content indicators (admin panel, API data, etc.)
3. ✅ Causal layer analysis (WAF → Backend)
4. ✅ Behavioral differential (timing, entropy, cookies)
5. ✅ Bayesian confidence scoring

---

## 📁 STRUTTURA FILE

```
extensions/response/
├── __init__.py
├── causal_response_analyzer.py      # Main analyzer (400 righe)
├── content_classifier.py             # Content classification (300 righe)
├── protected_content_detector.py     # Protected indicators (250 righe)
├── behavioral_analyzer.py            # Behavioral analysis (300 righe)
└── layer_identifier.py               # Layer identification (250 righe)
```

---

## 📝 FILE 1: causal_response_analyzer.py

```python
"""
extensions/response/causal_response_analyzer.py

Causal Response Analyzer for verifying TRUE bypasses
Uses multi-dimensional analysis + Bayesian inference
"""

import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import requests

# Import existing modules
from advanced_bypass_engine import (
    BayesianBypassInference,
    BypassEvidence,
    BypassConfidence
)

# Import new modules (same package)
from .content_classifier import ContentClassifier, ContentType
from .protected_content_detector import ProtectedContentDetector
from .behavioral_analyzer import BehavioralAnalyzer
from .layer_identifier import LayerIdentifier


@dataclass
class VerificationResult:
    """Result of bypass verification"""
    is_true_bypass: bool
    confidence: float  # 0.0-1.0
    confidence_level: str  # NEGLIGIBLE, LOW, MEDIUM, HIGH, CERTAIN
    evidence: List[Dict]
    causal_chain: List[Dict]
    reasoning: str
    
    def to_dict(self) -> Dict:
        return {
            'is_true_bypass': self.is_true_bypass,
            'confidence': self.confidence,
            'confidence_level': self.confidence_level,
            'evidence': self.evidence,
            'causal_chain': self.causal_chain,
            'reasoning': self.reasoning
        }


class CausalResponseAnalyzer:
    """
    Causal Response Analyzer for TRUE bypass verification.
    
    Multi-level verification:
    1. Status code analysis
    2. Content semantic classification
    3. Protected content indicators
    4. Causal layer analysis
    5. Behavioral differential
    6. Bayesian confidence scoring
    
    Example:
        analyzer = CausalResponseAnalyzer(stack_info)
        
        result = analyzer.verify_true_bypass(
            baseline_response=baseline_403,
            test_response=response_200,
            bypass_info={'type': 'Header Confusion', ...}
        )
        
        if result.is_true_bypass:
            print(f"TRUE BYPASS: {result.confidence:.1%}")
    """
    
    def __init__(self, stack_info: Dict):
        """
        Initialize analyzer.
        
        Args:
            stack_info: Stack information from application_traceroute
                       {'layers': [...], 'technologies': {...}}
        """
        self.stack_info = stack_info
        
        # Initialize sub-analyzers
        self.content_classifier = ContentClassifier()
        self.protected_detector = ProtectedContentDetector()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.layer_identifier = LayerIdentifier(stack_info)
        
        # Bayesian engine for confidence
        self.bayesian = BayesianBypassInference(prior=0.05)
    
    def verify_true_bypass(
        self,
        baseline_response: requests.Response,
        test_response: requests.Response,
        bypass_info: Dict
    ) -> VerificationResult:
        """
        Verify if bypass is TRUE (not just different error).
        
        Args:
            baseline_response: Response without bypass (403/401)
            test_response: Response with bypass attempt
            bypass_info: {
                'type': 'Header Confusion',
                'test_name': 'X-Forwarded-For Internal',
                'headers': {...},
                'method': 'GET',
                'target_layers': ['WAF', 'Proxy']
            }
        
        Returns:
            VerificationResult with confidence + evidence
        """
        
        # Reset Bayesian for this test
        self.bayesian = BayesianBypassInference(prior=0.05)
        
        # === LEVEL 1: Status Code Analysis ===
        self._analyze_status_code(baseline_response, test_response)
        
        # === LEVEL 2: Content Semantic Classification ===
        self._analyze_content_semantics(baseline_response, test_response)
        
        # === LEVEL 3: Protected Content Indicators ===
        self._analyze_protected_content(test_response)
        
        # === LEVEL 4: Causal Layer Analysis ===
        self._analyze_causal_layers(test_response, bypass_info)
        
        # === LEVEL 5: Behavioral Differential ===
        self._analyze_behavioral_differential(baseline_response, test_response)
        
        # === FINAL VERDICT ===
        posterior = self.bayesian.get_posterior_probability()
        confidence_level = self.bayesian.get_confidence_level()
        
        # Build causal chain
        causal_chain = self._build_causal_chain(
            bypass_info, 
            self.layer_identifier.get_reached_layers(test_response)
        )
        
        # Generate reasoning
        reasoning = self.bayesian.explain_reasoning()
        
        return VerificationResult(
            is_true_bypass=(posterior > 0.75),
            confidence=posterior,
            confidence_level=confidence_level.name,
            evidence=self.bayesian.evidence_collected,
            causal_chain=causal_chain,
            reasoning=reasoning
        )
    
    def _analyze_status_code(
        self,
        baseline: requests.Response,
        test: requests.Response
    ) -> None:
        """Analyze status code change."""
        
        if test.status_code == 200 and baseline.status_code in [401, 403]:
            # Strong signal but not definitive
            self.bayesian.add_evidence(BypassEvidence(
                evidence_type="Status Code Change",
                strength=0.6,
                description=f"{baseline.status_code} → 200",
                likelihood_ratio=20.0
            ))
        
        elif test.status_code in [301, 302] and baseline.status_code == 403:
            # Redirect might be bypass
            self.bayesian.add_evidence(BypassEvidence(
                evidence_type="Status Code Redirect",
                strength=0.4,
                description=f"403 → {test.status_code}",
                likelihood_ratio=10.0
            ))
    
    def _analyze_content_semantics(
        self,
        baseline: requests.Response,
        test: requests.Response
    ) -> None:
        """Analyze semantic content transition."""
        
        baseline_type = self.content_classifier.classify(baseline)
        test_type = self.content_classifier.classify(test)
        
        if baseline_type == ContentType.ERROR_PAGE and \
           test_type == ContentType.PROTECTED_CONTENT:
            # THIS IS THE STRONG SIGNAL!
            self.bayesian.add_evidence(BypassEvidence(
                evidence_type="Content Type Transition",
                strength=0.95,
                description=f"{baseline_type.name} → {test_type.name}",
                likelihood_ratio=100.0  # Very strong!
            ))
        
        elif baseline_type == ContentType.ERROR_PAGE and \
             test_type == ContentType.DIFFERENT_ERROR:
            # False positive! Just different error
            self.bayesian.add_evidence(BypassEvidence(
                evidence_type="False Positive Detected",
                strength=0.9,
                description="Different error page, not real bypass",
                likelihood_ratio=0.01  # Against bypass
            ))
    
    def _analyze_protected_content(
        self,
        test: requests.Response
    ) -> None:
        """Detect protected content indicators."""
        
        indicators = self.protected_detector.detect(test)
        
        if indicators:
            # Found protected content markers
            self.bayesian.add_evidence(BypassEvidence(
                evidence_type="Protected Content Indicators",
                strength=0.85,
                description=f"Found: {', '.join(indicators)}",
                likelihood_ratio=50.0
            ))
    
    def _analyze_causal_layers(
        self,
        test: requests.Response,
        bypass_info: Dict
    ) -> None:
        """Analyze which layers were reached."""
        
        reached_layers = self.layer_identifier.identify(test)
        target_layers = bypass_info.get('target_layers', [])
        
        # Check if bypass reached target
        if 'Backend' in reached_layers and 'WAF' in target_layers:
            # WAF bypassed, backend reached!
            self.bayesian.add_evidence(BypassEvidence(
                evidence_type="Causal Layer Bypass",
                strength=0.9,
                description="WAF bypassed, backend reached",
                likelihood_ratio=80.0
            ))
    
    def _analyze_behavioral_differential(
        self,
        baseline: requests.Response,
        test: requests.Response
    ) -> None:
        """Analyze behavioral differences."""
        
        analysis = self.behavioral_analyzer.analyze(baseline, test)
        
        if analysis['significant_change']:
            self.bayesian.add_evidence(BypassEvidence(
                evidence_type="Behavioral Differential",
                strength=analysis['strength'],
                description=analysis['description'],
                likelihood_ratio=analysis['likelihood_ratio']
            ))
    
    def _build_causal_chain(
        self,
        bypass_info: Dict,
        reached_layers: List[str]
    ) -> List[Dict]:
        """Build causal chain of bypass."""
        
        chain = [
            {
                'step': 1,
                'action': 'Request Sent',
                'details': f"Method: {bypass_info.get('method', 'GET')}"
            },
            {
                'step': 2,
                'action': 'Bypass Applied',
                'details': f"Type: {bypass_info.get('type')}"
            }
        ]
        
        for i, layer in enumerate(reached_layers, start=3):
            chain.append({
                'step': i,
                'action': f'{layer} Reached',
                'details': 'Successfully passed previous layers'
            })
        
        return chain


# Export
__all__ = ['CausalResponseAnalyzer', 'VerificationResult']
```

---

## 📝 FILE 2: content_classifier.py

```python
"""
extensions/response/content_classifier.py

Content type classification for response analysis
"""

from enum import Enum
from typing import Dict
import requests
import re


class ContentType(Enum):
    """Content type classification"""
    ERROR_PAGE = "error_page"              # WAF block, 403 page
    PROTECTED_CONTENT = "protected_content"  # Admin panel, API
    DIFFERENT_ERROR = "different_error_page" # Different error
    REDIRECT = "redirect"
    EMPTY = "empty"


class ContentClassifier:
    """
    Classifies response content type.
    
    Uses pattern matching + heuristics to distinguish:
    - Error pages (WAF, 403, etc.)
    - Protected content (admin, API, etc.)
    - Different error pages
    """
    
    def __init__(self):
        # Error page indicators
        self.error_patterns = [
            'access denied', 'forbidden', 'not authorized',
            'permission denied', 'blocked', 'security',
            'waf', 'firewall', 'error 403', 'error 401',
            'unauthorized access', 'request denied'
        ]
        
        # Protected content indicators  
        self.protected_patterns = [
            'dashboard', 'admin panel', 'user profile',
            'settings', 'configuration', 'management',
            'api response', '"users":', '"data":',
            '<form', 'logout', 'welcome back',
            'administration', 'control panel'
        ]
    
    def classify(self, response: requests.Response) -> ContentType:
        """
        Classify response content type.
        
        Args:
            response: Response to classify
        
        Returns:
            ContentType enum
        """
        
        content = response.text.lower()
        status = response.status_code
        
        # Empty response
        if len(content.strip()) < 50:
            return ContentType.EMPTY
        
        # Redirect
        if status in [301, 302, 303, 307, 308]:
            return ContentType.REDIRECT
        
        # Count matches
        error_matches = sum(
            1 for pattern in self.error_patterns 
            if pattern in content
        )
        
        protected_matches = sum(
            1 for pattern in self.protected_patterns
            if pattern in content
        )
        
        # Decision logic
        if protected_matches >= 2:
            return ContentType.PROTECTED_CONTENT
        
        elif error_matches >= 2:
            return ContentType.ERROR_PAGE
        
        elif error_matches == 1 and protected_matches == 0:
            return ContentType.DIFFERENT_ERROR
        
        # Default: check status code
        if status == 200 and protected_matches > 0:
            return ContentType.PROTECTED_CONTENT
        
        elif status in [401, 403]:
            return ContentType.ERROR_PAGE
        
        return ContentType.DIFFERENT_ERROR


__all__ = ['ContentClassifier', 'ContentType']
```

---

## 📝 FILE 3: protected_content_detector.py

```python
"""
extensions/response/protected_content_detector.py

Detects specific protected content indicators
"""

from typing import List, Set
import requests
import re
import json


class ProtectedContentDetector:
    """
    Detects protected content indicators in response.
    
    Looks for specific markers that indicate:
    - Admin interfaces
    - API responses with data
    - User-specific content
    - Interactive forms
    - Database content
    """
    
    def detect(self, response: requests.Response) -> List[str]:
        """
        Detect protected content indicators.
        
        Args:
            response: Response to analyze
        
        Returns:
            List of indicator names found
        """
        indicators = []
        content = response.text.lower()
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # [1] Admin panel indicators
        if any(x in content for x in [
            'admin panel', 'administration', 'dashboard',
            'control panel', 'admin console'
        ]):
            indicators.append('admin_interface')
        
        # [2] API response indicators
        if 'application/json' in headers.get('content-type', ''):
            try:
                json_data = response.json()
                data_keys = ['users', 'data', 'items', 'results', 'records']
                if any(k in json_data for k in data_keys):
                    indicators.append('api_data_response')
            except:
                pass
        
        # [3] User-specific content
        if any(x in content for x in [
            'welcome back', 'logout', 'my account',
            'user profile', 'settings', 'preferences'
        ]):
            indicators.append('user_authenticated_content')
        
        # [4] Interactive forms (CRUD)
        if '<form' in content:
            form_actions = ['submit', 'save', 'delete', 'update', 'create']
            if any(action in content for action in form_actions):
                indicators.append('interactive_forms')
        
        # [5] Database content
        if any(x in content for x in ['<table', 'rows', 'records', 'entries']):
            if content.count('<tr') > 3:  # At least 3 table rows
                indicators.append('database_content')
        
        # [6] File management
        if any(x in content for x in [
            'upload', 'download', 'file manager',
            'directory', 'browse files'
        ]):
            indicators.append('file_management')
        
        return indicators


__all__ = ['ProtectedContentDetector']
```

---

## 📝 FILE 4: behavioral_analyzer.py

```python
"""
extensions/response/behavioral_analyzer.py

Behavioral differential analysis (timing, entropy, cookies)
"""

from typing import Dict
import requests
import math
from collections import Counter


class BehavioralAnalyzer:
    """
    Analyzes behavioral differences between responses.
    
    Metrics:
    - Timing differential
    - Entropy differential (Shannon)
    - Cookie differential
    - Header differential
    """
    
    def analyze(
        self,
        baseline: requests.Response,
        test: requests.Response
    ) -> Dict:
        """
        Analyze behavioral differences.
        
        Returns:
            {
                'significant_change': bool,
                'strength': float,
                'description': str,
                'likelihood_ratio': float
            }
        """
        
        significant = False
        strength = 0.0
        descriptions = []
        likelihood_ratio = 1.0
        
        # [1] Timing differential
        timing_diff = abs(
            test.elapsed.total_seconds() - 
            baseline.elapsed.total_seconds()
        )
        
        if timing_diff > 0.5:  # >500ms
            significant = True
            strength += 0.3
            descriptions.append(f"Timing: +{timing_diff:.2f}s")
            likelihood_ratio *= 5.0
        
        # [2] Entropy differential
        baseline_entropy = self._calculate_entropy(baseline.content)
        test_entropy = self._calculate_entropy(test.content)
        entropy_diff = abs(test_entropy - baseline_entropy)
        
        if entropy_diff > 1.0:
            significant = True
            strength += 0.4
            descriptions.append(f"Entropy: Δ{entropy_diff:.2f}")
            likelihood_ratio *= 10.0
        
        # [3] Cookie differential
        baseline_cookies = set(baseline.cookies.keys())
        test_cookies = set(test.cookies.keys())
        new_cookies = test_cookies - baseline_cookies
        
        if new_cookies:
            significant = True
            strength += 0.5
            descriptions.append(f"New cookies: {len(new_cookies)}")
            likelihood_ratio *= 15.0
        
        # [4] Header differential
        baseline_headers = set(baseline.headers.keys())
        test_headers = set(test.headers.keys())
        new_headers = test_headers - baseline_headers
        
        if new_headers:
            significant = True
            strength += 0.3
            descriptions.append(f"New headers: {len(new_headers)}")
            likelihood_ratio *= 8.0
        
        return {
            'significant_change': significant,
            'strength': min(strength, 1.0),
            'description': ', '.join(descriptions) if descriptions else 'No significant changes',
            'likelihood_ratio': likelihood_ratio
        }
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy: H(X) = -Σ p(x) log₂ p(x)
        """
        if not data or len(data) == 0:
            return 0.0
        
        # Count byte frequencies
        counter = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy


__all__ = ['BehavioralAnalyzer']
```

---

## 📝 FILE 5: layer_identifier.py

```python
"""
extensions/response/layer_identifier.py

Identifies which infrastructure layers were reached
"""

from typing import List, Dict
import requests


class LayerIdentifier:
    """
    Identifies reached infrastructure layers from response.
    
    Uses headers, timing, content to infer which layers
    of the stack were successfully reached.
    """
    
    def __init__(self, stack_info: Dict):
        """
        Initialize with stack info.
        
        Args:
            stack_info: Stack info from application_traceroute
        """
        self.stack_info = stack_info
    
    def identify(self, response: requests.Response) -> List[str]:
        """
        Identify reached layers.
        
        Args:
            response: Response to analyze
        
        Returns:
            List of layer names reached (e.g., ['CDN', 'Backend'])
        """
        reached = []
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # Backend indicators
        backend_headers = [
            'x-powered-by', 'server', 'x-aspnet-version',
            'x-runtime', 'x-backend', 'x-served-by'
        ]
        
        if any(h in headers for h in backend_headers):
            reached.append('Backend')
        
        # CDN indicators
        cdn_headers = ['cf-ray', 'x-cdn', 'x-cache', 'via', 'x-cache-hits']
        if any(h in headers for h in cdn_headers):
            reached.append('CDN')
        
        # Load Balancer indicators
        lb_headers = ['x-lb-', 'x-loadbalancer', 'x-forwarded-by']
        if any(h in str(headers) for h in lb_headers):
            reached.append('LoadBalancer')
        
        # WAF indicators (presence = NOT bypassed)
        waf_headers = ['x-waf', 'x-blocked', 'x-firewall']
        if any(h in headers for h in waf_headers):
            # WAF still active
            pass
        else:
            # No WAF headers = might be bypassed
            if 'Backend' in reached:
                reached.append('WAF_Bypassed')
        
        return reached
    
    def get_reached_layers(self, response: requests.Response) -> List[str]:
        """Alias for identify()"""
        return self.identify(response)


__all__ = ['LayerIdentifier']
```

---

## 📝 FILE 6: __init__.py

```python
"""
extensions/response package

Causal response analysis for TRUE bypass verification
"""

from .causal_response_analyzer import CausalResponseAnalyzer, VerificationResult
from .content_classifier import ContentClassifier, ContentType
from .protected_content_detector import ProtectedContentDetector
from .behavioral_analyzer import BehavioralAnalyzer
from .layer_identifier import LayerIdentifier

__all__ = [
    'CausalResponseAnalyzer',
    'VerificationResult',
    'ContentClassifier',
    'ContentType',
    'ProtectedContentDetector',
    'BehavioralAnalyzer',
    'LayerIdentifier'
]
```

---

## 🔧 INTEGRAZIONE in application_traceroute.py

```python
# AGGIUNGI ALL'INIZIO DEL FILE (dopo import advanced_bypass_engine)

try:
    from extensions.response import CausalResponseAnalyzer
    CAUSAL_RESPONSE_AVAILABLE = True
except ImportError:
    CAUSAL_RESPONSE_AVAILABLE = False

# POI, MODIFICA DiscrepancyTester.__init__():

def __init__(self, target_url: str, forbidden_endpoint: str, 
             session: requests.Response, stack_analyzer: ProgressiveStackAnalyzer):
    # ... existing code ...
    
    # ADD: Causal Response Analyzer
    self.response_analyzer = None
    if CAUSAL_RESPONSE_AVAILABLE:
        try:
            self.response_analyzer = CausalResponseAnalyzer(
                stack_info=self.stack_analyzer.stack
            )
            print("  ✅ Causal Response Analyzer initialized")
        except Exception as e:
            print(f"  ⚠️  Response Analyzer init failed: {e}")

# POI, MODIFICA test_header_confusion() E ALTRI TEST:

def test_header_confusion(self):
    print("\n  🔬 Testing Header Confusion & Proxy Bypasses...")
    
    # Get baseline response
    baseline_response = self.session.get(
        self.forbidden_endpoint,
        timeout=5,
        allow_redirects=False
    )
    
    for test in header_tests:
        self.rate_limiter.wait()
        
        response = self.session.get(
            self.forbidden_endpoint,
            headers=test['headers'],
            timeout=5,
            allow_redirects=False
        )
        
        # OLD WAY (keep as fallback):
        status = response.status_code
        if status not in [400, 401, 403, 429]:
            
            # NEW WAY: Verify with Causal Response Analyzer
            if self.response_analyzer:
                verification = self.response_analyzer.verify_true_bypass(
                    baseline_response=baseline_response,
                    test_response=response,
                    bypass_info={
                        'type': 'Header Confusion',
                        'test_name': test['name'],
                        'headers': test['headers'],
                        'method': 'GET',
                        'target_layers': ['WAF', 'Proxy']
                    }
                )
                
                if verification.is_true_bypass:
                    # TRUE BYPASS CONFIRMED
                    self.discrepancies.append({
                        'type': 'Header Confusion Bypass',
                        'test_name': test['name'],
                        'forbidden_url': self.forbidden_endpoint,
                        'headers': test['headers'],
                        'response_code': status,
                        'severity': 'CRITICAL' if verification.confidence > 0.9 else 'HIGH',
                        'confidence': verification.confidence,
                        'confidence_level': verification.confidence_level,
                        'evidence': verification.evidence,
                        'causal_chain': verification.causal_chain,
                        'reasoning': verification.reasoning
                    })
                    
                    print(f"    [!] TRUE BYPASS: {test['name']} (confidence: {verification.confidence:.1%})")
                
                else:
                    # False positive filtered
                    print(f"    [~] False positive filtered: {test['name']}")
            
            else:
                # Fallback to old way (no verification)
                self.discrepancies.append({
                    'type': 'Header Confusion Bypass',
                    'test_name': test['name'],
                    'forbidden_url': self.forbidden_endpoint,
                    'headers': test['headers'],
                    'response_code': status,
                    'severity': 'CRITICAL' if status == 200 else 'HIGH',
                    'evidence': f"Bypassed 403 with status {status}"
                })
```

---

## ✅ TESTING

```python
# test_causal_response_analyzer.py

import requests
from extensions.response import CausalResponseAnalyzer

# Mock responses
baseline = requests.Response()
baseline.status_code = 403
baseline._content = b"<html><body>Access Denied - WAF Block</body></html>"

test = requests.Response()
test.status_code = 200
test._content = b"<html><body><h1>Admin Panel</h1><form>...</form></body></html>"

# Test
analyzer = CausalResponseAnalyzer(stack_info={'layers': []})
result = analyzer.verify_true_bypass(
    baseline,
    test,
    {'type': 'Header Confusion', 'target_layers': ['WAF']}
)

print(f"Is true bypass: {result.is_true_bypass}")
print(f"Confidence: {result.confidence:.1%}")
print(f"Evidence: {len(result.evidence)} signals")
```

---

## 📊 SUMMARY

**Modulo 1 Completo**:
- ✅ 6 file (~1,500 righe totali)
- ✅ Multi-level verification
- ✅ Bayesian confidence scoring
- ✅ Integrazione non-invasiva con application_traceroute
- ✅ Fallback se modulo non disponibile

**Beneficio**: Riduce drasticamente falsi positivi nella bypass detection! 🎯
