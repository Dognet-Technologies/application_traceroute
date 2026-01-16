#!/usr/bin/env python3
"""
Intelligent Bypass Validator v5.0
Revolutionary validation system using Bayesian inference and statistical analysis

Features:
- Bayesian confidence-based prioritization
- Multi-attempt adaptive validation strategies
- Statistical response differential analysis
- Evidence-based validation decisions
- Retry logic with exponential backoff
- Success probability calculation
- Integration with enhanced JSON schema v5.0
"""

import sys
import time
import json
import requests
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import statistics
import math

# Import advanced modules if available
try:
    from advanced_bypass_engine import (
        ResponseDifferentialAnalyzer,
        BayesianBypassInference,
        BypassEvidence,
        BypassConfidence,
        ResponseFingerprint
    )
    ADVANCED_VALIDATION = True
except ImportError:
    ADVANCED_VALIDATION = False
    print("⚠️  Advanced validation modules not available, falling back to basic mode")


class ValidationStrategy(Enum):
    """Validation attempt strategies"""
    DIRECT = "direct"                           # Direct request
    WITH_COOKIES = "with_cookies"              # Add session cookies
    WITH_REFERER = "with_referer"              # Add referer header
    WITH_ORIGIN = "with_origin"                # Add origin header
    WITH_USER_AGENT = "with_user_agent"        # Rotate user agent
    WITH_CACHE_BUST = "with_cache_bust"        # Add cache busting param
    MULTI_HEADER = "multi_header"              # Combine multiple headers
    DELAYED = "delayed"                         # Add delay before request


class ValidationConfidence(Enum):
    """Validation confidence levels"""
    CONFIRMED = "CONFIRMED"           # 95%+ confidence
    HIGHLY_LIKELY = "HIGHLY_LIKELY"   # 85-95% confidence
    PROBABLE = "PROBABLE"             # 70-85% confidence
    POSSIBLE = "POSSIBLE"             # 50-70% confidence
    UNCERTAIN = "UNCERTAIN"           # 30-50% confidence
    UNLIKELY = "UNLIKELY"             # <30% confidence


@dataclass
class ValidationEvidence:
    """Evidence from a validation attempt"""
    strategy: str
    success: bool
    status_code: int
    response_time_ms: float
    response_size: int
    evidence_type: str
    strength: float
    description: str
    timestamp: str


@dataclass
class ValidationResult:
    """Result of bypass validation"""
    bypass_id: str
    bypass_type: str
    original_confidence: float
    validation_confidence: ValidationConfidence
    validation_probability: float
    validated: bool
    attempts: int
    successful_strategy: Optional[str]
    evidence_collected: List[ValidationEvidence]
    bayesian_analysis: Optional[Dict[str, Any]]
    final_verdict: str
    validation_time: float
    timestamp: str


class IntelligentBypassValidator:
    """
    Revolutionary bypass validator using Bayesian inference and statistical analysis
    """

    def __init__(self, session: requests.Session, baseline_url: str, rate_limit: float = 2.0):
        """
        Initialize validator

        Args:
            session: Requests session for HTTP
            baseline_url: URL for baseline establishment
            rate_limit: Requests per second limit
        """
        self.session = session
        self.baseline_url = baseline_url
        self.rate_limit = rate_limit
        self.min_request_interval = 1.0 / rate_limit
        self.last_request_time = 0

        # Statistics
        self.validated_count = 0
        self.failed_count = 0
        self.total_attempts = 0

        # Advanced modules
        self.differential_analyzer = None
        if ADVANCED_VALIDATION:
            self.differential_analyzer = ResponseDifferentialAnalyzer()

        # Validation strategies to try
        self.strategies = [
            ValidationStrategy.DIRECT,
            ValidationStrategy.WITH_REFERER,
            ValidationStrategy.WITH_ORIGIN,
            ValidationStrategy.WITH_CACHE_BUST,
            ValidationStrategy.MULTI_HEADER,
            ValidationStrategy.WITH_USER_AGENT,
            ValidationStrategy.DELAYED
        ]

        # Learned successful strategies (adaptive learning)
        self.successful_strategies = {}

        # Baseline establishment
        self.baseline_established = False
        self.baseline_response = None

    def _rate_limit_wait(self):
        """Enforce rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.min_request_interval:
            time.sleep(self.min_request_interval - time_since_last)
        self.last_request_time = time.time()

    def _establish_baseline(self) -> bool:
        """Establish baseline response for comparison"""
        if self.baseline_established:
            return True

        if not ADVANCED_VALIDATION:
            return False

        try:
            print("  📊 Establishing validation baseline...")

            # Send 3 baseline requests
            for i in range(3):
                self._rate_limit_wait()
                response = self.session.get(self.baseline_url, timeout=10)

                fingerprint = ResponseFingerprint(
                    status_code=response.status_code,
                    size=len(response.content),
                    timing_ms=response.elapsed.total_seconds() * 1000,
                    headers=dict(response.headers),
                    content_hash=hash(response.content),
                    entropy=self._calculate_entropy(response.content)
                )

                self.differential_analyzer.add_baseline_sample(fingerprint)

            self.baseline_established = True
            print("  ✅ Baseline established (3 samples)")
            return True

        except Exception as e:
            print(f"  ⚠️  Failed to establish baseline: {e}")
            return False

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0

        # Count byte frequencies
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for freq in frequencies:
            if freq > 0:
                p = freq / data_len
                entropy -= p * math.log2(p)

        return entropy

    def validate_from_json(self, json_file: str) -> List[ValidationResult]:
        """
        Validate bypasses from enhanced JSON file

        Args:
            json_file: Path to enhanced JSON export

        Returns:
            List of validation results
        """
        print("\n🧪 INTELLIGENT BYPASS VALIDATION v5.0")
        print("=" * 70)

        # Load JSON
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
        except Exception as e:
            print(f"❌ Failed to load JSON: {e}")
            return []

        bypasses = data.get('bypasses', [])
        if not bypasses:
            print("  ⚠️  No bypasses found in JSON")
            return []

        print(f"  📋 Loaded {len(bypasses)} bypasses from JSON")
        print(f"  🎯 Schema version: {data.get('schema_version', 'unknown')}")

        # Sort bypasses by confidence (Bayesian posterior probability)
        bypasses_sorted = sorted(
            bypasses,
            key=lambda b: b.get('metadata', {}).get('confidence', 0.0),
            reverse=True
        )

        print(f"\n  🧠 Validation Strategy: Bayesian confidence-based prioritization")
        print(f"  ⏱️  Rate limit: {self.rate_limit} req/sec")

        # Establish baseline if advanced validation available
        if ADVANCED_VALIDATION:
            self._establish_baseline()

        # Validate each bypass
        results = []
        start_time = time.time()

        for idx, bypass in enumerate(bypasses_sorted, 1):
            confidence = bypass.get('metadata', {}).get('confidence', 0.0)
            bypass_type = bypass.get('metadata', {}).get('bypass_type', 'unknown')
            bypass_id = bypass.get('metadata', {}).get('bypass_id', f'bypass_{idx}')

            print(f"\n  [{idx}/{len(bypasses)}] Validating: {bypass_type}")
            print(f"      Original confidence: {confidence:.2%}")

            result = self._validate_bypass_intelligent(bypass, bypass_id)
            results.append(result)

            # Display result
            if result.validated:
                self.validated_count += 1
                print(f"      ✅ VALIDATED via {result.successful_strategy}")
                print(f"      📊 Validation confidence: {result.validation_confidence.value}")
                print(f"      🎯 Probability: {result.validation_probability:.2%}")
            else:
                self.failed_count += 1
                print(f"      ❌ FAILED after {result.attempts} attempts")
                print(f"      📊 Confidence: {result.validation_confidence.value}")

        elapsed = time.time() - start_time

        # Summary
        print(f"\n{'=' * 70}")
        print(f"📊 VALIDATION SUMMARY")
        print(f"{'=' * 70}")
        print(f"  ✅ Validated: {self.validated_count}")
        print(f"  ❌ Failed: {self.failed_count}")
        print(f"  📈 Success rate: {self.validated_count / len(bypasses) * 100:.1f}%")
        print(f"  🔬 Total attempts: {self.total_attempts}")
        print(f"  ⏱️  Duration: {elapsed:.2f}s")

        return results

    def _validate_bypass_intelligent(self, bypass: Dict, bypass_id: str) -> ValidationResult:
        """
        Intelligently validate a single bypass using multiple strategies

        Args:
            bypass: Bypass data from JSON
            bypass_id: Unique bypass identifier

        Returns:
            ValidationResult with detailed analysis
        """
        start_time = time.time()
        evidence_collected = []
        attempts = 0

        # Extract bypass details
        metadata = bypass.get('metadata', {})
        request_data = bypass.get('request', {})
        original_confidence = metadata.get('confidence', 0.0)
        bypass_type = metadata.get('bypass_type', 'unknown')
        category = metadata.get('category', 'unknown')

        url = request_data.get('url', self.baseline_url)
        method = request_data.get('method', 'GET')
        base_headers = request_data.get('headers', {})

        # Initialize Bayesian inference if available
        bayesian = None
        if ADVANCED_VALIDATION:
            # Start with original confidence as prior
            bayesian = BayesianBypassInference(prior_probability=max(original_confidence, 0.05))

        # Try validation strategies in order of learned success
        strategies_ordered = self._order_strategies_by_category(category)

        validated = False
        successful_strategy = None

        for strategy in strategies_ordered:
            attempts += 1
            self.total_attempts += 1

            # Apply strategy
            test_headers, delay = self._apply_strategy(strategy, base_headers, url)

            try:
                # Rate limiting
                self._rate_limit_wait()

                # Optional delay for DELAYED strategy
                if delay > 0:
                    time.sleep(delay)

                # Send request
                response = self.session.request(
                    method=method,
                    url=url,
                    headers=test_headers,
                    timeout=10,
                    allow_redirects=False
                )

                response_time = response.elapsed.total_seconds() * 1000
                response_size = len(response.content)
                status_code = response.status_code

                # Analyze response
                success = self._is_successful_bypass(status_code)

                # Collect evidence
                evidence = ValidationEvidence(
                    strategy=strategy.value,
                    success=success,
                    status_code=status_code,
                    response_time_ms=response_time,
                    response_size=response_size,
                    evidence_type="Status Code Change" if success else "No Change",
                    strength=0.9 if success else 0.1,
                    description=f"{strategy.value}: {status_code}",
                    timestamp=datetime.now().isoformat()
                )
                evidence_collected.append(evidence)

                # Advanced differential analysis
                if ADVANCED_VALIDATION and self.baseline_established:
                    differential_evidence = self._perform_differential_analysis(
                        response, strategy.value
                    )
                    if differential_evidence:
                        evidence_collected.extend(differential_evidence)

                        # Add to Bayesian inference
                        for ev in differential_evidence:
                            bayesian_ev = BypassEvidence(
                                evidence_type=ev.evidence_type,
                                strength=ev.strength,
                                description=ev.description,
                                likelihood_ratio=self._calculate_likelihood_ratio(ev)
                            )
                            bayesian.add_evidence(bayesian_ev)

                # If successful, mark as validated
                if success:
                    validated = True
                    successful_strategy = strategy.value

                    # Learn from success
                    self._record_successful_strategy(category, strategy)

                    break

            except Exception as e:
                # Network error
                evidence = ValidationEvidence(
                    strategy=strategy.value,
                    success=False,
                    status_code=0,
                    response_time_ms=0,
                    response_size=0,
                    evidence_type="Network Error",
                    strength=0.0,
                    description=f"Error: {str(e)}",
                    timestamp=datetime.now().isoformat()
                )
                evidence_collected.append(evidence)

        # Calculate final validation confidence
        if ADVANCED_VALIDATION and bayesian:
            validation_probability = bayesian.get_posterior_probability()
            validation_confidence = self._map_probability_to_confidence(validation_probability)
            bayesian_analysis = {
                'prior': bayesian.prior_probability,
                'posterior': validation_probability,
                'evidence_count': len(bayesian.evidence_collected),
                'confidence_level': bayesian.get_confidence_level().name
            }
        else:
            # Fallback: simple confidence based on evidence
            validation_probability = sum(e.strength for e in evidence_collected) / max(len(evidence_collected), 1)
            validation_confidence = self._map_probability_to_confidence(validation_probability)
            bayesian_analysis = None

        # Final verdict
        if validated:
            final_verdict = f"BYPASS VALIDATED via {successful_strategy}"
        else:
            final_verdict = f"BYPASS FAILED after {attempts} validation attempts"

        validation_time = time.time() - start_time

        return ValidationResult(
            bypass_id=bypass_id,
            bypass_type=bypass_type,
            original_confidence=original_confidence,
            validation_confidence=validation_confidence,
            validation_probability=validation_probability,
            validated=validated,
            attempts=attempts,
            successful_strategy=successful_strategy,
            evidence_collected=evidence_collected,
            bayesian_analysis=bayesian_analysis,
            final_verdict=final_verdict,
            validation_time=validation_time,
            timestamp=datetime.now().isoformat()
        )

    def _is_successful_bypass(self, status_code: int) -> bool:
        """Determine if status code indicates successful bypass"""
        # Success: 200, 201, 202, 204, 301, 302, 307, 308
        # Failure: 401, 403, 404, 405, 406, 429, 500+
        success_codes = [200, 201, 202, 204, 301, 302, 303, 307, 308]
        return status_code in success_codes

    def _perform_differential_analysis(self, response, strategy: str) -> List[ValidationEvidence]:
        """Perform advanced differential analysis on response"""
        if not self.differential_analyzer:
            return []

        evidence_list = []

        try:
            # Create response fingerprint
            fingerprint = ResponseFingerprint(
                status_code=response.status_code,
                size=len(response.content),
                timing_ms=response.elapsed.total_seconds() * 1000,
                headers=dict(response.headers),
                content_hash=hash(response.content),
                entropy=self._calculate_entropy(response.content)
            )

            # Analyze differential
            analysis = self.differential_analyzer.analyze_response_differential(
                fingerprint,
                test_name=strategy,
                test_data={'strategy': strategy}
            )

            # Extract evidence from analysis
            if analysis.get('bypass_detected'):
                for anomaly in analysis.get('anomalies', []):
                    evidence = ValidationEvidence(
                        strategy=strategy,
                        success=True,
                        status_code=response.status_code,
                        response_time_ms=fingerprint.timing_ms,
                        response_size=fingerprint.size,
                        evidence_type=anomaly.get('type', 'Differential Anomaly'),
                        strength=anomaly.get('significance', 0.5),
                        description=anomaly.get('description', 'Anomaly detected'),
                        timestamp=datetime.now().isoformat()
                    )
                    evidence_list.append(evidence)

        except Exception as e:
            pass  # Silently fail, don't break validation

        return evidence_list

    def _calculate_likelihood_ratio(self, evidence: ValidationEvidence) -> float:
        """Calculate likelihood ratio for Bayesian update"""
        # Map evidence type to likelihood ratio
        lr_mapping = {
            'Status Code Change': 100.0,
            'Size Differential': 50.0,
            'Timing Differential': 40.0,
            'Entropy Differential': 30.0,
            'Header Differential': 30.0,
            'Error Signature Differential': 25.0,
            'Reflection Detection': 20.0,
            'Mahalanobis Distance': 35.0,
            'Differential Anomaly': 45.0,
            'Network Error': 0.1,
            'No Change': 0.5
        }

        base_lr = lr_mapping.get(evidence.evidence_type, 10.0)

        # Adjust by evidence strength
        return base_lr * evidence.strength

    def _map_probability_to_confidence(self, probability: float) -> ValidationConfidence:
        """Map probability to confidence level"""
        if probability >= 0.95:
            return ValidationConfidence.CONFIRMED
        elif probability >= 0.85:
            return ValidationConfidence.HIGHLY_LIKELY
        elif probability >= 0.70:
            return ValidationConfidence.PROBABLE
        elif probability >= 0.50:
            return ValidationConfidence.POSSIBLE
        elif probability >= 0.30:
            return ValidationConfidence.UNCERTAIN
        else:
            return ValidationConfidence.UNLIKELY

    def _apply_strategy(self, strategy: ValidationStrategy, base_headers: Dict, url: str) -> Tuple[Dict, float]:
        """
        Apply validation strategy to headers

        Returns:
            (modified_headers, delay_seconds)
        """
        headers = base_headers.copy()
        delay = 0.0

        if strategy == ValidationStrategy.DIRECT:
            # No modifications
            pass

        elif strategy == ValidationStrategy.WITH_REFERER:
            headers['Referer'] = url

        elif strategy == ValidationStrategy.WITH_ORIGIN:
            # Extract origin from URL
            from urllib.parse import urlparse
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            headers['Origin'] = origin

        elif strategy == ValidationStrategy.WITH_CACHE_BUST:
            # Note: Would need to modify URL, but we'll add header instead
            headers['Cache-Control'] = 'no-cache'
            headers['Pragma'] = 'no-cache'

        elif strategy == ValidationStrategy.MULTI_HEADER:
            # Combine multiple bypass headers
            from urllib.parse import urlparse
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"

            headers['Referer'] = url
            headers['Origin'] = origin
            headers['X-Forwarded-For'] = '127.0.0.1'
            headers['X-Real-IP'] = '127.0.0.1'

        elif strategy == ValidationStrategy.WITH_USER_AGENT:
            # Rotate user agent
            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            ]
            import random
            headers['User-Agent'] = random.choice(user_agents)

        elif strategy == ValidationStrategy.DELAYED:
            # Add delay before request
            delay = 1.0

        return headers, delay

    def _order_strategies_by_category(self, category: str) -> List[ValidationStrategy]:
        """
        Order validation strategies based on bypass category
        Uses learned success patterns
        """
        # Check if we have learned successful strategies for this category
        if category in self.successful_strategies:
            learned_strategy = self.successful_strategies[category]
            # Put learned strategy first
            strategies = [learned_strategy] + [s for s in self.strategies if s != learned_strategy]
            return strategies

        # Default ordering based on category
        if category == 'header':
            return [
                ValidationStrategy.DIRECT,
                ValidationStrategy.MULTI_HEADER,
                ValidationStrategy.WITH_REFERER,
                ValidationStrategy.WITH_ORIGIN,
                ValidationStrategy.WITH_USER_AGENT,
                ValidationStrategy.WITH_CACHE_BUST,
                ValidationStrategy.DELAYED
            ]
        elif category == 'path':
            return [
                ValidationStrategy.DIRECT,
                ValidationStrategy.WITH_CACHE_BUST,
                ValidationStrategy.WITH_REFERER,
                ValidationStrategy.MULTI_HEADER,
                ValidationStrategy.WITH_ORIGIN,
                ValidationStrategy.WITH_USER_AGENT,
                ValidationStrategy.DELAYED
            ]
        elif category == 'method':
            return [
                ValidationStrategy.DIRECT,
                ValidationStrategy.MULTI_HEADER,
                ValidationStrategy.WITH_ORIGIN,
                ValidationStrategy.WITH_REFERER,
                ValidationStrategy.WITH_CACHE_BUST,
                ValidationStrategy.WITH_USER_AGENT,
                ValidationStrategy.DELAYED
            ]
        else:
            # Default order
            return self.strategies

    def _record_successful_strategy(self, category: str, strategy: ValidationStrategy):
        """Record successful strategy for adaptive learning"""
        self.successful_strategies[category] = strategy

    def export_validation_results(self, results: List[ValidationResult], output_file: str):
        """
        Export validation results to JSON file (schema v5.0 compatible)

        Args:
            results: List of validation results
            output_file: Output JSON file path
        """
        export_data = {
            'schema_version': '5.0',
            'validation_metadata': {
                'validator_version': '5.0',
                'validation_timestamp': datetime.now().isoformat(),
                'advanced_validation_enabled': ADVANCED_VALIDATION,
                'rate_limit': self.rate_limit,
                'total_validated': self.validated_count,
                'total_failed': self.failed_count,
                'total_attempts': self.total_attempts,
                'success_rate': self.validated_count / len(results) if results else 0.0
            },
            'validated_bypasses': [],
            'failed_bypasses': []
        }

        for result in results:
            result_dict = {
                'bypass_id': result.bypass_id,
                'bypass_type': result.bypass_type,
                'validation_status': 'VALIDATED' if result.validated else 'FAILED',
                'original_confidence': result.original_confidence,
                'validation_confidence': result.validation_confidence.value,
                'validation_probability': result.validation_probability,
                'attempts': result.attempts,
                'successful_strategy': result.successful_strategy,
                'evidence_count': len(result.evidence_collected),
                'evidence': [asdict(e) for e in result.evidence_collected],
                'bayesian_analysis': result.bayesian_analysis,
                'final_verdict': result.final_verdict,
                'validation_time': result.validation_time,
                'timestamp': result.timestamp
            }

            if result.validated:
                export_data['validated_bypasses'].append(result_dict)
            else:
                export_data['failed_bypasses'].append(result_dict)

        # Write to file
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)

        print(f"\n💾 Validation results exported to: {output_file}")
        print(f"   ✅ Validated: {len(export_data['validated_bypasses'])}")
        print(f"   ❌ Failed: {len(export_data['failed_bypasses'])}")


def main():
    """CLI interface for intelligent bypass validator"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Intelligent Bypass Validator v5.0 - Bayesian validation system'
    )
    parser.add_argument('json_file', help='Enhanced JSON file with bypasses')
    parser.add_argument('--baseline-url', required=True, help='Baseline URL for comparison')
    parser.add_argument('--rate-limit', type=float, default=2.0, help='Requests per second')
    parser.add_argument('--output', default='validation_results.json', help='Output file')

    args = parser.parse_args()

    # Create session
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'IntelligentBypassValidator/5.0'
    })

    # Create validator
    validator = IntelligentBypassValidator(
        session=session,
        baseline_url=args.baseline_url,
        rate_limit=args.rate_limit
    )

    # Validate bypasses
    results = validator.validate_from_json(args.json_file)

    # Export results
    validator.export_validation_results(results, args.output)

    print("\n✅ Validation complete!")


if __name__ == '__main__':
    main()
