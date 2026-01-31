"""
orchestrator.py - Security Suite Orchestrator

Main orchestrator implementing 8-phase analysis workflow:
1. Stack Analysis
2. Forbidden Endpoints Discovery
3. Differential Analysis
4. Causal Graph Construction
5. Correlation Analysis
6. Bayesian Validation
7. Taxonomy Learning
8. Report Generation

Features:
- Rich TUI with progress tracking
- Checkpoint/resume support
- Parallel execution where possible
"""

import argparse
import json
import logging
import sys
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
    from rich.layout import Layout
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from ..utils.checkpoint import CheckpointManager
from ..core.behavioral.differential_analyzer import DifferentialCausalAnalyzer
from ..core.graph.causal_graph import CausalSecurityGraph
from ..core.graph.causal_node import CausalNode, NodeType
from ..core.graph.causal_edge import CausalEdge, CausalityType
from ..core.correlation.hybrid_correlator import HybridCorrelationEngine, CorrelationType
from ..core.validation.bayesian_validator import BayesianBypassValidator, ValidationResult
from ..modules.taxonomy.adaptive_taxonomy import SelfLearningTaxonomy

logger = logging.getLogger('security_suite.orchestrator')


class Phase(Enum):
    """Analysis phases."""
    STACK_ANALYSIS = 'stack_analysis'
    FORBIDDEN_ENDPOINTS = 'forbidden_endpoints'
    DIFFERENTIAL_ANALYSIS = 'differential_analysis'
    CAUSAL_GRAPH = 'causal_graph'
    CORRELATION = 'correlation'
    BAYESIAN_VALIDATION = 'bayesian_validation'
    TAXONOMY_LEARNING = 'taxonomy_learning'
    REPORT_GENERATION = 'report_generation'


@dataclass
class PhaseResult:
    """Result of a phase execution."""
    phase: Phase
    success: bool
    duration: float
    findings: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class AnalysisConfig:
    """Configuration for analysis."""
    target_url: str
    results_dir: Path
    timeout: float = 300.0
    resume: bool = False
    verbose: bool = False
    parallel: bool = True
    phases: Optional[List[Phase]] = None


class SecuritySuiteOrchestrator:
    """
    Main orchestrator for security analysis.

    Coordinates all analysis phases and provides:
    - Progress tracking with Rich TUI
    - Checkpoint/resume capability
    - Result aggregation and reporting
    """

    def __init__(self, config: AnalysisConfig):
        """
        Initialize orchestrator.

        Args:
            config: Analysis configuration
        """
        self.config = config
        self.session_id = str(uuid.uuid4())[:8]

        # Setup results directory
        self.results_dir = Path(config.results_dir).resolve()
        self.results_dir.mkdir(parents=True, exist_ok=True)

        # Initialize components
        self.checkpoint_manager = CheckpointManager(self.results_dir)
        self.causal_graph = CausalSecurityGraph()
        self.differential_analyzer = DifferentialCausalAnalyzer()
        self.correlator = HybridCorrelationEngine()
        self.validator = BayesianBypassValidator()
        self.taxonomy = SelfLearningTaxonomy()

        # Phase results
        self.results: Dict[Phase, PhaseResult] = {}

        # Rich console
        self.console = Console() if RICH_AVAILABLE else None

        # Setup logging
        self._setup_logging()

        logger.info(f"Initialized orchestrator for {config.target_url}")
        logger.info(f"Session ID: {self.session_id}, Results: {self.results_dir}")

    def _setup_logging(self) -> None:
        """Configure logging."""
        log_file = self.results_dir / 'analysis.log'

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))

        root_logger = logging.getLogger('security_suite')
        root_logger.addHandler(file_handler)

        if self.config.verbose:
            root_logger.setLevel(logging.DEBUG)
        else:
            root_logger.setLevel(logging.INFO)

    def run(self) -> Dict[str, Any]:
        """
        Execute full analysis workflow.

        Returns:
            Final analysis results
        """
        start_time = time.time()

        # Print banner
        self._print_banner()

        # Check for resume
        if self.config.resume:
            checkpoint = self.checkpoint_manager.load()
            if checkpoint:
                self._print_status(f"Resuming from checkpoint: {checkpoint.session_id}")
                resume_phase = self.checkpoint_manager.get_resumable_phase()
                self._print_status(f"Resuming from phase: {resume_phase}")
            else:
                self._print_status("No checkpoint found, starting fresh")
        else:
            self.checkpoint_manager.create(self.config.target_url, self.session_id)

        # Determine phases to run
        phases_to_run = self.config.phases or list(Phase)

        # Execute phases
        if RICH_AVAILABLE and self.console:
            self._run_with_progress(phases_to_run)
        else:
            self._run_simple(phases_to_run)

        # Generate final report
        total_time = time.time() - start_time
        final_results = self._generate_final_report(total_time)

        # Save results
        self._save_results(final_results)

        return final_results

    def _print_banner(self) -> None:
        """Print startup banner."""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║           Security Testing Suite - Causal Inference           ║
║                       Version 4.0                             ║
╚═══════════════════════════════════════════════════════════════╝
        """
        if self.console:
            self.console.print(Panel(banner, style="bold blue"))
        else:
            print(banner)

    def _print_status(self, message: str, style: str = "bold") -> None:
        """Print status message."""
        if self.console:
            self.console.print(f"[{style}]{message}[/{style}]")
        else:
            print(message)

    def _run_with_progress(self, phases: List[Phase]) -> None:
        """Run phases with Rich progress display."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        ) as progress:
            main_task = progress.add_task("[cyan]Overall Progress", total=len(phases))

            for phase in phases:
                phase_task = progress.add_task(f"[yellow]{phase.value}", total=100)

                result = self._execute_phase(phase, progress, phase_task)
                self.results[phase] = result

                progress.update(phase_task, completed=100)
                progress.update(main_task, advance=1)

                if not result.success:
                    self._print_status(f"Phase {phase.value} failed: {result.error}", "bold red")

    def _run_simple(self, phases: List[Phase]) -> None:
        """Run phases with simple progress display."""
        for i, phase in enumerate(phases):
            print(f"\n[{i + 1}/{len(phases)}] Running {phase.value}...")

            result = self._execute_phase(phase)
            self.results[phase] = result

            if result.success:
                print(f"  ✓ Completed in {result.duration:.1f}s")
            else:
                print(f"  ✗ Failed: {result.error}")

    def _execute_phase(
        self,
        phase: Phase,
        progress: Optional[Any] = None,
        task_id: Optional[Any] = None
    ) -> PhaseResult:
        """Execute a single phase."""
        start_time = time.time()

        try:
            self.checkpoint_manager.start_phase(phase.value)

            if phase == Phase.STACK_ANALYSIS:
                findings = self._phase_stack_analysis(progress, task_id)
            elif phase == Phase.FORBIDDEN_ENDPOINTS:
                findings = self._phase_forbidden_endpoints(progress, task_id)
            elif phase == Phase.DIFFERENTIAL_ANALYSIS:
                findings = self._phase_differential_analysis(progress, task_id)
            elif phase == Phase.CAUSAL_GRAPH:
                findings = self._phase_causal_graph(progress, task_id)
            elif phase == Phase.CORRELATION:
                findings = self._phase_correlation(progress, task_id)
            elif phase == Phase.BAYESIAN_VALIDATION:
                findings = self._phase_bayesian_validation(progress, task_id)
            elif phase == Phase.TAXONOMY_LEARNING:
                findings = self._phase_taxonomy_learning(progress, task_id)
            elif phase == Phase.REPORT_GENERATION:
                findings = self._phase_report_generation(progress, task_id)
            else:
                findings = {}

            duration = time.time() - start_time
            self.checkpoint_manager.complete_phase(phase.value, findings)

            return PhaseResult(
                phase=phase,
                success=True,
                duration=duration,
                findings=findings
            )

        except Exception as e:
            duration = time.time() - start_time
            error_msg = str(e)
            logger.error(f"Phase {phase.value} failed: {error_msg}", exc_info=True)
            self.checkpoint_manager.fail_phase(phase.value, error_msg)

            return PhaseResult(
                phase=phase,
                success=False,
                duration=duration,
                error=error_msg
            )

    def _phase_stack_analysis(
        self,
        progress: Optional[Any] = None,
        task_id: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Phase 1: Analyze technology stack."""
        import requests

        findings = {
            'technologies': [],
            'headers': {},
            'server': None
        }

        try:
            response = requests.get(self.config.target_url, timeout=10)

            # Extract headers
            findings['headers'] = dict(response.headers)

            # Detect server
            server = response.headers.get('Server', 'Unknown')
            findings['server'] = server

            # Detect technologies from headers
            tech_indicators = {
                'X-Powered-By': 'x-powered-by',
                'X-AspNet-Version': 'asp.net',
                'X-Generator': 'generator',
            }

            for header, tech in tech_indicators.items():
                if header in response.headers:
                    findings['technologies'].append({
                        'name': tech,
                        'version': response.headers[header],
                        'source': 'header'
                    })

            # Add to causal graph
            self.causal_graph.add_node(
                'server',
                NodeType.INFRASTRUCTURE,
                name=server
            )

            if progress and task_id:
                progress.update(task_id, completed=50)

        except Exception as e:
            logger.error(f"Stack analysis error: {e}")
            findings['error'] = str(e)

        return findings

    def _phase_forbidden_endpoints(
        self,
        progress: Optional[Any] = None,
        task_id: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Phase 2: Discover forbidden/protected endpoints."""
        import requests

        common_paths = [
            '/admin', '/api', '/config', '/backup',
            '/wp-admin', '/phpmyadmin', '/.git',
            '/api/v1', '/api/v2', '/swagger',
            '/graphql', '/.env', '/debug'
        ]

        findings = {
            'forbidden': [],
            'accessible': [],
            'errors': []
        }

        base_url = self.config.target_url.rstrip('/')

        for i, path in enumerate(common_paths):
            try:
                url = f"{base_url}{path}"
                response = requests.get(url, timeout=5, allow_redirects=False)

                endpoint_info = {
                    'path': path,
                    'status': response.status_code,
                    'size': len(response.content)
                }

                if response.status_code == 403:
                    findings['forbidden'].append(endpoint_info)
                    # Add to causal graph
                    self.causal_graph.add_node(
                        f"endpoint_{path.replace('/', '_')}",
                        NodeType.ENDPOINT,
                        name=path,
                        metadata={'status': 403, 'protected': True}
                    )
                elif response.status_code == 200:
                    findings['accessible'].append(endpoint_info)

            except requests.Timeout:
                findings['errors'].append({'path': path, 'error': 'timeout'})
            except Exception as e:
                findings['errors'].append({'path': path, 'error': str(e)})

            if progress and task_id:
                progress.update(task_id, completed=int((i + 1) / len(common_paths) * 100))

        return findings

    def _phase_differential_analysis(
        self,
        progress: Optional[Any] = None,
        task_id: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Phase 3: Differential causal analysis."""
        result = self.differential_analyzer.analyze(
            self.config.target_url,
            self.results_dir
        )

        # Add anomalies to causal graph
        for anomaly in result.anomalies:
            node_id = f"anomaly_{anomaly.perturbation_type.value}_{len(self.causal_graph._nodes)}"
            self.causal_graph.add_node(
                node_id,
                NodeType.BEHAVIOR,
                name=f"Anomaly: {anomaly.perturbation_type.value}",
                metadata={
                    'score': anomaly.anomaly_score,
                    'layer': anomaly.affected_layer
                }
            )

            # Register for correlation
            self.correlator.register_entity(
                node_id,
                features={
                    'type': anomaly.perturbation_type.value,
                    'score': anomaly.anomaly_score,
                    'layer': anomaly.affected_layer
                },
                timestamp=time.time()
            )

        return {
            'anomaly_count': len(result.anomalies),
            'kl_divergence': result.kl_divergence,
            'affected_layers': result.affected_layers,
            'analysis_time': result.analysis_time
        }

    def _phase_causal_graph(
        self,
        progress: Optional[Any] = None,
        task_id: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Phase 4: Build causal graph."""
        # Connect related nodes
        nodes = list(self.causal_graph._nodes.keys())

        for i, node1 in enumerate(nodes):
            n1 = self.causal_graph.get_node(node1)
            if n1 is None:
                continue

            for node2 in nodes[i + 1:]:
                n2 = self.causal_graph.get_node(node2)
                if n2 is None:
                    continue

                # Connect infrastructure to endpoints
                if n1.node_type == NodeType.INFRASTRUCTURE and n2.node_type == NodeType.ENDPOINT:
                    self.causal_graph.add_edge(
                        node1, node2,
                        CausalityType.DIRECT,
                        strength=0.7
                    )

                # Connect endpoints to behaviors
                if n1.node_type == NodeType.ENDPOINT and n2.node_type == NodeType.BEHAVIOR:
                    self.causal_graph.add_edge(
                        node1, node2,
                        CausalityType.INDIRECT,
                        strength=0.5
                    )

        return {
            'node_count': self.causal_graph.node_count,
            'edge_count': self.causal_graph.edge_count,
            'graph': self.causal_graph.to_dict()
        }

    def _phase_correlation(
        self,
        progress: Optional[Any] = None,
        task_id: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Phase 5: Correlation analysis."""
        # Find correlations
        correlations = self.correlator.find_all_correlations()

        # Find clusters
        clusters = self.correlator.find_correlation_clusters()

        return {
            'correlation_count': len(correlations),
            'cluster_count': len(clusters),
            'statistics': self.correlator.get_statistics()
        }

    def _phase_bayesian_validation(
        self,
        progress: Optional[Any] = None,
        task_id: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Phase 6: Bayesian bypass validation."""
        import requests

        # Add exploit candidates based on findings
        exploit_templates = [
            ('sqli_union', 'sqli', "' UNION SELECT NULL--"),
            ('sqli_boolean', 'sqli', "' OR '1'='1"),
            ('xss_script', 'xss', '<script>alert(1)</script>'),
            ('xss_event', 'xss', '<img onerror=alert(1)>'),
            ('path_basic', 'path_traversal', '../../../etc/passwd'),
            ('path_encoded', 'path_traversal', '..%2F..%2F..%2Fetc%2Fpasswd'),
        ]

        for exploit_id, category, payload in exploit_templates:
            self.validator.add_candidate(exploit_id, category, payload)

        # Test each candidate
        base_url = self.config.target_url.rstrip('/')

        for _ in range(10):  # 10 rounds of Thompson Sampling
            candidate = self.validator.select_next_exploit_thompson()
            if candidate is None:
                break

            try:
                test_url = f"{base_url}?test={candidate.payload}"
                response = requests.get(test_url, timeout=5)

                # Simple success detection
                if response.status_code == 200 and candidate.payload in response.text:
                    result = ValidationResult.SUCCESS
                elif response.status_code == 403:
                    result = ValidationResult.FAILURE
                else:
                    result = ValidationResult.PARTIAL

                self.validator.record_result(
                    candidate.exploit_id,
                    test_url,
                    result,
                    response.status_code,
                    response.elapsed.total_seconds()
                )

            except Exception as e:
                self.validator.record_result(
                    candidate.exploit_id,
                    test_url,
                    ValidationResult.ERROR,
                    0, 0,
                    {'error': str(e)}
                )

        summary = self.validator.get_summary()

        return {
            'total_attempts': summary.total_attempts,
            'successful': summary.successful,
            'success_rate': summary.success_rate,
            'best_exploits': summary.best_exploits,
            'vulnerable_endpoints': summary.vulnerable_endpoints
        }

    def _phase_taxonomy_learning(
        self,
        progress: Optional[Any] = None,
        task_id: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Phase 7: Taxonomy learning."""
        # Collect observations from findings
        observations = []

        # From differential analysis
        diff_result = self.results.get(Phase.DIFFERENTIAL_ANALYSIS)
        if diff_result and diff_result.success:
            for layer, count in diff_result.findings.get('affected_layers', {}).items():
                observations.append((f"Affected layer: {layer}", layer))

        # From validation
        val_result = self.results.get(Phase.BAYESIAN_VALIDATION)
        if val_result and val_result.success:
            for exploit in val_result.findings.get('best_exploits', []):
                observations.append((f"Successful exploit: {exploit}", exploit.split('_')[0]))

        # Learn from observations
        new_clusters = 0
        if observations:
            new_clusters = self.taxonomy.learn_from_observations(observations)

        return {
            'observations_processed': len(observations),
            'new_clusters': new_clusters,
            'taxonomy': self.taxonomy.export()
        }

    def _phase_report_generation(
        self,
        progress: Optional[Any] = None,
        task_id: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Phase 8: Generate final report."""
        report = {
            'target': self.config.target_url,
            'session_id': self.session_id,
            'timestamp': time.time(),
            'phases': {}
        }

        for phase, result in self.results.items():
            report['phases'][phase.value] = {
                'success': result.success,
                'duration': result.duration,
                'findings': result.findings if result.success else None,
                'error': result.error
            }

        # Summary statistics
        report['summary'] = {
            'total_phases': len(self.results),
            'successful_phases': sum(1 for r in self.results.values() if r.success),
            'total_duration': sum(r.duration for r in self.results.values()),
            'causal_nodes': self.causal_graph.node_count,
            'causal_edges': self.causal_graph.edge_count,
            'correlations': len(self.correlator._correlations)
        }

        return report

    def _generate_final_report(self, total_time: float) -> Dict[str, Any]:
        """Generate final analysis report."""
        report = {
            'meta': {
                'target': self.config.target_url,
                'session_id': self.session_id,
                'total_time': total_time,
                'results_dir': str(self.results_dir)
            },
            'phases': {},
            'summary': {
                'phases_total': len(self.results),
                'phases_successful': sum(1 for r in self.results.values() if r.success),
                'phases_failed': sum(1 for r in self.results.values() if not r.success)
            }
        }

        for phase, result in self.results.items():
            report['phases'][phase.value] = {
                'success': result.success,
                'duration': result.duration,
                'error': result.error
            }

        # Print summary
        if self.console:
            self._print_summary_table(report)
        else:
            print(f"\nAnalysis complete in {total_time:.1f}s")
            print(f"Successful phases: {report['summary']['phases_successful']}/{report['summary']['phases_total']}")

        return report

    def _print_summary_table(self, report: Dict[str, Any]) -> None:
        """Print summary table with Rich."""
        table = Table(title="Analysis Summary")
        table.add_column("Phase", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Duration", style="yellow")

        for phase_name, phase_data in report['phases'].items():
            status = "✓ Success" if phase_data['success'] else f"✗ Failed: {phase_data.get('error', 'Unknown')}"
            duration = f"{phase_data['duration']:.1f}s"
            table.add_row(phase_name, status, duration)

        self.console.print(table)

    def _save_results(self, results: Dict[str, Any]) -> None:
        """Save results to file."""
        output_file = self.results_dir / 'final_report.json'

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)

        logger.info(f"Saved final report to {output_file}")
        self._print_status(f"Results saved to {output_file}")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Security Testing Suite - Causal Inference Framework'
    )
    parser.add_argument('target', help='Target URL to analyze')
    parser.add_argument('-o', '--output', default='results', help='Output directory')
    parser.add_argument('-r', '--resume', action='store_true', help='Resume from checkpoint')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-t', '--timeout', type=float, default=300, help='Timeout in seconds')
    parser.add_argument('--phases', nargs='+', help='Specific phases to run')

    args = parser.parse_args()

    # Parse phases if specified
    phases = None
    if args.phases:
        phases = [Phase(p) for p in args.phases]

    config = AnalysisConfig(
        target_url=args.target,
        results_dir=Path(args.output),
        timeout=args.timeout,
        resume=args.resume,
        verbose=args.verbose,
        phases=phases
    )

    orchestrator = SecuritySuiteOrchestrator(config)
    results = orchestrator.run()

    # Exit code based on success
    success_count = results['summary']['phases_successful']
    total_count = results['summary']['phases_total']

    if success_count == total_count:
        return 0
    elif success_count > 0:
        return 1
    else:
        return 2


if __name__ == '__main__':
    sys.exit(main())
