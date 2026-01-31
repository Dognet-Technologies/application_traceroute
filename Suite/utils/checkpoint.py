"""
checkpoint.py - Progress save/resume functionality for security-suite

Enables saving and resuming analysis progress for long-running operations.
"""

import json
import logging
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger('security_suite.checkpoint')


@dataclass
class PhaseProgress:
    """Progress information for a single phase."""
    phase_name: str
    status: str = 'pending'  # pending, in_progress, completed, failed
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    progress_percent: float = 0.0
    items_processed: int = 0
    items_total: int = 0
    error_message: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Checkpoint:
    """
    Checkpoint data for analysis progress.

    Attributes:
        target_url: URL being analyzed
        session_id: Unique session identifier
        created_at: Checkpoint creation timestamp
        updated_at: Last update timestamp
        current_phase: Name of current phase
        phases: Progress for each phase
        results: Accumulated results data
    """
    target_url: str
    session_id: str
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    current_phase: str = ''
    phases: Dict[str, PhaseProgress] = field(default_factory=dict)
    results: Dict[str, Any] = field(default_factory=dict)


class CheckpointManager:
    """
    Manages saving and loading of analysis checkpoints.

    Supports:
    - Automatic periodic saves
    - Phase-level progress tracking
    - Resume from last checkpoint
    """

    PHASE_NAMES = [
        'stack_analysis',
        'forbidden_endpoints',
        'differential_analysis',
        'causal_graph',
        'correlation',
        'bayesian_validation',
        'taxonomy_learning',
        'report_generation'
    ]

    def __init__(self, results_dir: Path, auto_save_interval: int = 60):
        """
        Initialize checkpoint manager.

        Args:
            results_dir: Directory for checkpoint files
            auto_save_interval: Seconds between auto-saves
        """
        self.results_dir = Path(results_dir).resolve()
        self.results_dir.mkdir(parents=True, exist_ok=True)

        self.checkpoint_file = self.results_dir / 'checkpoint.json'
        self.auto_save_interval = auto_save_interval
        self.last_save_time = time.time()

        self._checkpoint: Optional[Checkpoint] = None

    def create(self, target_url: str, session_id: str) -> Checkpoint:
        """
        Create a new checkpoint.

        Args:
            target_url: Target URL for analysis
            session_id: Unique session identifier

        Returns:
            New Checkpoint instance
        """
        phases = {
            name: PhaseProgress(phase_name=name)
            for name in self.PHASE_NAMES
        }

        self._checkpoint = Checkpoint(
            target_url=target_url,
            session_id=session_id,
            phases=phases
        )

        self.save()
        logger.info(f"Created checkpoint for session {session_id}")

        return self._checkpoint

    def load(self) -> Optional[Checkpoint]:
        """
        Load checkpoint from file.

        Returns:
            Loaded Checkpoint or None if not found
        """
        if not self.checkpoint_file.exists():
            return None

        try:
            with open(self.checkpoint_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Reconstruct phases
            phases = {}
            for name, phase_data in data.get('phases', {}).items():
                phases[name] = PhaseProgress(**phase_data)

            self._checkpoint = Checkpoint(
                target_url=data['target_url'],
                session_id=data['session_id'],
                created_at=data['created_at'],
                updated_at=data['updated_at'],
                current_phase=data.get('current_phase', ''),
                phases=phases,
                results=data.get('results', {})
            )

            logger.info(f"Loaded checkpoint from {self.checkpoint_file}")
            return self._checkpoint

        except Exception as e:
            logger.error(f"Failed to load checkpoint: {e}")
            return None

    def save(self, force: bool = False) -> bool:
        """
        Save checkpoint to file.

        Args:
            force: Save even if auto-save interval hasn't elapsed

        Returns:
            True if saved, False otherwise
        """
        if self._checkpoint is None:
            return False

        # Check auto-save interval
        if not force and (time.time() - self.last_save_time) < self.auto_save_interval:
            return False

        try:
            self._checkpoint.updated_at = time.time()

            # Convert to serializable dict
            data = {
                'target_url': self._checkpoint.target_url,
                'session_id': self._checkpoint.session_id,
                'created_at': self._checkpoint.created_at,
                'updated_at': self._checkpoint.updated_at,
                'current_phase': self._checkpoint.current_phase,
                'phases': {
                    name: asdict(phase)
                    for name, phase in self._checkpoint.phases.items()
                },
                'results': self._checkpoint.results
            }

            # Write atomically
            temp_file = self.checkpoint_file.with_suffix('.tmp')
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)

            temp_file.replace(self.checkpoint_file)
            self.last_save_time = time.time()

            logger.debug(f"Saved checkpoint to {self.checkpoint_file}")
            return True

        except Exception as e:
            logger.error(f"Failed to save checkpoint: {e}")
            return False

    def start_phase(self, phase_name: str, total_items: int = 0) -> None:
        """
        Mark a phase as started.

        Args:
            phase_name: Name of the phase
            total_items: Total items to process in this phase
        """
        if self._checkpoint is None:
            return

        if phase_name not in self._checkpoint.phases:
            self._checkpoint.phases[phase_name] = PhaseProgress(phase_name=phase_name)

        phase = self._checkpoint.phases[phase_name]
        phase.status = 'in_progress'
        phase.started_at = time.time()
        phase.items_total = total_items
        phase.items_processed = 0
        phase.progress_percent = 0.0

        self._checkpoint.current_phase = phase_name
        self.save()

    def update_progress(
        self,
        phase_name: str,
        items_processed: int,
        data: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Update progress for a phase.

        Args:
            phase_name: Name of the phase
            items_processed: Number of items processed
            data: Additional data to store
        """
        if self._checkpoint is None or phase_name not in self._checkpoint.phases:
            return

        phase = self._checkpoint.phases[phase_name]
        phase.items_processed = items_processed

        if phase.items_total > 0:
            phase.progress_percent = (items_processed / phase.items_total) * 100

        if data:
            phase.data.update(data)

        # Auto-save if interval elapsed
        self.save()

    def complete_phase(
        self,
        phase_name: str,
        results: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Mark a phase as completed.

        Args:
            phase_name: Name of the phase
            results: Results from the phase
        """
        if self._checkpoint is None or phase_name not in self._checkpoint.phases:
            return

        phase = self._checkpoint.phases[phase_name]
        phase.status = 'completed'
        phase.completed_at = time.time()
        phase.progress_percent = 100.0

        if results:
            self._checkpoint.results[phase_name] = results

        self.save(force=True)
        logger.info(f"Completed phase: {phase_name}")

    def fail_phase(self, phase_name: str, error: str) -> None:
        """
        Mark a phase as failed.

        Args:
            phase_name: Name of the phase
            error: Error message
        """
        if self._checkpoint is None or phase_name not in self._checkpoint.phases:
            return

        phase = self._checkpoint.phases[phase_name]
        phase.status = 'failed'
        phase.completed_at = time.time()
        phase.error_message = error

        self.save(force=True)
        logger.error(f"Phase {phase_name} failed: {error}")

    def get_resumable_phase(self) -> Optional[str]:
        """
        Get the phase to resume from.

        Returns:
            Name of phase to resume, or None if starting fresh
        """
        if self._checkpoint is None:
            return None

        for phase_name in self.PHASE_NAMES:
            phase = self._checkpoint.phases.get(phase_name)
            if phase is None:
                return phase_name
            if phase.status in ('pending', 'in_progress', 'failed'):
                return phase_name

        return None

    def get_phase_results(self, phase_name: str) -> Optional[Dict[str, Any]]:
        """Get results from a completed phase."""
        if self._checkpoint is None:
            return None
        return self._checkpoint.results.get(phase_name)

    @property
    def checkpoint(self) -> Optional[Checkpoint]:
        """Get current checkpoint."""
        return self._checkpoint
