"""
config.py - Configuration management for security-suite

Handles loading, merging, and accessing configuration values
with support for defaults and deep merging.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional, TypeVar, Union

logger = logging.getLogger('security_suite.config')

T = TypeVar('T')


class Config:
    """
    Configuration manager with support for:
    - JSON file loading
    - Default values
    - Deep merging of nested configs
    - Dot-notation access
    """

    # Default configuration values
    DEFAULTS: Dict[str, Any] = {
        'differential_analyzer': {
            'n_baseline_samples': 50,
            'n_perturbations': 75,
            'kl_threshold': 0.05,
            'timeout': 60.0,
            'request_timeout': 10.0,
            'parallel_workers': 4
        },
        'bayesian_validator': {
            'min_tests_per_bypass': 3,
            'max_total_tests': 100,
            'success_threshold': 0.8,
            'convergence_threshold': 0.01,
            'exploration_weight': 2.0
        },
        'self_learning_taxonomy': {
            'min_cluster_size': 5,
            'min_samples': 3,
            'recluster_threshold': 20,
            'feature_dimensions': 9
        },
        'causal_graph': {
            'max_cycle_depth': 100,
            'default_edge_strength': 0.5,
            'propagation_decay': 0.9
        },
        'hybrid_correlator': {
            'graph_weight': 0.4,
            'feature_weight': 0.6,
            'similarity_threshold': 0.3
        },
        'orchestrator': {
            'checkpoint_interval': 60,
            'max_retries': 3,
            'report_format': 'markdown'
        },
        'logging': {
            'level': 'INFO',
            'file': 'security_suite.log',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        }
    }

    def __init__(self, config_path: Optional[Union[str, Path]] = None):
        """
        Initialize configuration.

        Args:
            config_path: Path to JSON config file (optional)
        """
        self._config: Dict[str, Any] = self._deep_copy(self.DEFAULTS)

        if config_path:
            self._load_from_file(config_path)

    def _load_from_file(self, config_path: Union[str, Path]) -> None:
        """Load configuration from JSON file and merge with defaults."""
        path = Path(config_path).resolve()

        if not path.exists():
            logger.warning(f"Config file not found: {path}, using defaults")
            return

        try:
            with open(path, 'r', encoding='utf-8') as f:
                user_config = json.load(f)

            self._config = self._deep_merge(self._config, user_config)
            logger.info(f"Loaded configuration from {path}")

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
            raise
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            raise

    def _deep_copy(self, obj: Any) -> Any:
        """Create a deep copy of nested dict/list structures."""
        if isinstance(obj, dict):
            return {k: self._deep_copy(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._deep_copy(item) for item in obj]
        return obj

    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deep merge two dictionaries.

        Args:
            base: Base dictionary (defaults)
            override: Override dictionary (user values)

        Returns:
            Merged dictionary with override taking precedence
        """
        result = self._deep_copy(base)

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = self._deep_copy(value)

        return result

    def get(self, section: str, key: Optional[str] = None, default: T = None) -> Union[T, Any]:
        """
        Get configuration value.

        Args:
            section: Top-level section name
            key: Key within section (optional, returns whole section if None)
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        if section not in self._config:
            return default

        section_data = self._config[section]

        if key is None:
            return section_data

        return section_data.get(key, default)

    def set(self, section: str, key: str, value: Any) -> None:
        """
        Set configuration value at runtime.

        Args:
            section: Top-level section name
            key: Key within section
            value: Value to set
        """
        if section not in self._config:
            self._config[section] = {}

        self._config[section][key] = value

    def get_section(self, section: str) -> Dict[str, Any]:
        """Get entire section as dictionary."""
        return self._deep_copy(self._config.get(section, {}))

    def save(self, config_path: Union[str, Path]) -> None:
        """
        Save current configuration to file.

        Args:
            config_path: Path to save configuration
        """
        path = Path(config_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self._config, f, indent=2)

        logger.info(f"Saved configuration to {path}")

    def __getitem__(self, key: str) -> Any:
        """Dictionary-style access to sections."""
        return self._config.get(key, {})

    def __contains__(self, key: str) -> bool:
        """Check if section exists."""
        return key in self._config

    def as_dict(self) -> Dict[str, Any]:
        """Return full configuration as dictionary."""
        return self._deep_copy(self._config)


# Global configuration instance
_global_config: Optional[Config] = None


def get_config(config_path: Optional[Union[str, Path]] = None) -> Config:
    """
    Get or create global configuration instance.

    Args:
        config_path: Path to config file (only used on first call)

    Returns:
        Global Config instance
    """
    global _global_config

    if _global_config is None:
        _global_config = Config(config_path)

    return _global_config


def reset_config() -> None:
    """Reset global configuration (useful for testing)."""
    global _global_config
    _global_config = None
