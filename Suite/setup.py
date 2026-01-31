"""
setup.py - Installation script for security-suite
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_file = Path(__file__).parent / "README.md"
if readme_file.exists():
    with open(readme_file, "r", encoding="utf-8") as fh:
        long_description = fh.read()
else:
    long_description = "Causal Inference Security Testing Framework"

setup(
    name="security-testing-suite",
    version="1.0.0",
    author="Security Research Team",
    author_email="security@example.com",
    description="Causal Inference Security Testing Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/security-suite",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
    install_requires=[
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
        "numpy>=1.24.0",
        "scipy>=1.10.0",
        "rich>=13.0.0",
        "click>=8.1.0",
        "hdbscan>=0.8.33",
        "scikit-learn>=1.3.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "viz": [
            "matplotlib>=3.7.0",
            "networkx>=3.1",
        ],
    },
    entry_points={
        'console_scripts': [
            'security-suite=cli.orchestrator:main',
        ],
    },
    package_dir={'': '.'},
    include_package_data=True,
    zip_safe=False,
)
