"""
setup.py

Installation script for security-testing-suite
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="security-testing-suite",
    version="4.0.0",
    description="Advanced Security Testing Suite with Causal Inference",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Simone",
    packages=find_packages(),
    install_requires=[
        'requests>=2.31.0',
        'beautifulsoup4>=4.12.0',
        'numpy>=1.24.0',
        'scipy>=1.10.0',
        'scikit-learn>=1.3.0',
        'hdbscan>=0.8.33',
        'lxml>=4.9.0',
        'urllib3>=2.0.0',
    ],
    python_requires='>=3.10',
    entry_points={
        'console_scripts': [
            'security-traceroute=core.traceroute.application_traceroute_v3_5:main',
            'security-crawler=core.crawler.smart_vuln_crawler2:main',
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
