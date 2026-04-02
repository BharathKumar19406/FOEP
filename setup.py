# setup.py
"""
Forensic OSINT-to-Evidence Pipeline (FOEP)
Complete setup configuration for installation and distribution.
Properly configured for CLI entry points and Kali Linux compatibility.
"""

from setuptools import setup, find_packages, find_namespace_packages
import os
import sys

# Read README for long description
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

# Read requirements from requirements.txt
def read_requirements(filename):
    """Read requirements from file, ignoring comments and empty lines."""
    requirements = []
    if os.path.exists(filename):
        with open(filename, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    # Handle lines with extras (e.g., pydantic>=2.0)
                    if not line.startswith("-"):
                        requirements.append(line)
    return requirements

# Find all packages in src/ directory
packages = find_packages(where="src")
# Add scripts as a package
packages.append("scripts")

setup(
    name="foep",
    version="0.1.0",
    description="Forensic OSINT-to-Evidence Pipeline: Unified framework for correlating digital forensics and open-source intelligence",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="FOEP Development Team",
    author_email="foep-team@example.com",
    url="https://github.com/BharathKumar19406/FOEP",
    license="MIT",
    
    # Properly configured package structure
    packages=packages,
    package_dir={
        "": "src",          # src/foep, src/foep/*, etc.
        "scripts": "scripts"  # scripts/ as root level package
    },
    
    python_requires=">=3.10",
    install_requires=read_requirements("requirements.txt"),
    extras_require={
        "dev": read_requirements("requirements-dev.txt"),
    },
    # CLI entry points - THIS FIXES YOUR ERROR
    entry_points={
        "console_scripts": [
            "foep-ingest=scripts.foep_ingest:main",
            "foep-correlate=scripts.foep_correlate:main",
            "foep-report=scripts.foep_report:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Legal Industry",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Forensics",
        "Topic :: Utilities",
    ],
    keywords="forensics osint cybersecurity incident-response threat-intelligence",
    project_urls={
        "Documentation": "https://github.com/your-org/foep/blob/main/README.md",
        "Source": "https://github.com/your-org/foep",
        "Tracker": "https://github.com/your-org/foep/issues",
    },
    zip_safe=False,
)
