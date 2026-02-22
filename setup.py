# setup.py
"""
Forensic OSINT-to-Evidence Pipeline (FOEP)
Complete setup configuration for installation and distribution.
"""

from setuptools import setup, find_packages
import os

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
                    requirements.append(line)
    return requirements

setup(
    name="foep",
    version="0.1.0",
    description="Forensic OSINT-to-Evidence Pipeline: Unified framework for correlating digital forensics and open-source intelligence",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="FOEP Development Team",
    author_email="foep-team@example.com",
    url="https://github.com/your-org/foep",
    license="MIT",
    # Core package structure
    packages=find_packages(where="src") + ["scripts"],
    package_dir={
        "": "src",
        "scripts": "scripts"
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
