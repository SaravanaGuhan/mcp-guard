#!/usr/bin/env python3
"""
Setup script for MCP Guard - Professional Security Scanner
"""

from setuptools import setup, find_packages
import os

# Read the README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="mcp-guard",
    version="1.0.0",
    author="MCP Security Research Team",
    author_email="security@mcpguard.dev",
    description="Professional security scanner for Model Context Protocol (MCP) servers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-username/mcp-guard",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "pyyaml>=6.0",
    ],
    extras_require={
        "full": [
            "websockets>=11.0.0",
            "aiohttp>=3.8.0", 
            "tomli>=2.0.0",
            "bandit>=1.7.0",
            "safety>=2.3.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
        ],
        "docs": [
            "mkdocs>=1.5.0",
            "mkdocs-material>=9.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "mcp-guard=mcp_scanner:main",
            "mcp-scanner=mcp_scanner:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords="mcp security scanner vulnerability assessment model context protocol ai",
    project_urls={
        "Bug Reports": "https://github.com/your-username/mcp-guard/issues",
        "Source": "https://github.com/your-username/mcp-guard",
        "Documentation": "https://github.com/your-username/mcp-guard/wiki",
        "Changelog": "https://github.com/your-username/mcp-guard/blob/main/CHANGELOG.md",
    },
)