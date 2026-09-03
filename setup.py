#!/usr/bin/env python3
"""Packaging for MCP Guard."""

from setuptools import find_packages, setup

with open("README.md", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="mcp-guard",
    version="2.0.0",
    description="Evidence-backed security scanner for Model Context Protocol servers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/SaravanaGuhan/mcp-guard",
    license="MIT",
    packages=find_packages(include=["mcp_guard", "mcp_guard.*"]),
    python_requires=">=3.10",
    install_requires=[
        "requests>=2.31.0",
        "cvss>=3.0",
        "tomli>=2.0.0; python_version < '3.11'",
        "PyYAML>=6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "jsonschema>=4.0.0",
        ],
    },
    entry_points={"console_scripts": ["mcp-guard=mcp_guard.cli:main"]},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
)
