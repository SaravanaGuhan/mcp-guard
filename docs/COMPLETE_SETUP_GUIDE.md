# MCP Guard - Complete Setup Guide

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [System Requirements](#system-requirements)
3. [Step-by-Step Installation](#step-by-step-installation)
4. [Verification](#verification)
5. [First Scan](#first-scan)
6. [Troubleshooting](#troubleshooting)
7. [Next Steps](#next-steps)

## 🔧 Prerequisites

Before installing MCP Guard, ensure you have:

### Required Software
- **Python 3.8 or higher** (Python 3.11 recommended)
- **Git** (for downloading the repository)
- **Internet connection** (for downloading dependencies and scanning repositories)

### Windows-Specific Requirements
- **Windows 10 or higher**
- **PowerShell** or **Command Prompt**
- **Administrator privileges** (for installing Python packages)

## 💻 System Requirements

### Minimum Requirements
- **OS**: Windows 10/11, macOS 10.15+, or Linux
- **Python**: 3.8+
- **RAM**: 512 MB available
- **Storage**: 100 MB free space
- **Network**: Internet connection

### Recommended Requirements
- **OS**: Windows 11, macOS 12+, or Ubuntu 20.04+
- **Python**: 3.11+
- **RAM**: 2 GB available
- **Storage**: 1 GB free space
- **CPU**: Multi-core processor

## 🚀 Step-by-Step Installation

### Step 1: Install Python (if not already installed)

#### Option A: Download from Python.org
1. Go to [python.org/downloads](https://python.org/downloads)
2. Download Python 3.11 or higher
3. Run the installer
4. **IMPORTANT**: Check "Add Python to PATH" during installation
5. Click "Install Now"

#### Option B: Using Microsoft Store (Windows 11)
1. Open Microsoft Store
2. Search for "Python 3.11"
3. Click "Install"

#### Verify Python Installation
Open Command Prompt or PowerShell and run:
```cmd
python --version
```
You should see something like: `Python 3.11.x`

If you see an error, try:
```cmd
python3 --version
```

### Step 2: Install Git (if not already installed)

1. Go to [git-scm.com/download/win](https://git-scm.com/download/win)
2. Download Git for Windows
3. Run the installer with default settings
4. Verify installation:
```cmd
git --version
```

### Step 3: Download MCP Guard

#### Option A: Using Git (Recommended)
Open Command Prompt or PowerShell and navigate to your desired location:

```cmd
# Navigate to Downloads folder
cd C:\Users\[username]\Downloads

# Create a folder for MCP security tools
mkdir "Secure MCP"
cd "Secure MCP"

# Clone the repository
git clone https://github.com/your-username/mcp-guard.git
cd mcp-guard
```

#### Option B: Download ZIP file
1. Go to the GitHub repository
2. Click "Code" → "Download ZIP"
3. Extract to: `C:\Users\[username]\Downloads\mcp-guard`
4. Open Command Prompt and navigate:
```cmd
cd "C:\Users\[username]\Downloads\mcp-guard"
```

### Step 4: Set Up Python Virtual Environment (Recommended)

Create an isolated Python environment:

```cmd
# Create virtual environment
python -m venv mcp-guard-env

# Activate virtual environment
# For Command Prompt:
mcp-guard-env\Scripts\activate

# For PowerShell:
mcp-guard-env\Scripts\Activate.ps1
```

You should see `(mcp-guard-env)` at the beginning of your command prompt.

### Step 5: Install Dependencies

With the virtual environment activated:

```cmd
# Upgrade pip first
python -m pip install --upgrade pip

# Install MCP Guard dependencies
pip install -r requirements.txt
```

This will install:
- `requests` - For downloading repositories
- `pyyaml` - For configuration files
- `colorama` - For colored console output
- Other security analysis tools

### Step 6: Verify Installation

Run the test suite to ensure everything is working:

```cmd
# Test basic functionality
python test_mcp_scanner.py

# Test download functionality
python test_download.py
```

You should see output like:
```
✅ Successfully imported MCP Guard modules
✅ Scanner initialized successfully
✅ Repository handler initialized successfully
✅ Basic functionality: PASSED
```

## ✅ Verification

### Quick Verification Test

Run this command to verify MCP Guard is working:

```cmd
python mcp_scanner.py --help
```

You should see the help message with available options.

### Full Verification Test

Run a quick scan on a test repository:

```cmd
python mcp_scanner.py https://github.com/octocat/Hello-World
```

This should complete without errors (though it may not find vulnerabilities in this simple repository).

## 🎯 First Scan

Now let's run your first real security scan:

### Scan an MCP Server

```cmd
# Scan the Airbnb MCP Server (Node.js)
python mcp_scanner.py <repository-url>
```

### Expected Output

You should see output similar to:

```
================================================================================
MCP GUARD SECURITY ASSESSMENT REPORT
================================================================================
Target: <repository-url>
Scan Type: COMPREHENSIVE (STATIC + DYNAMIC)
Timestamp: 2025-08-02 12:00:00 UTC

--------------------------------------------------------------------------------
SERVER INFORMATION
--------------------------------------------------------------------------------
Server Type: NODEJS
Package Manager: npm
Transport: stdio

--------------------------------------------------------------------------------
VULNERABILITY SUMMARY
--------------------------------------------------------------------------------
Total Vulnerabilities: 5
Overall Risk: MEDIUM
Business Impact: MODERATE

Severity Distribution:
  CRITICAL: 1
  HIGH: 2
  MEDIUM: 2

CRITICAL SEVERITY (1 findings):
  [1] Command Injection Vulnerability
      Type: Dynamic
      CVSS Score: 8.5
      File: src/server.js
      Line: 45
      Description: Security vulnerability detected during runtime analysis...
      Remediation: Avoid executing system commands with user input...
```

### Report Files

After the scan, you'll find detailed reports in your directory:
- `mcp_security_scan_<repo>_YYYYMMDD_HHMMSS.json`

## 🚨 Troubleshooting

### Common Issues and Solutions

#### Issue 1: "python is not recognized"
**Problem**: Python not in PATH
**Solution**:
```cmd
# Try python3 instead
python3 --version

# Or add Python to PATH manually
# Add C:\Users\[username]\AppData\Local\Programs\Python\Python311\ to PATH
```

#### Issue 2: "pip install failed"
**Problem**: Network or permission issues
**Solution**:
```cmd
# Try with user flag
pip install --user -r requirements.txt

# Or run as administrator
# Right-click Command Prompt → "Run as administrator"
```

#### Issue 3: "Module not found" errors
**Problem**: Virtual environment not activated
**Solution**:
```cmd
# Make sure virtual environment is activated
mcp-guard-env\Scripts\activate

# Reinstall dependencies
pip install -r requirements.txt
```

#### Issue 4: "Failed to download repository"
**Problem**: Network connectivity or firewall
**Solution**:
```cmd
# Test internet connection
ping github.com

# Check if behind corporate firewall
# Contact IT department for proxy settings
```

#### Issue 5: PowerShell execution policy error
**Problem**: PowerShell script execution blocked
**Solution**:
```powershell
# Run as administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Getting Help

If you encounter issues:

1. **Check the logs**: Look for error messages in the console
2. **Verify Python version**: Ensure Python 3.8+
3. **Check internet connection**: Ensure you can access GitHub
4. **Try different repository**: Test with a different MCP server
5. **Create an issue**: Report bugs on GitHub

## 📚 Next Steps

### Explore Examples

Try the interactive examples:

```cmd
# Basic scanning examples
python examples/basic_scan.py

# Advanced analysis features
python examples/advanced_analysis.py

# CI/CD integration examples
python examples/ci_cd_integration.py
```

### Scan More MCP Servers

```cmd
# Cloudflare MCP Server (Node.js)
python mcp_scanner.py https://github.com/cloudflare/mcp-server-cloudflare

# GitHub MCP Server (Go)
python mcp_scanner.py https://github.com/github/github-mcp-server

# PostgreSQL MCP Server (Python)
python mcp_scanner.py https://github.com/crystaldba/postgres-mcp
```

### Read Documentation

- **Usage Guide**: `docs/USAGE.md`
- **API Documentation**: `docs/API.md`
- **Security Policy**: `docs/SECURITY.md`
- **Examples**: `docs/EXAMPLES.md`

### Set Up CI/CD Integration

If you're a developer, consider integrating MCP Guard into your CI/CD pipeline:

```cmd
# Create GitHub Actions workflow
python examples/ci_cd_integration.py --create-workflow
```

## 🎉 Congratulations!

You've successfully installed and configured MCP Guard! You're now ready to:

- ✅ Scan MCP servers for security vulnerabilities
- ✅ Generate professional security reports
- ✅ Integrate security scanning into your development workflow
- ✅ Contribute to MCP security research

### Quick Reference Commands

```cmd
# Activate virtual environment
mcp-guard-env\Scripts\activate

# Scan an MCP server
python mcp_scanner.py <github-repository-url>

# Run examples
python examples/basic_scan.py

# Get help
python mcp_scanner.py --help
```

### File Locations

Your MCP Guard installation is located at:
```
C:\Users\[username]\Downloads\mcp-guard\
├── mcp_scanner.py          # Main scanner
├── examples/               # Usage examples
├── docs/                   # Documentation
├── requirements.txt        # Dependencies
└── mcp-guard-env/         # Virtual environment
```

---

**Happy scanning!** 🛡️ You're now equipped to secure the MCP ecosystem!
