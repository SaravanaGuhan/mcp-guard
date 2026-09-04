# Contributing to MCP Guard

Thank you for your interest in contributing to MCP Guard! This document provides guidelines for contributing to the project.

## 🤝 Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## 🚀 How to Contribute

### 🐛 Reporting Issues

1. **Security Issues**: Please report security vulnerabilities privately by emailing the maintainers at security@mcpguard.dev
2. **Bug Reports**: Use the GitHub issue tracker for bug reports
3. **Feature Requests**: Use the GitHub issue tracker for feature requests
4. **Questions**: Use GitHub Discussions for questions and general discussion

### 🛠️ Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/mcp-guard.git
   cd mcp-guard
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -e ".[dev]"  # runtime plus test and lint tooling
   ```

4. **Run tests**:
   ```bash
   python -m pytest tests
   python test_download.py
   ```

### 🔄 Making Changes

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**:
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed
   - Ensure security best practices

3. **Test your changes**:
   ```bash
   python -m pytest tests
   python test_download.py
   python -m mcp_guard.cli --help  # Test CLI functionality
   ```

4. **Commit your changes**:
   ```bash
   git add .
   git commit -m "feat: Brief description of your changes"
   ```

5. **Push and create a pull request**:
   ```bash
   git push origin feature/your-feature-name
   ```

## 📝 Code Style Guidelines

### Python Code Style
- **Follow PEP 8** style guidelines
- **Use type hints** where appropriate
- **Write docstrings** for all functions and classes
- **Keep functions focused** and single-purpose
- **Use meaningful variable names**

### Documentation
- **Clear docstrings** with parameter descriptions
- **Update README.md** for new features
- **Include code examples** in documentation
- **Comment complex logic** and security considerations

### Security Considerations
- **Never commit sensitive information** (API keys, tokens, etc.)
- **Follow secure coding practices**
- **Validate all inputs** thoroughly
- **Handle errors gracefully**
- **Test security features** thoroughly
- **Document security implications** of changes

## 🧪 Testing Guidelines

### Writing Tests
- **Write tests for new functionality**
- **Ensure existing tests pass**
- **Test edge cases and error conditions**
- **Include integration tests for new analyzers**
- **Test with real MCP servers when possible**

### Test Categories
- **Unit Tests**: Test individual functions and classes
- **Integration Tests**: Test component interactions
- **End-to-End Tests**: Test complete workflows
- **Security Tests**: Test vulnerability detection accuracy

## 📋 Pull Request Process

### Before Submitting
1. **Ensure tests pass**: All tests must pass before merging
2. **Update documentation**: Include relevant documentation updates
3. **Check code style**: Follow the project's coding standards
4. **Test thoroughly**: Test your changes in different scenarios

### PR Description
- **Clear title**: Describe what the PR does
- **Detailed description**: Explain the changes and why they're needed
- **Link issues**: Reference any related GitHub issues
- **Include screenshots**: For UI changes or new features
- **List breaking changes**: If any

### Review Process
1. **Automated checks**: CI/CD pipeline must pass
2. **Code review**: Maintainer review and feedback
3. **Address feedback**: Make requested changes
4. **Final approval**: Maintainer approval required for merge

## 🎯 Development Areas

### 🔥 High Priority
- **Additional MCP server type support** (Rust, Java, C#)
- **Enhanced dynamic analysis capabilities**
- **Improved vulnerability detection accuracy**
- **Performance optimizations**
- **Better error handling and user experience**

### 📈 Medium Priority
- **Additional security scanner integrations** (CodeQL, Snyk)
- **Enhanced reporting formats** (PDF, HTML, SARIF)
- **CI/CD pipeline improvements**
- **Documentation enhancements**
- **Internationalization support**

### 💡 Low Priority
- **Web UI interface**
- **Plugin architecture**
- **Advanced configuration options**
- **Integration with security platforms**
- **Machine learning-based detection**

## 🏗️ Architecture Guidelines

### Code Organization
```
mcp-guard/
├── src/mcp_guard/          # Scanner package (models, rules, static, dynamic, deps, report)
├── scripts/                # golden.py, benchmark.py, profile.py
├── docs/generated/         # produced by make targets, not edited by hand
├── simple_vulnerability_scoring.py  # Scoring system
├── test_*.py               # Test files
├── docs/                   # Documentation
├── .github/                # GitHub workflows
└── examples/               # Usage examples
```

### Adding New Features

#### New MCP Server Type Support
1. Add detection logic in `detect_mcp_server_type()`
2. Implement analyzer in `_analyze_[type]_server()`
3. Add tests for the new server type
4. Update documentation

#### New Vulnerability Detection
1. Add pattern in appropriate analyzer
2. Include CWE mapping
3. Add test cases
4. Update vulnerability documentation

#### New Scoring System
1. Implement in `simple_vulnerability_scoring.py`
2. Add comprehensive tests
3. Update documentation
4. Ensure backward compatibility

## 🔍 Code Review Checklist

### For Contributors
- [ ] Code follows project style guidelines
- [ ] All tests pass
- [ ] Documentation is updated
- [ ] Security implications are considered
- [ ] Performance impact is minimal
- [ ] Error handling is comprehensive

### For Reviewers
- [ ] Code quality and style
- [ ] Test coverage and quality
- [ ] Security considerations
- [ ] Performance implications
- [ ] Documentation completeness
- [ ] Backward compatibility

## 🆘 Getting Help

### Resources
- **Documentation**: Check the `docs/` folder
- **Examples**: See the `examples/` folder
- **Issues**: Search existing GitHub issues
- **Discussions**: Use GitHub Discussions for questions

### Contact
- **General Questions**: GitHub Discussions
- **Bug Reports**: GitHub Issues
- **Security Issues**: security@mcpguard.dev
- **Feature Requests**: GitHub Issues

## 🎉 Recognition

Contributors will be recognized in:
- **CHANGELOG.md**: For significant contributions
- **README.md**: For major features or improvements
- **GitHub Contributors**: Automatic recognition
- **Release Notes**: For notable contributions

## 📄 License

By contributing to MCP Guard, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to MCP Guard and helping secure the MCP ecosystem!** 🛡️