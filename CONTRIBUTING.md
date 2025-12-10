# Contributing to isilon-mcp-server

Thank you for your interest in contributing to isilon-mcp-server! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and collaborative environment.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Description**: Clear description of the bug
- **Steps to Reproduce**: Minimal steps to reproduce the issue
- **Expected Behavior**: What you expected to happen
- **Actual Behavior**: What actually happened
- **Environment**: Python version, OS, PowerScale version
- **Logs**: Relevant error messages or logs

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear title**: Describe the enhancement
- **Provide details**: Explain why this enhancement would be useful
- **Include examples**: Show how it would work

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following the code style guidelines
3. **Add tests** if you've added code that should be tested
4. **Update documentation** for any changed functionality
5. **Ensure tests pass** by running `pytest`
6. **Run linting** with `ruff` and `black`
7. **Submit a pull request**

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/isilon-mcp-server.git
cd isilon-mcp-server

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

## Code Style

- **Python Version**: Target Python 3.10+
- **Formatting**: Use `black` with default settings
- **Import Sorting**: Use `isort` compatible with black
- **Linting**: Use `ruff` for linting
- **Type Hints**: Use type hints where appropriate
- **Docstrings**: Use Google-style docstrings

### Running Code Quality Tools

```bash
# Format code
black isilon_mcp tests

# Sort imports
isort isilon_mcp tests

# Lint
ruff check isilon_mcp tests

# Type check
mypy isilon_mcp --ignore-missing-imports
```

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=isilon_mcp --cov-report=html

# Run specific test file
pytest tests/test_api_client.py

# Run specific test
pytest tests/test_api_client.py::test_execute_operation_success
```

## Commit Messages

- Use clear, descriptive commit messages
- Start with a verb in present tense (e.g., "Add", "Fix", "Update")
- Reference issues and PRs where appropriate

Examples:
```
Add support for multiple API versions
Fix authentication error handling
Update documentation for new features
```

## Documentation

- Update README.md for user-facing changes
- Update docstrings for code changes
- Add examples for new features
- Update CHANGELOG.md following Keep a Changelog format

## Release Process

Releases are managed by project maintainers:

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Create a GitHub release with tag `vX.Y.Z`
4. CI/CD will automatically publish to PyPI

## Questions?

Feel free to open an issue with the `question` label.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
