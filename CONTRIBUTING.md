# Contributing to VulnScan Framework

Thank you for your interest in contributing! Here's how to get involved.

## Getting Started

1. Fork the repository and clone it locally
2. Create a virtual environment: `python -m venv venv && source venv/bin/activate`
3. Install dev dependencies: `pip install -r requirements.txt pytest flake8`
4. Create a feature branch: `git checkout -b feature/your-feature-name`

## Code Style

- Follow PEP 8
- Max line length: 120 characters
- Type hints encouraged
- Docstrings on all public classes and methods

## Adding a Vulnerability Module

1. Add payload lists and detection patterns to `core/web_scanner.py`
2. Implement `_test_<module>()` method in `WebVulnScanner`
3. Register it in `module_map` inside `scan()`
4. Add it to `DEFAULT_MODULES` list
5. Write tests in `tests/test_framework.py`

## Adding an ML Rule

1. Add an entry to the `RULE_ENGINE` list in `ml/predictor.py`
2. Define: `name`, `condition` (lambda), `predicted_vulns`, `severity`, `confidence_base`, `cve_refs`

## Submitting a Pull Request

- Ensure all tests pass: `pytest tests/ -v`
- Run linting: `flake8 . --max-line-length=120`
- Update README if needed
- Reference any related issues

## Reporting Bugs

Open an issue with:
- Python version
- Operating system  
- Reproduction steps
- Expected vs actual behavior

## Security Disclosures

If you find a security issue in VulnScan itself, please email security@your-org.com instead of opening a public issue.
