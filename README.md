
# WEBSEC: Web Security Analyzer

A Python-based tool for analyzing web security configurations, including HTTPS redirects and HTTP security headers.

Built as a cybersecurity portfolio project to practice Python, networking, web security, and automated testing.

## Features

Currently implemented:

- URL validation and HTTP response collection using HTTPX
- Detection of HTTPS-to-HTTP redirects and missing HTTPS upgrades
- Security header analysis for:
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
- Structured findings with severity, evidence, and recommendations
- Automated tests using Pytest

Security header checks use basic configuration rules and do not replace a full security assessment.

## Tech Stack

Python · HTTPX · Pytest · Git

Planned: Python SSL, Rich, Streamlit

## Installation

Requires Python 3.11 or newer.

```bash
git clone https://github.com/mahikazi/web-security-analyzer.git
cd web-security-analyzer

python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install -e ".[dev]"
```

## Running Tests

```bash
python3 -m pytest -v
```

The HTTP and header analyzers currently work as Python modules. A command-line interface is planned.

## Development Roadmap

[x] Project setup and security finding models
[x] HTTP collection and redirect analysis
[x] HTTP security header analysis
[ ] TLS certificate and encryption analysis
[ ] Unified security scanner
[ ] CLI, JSON reports, and Streamlit dashboard
[ ] Final testing, documentation, and release


## Status

**In development.**
- The HTTP and security header modules are implemented.
- The complete scanning interface is still being built.