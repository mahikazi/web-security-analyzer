
# WEBSEC: Web Security Analyzer

A Python-based tool for analyzing web security configurations, including HTTPS redirects, HTTP security headers, and TLS certificates.

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
- TLS certificate and encryption analysis:
  - Certificate chain and hostname verification
  - Certificate expiration checks
  - Negotiated TLS version detection
  - Negotiated cipher information
- Structured findings with severity, evidence, and recommendations
- Automated tests using Pytest

Security header checks use basic configuration rules and do not replace a full security assessment. TLS analysis reports the protocol and cipher negotiated during a single connection.

## Tech Stack

Python · HTTPX · SSL · Pytest · Git

Planned: Rich, Streamlit

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

The HTTP, security header, and TLS analyzers currently work as Python modules. A unified scanner and command-line interface are planned.

## Development Roadmap

- [x] Project setup and security finding models
- [x] HTTP collection and redirect analysis
- [x] HTTP security header analysis
- [x] TLS certificate and encryption analysis
- [ ] Unified security scanner
- [ ] CLI, JSON reports, and Streamlit dashboard
- [ ] Final testing, documentation, and release

## Status

**In development.**

- The HTTP, security header, and TLS modules are implemented.
- The complete scanning interface is still being built.
