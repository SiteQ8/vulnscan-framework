# 🔍 VulnScan Framework

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen" alt="Active">
  <img src="https://img.shields.io/badge/Modules-10%2B-orange" alt="Modules">
  <img src="https://img.shields.io/badge/ML-Powered-purple?logo=scikit-learn" alt="ML Powered">
</p>

<p align="center">
  <strong>Automated Penetration Testing & Vulnerability Scanning Framework</strong><br>
  <em>ML-powered · Modular · Open Source · All-in-one</em>
</p>

> ⚠️ **LEGAL DISCLAIMER**: This tool is intended for **authorized security testing only**. Using VulnScan against systems you do not have explicit permission to test is illegal and unethical. The authors are not responsible for any misuse. Always obtain written authorization before testing.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🌐 **Web Reconnaissance** | DNS enum, WHOIS, SSL inspection, subdomain brute-force, WAF detection, tech fingerprinting |
| 🔌 **Port & Service Scanning** | Multi-threaded TCP scanning with banner grabbing and version detection |
| 🐛 **Web Vulnerability Scanning** | SQLi, XSS, LFI, RCE, SSRF, XXE, CSRF, IDOR, Open Redirect |
| 🔐 **Auth Testing** | Default credentials, JWT flaws, cookie security, admin panel enumeration |
| 🤖 **ML Predictions** | Random Forest + Gradient Boosting ensemble predicts vulnerabilities from recon data |
| 📊 **Professional Reports** | Beautiful HTML, JSON, and PDF reports with risk scoring |
| ⚙️ **Modular Architecture** | Run specific modules, configure depth/threads/timeout, YAML config support |
| 🔗 **Proxy Support** | Integrates with Burp Suite, ZAP, and other intercepting proxies |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- `nslookup`, `whois` (optional, for enhanced recon)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/vulnscan-framework.git
cd vulnscan-framework

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
python main.py --help
```

---

## 📖 Usage

### Basic Usage

```bash
# Full scan (all phases)
python main.py --target https://example.com --mode full

# Quick reconnaissance only
python main.py --target example.com --mode recon

# Port scan a network range
python main.py --target 192.168.1.0/24 --mode portscan --ports 1-65535

# Web vulnerability scan with specific modules
python main.py --target https://example.com --mode web --modules sqli,xss,lfi

# Authenticated scan (with session cookies)
python main.py --target https://example.com --mode full \
  --cookies '{"session": "abc123", "auth_token": "xyz"}'

# Full scan with Burp Suite proxy
python main.py --target https://example.com --mode full --proxy http://127.0.0.1:8080

# Generate all report formats
python main.py --target https://example.com --mode full --output all

# Verbose output with custom thread count
python main.py --target https://example.com -v --threads 100
```

### ML-Powered Scanning

```bash
# Generate sample training dataset
python -c "from ml.predictor import VulnPredictor; VulnPredictor().generate_sample_dataset()"

# Train ML model on your own labeled data
python main.py --target https://example.com --mode ml-predict --train-data data/my_vulns.csv

# Use existing trained model
python main.py --target https://example.com --mode full --ml-model models/vuln_predictor.pkl
```

### Config File Usage

```bash
# Use a YAML config file
python main.py --target https://example.com --config config/default.yaml
```

---

## 🏗 Architecture

```
vulnscan-framework/
├── main.py                  # CLI entry point & orchestration
├── core/
│   ├── recon.py             # Reconnaissance engine
│   ├── scanner.py           # Port & service scanner
│   ├── web_scanner.py       # Web vulnerability scanner (10 modules)
│   ├── auth_scanner.py      # Authentication & session testing
│   └── reporter.py          # Report generator (HTML/JSON/PDF)
├── ml/
│   └── predictor.py         # ML vulnerability predictor
├── modules/
│   ├── web/                 # Extended web attack modules
│   ├── network/             # Network-layer modules
│   └── auth/                # Authentication modules
├── utils/
│   ├── http_client.py       # Thread-safe HTTP client
│   ├── crawler.py           # Web crawler (BFS)
│   └── logger.py            # Colored logging
├── config/
│   └── default.yaml         # Default configuration
├── data/                    # Training datasets
├── models/                  # Saved ML models
├── reports/                 # Output reports
└── tests/                   # Unit tests
```

---

## 🧪 Scan Modes

| Mode | Description | Phases Run |
|---|---|---|
| `full` | Complete assessment | Recon + Ports + Web + Auth + ML |
| `recon` | Passive/active information gathering | DNS, WHOIS, headers, SSL, subdomains |
| `portscan` | TCP port scan with fingerprinting | Port scan, banner grab |
| `web` | Web vulnerability testing | Crawl + 10 vuln modules |
| `auth` | Authentication testing | Cookies, JWT, default creds, admin panels |
| `ml-predict` | ML-only prediction | Feature extraction + model inference |
| `report-only` | Re-generate report from existing results | Reporting only |

---

## 🔍 Vulnerability Modules

| Module | Technique | Severity |
|---|---|---|
| `sqli` | Error-based, blind boolean, time-based SQLi | Critical |
| `xss` | Reflected, stored, DOM-based XSS | High |
| `lfi` | Local File Inclusion, Path Traversal | Critical |
| `rce` | OS command injection | Critical |
| `ssrf` | Server-Side Request Forgery + IMDS | Critical |
| `xxe` | XML External Entity injection | Critical |
| `csrf` | Missing CSRF token detection | Medium |
| `idor` | Insecure Direct Object Reference | High |
| `redirect` | Open Redirect | Medium |
| `headers` | Security header misconfigurations | Low-High |

---

## 🤖 Machine Learning Engine

VulnScan's ML subsystem uses a **Random Forest + Gradient Boosting ensemble** to predict likely vulnerabilities before active exploitation attempts.

### How It Works

1. **Feature Extraction** — Converts recon results into a numeric feature vector:
   - Technology stack (WordPress, PHP, Laravel, etc.)
   - Open port flags (Redis, MongoDB, RDP, etc.)
   - SSL/TLS health metrics
   - Security header completeness score
   - Exposed paths count
   - Subdomain count
   - WAF presence
   - Server version disclosure

2. **Rule Engine** — 17 hand-crafted rules for deterministic high-confidence predictions

3. **ML Model** — Trained classifier predicts vulnerability classes with confidence scores

4. **Risk Scoring** — Combines finding severity with ML confidence into a 0–100 risk score

### Training Your Own Model

```python
from ml.predictor import VulnPredictor

# Generate sample dataset to understand the expected format
predictor = VulnPredictor()
predictor.generate_sample_dataset("data/sample.csv")

# Train on your labeled dataset
# CSV must have feature columns + 'vuln_type' label column
predictor.train("data/your_labeled_data.csv")
```

Expected CSV format:
```csv
has_wordpress,port_6379,ssl_valid,security_header_issues,...,vuln_type
1,0,1,4,...,XSS
0,1,0,6,...,RCE
```

---

## 📊 Sample Report

Reports include:
- **Risk Score** (0–100) with severity breakdown
- **Executive Summary** table
- **Vulnerability table** with type, URL, parameter, description, remediation
- **ML Predictions** with confidence percentages and CVE references
- **Open Ports** with service details and risk notes
- **Discovered Subdomains**
- **Exposed Sensitive Paths**
- **Technology Stack** detected
- **SSL/TLS** certificate details

---

## ⚙️ Configuration

Edit `config/default.yaml` to customize default behavior:

```yaml
scan:
  threads: 50
  timeout: 10
  depth: 3
  rate_limit: 0.5   # Add delay between requests

web_scanner:
  default_modules: [sqli, xss, lfi, rce, ssrf, xxe, csrf, headers]

ml:
  confidence_threshold: 0.6
```

---

## 🔌 Integrations

| Tool | How to Integrate |
|---|---|
| **Burp Suite** | `--proxy http://127.0.0.1:8080` |
| **OWASP ZAP** | `--proxy http://127.0.0.1:8090` |
| **Shodan** | Add `SHODAN_API_KEY` env var (coming soon) |
| **Slack alerts** | Configure webhook in `config/local.yaml` (coming soon) |

---

## 🧪 Running Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v --cov=.
```

---

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-module`)
3. Write tests for new functionality
4. Submit a pull request

### Adding a New Vulnerability Module

1. Add your payloads and detection logic to `core/web_scanner.py`
2. Register the method in `module_map` inside `WebVulnScanner.scan()`
3. Add the module name to `DEFAULT_MODULES`
4. Write a test in `tests/`

---

## 📋 Roadmap

- [ ] Nuclei template integration
- [ ] Shodan / Censys passive recon
- [ ] GraphQL vulnerability testing
- [ ] OAuth 2.0 / OIDC testing
- [ ] API security testing (REST/GraphQL)
- [ ] Subdomain takeover detection
- [ ] Docker image
- [ ] Web UI dashboard
- [ ] CI/CD pipeline security checks
- [ ] Slack / email alerting

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## ⚠️ Ethics & Legal

This tool must only be used for:
- Authorized penetration tests with written scope of work
- Bug bounty programs within defined scope
- Testing your own infrastructure
- CTF (Capture The Flag) competitions
- Security research in isolated lab environments

**Unauthorized use against systems you do not own or have explicit permission to test is illegal under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (UK), and equivalent laws worldwide.**

---

<p align="center">Built with ❤️ for the security community</p>
