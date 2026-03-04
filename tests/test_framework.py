"""
Unit Tests for VulnScan Framework
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import json
from unittest.mock import MagicMock, patch


# ── Test: Port Scanner ─────────────────────────────────────────────────────────

class TestPortScanner:
    def test_parse_port_range_simple(self):
        from core.scanner import PortScanner
        scanner = PortScanner.__new__(PortScanner)
        ports = scanner._parse_port_range("80,443,8080")
        assert 80 in ports
        assert 443 in ports
        assert 8080 in ports

    def test_parse_port_range_range(self):
        from core.scanner import PortScanner
        scanner = PortScanner.__new__(PortScanner)
        ports = scanner._parse_port_range("20-25")
        assert ports == [20, 21, 22, 23, 24, 25]

    def test_parse_port_range_mixed(self):
        from core.scanner import PortScanner
        scanner = PortScanner.__new__(PortScanner)
        ports = scanner._parse_port_range("22,80-82,443")
        assert 22 in ports
        assert 80 in ports
        assert 81 in ports
        assert 82 in ports
        assert 443 in ports

    def test_extract_version_from_banner(self):
        from core.scanner import PortScanner
        scanner = PortScanner.__new__(PortScanner)
        version = scanner._extract_version("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4")
        assert "OpenSSH_8.9p1" in version or "8.9" in version

    def test_vuln_summary_flags_redis(self):
        from core.scanner import PortScanner
        scanner = PortScanner.__new__(PortScanner)
        results = {
            6379: {"state": "open", "service": "Redis", "vulnerability": {
                "name": "Redis", "issue": "Unauthenticated", "severity": "critical"
            }}
        }
        vulns = scanner.get_vuln_summary(results)
        assert len(vulns) == 1
        assert vulns[0]["severity"] == "critical"


# ── Test: Web Vulnerability Scanner ───────────────────────────────────────────

class TestWebScanner:
    def test_extract_params(self):
        from core.web_scanner import WebVulnScanner
        scanner = WebVulnScanner.__new__(WebVulnScanner)
        params = scanner._extract_params("https://example.com/page?id=1&name=test")
        assert params == {"id": "1", "name": "test"}

    def test_inject_param(self):
        from core.web_scanner import WebVulnScanner
        scanner = WebVulnScanner.__new__(WebVulnScanner)
        url = scanner._inject_param("https://example.com/page?id=1", "id", "' OR 1=1--")
        assert "' OR 1=1--" in url or "%27" in url

    def test_sqli_error_patterns_match(self):
        import re
        from core.web_scanner import SQLI_ERROR_PATTERNS
        test_outputs = [
            "You have an error in your sql syntax",
            "ORA-00942: table or view does not exist",
            "Warning: mysql_fetch_array()",
        ]
        for output in test_outputs:
            matched = any(re.search(p, output, re.IGNORECASE) for p in SQLI_ERROR_PATTERNS)
            assert matched, f"Pattern should match: {output}"

    def test_lfi_patterns_detect_passwd(self):
        import re
        from core.web_scanner import LFI_SUCCESS_PATTERNS
        sample = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        matched = any(re.search(p, sample) for p in LFI_SUCCESS_PATTERNS)
        assert matched


# ── Test: Recon Engine ─────────────────────────────────────────────────────────

class TestReconEngine:
    def test_normalize_target_adds_https(self):
        from core.recon import ReconEngine
        engine = ReconEngine.__new__(ReconEngine)
        assert engine._normalize_target("example.com") == "https://example.com"

    def test_normalize_target_preserves_http(self):
        from core.recon import ReconEngine
        engine = ReconEngine.__new__(ReconEngine)
        assert engine._normalize_target("http://example.com") == "http://example.com"

    def test_extract_domain(self):
        from core.recon import ReconEngine
        engine = ReconEngine.__new__(ReconEngine)
        assert engine._extract_domain("https://example.com/path?q=1") == "example.com"
        assert engine._extract_domain("example.com:8080") == "example.com"

    def test_tech_signatures_not_empty(self):
        from core.recon import TECH_SIGNATURES
        assert len(TECH_SIGNATURES) > 0
        for tech, patterns in TECH_SIGNATURES.items():
            assert len(patterns) > 0, f"{tech} has no patterns"

    def test_waf_signatures_not_empty(self):
        from core.recon import WAF_SIGNATURES
        assert "Cloudflare" in WAF_SIGNATURES
        assert len(WAF_SIGNATURES) >= 5


# ── Test: ML Predictor ─────────────────────────────────────────────────────────

class TestMLPredictor:
    def test_extract_features_returns_dict(self):
        from ml.predictor import VulnPredictor
        predictor = VulnPredictor.__new__(VulnPredictor)
        predictor.model = None
        predictor.scaler = None
        predictor.feature_names = []

        import logging
        predictor.logger = logging.getLogger("test")

        recon = {
            "technologies": ["WordPress", "PHP"],
            "ssl_cert": {"valid": True, "days_remaining": 120, "issues": []},
            "http_headers": {"security_issues": [], "server_info": ""},
            "open_paths": [],
            "subdomains": [],
            "waf": {"detected": False},
            "dns": {"MX": ["mail.example.com"], "TXT": []},
        }
        ports = {80: {"state": "open"}, 6379: {"state": "open"}}

        features = predictor._extract_features(recon, ports)
        assert "has_wordpress" in features
        assert features["has_wordpress"] == 1
        assert "port_6379" in features
        assert features["port_6379"] == 1

    def test_rule_engine_redis_prediction(self):
        from ml.predictor import VulnPredictor, RULE_ENGINE
        predictor = VulnPredictor.__new__(VulnPredictor)
        predictor.model = None
        predictor.scaler = None
        predictor.feature_names = []

        import logging
        predictor.logger = logging.getLogger("test")

        recon = {
            "technologies": [],
            "ssl_cert": {"valid": True, "days_remaining": 365, "issues": []},
            "http_headers": {"security_issues": [], "server_info": ""},
            "open_paths": [],
            "subdomains": [],
            "waf": {"detected": False},
            "dns": {},
        }
        ports = {6379: {"state": "open"}}

        predictions = predictor.predict(recon, ports)
        redis_preds = [p for p in predictions if "Redis" in p["name"]]
        assert len(redis_preds) > 0
        assert redis_preds[0]["severity"] == "critical"

    def test_risk_scoring(self):
        from main import calculate_risk_score
        results = {
            "vulnerabilities": [
                {"severity": "critical"},
                {"severity": "high"},
                {"severity": "medium"},
                {"severity": "low"},
            ],
            "ml_predictions": [],
        }
        score = calculate_risk_score(results)
        assert 0 <= score <= 100
        assert score > 0

    def test_generate_sample_dataset(self, tmp_path):
        from ml.predictor import VulnPredictor
        predictor = VulnPredictor(model_path=str(tmp_path / "model.pkl"))
        output = predictor.generate_sample_dataset(str(tmp_path / "sample.csv"))
        assert os.path.exists(output)
        import csv
        with open(output) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 500
        assert "vuln_type" in rows[0]


# ── Test: Reporter ─────────────────────────────────────────────────────────────

class TestReporter:
    def test_json_report_generation(self, tmp_path):
        from core.reporter import ReportGenerator
        results = {
            "target": "https://example.com",
            "mode": "full",
            "scan_start": "2024-01-01T00:00:00",
            "scan_end": "2024-01-01T00:05:00",
            "risk_score": 45.0,
            "vulnerabilities": [
                {"type": "XSS", "severity": "high", "url": "https://example.com",
                 "parameter": "q", "description": "XSS found", "remediation": "Encode output"},
            ],
            "ml_predictions": [],
            "ports": {},
            "recon": {},
        }
        reporter = ReportGenerator(results, output_dir=str(tmp_path))
        path = reporter.generate("json")
        assert os.path.exists(path)
        with open(path) as f:
            data = json.load(f)
        assert data["target"] == "https://example.com"

    def test_html_report_generation(self, tmp_path):
        from core.reporter import ReportGenerator
        results = {
            "target": "https://example.com",
            "mode": "full",
            "scan_start": "2024-01-01T00:00:00",
            "scan_end": "2024-01-01T00:05:00",
            "risk_score": 30.0,
            "vulnerabilities": [],
            "ml_predictions": [],
            "ports": {},
            "recon": {},
        }
        reporter = ReportGenerator(results, output_dir=str(tmp_path))
        path = reporter.generate("html")
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "VulnScan" in content
        assert "example.com" in content


# ── Test: Crawler ──────────────────────────────────────────────────────────────

class TestCrawler:
    def test_extract_links(self):
        from utils.crawler import Crawler
        crawler = Crawler(http_client=None)
        html = '<a href="/page1">Link</a> <a href="https://example.com/page2">Link2</a>'
        links = crawler._extract_links(html, "https://example.com")
        assert any("page1" in l for l in links)
        assert any("page2" in l for l in links)

    def test_extract_forms(self):
        from utils.crawler import Crawler
        crawler = Crawler(http_client=None)
        html = '''<form action="/login" method="POST">
                    <input type="text" name="username">
                    <input type="password" name="password">
                    <input type="submit" value="Login">
                  </form>'''
        forms = crawler._extract_forms(html, "https://example.com")
        assert len(forms) == 1
        assert forms[0]["method"] == "post"
        names = [i["name"] for i in forms[0]["inputs"]]
        assert "username" in names
        assert "password" in names

    def test_javascript_links_excluded(self):
        from utils.crawler import Crawler
        crawler = Crawler(http_client=None)
        html = '<a href="javascript:void(0)">JS Link</a>'
        links = crawler._extract_links(html, "https://example.com")
        assert not any("javascript" in l for l in links)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
