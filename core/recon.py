"""
Reconnaissance Engine
Performs passive and active information gathering:
  - DNS enumeration & zone transfer attempts
  - WHOIS lookup
  - HTTP header analysis
  - SSL/TLS certificate inspection
  - Technology fingerprinting (Wappalyzer-style)
  - Subdomain enumeration
  - Google dorking helpers
  - WAF detection
  - Robots.txt & sitemap parsing
"""

import re
import json
import socket
import ssl
import urllib.request
import urllib.parse
import urllib.error
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from utils.logger import get_logger
from utils.http_client import HTTPClient


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "vpn", "api",
    "dev", "staging", "test", "admin", "portal", "app", "cdn", "static",
    "media", "images", "blog", "shop", "store", "secure", "login", "auth",
    "beta", "dashboard", "support", "help", "docs", "wiki", "git", "gitlab",
    "jenkins", "jira", "confluence", "remote", "webmail", "mx", "mail2",
    "intranet", "internal", "corp", "office", "mobile", "m", "wap",
]

TECH_SIGNATURES = {
    "WordPress":   [r"wp-content", r"wp-includes", r"wordpress"],
    "Drupal":      [r"Drupal", r"/sites/default/files"],
    "Joomla":      [r"/components/com_", r"Joomla"],
    "Laravel":     [r"laravel_session", r"XSRF-TOKEN"],
    "Django":      [r"csrfmiddlewaretoken", r"Django"],
    "Ruby on Rails": [r"_rails_session", r"X-Runtime"],
    "ASP.NET":     [r"__VIEWSTATE", r"ASP.NET_SessionId", r"X-AspNet-Version"],
    "PHP":         [r"PHPSESSID", r"X-Powered-By: PHP"],
    "Apache":      [r"Server: Apache"],
    "Nginx":       [r"Server: nginx"],
    "IIS":         [r"Server: Microsoft-IIS", r"X-Powered-By: ASP.NET"],
    "Cloudflare":  [r"cf-ray", r"__cfduid", r"cloudflare"],
    "jQuery":      [r"jquery", r"jquery.min.js"],
    "React":       [r"react", r"__REACT_", r"_reactRootContainer"],
    "Angular":     [r"ng-version", r"angular"],
    "Vue.js":      [r"__vue__", r"vue.min.js"],
    "Bootstrap":   [r"bootstrap.min.css", r"bootstrap.min.js"],
    "Elasticsearch": [r"elastic", r"kibana"],
    "Grafana":     [r"grafana"],
}

WAF_SIGNATURES = {
    "Cloudflare":    ["cloudflare", "cf-ray", "__cfduid"],
    "AWS WAF":       ["awswaf", "x-amzn-requestid"],
    "ModSecurity":   ["mod_security", "modsecurity"],
    "Sucuri":        ["sucuri", "x-sucuri-id"],
    "Imperva":       ["imperva", "incapsula", "visid_incap"],
    "Akamai":        ["akamai", "x-akamai-transformed"],
    "F5 BIG-IP":     ["bigip", "f5", "ts="],
    "Barracuda":     ["barracuda_", "barra_counter_session"],
    "Wordfence":     ["wordfence"],
    "SiteLock":      ["sitelock"],
}


class ReconEngine:
    """Full reconnaissance engine for a target domain/IP."""

    def __init__(self, target: str, timeout: int = 10, verify_ssl: bool = False, verbose: bool = False):
        self.target = self._normalize_target(target)
        self.domain = self._extract_domain(target)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.logger = get_logger(verbose=verbose)
        self.http = HTTPClient(timeout=timeout, verify_ssl=verify_ssl)

    def _normalize_target(self, target: str) -> str:
        if not target.startswith(("http://", "https://")):
            return f"https://{target}"
        return target

    def _extract_domain(self, target: str) -> str:
        target = re.sub(r"^https?://", "", target)
        return target.split("/")[0].split(":")[0]

    def run_all(self) -> dict:
        """Run all reconnaissance modules and return aggregated results."""
        self.logger.info(f"  [*] Starting reconnaissance on: {self.domain}")
        results = {
            "target": self.target,
            "domain": self.domain,
            "dns":          self._dns_enum(),
            "whois":        self._whois_lookup(),
            "http_headers": self._analyze_headers(),
            "ssl_cert":     self._inspect_ssl(),
            "technologies": self._fingerprint_tech(),
            "waf":          self._detect_waf(),
            "subdomains":   self._enumerate_subdomains(),
            "open_paths":   self._check_common_paths(),
            "emails":       self._harvest_emails(),
            "metadata":     self._gather_metadata(),
        }
        self.logger.info(f"  [+] Reconnaissance complete")
        return results

    def _dns_enum(self) -> dict:
        """Enumerate DNS records for the target domain."""
        dns_data = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}
        try:
            import subprocess
            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
                result = subprocess.run(
                    ["nslookup", "-type=" + rtype, self.domain],
                    capture_output=True, text=True, timeout=self.timeout
                )
                dns_data[rtype] = self._parse_nslookup(result.stdout, rtype)
        except Exception:
            # Fallback: basic A record via socket
            try:
                addrs = socket.getaddrinfo(self.domain, None)
                dns_data["A"] = list(set(addr[4][0] for addr in addrs if addr[0].name == "AF_INET"))
                dns_data["AAAA"] = list(set(addr[4][0] for addr in addrs if addr[0].name == "AF_INET6"))
            except Exception as e:
                self.logger.debug(f"DNS enum failed: {e}")
        return dns_data

    def _parse_nslookup(self, output: str, rtype: str) -> list:
        results = []
        for line in output.splitlines():
            line = line.strip()
            if "Address:" in line and rtype == "A":
                addr = line.split("Address:")[-1].strip()
                if not addr.endswith("#53"):
                    results.append(addr)
            elif "mail exchanger" in line and rtype == "MX":
                results.append(line.split("mail exchanger =")[-1].strip())
            elif "nameserver" in line and rtype == "NS":
                results.append(line.split("nameserver =")[-1].strip())
            elif "text =" in line and rtype == "TXT":
                results.append(line.split("text =")[-1].strip().strip('"'))
        return list(set(results))

    def _whois_lookup(self) -> dict:
        """Perform WHOIS lookup."""
        try:
            import subprocess
            result = subprocess.run(
                ["whois", self.domain],
                capture_output=True, text=True, timeout=self.timeout
            )
            whois_data = {}
            for line in result.stdout.splitlines():
                for key in ["Registrar:", "Creation Date:", "Updated Date:", "Expiry Date:",
                            "Registrant:", "Name Server:", "DNSSEC:", "Status:"]:
                    if line.strip().startswith(key):
                        whois_data[key.rstrip(":")] = line.split(":", 1)[-1].strip()
            return whois_data
        except Exception as e:
            self.logger.debug(f"WHOIS failed: {e}")
            return {}

    def _analyze_headers(self) -> dict:
        """Analyze HTTP response headers for security misconfigurations."""
        headers_data = {
            "raw": {},
            "security_issues": [],
            "server_info": "",
        }
        try:
            response = self.http.get(self.target)
            headers = dict(response.headers)
            headers_data["raw"] = headers

            # Check for security header presence
            security_headers = {
                "Strict-Transport-Security": "HSTS not set — downgrade attacks possible",
                "Content-Security-Policy": "CSP missing — XSS risk elevated",
                "X-Frame-Options": "Clickjacking protection absent",
                "X-Content-Type-Options": "MIME-sniffing protection absent",
                "Referrer-Policy": "Referrer policy not set",
                "Permissions-Policy": "Permissions policy not set",
                "X-XSS-Protection": "Legacy XSS filter not configured",
            }
            for header, message in security_headers.items():
                if header not in headers:
                    headers_data["security_issues"].append({
                        "header": header,
                        "issue": message,
                        "severity": "medium",
                    })

            # Information disclosure
            for info_header in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]:
                if info_header in headers:
                    headers_data["server_info"] = headers[info_header]
                    headers_data["security_issues"].append({
                        "header": info_header,
                        "issue": f"Server version disclosed: {headers[info_header]}",
                        "severity": "low",
                    })

        except Exception as e:
            self.logger.debug(f"Header analysis failed: {e}")

        return headers_data

    def _inspect_ssl(self) -> dict:
        """Inspect SSL/TLS certificate details."""
        ssl_data = {
            "valid": False,
            "issuer": {},
            "subject": {},
            "not_before": "",
            "not_after": "",
            "days_remaining": 0,
            "alt_names": [],
            "issues": [],
        }
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    ssl_data["valid"] = True
                    ssl_data["subject"] = dict(x[0] for x in cert.get("subject", []))
                    ssl_data["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    ssl_data["not_before"] = cert.get("notBefore", "")
                    ssl_data["not_after"] = cert.get("notAfter", "")

                    # Calculate days remaining
                    try:
                        expiry = datetime.datetime.strptime(ssl_data["not_after"], "%b %d %H:%M:%S %Y %Z")
                        ssl_data["days_remaining"] = (expiry - datetime.datetime.utcnow()).days
                        if ssl_data["days_remaining"] < 30:
                            ssl_data["issues"].append({
                                "issue": f"SSL certificate expires in {ssl_data['days_remaining']} days",
                                "severity": "medium",
                            })
                    except Exception:
                        pass

                    # SANs
                    san = cert.get("subjectAltName", ())
                    ssl_data["alt_names"] = [name for _, name in san]

        except ssl.SSLError as e:
            ssl_data["issues"].append({"issue": f"SSL error: {str(e)}", "severity": "high"})
        except Exception as e:
            self.logger.debug(f"SSL inspection failed: {e}")

        return ssl_data

    def _fingerprint_tech(self) -> list:
        """Identify technologies used by the target."""
        detected = []
        try:
            response = self.http.get(self.target)
            content = response.text + str(dict(response.headers))

            for tech, patterns in TECH_SIGNATURES.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        detected.append(tech)
                        break

        except Exception as e:
            self.logger.debug(f"Tech fingerprinting failed: {e}")

        return list(set(detected))

    def _detect_waf(self) -> dict:
        """Detect Web Application Firewall."""
        waf_data = {"detected": False, "name": None, "confidence": 0}
        try:
            # Send a malicious-looking payload to trigger WAF
            probe_url = f"{self.target}/?id=1' OR 1=1--&cmd=cat /etc/passwd&<script>alert(1)</script>"
            response = self.http.get(probe_url)
            headers_str = str(dict(response.headers)).lower()
            body = response.text.lower()

            for waf_name, signatures in WAF_SIGNATURES.items():
                matches = sum(1 for sig in signatures if sig in headers_str or sig in body)
                if matches > 0:
                    confidence = min(100, matches * 40)
                    if confidence > waf_data["confidence"]:
                        waf_data.update({"detected": True, "name": waf_name, "confidence": confidence})

        except Exception as e:
            self.logger.debug(f"WAF detection failed: {e}")

        return waf_data

    def _enumerate_subdomains(self, threads: int = 20) -> list:
        """Enumerate subdomains via DNS brute force."""
        found = []

        def check_subdomain(sub):
            hostname = f"{sub}.{self.domain}"
            try:
                ip = socket.gethostbyname(hostname)
                return {"subdomain": hostname, "ip": ip}
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in COMMON_SUBDOMAINS}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    self.logger.debug(f"  [subdomain] {result['subdomain']} → {result['ip']}")

        return found

    def _check_common_paths(self) -> list:
        """Check for exposed sensitive paths."""
        sensitive_paths = [
            "/.git/HEAD", "/.env", "/config.php", "/wp-config.php",
            "/phpinfo.php", "/.htaccess", "/backup.zip", "/dump.sql",
            "/admin/", "/administrator/", "/phpmyadmin/", "/wp-admin/",
            "/api/swagger.json", "/api/openapi.json", "/swagger-ui.html",
            "/actuator", "/actuator/health", "/actuator/env",
            "/.well-known/security.txt", "/crossdomain.xml", "/sitemap.xml",
            "/robots.txt", "/server-status", "/server-info",
            "/elmah.axd", "/trace.axd", "/__debug__/",
        ]
        exposed = []
        for path in sensitive_paths:
            try:
                url = self.target.rstrip("/") + path
                response = self.http.get(url)
                if response.status_code in (200, 403):
                    exposed.append({
                        "path": path,
                        "status": response.status_code,
                        "size": len(response.content),
                        "severity": "high" if response.status_code == 200 else "medium",
                    })
            except Exception:
                continue
        return exposed

    def _harvest_emails(self) -> list:
        """Harvest email addresses from the target's homepage."""
        emails = []
        try:
            response = self.http.get(self.target)
            pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
            found = re.findall(pattern, response.text)
            emails = list(set(found))
        except Exception:
            pass
        return emails

    def _gather_metadata(self) -> dict:
        """Gather basic metadata about the target."""
        meta = {}
        try:
            ip = socket.gethostbyname(self.domain)
            meta["ip"] = ip
            meta["reverse_dns"] = socket.getfqdn(ip)
        except Exception:
            pass
        meta["scan_timestamp"] = datetime.datetime.utcnow().isoformat()
        return meta
