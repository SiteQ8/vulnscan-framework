"""
Authentication & Access Control Scanner
Tests for:
  - Default credentials on common services
  - Weak password policies
  - JWT vulnerabilities
  - HTTP Basic Auth exposure
  - Cookie security flags
  - Session fixation indicators
"""

import re
import base64
import json
from utils.logger import get_logger
from utils.http_client import HTTPClient

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("root", "root"), ("root", "toor"),
    ("admin", ""), ("administrator", "administrator"),
    ("guest", "guest"), ("test", "test"), ("user", "user"),
    ("admin", "1234"), ("admin", "Pass@123"),
]

ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/wp-admin",
    "/login", "/signin", "/auth", "/user/login",
    "/console", "/manager", "/dashboard", "/panel",
    "/cpanel", "/phpmyadmin", "/adminer.php",
]

JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "key",
    "jwt_secret", "your-secret-key", "change_me",
]


class AuthScanner:
    """Authentication and session management vulnerability scanner."""

    def __init__(self, target: str, timeout: int = 10, verbose: bool = False):
        self.target = target.rstrip("/")
        self.http = HTTPClient(timeout=timeout)
        self.logger = get_logger(verbose=verbose)
        self.vulnerabilities = []

    def scan(self) -> list:
        """Run all authentication checks."""
        self.logger.info(f"  [*] Authentication scanning: {self.target}")
        self._check_cookie_security()
        self._check_admin_panels()
        self._check_http_auth()
        self._check_jwt_tokens()
        self._check_default_credentials()
        return self.vulnerabilities

    def _add_vuln(self, **kwargs):
        kwargs.setdefault("source", "auth_scan")
        self.vulnerabilities.append(kwargs)
        self.logger.info(f"  [{kwargs.get('severity','').upper()}] {kwargs.get('type','')} — {kwargs.get('description','')[:80]}")

    def _check_cookie_security(self):
        """Check for insecure cookie attributes."""
        try:
            resp = self.http.get(self.target)
            for cookie in resp.cookies:
                issues = []
                if not cookie.secure:
                    issues.append("missing Secure flag")
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    issues.append("missing HttpOnly flag")
                samesite = cookie.get_nonstandard_attr("SameSite")
                if not samesite:
                    issues.append("missing SameSite attribute")
                elif samesite.lower() == "none":
                    issues.append("SameSite=None (CSRF risk)")

                if issues:
                    self._add_vuln(
                        type="Insecure Cookie Configuration",
                        url=self.target,
                        parameter=f"Cookie: {cookie.name}",
                        payload="N/A",
                        evidence=", ".join(issues),
                        severity="medium",
                        description=f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}",
                        remediation="Set Secure, HttpOnly, and SameSite=Lax/Strict on all sensitive cookies.",
                    )
        except Exception as e:
            self.logger.debug(f"Cookie check failed: {e}")

    def _check_admin_panels(self):
        """Enumerate admin panel exposure."""
        for path in ADMIN_PATHS:
            try:
                url = self.target + path
                resp = self.http.get(url)
                if resp.status_code in (200, 302, 401, 403):
                    severity = "high" if resp.status_code in (200, 302) else "medium"
                    self._add_vuln(
                        type="Admin Panel Exposed",
                        url=url,
                        parameter="path",
                        payload=path,
                        evidence=f"HTTP {resp.status_code}",
                        severity=severity,
                        description=f"Admin panel accessible at {path} (HTTP {resp.status_code})",
                        remediation="Restrict admin access by IP, require MFA, and rename default paths.",
                    )
            except Exception:
                continue

    def _check_http_auth(self):
        """Test HTTP Basic Authentication for weak credentials."""
        for path in ["/", "/admin", "/api"]:
            url = self.target + path
            try:
                resp = self.http.get(url)
                if resp.status_code == 401 and "WWW-Authenticate" in resp.headers:
                    # Try default credentials
                    for username, password in DEFAULT_CREDS[:5]:
                        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
                        auth_resp = self.http.get(
                            url, headers={"Authorization": f"Basic {creds}"}
                        )
                        if auth_resp.status_code == 200:
                            self._add_vuln(
                                type="Weak HTTP Basic Auth Credentials",
                                url=url,
                                parameter="Authorization",
                                payload=f"{username}:{password}",
                                evidence=f"Authenticated with {username}/{password}",
                                severity="critical",
                                description=f"Default credentials {username}/{password} accepted.",
                                remediation="Change default credentials immediately. Use strong unique passwords.",
                            )
                            break
            except Exception:
                continue

    def _check_jwt_tokens(self):
        """Detect JWT tokens and test for weak secrets / algorithm confusion."""
        try:
            resp = self.http.get(self.target)

            # Look for JWTs in cookies and response body
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            jwt_tokens = re.findall(jwt_pattern, resp.text)

            for cookie in resp.cookies:
                cookie_val = cookie.value or ""
                if re.match(jwt_pattern, cookie_val):
                    jwt_tokens.append(cookie_val)

            for token in set(jwt_tokens):
                parts = token.split(".")
                if len(parts) == 3:
                    try:
                        # Decode header (no verification)
                        header_pad = parts[0] + "=" * (-len(parts[0]) % 4)
                        header = json.loads(base64.urlsafe_b64decode(header_pad))
                        alg = header.get("alg", "")

                        if alg == "none":
                            self._add_vuln(
                                type="JWT None Algorithm",
                                url=self.target,
                                parameter="JWT",
                                payload=token[:50] + "...",
                                evidence=f"alg=none in JWT header",
                                severity="critical",
                                description="JWT uses 'none' algorithm — signature verification bypassed.",
                                remediation="Reject JWTs with alg=none. Enforce strong algorithms (RS256, ES256).",
                            )

                        elif alg in ("HS256", "HS384", "HS512"):
                            self._add_vuln(
                                type="JWT Weak Algorithm (HMAC)",
                                url=self.target,
                                parameter="JWT",
                                payload=token[:50] + "...",
                                evidence=f"alg={alg} — susceptible to brute-force",
                                severity="medium",
                                description=f"JWT signed with {alg}. Consider asymmetric algorithms.",
                                remediation="Use RS256/ES256. Ensure secret is cryptographically random (256+ bits).",
                            )

                    except Exception:
                        pass

        except Exception as e:
            self.logger.debug(f"JWT check failed: {e}")

    def _check_default_credentials(self):
        """Test for default credentials on login forms."""
        try:
            resp = self.http.get(self.target + "/login")
            if resp.status_code != 200:
                resp = self.http.get(self.target)

            # Look for a login form
            has_login_form = any(
                re.search(pattern, resp.text, re.IGNORECASE)
                for pattern in [r'type=["\']password["\']', r'name=["\']password["\']']
            )

            if has_login_form:
                # Extract CSRF token if present
                csrf_match = re.search(
                    r'name=["\'](?:csrf|_token|authenticity_token)["\'][^>]*value=["\']([^"\']+)["\']',
                    resp.text, re.IGNORECASE
                )
                csrf_token = csrf_match.group(1) if csrf_match else None

                login_url = self.target + "/login"
                for username, password in DEFAULT_CREDS[:8]:
                    try:
                        data = {"username": username, "password": password,
                                "email": username, "user": username, "pass": password}
                        if csrf_token:
                            data["_token"] = csrf_token
                            data["csrf_token"] = csrf_token

                        login_resp = self.http.post(login_url, data=data)

                        # Heuristic: look for post-login indicators
                        success_indicators = ["dashboard", "welcome", "logout", "sign out", "my account"]
                        if (login_resp.status_code in (200, 302) and
                                any(ind in login_resp.text.lower() for ind in success_indicators)):
                            self._add_vuln(
                                type="Default Credentials Accepted",
                                url=login_url,
                                parameter="username/password",
                                payload=f"{username}:{password}",
                                evidence="Post-login success indicators found in response",
                                severity="critical",
                                description=f"Login succeeded with default credentials: {username}/{password}",
                                remediation="Remove default accounts. Enforce strong password policies and MFA.",
                            )
                            break
                    except Exception:
                        continue

        except Exception as e:
            self.logger.debug(f"Default cred check failed: {e}")
