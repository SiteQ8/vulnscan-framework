"""
HTTP Client Utility
Thread-safe HTTP client with retry logic, proxy support, and session management.
"""
import time
import urllib3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


class HTTPClient:
    """Reusable HTTP client with session pooling and retry logic."""

    def __init__(
        self,
        timeout: int = 10,
        verify_ssl: bool = False,
        cookies: dict = None,
        headers: dict = None,
        proxy: str = None,
        retries: int = 2,
        user_agent: str = DEFAULT_UA,
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()

        # Retry strategy
        retry = Retry(total=retries, backoff_factor=0.3,
                      status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=100)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Headers
        self.session.headers.update({"User-Agent": user_agent})
        if headers:
            self.session.headers.update(headers)

        # Cookies
        if cookies:
            self.session.cookies.update(cookies)

        # Proxy
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def get(self, url: str, params: dict = None, allow_redirects: bool = True, **kwargs) -> requests.Response:
        return self.session.get(
            url, params=params, timeout=self.timeout,
            verify=self.verify_ssl, allow_redirects=allow_redirects, **kwargs
        )

    def post(self, url: str, data: dict = None, json: dict = None,
             headers: dict = None, **kwargs) -> requests.Response:
        extra_headers = headers or {}
        return self.session.post(
            url, data=data, json=json, timeout=self.timeout,
            verify=self.verify_ssl, headers={**self.session.headers, **extra_headers}, **kwargs
        )

    def head(self, url: str, **kwargs) -> requests.Response:
        return self.session.head(url, timeout=self.timeout, verify=self.verify_ssl, **kwargs)
