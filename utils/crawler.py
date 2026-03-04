"""
Web Crawler
Crawls a target URL to discover pages, forms, and input parameters.
"""

import re
from urllib.parse import urljoin, urlparse
from collections import deque
from utils.logger import get_logger


class Crawler:
    """BFS web crawler for discovering URLs and forms."""

    def __init__(self, http_client, depth: int = 3, max_urls: int = 200):
        self.http = http_client
        self.max_depth = depth
        self.max_urls = max_urls
        self.logger = get_logger()

    def crawl(self, start_url: str):
        """
        Crawl starting from start_url.
        Returns (set of discovered URLs, list of forms).
        """
        base_domain = urlparse(start_url).netloc
        visited = set()
        forms = []
        queue = deque([(start_url, 0)])

        while queue and len(visited) < self.max_urls:
            url, depth = queue.popleft()
            if url in visited or depth > self.max_depth:
                continue
            if urlparse(url).netloc != base_domain:
                continue

            try:
                resp = self.http.get(url)
                visited.add(url)

                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue

                content = resp.text

                # Extract links
                if depth < self.max_depth:
                    links = self._extract_links(content, url)
                    for link in links:
                        if link not in visited:
                            queue.append((link, depth + 1))

                # Extract forms
                page_forms = self._extract_forms(content, url)
                forms.extend(page_forms)

            except Exception as e:
                self.logger.debug(f"Crawl error on {url}: {e}")
                continue

        return visited, forms

    def _extract_links(self, html: str, base_url: str) -> list:
        links = []
        pattern = r'href=["\']([^"\'#>]+)["\']'
        for match in re.finditer(pattern, html, re.IGNORECASE):
            href = match.group(1).strip()
            if href.startswith(("javascript:", "mailto:", "tel:")):
                continue
            full_url = urljoin(base_url, href).split("#")[0]
            if full_url not in links:
                links.append(full_url)
        return links

    def _extract_forms(self, html: str, page_url: str) -> list:
        forms = []
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)

            # Extract action
            action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            action = urljoin(page_url, action_match.group(1)) if action_match else page_url

            # Extract method
            method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            method = method_match.group(1).lower() if method_match else "get"

            # Extract inputs
            inputs = []
            for input_match in re.finditer(r'<input[^>]*>', form_html, re.IGNORECASE):
                inp_html = input_match.group(0)
                name_m = re.search(r'name=["\']([^"\']+)["\']', inp_html, re.IGNORECASE)
                type_m = re.search(r'type=["\']([^"\']+)["\']', inp_html, re.IGNORECASE)
                value_m = re.search(r'value=["\']([^"\']*)["\']', inp_html, re.IGNORECASE)
                if name_m:
                    inputs.append({
                        "name": name_m.group(1),
                        "type": type_m.group(1) if type_m else "text",
                        "value": value_m.group(1) if value_m else "",
                    })

            # Extract textareas
            for ta_match in re.finditer(r'<textarea[^>]*name=["\']([^"\']+)["\']', form_html, re.IGNORECASE):
                inputs.append({"name": ta_match.group(1), "type": "textarea", "value": ""})

            if inputs:
                forms.append({"action": action, "method": method, "inputs": inputs, "page": page_url})

        return forms
