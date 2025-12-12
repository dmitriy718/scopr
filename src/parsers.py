"""
Web Resource Parsers Module
Parses robots.txt, sitemap.xml, and HTML for additional paths and endpoints.
"""

import re
import asyncio
import aiohttp
from typing import List, Set, Optional, Dict
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET


class RobotsTxtParser:
    """Parser for robots.txt files to extract paths."""

    def __init__(self, base_url: str):
        """
        Initialize the robots.txt parser.
        
        Args:
            base_url: The base URL of the target site
        """
        self.base_url = base_url.rstrip('/')
        self.paths: Set[str] = set()
        self.sitemaps: Set[str] = set()
        self.disallowed: Set[str] = set()
        self.allowed: Set[str] = set()

    async def fetch_and_parse(self, session: aiohttp.ClientSession) -> Dict[str, List[str]]:
        """
        Fetch and parse robots.txt from the target site.
        
        Args:
            session: aiohttp ClientSession to use for requests
            
        Returns:
            Dictionary with 'paths', 'sitemaps', 'disallowed', 'allowed' keys
        """
        robots_url = f"{self.base_url}/robots.txt"
        
        try:
            async with session.get(robots_url, timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    self._parse_content(content)
        except Exception:
            pass

        return {
            "paths": sorted(list(self.paths)),
            "sitemaps": sorted(list(self.sitemaps)),
            "disallowed": sorted(list(self.disallowed)),
            "allowed": sorted(list(self.allowed))
        }

    def _parse_content(self, content: str):
        """
        Parse the robots.txt content.
        
        Args:
            content: Raw robots.txt content
        """
        for line in content.split('\n'):
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue

            line_lower = line.lower()
            
            if line_lower.startswith('sitemap:'):
                sitemap_url = line.split(':', 1)[1].strip()
                self.sitemaps.add(sitemap_url)
                self.paths.add(sitemap_url)
            
            elif line_lower.startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                if path and path != '/':
                    clean_path = path.split('*')[0].split('?')[0].rstrip('$')
                    if clean_path:
                        self.disallowed.add(clean_path)
                        self.paths.add(urljoin(self.base_url, clean_path))
            
            elif line_lower.startswith('allow:'):
                path = line.split(':', 1)[1].strip()
                if path:
                    clean_path = path.split('*')[0].split('?')[0].rstrip('$')
                    if clean_path:
                        self.allowed.add(clean_path)
                        self.paths.add(urljoin(self.base_url, clean_path))


class SitemapParser:
    """Parser for sitemap.xml files to extract URLs."""

    def __init__(self, base_url: str):
        """
        Initialize the sitemap parser.
        
        Args:
            base_url: The base URL of the target site
        """
        self.base_url = base_url.rstrip('/')
        self.urls: Set[str] = set()
        self.nested_sitemaps: Set[str] = set()

    async def fetch_and_parse(
        self, 
        session: aiohttp.ClientSession,
        sitemap_urls: Optional[List[str]] = None,
        max_urls: int = 500
    ) -> List[str]:
        """
        Fetch and parse sitemap(s) from the target site.
        
        Args:
            session: aiohttp ClientSession to use for requests
            sitemap_urls: Optional list of specific sitemap URLs to parse
            max_urls: Maximum number of URLs to extract
            
        Returns:
            List of discovered URLs
        """
        if sitemap_urls:
            urls_to_parse = sitemap_urls
        else:
            urls_to_parse = [
                f"{self.base_url}/sitemap.xml",
                f"{self.base_url}/sitemap_index.xml",
                f"{self.base_url}/sitemap1.xml",
                f"{self.base_url}/post-sitemap.xml",
                f"{self.base_url}/page-sitemap.xml"
            ]

        for sitemap_url in urls_to_parse:
            if len(self.urls) >= max_urls:
                break
            await self._parse_sitemap(session, sitemap_url)

        for nested_url in list(self.nested_sitemaps):
            if len(self.urls) >= max_urls:
                break
            await self._parse_sitemap(session, nested_url)

        return sorted(list(self.urls))[:max_urls]

    async def _parse_sitemap(self, session: aiohttp.ClientSession, url: str):
        """
        Parse a single sitemap file.
        
        Args:
            session: aiohttp ClientSession
            url: URL of the sitemap to parse
        """
        try:
            async with session.get(url, timeout=15) as response:
                if response.status == 200:
                    content = await response.text()
                    self._extract_urls(content)
        except Exception:
            pass

    def _extract_urls(self, content: str):
        """
        Extract URLs from sitemap XML content.
        
        Args:
            content: Raw XML content
        """
        try:
            namespaces = {
                'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'
            }
            
            root = ET.fromstring(content)
            
            for loc in root.findall('.//sm:loc', namespaces):
                if loc.text:
                    url = loc.text.strip()
                    if url.endswith('.xml'):
                        self.nested_sitemaps.add(url)
                    else:
                        self.urls.add(url)

            for loc in root.findall('.//loc'):
                if loc.text:
                    url = loc.text.strip()
                    if url.endswith('.xml'):
                        self.nested_sitemaps.add(url)
                    else:
                        self.urls.add(url)

        except ET.ParseError:
            url_pattern = r'<loc>\s*(https?://[^<]+)\s*</loc>'
            matches = re.findall(url_pattern, content)
            for url in matches:
                if url.endswith('.xml'):
                    self.nested_sitemaps.add(url)
                else:
                    self.urls.add(url)


class HTMLLinkParser:
    """Parser to extract links and paths from HTML content."""

    def __init__(self, base_url: str):
        """
        Initialize the HTML link parser.
        
        Args:
            base_url: The base URL for resolving relative links
        """
        self.base_url = base_url.rstrip('/')
        self.base_domain = urlparse(base_url).netloc

    def extract_links(self, html_content: str) -> List[str]:
        """
        Extract all links from HTML content.
        
        Args:
            html_content: Raw HTML content
            
        Returns:
            List of discovered URLs
        """
        urls = set()
        
        try:
            soup = BeautifulSoup(html_content, 'lxml')
        except Exception:
            soup = BeautifulSoup(html_content, 'html.parser')

        link_attrs = ['href', 'src', 'data-src', 'action']
        for attr in link_attrs:
            for tag in soup.find_all(attrs={attr: True}):
                url = tag.get(attr)
                if url:
                    resolved = self._resolve_url(url)
                    if resolved:
                        urls.add(resolved)

        script_pattern = r'["\']/([\w\-/\.]+)["\']'
        for match in re.findall(script_pattern, html_content):
            if not match.startswith('//'):
                resolved = f"{self.base_url}/{match}"
                urls.add(resolved)

        return sorted(list(urls))

    def _resolve_url(self, url: str) -> Optional[str]:
        """
        Resolve a relative or absolute URL to a full URL.
        
        Args:
            url: URL to resolve
            
        Returns:
            Resolved full URL or None if invalid/external
        """
        if not url or url.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
            return None

        if url.startswith('//'):
            url = f"https:{url}"

        if url.startswith(('http://', 'https://')):
            parsed = urlparse(url)
            if parsed.netloc == self.base_domain:
                return url
            return None

        return urljoin(self.base_url + '/', url)

    def extract_forms(self, html_content: str) -> List[Dict]:
        """
        Extract form information from HTML.
        
        Args:
            html_content: Raw HTML content
            
        Returns:
            List of form dictionaries with action, method, and inputs
        """
        forms = []
        
        try:
            soup = BeautifulSoup(html_content, 'lxml')
        except Exception:
            soup = BeautifulSoup(html_content, 'html.parser')

        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            for inp in form.find_all(['input', 'select', 'textarea']):
                input_data = {
                    'name': inp.get('name', ''),
                    'type': inp.get('type', 'text'),
                    'value': inp.get('value', '')
                }
                if input_data['name']:
                    form_data['inputs'].append(input_data)
            
            if form_data['action']:
                form_data['action'] = self._resolve_url(form_data['action'])
            
            forms.append(form_data)

        return forms


async def parse_all_sources(base_url: str, session: aiohttp.ClientSession) -> Dict[str, List[str]]:
    """
    Parse all available sources (robots.txt, sitemap.xml) for paths.
    
    Args:
        base_url: The target base URL
        session: aiohttp ClientSession
        
    Returns:
        Dictionary with discovered paths from each source
    """
    robots_parser = RobotsTxtParser(base_url)
    sitemap_parser = SitemapParser(base_url)

    robots_data = await robots_parser.fetch_and_parse(session)
    
    sitemap_urls = robots_data.get('sitemaps', [])
    sitemap_data = await sitemap_parser.fetch_and_parse(session, sitemap_urls)

    return {
        'robots_paths': robots_data['paths'],
        'sitemap_urls': sitemap_data,
        'disallowed': robots_data['disallowed'],
        'allowed': robots_data['allowed']
    }
