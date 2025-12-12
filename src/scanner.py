"""
Asynchronous HTTP Scanner Module
Handles concurrent HTTP requests for endpoint discovery with support for
redirects, soft 404 detection, and status code categorization.
"""

import asyncio
import aiohttp
import ssl
from typing import Dict, List, Optional, Callable, Set
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
import time
import re


@dataclass
class ScanResult:
    """Represents the result of scanning a single URL."""
    url: str
    status_code: int
    content_length: int = 0
    redirect_url: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    is_soft_404: bool = False
    response_time: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert result to dictionary for JSON export."""
        return {
            "url": self.url,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "redirect_url": self.redirect_url,
            "is_soft_404": self.is_soft_404,
            "response_time": round(self.response_time, 3),
            "error": self.error
        }


@dataclass
class ScanConfig:
    """Configuration for the scanner."""
    timeout: int = 10
    max_concurrent: int = 20
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    follow_redirects: bool = True
    verify_ssl: bool = False
    auth_type: Optional[str] = None
    auth_value: Optional[str] = None
    custom_headers: Dict[str, str] = field(default_factory=dict)


class AsyncScanner:
    """
    Asynchronous HTTP scanner for discovering web endpoints.
    Uses aiohttp for concurrent requests with configurable limits.
    """

    def __init__(self, config: ScanConfig):
        """
        Initialize the scanner with configuration.
        
        Args:
            config: ScanConfig object with timeout, concurrency, and auth settings
        """
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore: Optional[asyncio.Semaphore] = None
        self.baseline_404_content: Optional[str] = None
        self.baseline_404_length: int = 0
        self.scanned_urls: Set[str] = set()
        self.results: List[ScanResult] = []

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def start(self):
        """Initialize the aiohttp session and semaphore."""
        ssl_context = ssl.create_default_context()
        if not self.config.verify_ssl:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(
            limit=self.config.max_concurrent,
            ssl=ssl_context,
            force_close=True
        )

        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        headers.update(self.config.custom_headers)

        if self.config.auth_type == "bearer" and self.config.auth_value:
            headers["Authorization"] = f"Bearer {self.config.auth_value}"
        elif self.config.auth_type == "basic" and self.config.auth_value:
            import base64
            encoded = base64.b64encode(self.config.auth_value.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector,
            headers=headers,
            timeout=timeout
        )
        self.semaphore = asyncio.Semaphore(self.config.max_concurrent)

    async def close(self):
        """Close the aiohttp session."""
        if self.session:
            await self.session.close()
            self.session = None

    async def establish_baseline(self, base_url: str):
        """
        Establish a baseline for soft 404 detection by requesting a random non-existent path.
        
        Args:
            base_url: The base URL to test against
        """
        import random
        import string
        random_path = ''.join(random.choices(string.ascii_lowercase, k=16))
        test_url = urljoin(base_url, f"/{random_path}")
        
        try:
            async with self.semaphore:
                async with self.session.get(test_url, allow_redirects=False) as response:
                    self.baseline_404_content = await response.text()
                    self.baseline_404_length = len(self.baseline_404_content)
        except Exception:
            self.baseline_404_content = None
            self.baseline_404_length = 0

    def is_soft_404(self, content: str, status_code: int) -> bool:
        """
        Detect if a response is a soft 404 (200 response that's actually a not found page).
        
        Args:
            content: Response body content
            status_code: HTTP status code
            
        Returns:
            True if the response appears to be a soft 404
        """
        if status_code != 200:
            return False

        if not self.baseline_404_content:
            return False

        content_len = len(content)
        if abs(content_len - self.baseline_404_length) < 50:
            return True

        soft_404_patterns = [
            r"page\s*not\s*found",
            r"404\s*error",
            r"not\s*found",
            r"does\s*not\s*exist",
            r"no\s*longer\s*available",
            r"couldn't\s*find",
            r"cannot\s*find"
        ]
        
        content_lower = content.lower()
        for pattern in soft_404_patterns:
            if re.search(pattern, content_lower):
                return True

        return False

    async def scan_url(self, url: str) -> ScanResult:
        """
        Scan a single URL and return the result.
        
        Args:
            url: The URL to scan
            
        Returns:
            ScanResult object with status code, headers, and metadata
        """
        if url in self.scanned_urls:
            return None
        self.scanned_urls.add(url)

        start_time = time.time()
        
        try:
            async with self.semaphore:
                async with self.session.get(
                    url, 
                    allow_redirects=self.config.follow_redirects
                ) as response:
                    response_time = time.time() - start_time
                    content = await response.text()
                    
                    redirect_url = None
                    if response.history:
                        redirect_url = str(response.url)
                    elif response.status in (301, 302, 303, 307, 308):
                        redirect_url = response.headers.get("Location")

                    headers_dict = {k: v for k, v in response.headers.items()}
                    
                    result = ScanResult(
                        url=url,
                        status_code=response.status,
                        content_length=len(content),
                        redirect_url=redirect_url,
                        headers=headers_dict,
                        is_soft_404=self.is_soft_404(content, response.status),
                        response_time=response_time
                    )
                    
                    return result

        except asyncio.TimeoutError:
            return ScanResult(
                url=url,
                status_code=0,
                error="Timeout",
                response_time=time.time() - start_time
            )
        except aiohttp.ClientError as e:
            return ScanResult(
                url=url,
                status_code=0,
                error=str(e),
                response_time=time.time() - start_time
            )
        except Exception as e:
            return ScanResult(
                url=url,
                status_code=0,
                error=f"Unknown error: {str(e)}",
                response_time=time.time() - start_time
            )

    async def scan_urls(
        self, 
        urls: List[str], 
        progress_callback: Optional[Callable[[int, int, ScanResult], None]] = None
    ) -> List[ScanResult]:
        """
        Scan multiple URLs concurrently.
        
        Args:
            urls: List of URLs to scan
            progress_callback: Optional callback function(completed, total, result)
            
        Returns:
            List of ScanResult objects
        """
        self.results = []
        total = len(urls)
        completed = 0

        tasks = []
        for url in urls:
            tasks.append(self.scan_url(url))

        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                self.results.append(result)
                completed += 1
                if progress_callback:
                    progress_callback(completed, total, result)

        return self.results

    def get_results_by_status(self) -> Dict[str, List[ScanResult]]:
        """
        Categorize results by status code type.
        
        Returns:
            Dictionary with categories: success, redirect, client_error, server_error, error
        """
        categorized = {
            "success": [],
            "redirect": [],
            "client_error": [],
            "server_error": [],
            "error": []
        }

        for result in self.results:
            if result.error:
                categorized["error"].append(result)
            elif 200 <= result.status_code < 300:
                if not result.is_soft_404:
                    categorized["success"].append(result)
            elif 300 <= result.status_code < 400:
                categorized["redirect"].append(result)
            elif 400 <= result.status_code < 500:
                categorized["client_error"].append(result)
            elif result.status_code >= 500:
                categorized["server_error"].append(result)

        return categorized


def normalize_url(domain: str) -> str:
    """
    Normalize a domain input to a proper base URL.
    
    Args:
        domain: Domain like 'example.com' or 'https://example.com'
        
    Returns:
        Normalized URL with scheme
    """
    domain = domain.strip()
    if not domain.startswith(('http://', 'https://')):
        domain = f"https://{domain}"
    
    parsed = urlparse(domain)
    return f"{parsed.scheme}://{parsed.netloc}"
