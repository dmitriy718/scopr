"""
Parameter Discovery Module
Tests URLs with common query parameters to discover hidden functionality.
"""

import asyncio
import aiohttp
from typing import List, Dict, Optional, Callable, Set
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, urlencode
from src.wordlists import PARAMETER_WORDLIST


@dataclass
class ParameterResult:
    """Result of a parameter discovery check."""
    url: str
    base_url: str
    parameter: str
    value: str
    status_code: int
    content_length: int = 0
    is_different: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "url": self.url,
            "base_url": self.base_url,
            "parameter": self.parameter,
            "value": self.value,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "is_different": self.is_different,
            "error": self.error
        }


class ParameterScanner:
    """Scans URLs for interesting query parameters."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        parameters: Optional[List[str]] = None,
        max_concurrent: int = 10,
        timeout: float = 5.0
    ):
        """
        Initialize the parameter scanner.
        
        Args:
            session: aiohttp ClientSession to use
            parameters: Custom list of parameters to test (uses defaults if None)
            max_concurrent: Maximum concurrent requests
            timeout: Request timeout in seconds
        """
        self.session = session
        self.parameters = parameters or PARAMETER_WORDLIST
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.results: List[ParameterResult] = []
        self.baseline_lengths: Dict[str, int] = {}

    async def establish_baseline(self, url: str) -> int:
        """
        Get the baseline response length for a URL without parameters.
        
        Args:
            url: The URL to test
            
        Returns:
            Content length of the baseline response
        """
        try:
            async with self.semaphore:
                async with self.session.get(url, timeout=self.timeout) as response:
                    content = await response.text()
                    self.baseline_lengths[url] = len(content)
                    return len(content)
        except Exception:
            return 0

    async def test_parameter(self, base_url: str, param: str, value: str = "1") -> Optional[ParameterResult]:
        """
        Test a single parameter on a URL.
        
        Args:
            base_url: The base URL to test
            param: The parameter name to test
            value: The value to use for the parameter
            
        Returns:
            ParameterResult if the test completed
        """
        parsed = urlparse(base_url)
        if parsed.query:
            test_url = f"{base_url}&{param}={value}"
        else:
            test_url = f"{base_url}?{param}={value}"

        try:
            async with self.semaphore:
                async with self.session.get(test_url, timeout=self.timeout) as response:
                    content = await response.text()
                    content_length = len(content)
                    
                    baseline = self.baseline_lengths.get(base_url, 0)
                    is_different = abs(content_length - baseline) > 100

                    result = ParameterResult(
                        url=test_url,
                        base_url=base_url,
                        parameter=param,
                        value=value,
                        status_code=response.status,
                        content_length=content_length,
                        is_different=is_different
                    )
                    
                    return result

        except asyncio.TimeoutError:
            return ParameterResult(
                url=test_url,
                base_url=base_url,
                parameter=param,
                value=value,
                status_code=0,
                error="Timeout"
            )
        except Exception as e:
            return ParameterResult(
                url=test_url,
                base_url=base_url,
                parameter=param,
                value=value,
                status_code=0,
                error=str(e)
            )

    async def scan_url(
        self,
        url: str,
        progress_callback: Optional[Callable[[int, int, ParameterResult], None]] = None
    ) -> List[ParameterResult]:
        """
        Scan a URL with all configured parameters.
        
        Args:
            url: The URL to test
            progress_callback: Optional callback(completed, total, result)
            
        Returns:
            List of ParameterResult objects for interesting findings
        """
        await self.establish_baseline(url)

        total = len(self.parameters)
        completed = 0
        results = []

        tasks = [
            self.test_parameter(url, param)
            for param in self.parameters
        ]

        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1

            if result:
                if result.is_different or result.status_code in (200, 302, 500):
                    results.append(result)
                    self.results.append(result)

                if progress_callback:
                    progress_callback(completed, total, result)

        return results

    async def scan_urls(
        self,
        urls: List[str],
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[ParameterResult]:
        """
        Scan multiple URLs for interesting parameters.
        
        Args:
            urls: List of URLs to test
            progress_callback: Optional callback(completed, total)
            
        Returns:
            List of interesting ParameterResult objects
        """
        self.results = []
        
        for i, url in enumerate(urls):
            await self.scan_url(url)
            if progress_callback:
                progress_callback(i + 1, len(urls))

        return self.results

    def get_interesting_results(self) -> List[ParameterResult]:
        """Get results where the response differed from baseline."""
        return [r for r in self.results if r.is_different and not r.error]

    def get_results_as_dict(self) -> List[Dict]:
        """Get all results as list of dictionaries."""
        return [r.to_dict() for r in self.results if r.is_different or r.status_code == 200]


async def discover_parameters(
    session: aiohttp.ClientSession,
    urls: List[str],
    parameters: Optional[List[str]] = None,
    max_urls: int = 10
) -> List[Dict]:
    """
    Convenience function to discover parameters on a list of URLs.
    
    Args:
        session: aiohttp ClientSession
        urls: List of URLs to test (will be limited to max_urls)
        parameters: Optional custom parameter list
        max_urls: Maximum number of URLs to test
        
    Returns:
        List of interesting parameter discoveries
    """
    urls_to_test = [u for u in urls if u.endswith('/') or '.' not in u.split('/')[-1]][:max_urls]
    
    if not urls_to_test:
        urls_to_test = urls[:max_urls]

    scanner = ParameterScanner(session, parameters)
    await scanner.scan_urls(urls_to_test)
    
    return scanner.get_results_as_dict()
