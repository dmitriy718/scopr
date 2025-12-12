"""
Subdomain Enumeration Module
Discovers subdomains using DNS resolution and common subdomain lists.
"""

import asyncio
import dns.resolver
import dns.asyncresolver
from typing import List, Set, Optional, Callable, Dict
from dataclasses import dataclass
from src.wordlists import COMMON_SUBDOMAINS


@dataclass
class SubdomainResult:
    """Result of a subdomain enumeration check."""
    subdomain: str
    full_domain: str
    ip_addresses: List[str]
    cname: Optional[str] = None
    is_alive: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "subdomain": self.subdomain,
            "full_domain": self.full_domain,
            "ip_addresses": self.ip_addresses,
            "cname": self.cname,
            "is_alive": self.is_alive,
            "error": self.error
        }


class SubdomainEnumerator:
    """Enumerates subdomains for a given domain using DNS resolution."""

    def __init__(
        self,
        domain: str,
        wordlist: Optional[List[str]] = None,
        max_concurrent: int = 20,
        timeout: float = 3.0
    ):
        """
        Initialize the subdomain enumerator.
        
        Args:
            domain: Base domain to enumerate (e.g., 'example.com')
            wordlist: Custom list of subdomain prefixes to check
            max_concurrent: Maximum concurrent DNS queries
            timeout: DNS query timeout in seconds
        """
        self.domain = domain.lower().strip()
        if self.domain.startswith('www.'):
            self.domain = self.domain[4:]
        
        self.wordlist = wordlist or COMMON_SUBDOMAINS
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.results: List[SubdomainResult] = []
        self.semaphore: Optional[asyncio.Semaphore] = None

    async def enumerate(
        self,
        progress_callback: Optional[Callable[[int, int, SubdomainResult], None]] = None
    ) -> List[SubdomainResult]:
        """
        Enumerate subdomains asynchronously.
        
        Args:
            progress_callback: Optional callback(completed, total, result)
            
        Returns:
            List of SubdomainResult objects for discovered subdomains
        """
        self.results = []
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        
        total = len(self.wordlist)
        completed = 0
        discovered = []

        tasks = [
            self._check_subdomain(subdomain)
            for subdomain in self.wordlist
        ]

        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1
            
            if result and result.is_alive:
                discovered.append(result)
                self.results.append(result)
            
            if progress_callback and result:
                progress_callback(completed, total, result)

        return discovered

    async def _check_subdomain(self, subdomain: str) -> Optional[SubdomainResult]:
        """
        Check if a subdomain exists via DNS resolution.
        
        Args:
            subdomain: Subdomain prefix to check
            
        Returns:
            SubdomainResult if check completed (alive or not)
        """
        full_domain = f"{subdomain}.{self.domain}"
        
        try:
            async with self.semaphore:
                resolver = dns.asyncresolver.Resolver()
                resolver.timeout = self.timeout
                resolver.lifetime = self.timeout

                ip_addresses = []
                cname = None

                try:
                    a_records = await resolver.resolve(full_domain, 'A')
                    ip_addresses = [str(rdata) for rdata in a_records]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                    pass

                if not ip_addresses:
                    try:
                        cname_records = await resolver.resolve(full_domain, 'CNAME')
                        for rdata in cname_records:
                            cname = str(rdata.target)
                            break
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                        pass

                is_alive = bool(ip_addresses) or bool(cname)

                return SubdomainResult(
                    subdomain=subdomain,
                    full_domain=full_domain,
                    ip_addresses=ip_addresses,
                    cname=cname,
                    is_alive=is_alive
                )

        except dns.resolver.NXDOMAIN:
            return SubdomainResult(
                subdomain=subdomain,
                full_domain=full_domain,
                ip_addresses=[],
                is_alive=False
            )
        except dns.exception.Timeout:
            return SubdomainResult(
                subdomain=subdomain,
                full_domain=full_domain,
                ip_addresses=[],
                is_alive=False,
                error="Timeout"
            )
        except Exception as e:
            return SubdomainResult(
                subdomain=subdomain,
                full_domain=full_domain,
                ip_addresses=[],
                is_alive=False,
                error=str(e)
            )

    def get_alive_domains(self) -> List[str]:
        """
        Get list of discovered alive subdomains.
        
        Returns:
            List of full domain names that resolved
        """
        return [r.full_domain for r in self.results if r.is_alive]

    def get_results_as_dict(self) -> List[Dict]:
        """Get all results as list of dictionaries."""
        return [r.to_dict() for r in self.results if r.is_alive]


async def quick_subdomain_check(domain: str, subdomains: List[str] = None) -> List[str]:
    """
    Quick check for subdomains without full enumeration.
    
    Args:
        domain: Base domain
        subdomains: List of subdomains to check (uses defaults if None)
        
    Returns:
        List of alive subdomain full names
    """
    if subdomains is None:
        subdomains = COMMON_SUBDOMAINS[:30]
    
    enumerator = SubdomainEnumerator(
        domain=domain,
        wordlist=subdomains,
        max_concurrent=10,
        timeout=2.0
    )
    
    await enumerator.enumerate()
    return enumerator.get_alive_domains()
