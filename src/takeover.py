"""
Subdomain Takeover Detection Module
Identifies subdomains with dangling DNS records pointing to unclaimed services.
"""

import asyncio
import aiohttp
import dns.resolver
import dns.asyncresolver
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field


VULNERABLE_SERVICES = {
    "aws_s3": {
        "cname_patterns": [".s3.amazonaws.com", ".s3-website", ".s3-", "s3.amazonaws.com"],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "service": "AWS S3",
        "severity": "high"
    },
    "github_pages": {
        "cname_patterns": [".github.io", "github.io"],
        "fingerprints": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)"],
        "service": "GitHub Pages",
        "severity": "high"
    },
    "heroku": {
        "cname_patterns": [".herokuapp.com", ".herokussl.com", "herokuapp.com"],
        "fingerprints": ["No such app", "there is no app configured at that hostname", "herokucdn.com/error-pages"],
        "service": "Heroku",
        "severity": "high"
    },
    "azure": {
        "cname_patterns": [".azurewebsites.net", ".cloudapp.net", ".azure-api.net", ".azurefd.net", ".blob.core.windows.net", ".cloudapp.azure.com", ".trafficmanager.net"],
        "fingerprints": ["404 Web Site not found", "Azure Web Apps", "Web App - Pair isn't registered"],
        "service": "Microsoft Azure",
        "severity": "high"
    },
    "shopify": {
        "cname_patterns": [".myshopify.com", "shops.myshopify.com"],
        "fingerprints": ["Sorry, this shop is currently unavailable", "Only one step left"],
        "service": "Shopify",
        "severity": "medium"
    },
    "tumblr": {
        "cname_patterns": [".tumblr.com", "domains.tumblr.com"],
        "fingerprints": ["There's nothing here", "Whatever you were looking for doesn't currently exist at this address"],
        "service": "Tumblr",
        "severity": "medium"
    },
    "wordpress": {
        "cname_patterns": [".wordpress.com"],
        "fingerprints": ["Do you want to register"],
        "service": "WordPress",
        "severity": "medium"
    },
    "pantheon": {
        "cname_patterns": [".pantheonsite.io", ".pantheon.io"],
        "fingerprints": ["The gods are wise", "404 error unknown site"],
        "service": "Pantheon",
        "severity": "medium"
    },
    "zendesk": {
        "cname_patterns": [".zendesk.com"],
        "fingerprints": ["Help Center Closed", "Oops, this help center no longer exists"],
        "service": "Zendesk",
        "severity": "medium"
    },
    "fastly": {
        "cname_patterns": [".fastly.net", ".fastlylb.net", "fastly.com"],
        "fingerprints": ["Fastly error: unknown domain"],
        "service": "Fastly",
        "severity": "high"
    },
    "ghost": {
        "cname_patterns": [".ghost.io"],
        "fingerprints": ["The thing you were looking for is no longer here"],
        "service": "Ghost",
        "severity": "medium"
    },
    "cargo": {
        "cname_patterns": [".cargocollective.com"],
        "fingerprints": ["404 Not Found"],
        "service": "Cargo",
        "severity": "low"
    },
    "feedpress": {
        "cname_patterns": [".redirect.feedpress.me"],
        "fingerprints": ["The feed has not been found"],
        "service": "FeedPress",
        "severity": "low"
    },
    "surge": {
        "cname_patterns": [".surge.sh"],
        "fingerprints": ["project not found"],
        "service": "Surge.sh",
        "severity": "medium"
    },
    "bitbucket": {
        "cname_patterns": [".bitbucket.io"],
        "fingerprints": ["Repository not found"],
        "service": "Bitbucket",
        "severity": "medium"
    },
    "intercom": {
        "cname_patterns": [".custom.intercom.help"],
        "fingerprints": ["This page is reserved for", "Uh oh. That page doesn't exist"],
        "service": "Intercom",
        "severity": "medium"
    },
    "webflow": {
        "cname_patterns": [".webflow.io", ".proxy.webflow.com"],
        "fingerprints": ["The page you are looking for doesn't exist or has been moved"],
        "service": "Webflow",
        "severity": "medium"
    },
    "netlify": {
        "cname_patterns": [".netlify.app", ".netlify.com"],
        "fingerprints": ["Not Found - Request ID"],
        "service": "Netlify",
        "severity": "medium"
    },
    "fly_io": {
        "cname_patterns": [".fly.dev"],
        "fingerprints": ["404 Not Found"],
        "service": "Fly.io",
        "severity": "medium"
    },
    "vercel": {
        "cname_patterns": [".vercel.app", ".now.sh"],
        "fingerprints": ["The deployment could not be found"],
        "service": "Vercel",
        "severity": "medium"
    }
}


@dataclass
class TakeoverResult:
    """Result of a subdomain takeover check."""
    subdomain: str
    full_domain: str
    cname: str
    service: str
    is_vulnerable: bool
    severity: str
    fingerprint_matched: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "subdomain": self.subdomain,
            "full_domain": self.full_domain,
            "cname": self.cname,
            "service": self.service,
            "is_vulnerable": self.is_vulnerable,
            "severity": self.severity,
            "fingerprint_matched": self.fingerprint_matched,
            "error": self.error
        }


class TakeoverDetector:
    """Detects potential subdomain takeover vulnerabilities."""

    def __init__(self, timeout: float = 10.0, max_concurrent: int = 10):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.results: List[TakeoverResult] = []
        self.semaphore: Optional[asyncio.Semaphore] = None

    def _identify_service(self, cname: str) -> Optional[Tuple[str, Dict]]:
        """Identify which vulnerable service the CNAME points to."""
        cname_lower = cname.lower().rstrip('.')
        for service_key, service_data in VULNERABLE_SERVICES.items():
            for pattern in service_data["cname_patterns"]:
                if pattern.lower() in cname_lower:
                    return service_key, service_data
        return None

    async def check_subdomain(
        self,
        subdomain: str,
        full_domain: str,
        cname: str,
        session: aiohttp.ClientSession
    ) -> Optional[TakeoverResult]:
        """Check if a subdomain with a CNAME is vulnerable to takeover."""
        async with self.semaphore:
            service_info = self._identify_service(cname)
            
            if not service_info:
                return None
            
            service_key, service_data = service_info
            
            try:
                for protocol in ['https', 'http']:
                    try:
                        url = f"{protocol}://{full_domain}"
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            allow_redirects=True,
                            ssl=False
                        ) as response:
                            body = await response.text()
                            
                            for fingerprint in service_data["fingerprints"]:
                                if fingerprint.lower() in body.lower():
                                    return TakeoverResult(
                                        subdomain=subdomain,
                                        full_domain=full_domain,
                                        cname=cname,
                                        service=service_data["service"],
                                        is_vulnerable=True,
                                        severity=service_data["severity"],
                                        fingerprint_matched=fingerprint
                                    )
                            
                            return TakeoverResult(
                                subdomain=subdomain,
                                full_domain=full_domain,
                                cname=cname,
                                service=service_data["service"],
                                is_vulnerable=False,
                                severity=service_data["severity"]
                            )
                    except aiohttp.ClientConnectorError:
                        continue
                    except Exception:
                        continue
                
                return TakeoverResult(
                    subdomain=subdomain,
                    full_domain=full_domain,
                    cname=cname,
                    service=service_data["service"],
                    is_vulnerable=False,
                    severity=service_data["severity"],
                    error="Connection failed - manual verification recommended"
                )
                
            except Exception as e:
                return TakeoverResult(
                    subdomain=subdomain,
                    full_domain=full_domain,
                    cname=cname,
                    service=service_data["service"],
                    is_vulnerable=False,
                    severity=service_data["severity"],
                    error=str(e)
                )

    async def scan_subdomains(
        self,
        subdomain_results: List[Dict]
    ) -> List[TakeoverResult]:
        """
        Scan a list of subdomain results for takeover vulnerabilities.
        
        Args:
            subdomain_results: List of subdomain dicts with 'subdomain', 'full_domain', 'cname'
            
        Returns:
            List of TakeoverResult objects
        """
        self.results = []
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        
        subdomains_with_cname = [
            s for s in subdomain_results 
            if s.get('cname')
        ]
        
        if not subdomains_with_cname:
            return []
        
        connector = aiohttp.TCPConnector(ssl=False, limit=self.max_concurrent)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [
                self.check_subdomain(
                    s['subdomain'],
                    s['full_domain'],
                    s['cname'],
                    session
                )
                for s in subdomains_with_cname
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, TakeoverResult):
                    self.results.append(result)
        
        return self.results

    def get_vulnerable(self) -> List[TakeoverResult]:
        """Get only vulnerable subdomains."""
        return [r for r in self.results if r.is_vulnerable]

    def get_all_results(self) -> List[Dict]:
        """Get all results as dictionaries."""
        return [r.to_dict() for r in self.results]

    def get_vulnerable_as_dict(self) -> List[Dict]:
        """Get vulnerable results as dictionaries."""
        return [r.to_dict() for r in self.get_vulnerable()]

    def get_stats(self) -> Dict:
        """Get statistics about the scan."""
        vulnerable = self.get_vulnerable()
        return {
            "total_checked": len(self.results),
            "vulnerable_count": len(vulnerable),
            "by_severity": {
                "high": len([r for r in vulnerable if r.severity == "high"]),
                "medium": len([r for r in vulnerable if r.severity == "medium"]),
                "low": len([r for r in vulnerable if r.severity == "low"])
            },
            "by_service": self._count_by_service(vulnerable)
        }

    def _count_by_service(self, results: List[TakeoverResult]) -> Dict[str, int]:
        """Count results by service."""
        counts = {}
        for r in results:
            counts[r.service] = counts.get(r.service, 0) + 1
        return counts


async def check_domain_for_takeover(domain: str) -> List[Dict]:
    """
    Quick check for subdomain takeover on a domain.
    First enumerates subdomains, then checks for takeover.
    
    Args:
        domain: The base domain to check
        
    Returns:
        List of vulnerable subdomain dictionaries
    """
    from src.subdomain import SubdomainEnumerator
    
    enumerator = SubdomainEnumerator(domain, max_concurrent=20, timeout=3.0)
    await enumerator.enumerate()
    subdomain_results = enumerator.get_results_as_dict()
    
    detector = TakeoverDetector()
    await detector.scan_subdomains(subdomain_results)
    
    return detector.get_vulnerable_as_dict()
