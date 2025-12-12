"""
Technology Fingerprinting Module
Identifies web frameworks, CMS, server types, and JavaScript libraries.
"""

import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field


@dataclass
class TechnologyInfo:
    """Information about a detected technology."""
    name: str
    category: str
    version: Optional[str] = None
    confidence: str = "medium"
    evidence: str = ""

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "confidence": self.confidence,
            "evidence": self.evidence
        }


HEADER_SIGNATURES = {
    "X-Powered-By": {
        "PHP": ("PHP", "backend"),
        "ASP.NET": ("ASP.NET", "backend"),
        "Express": ("Express.js", "backend"),
        "Next.js": ("Next.js", "frontend"),
        "Nuxt": ("Nuxt.js", "frontend"),
    },
    "Server": {
        "nginx": ("Nginx", "server"),
        "Apache": ("Apache", "server"),
        "Microsoft-IIS": ("IIS", "server"),
        "cloudflare": ("Cloudflare", "cdn"),
        "LiteSpeed": ("LiteSpeed", "server"),
        "openresty": ("OpenResty", "server"),
        "Caddy": ("Caddy", "server"),
        "gunicorn": ("Gunicorn", "server"),
        "Werkzeug": ("Werkzeug/Flask", "backend"),
        "uvicorn": ("Uvicorn", "server"),
        "Kestrel": ("Kestrel/.NET", "server"),
    },
    "X-AspNet-Version": {
        "": ("ASP.NET", "backend")
    },
    "X-AspNetMvc-Version": {
        "": ("ASP.NET MVC", "backend")
    },
    "X-Drupal-Cache": {
        "": ("Drupal", "cms")
    },
    "X-Generator": {
        "Drupal": ("Drupal", "cms"),
        "WordPress": ("WordPress", "cms"),
        "Joomla": ("Joomla", "cms"),
    },
    "X-Shopify-Stage": {
        "": ("Shopify", "ecommerce")
    },
    "X-Wix-Request-Id": {
        "": ("Wix", "cms")
    }
}


COOKIE_SIGNATURES = {
    "PHPSESSID": ("PHP", "backend"),
    "JSESSIONID": ("Java", "backend"),
    "ASP.NET_SessionId": ("ASP.NET", "backend"),
    "laravel_session": ("Laravel", "backend"),
    "wp-settings": ("WordPress", "cms"),
    "CRAFT_CSRF_TOKEN": ("Craft CMS", "cms"),
    "django": ("Django", "backend"),
    "rack.session": ("Ruby/Rails", "backend"),
    "_shopify_s": ("Shopify", "ecommerce")
}


HTML_SIGNATURES = [
    (r'<meta\s+name="generator"\s+content="WordPress', "WordPress", "cms", "high"),
    (r'wp-content/', "WordPress", "cms", "high"),
    (r'wp-includes/', "WordPress", "cms", "high"),
    (r'<meta\s+name="generator"\s+content="Drupal', "Drupal", "cms", "high"),
    (r'/sites/default/files/', "Drupal", "cms", "medium"),
    (r'<meta\s+name="generator"\s+content="Joomla', "Joomla", "cms", "high"),
    (r'/media/system/js/', "Joomla", "cms", "medium"),
    (r'<script[^>]+react', "React", "frontend", "high"),
    (r'__NEXT_DATA__', "Next.js", "frontend", "high"),
    (r'__NUXT__', "Nuxt.js", "frontend", "high"),
    (r'ng-version=', "Angular", "frontend", "high"),
    (r'<div\s+id="__next"', "Next.js", "frontend", "medium"),
    (r'data-v-[a-f0-9]+', "Vue.js", "frontend", "medium"),
    (r'<script[^>]+vue', "Vue.js", "frontend", "high"),
    (r'jquery', "jQuery", "library", "medium"),
    (r'bootstrap', "Bootstrap", "library", "medium"),
    (r'tailwind', "Tailwind CSS", "library", "medium"),
    (r'cdn\.shopify\.com', "Shopify", "ecommerce", "high"),
    (r'squarespace\.com', "Squarespace", "cms", "high"),
    (r'wix\.com', "Wix", "cms", "high"),
    (r'googleapis\.com/maps', "Google Maps", "service", "high"),
    (r'google-analytics\.com|gtag', "Google Analytics", "analytics", "high"),
    (r'facebook\.net/signals', "Facebook Pixel", "analytics", "high"),
    (r'hotjar\.com', "Hotjar", "analytics", "medium"),
    (r'cloudflare', "Cloudflare", "cdn", "medium"),
    (r'akamai', "Akamai", "cdn", "medium"),
    (r'fastly', "Fastly", "cdn", "medium"),
    (r'amazonaws\.com', "AWS", "cloud", "medium"),
    (r'fonts\.googleapis\.com', "Google Fonts", "service", "high"),
    (r'stripe\.com', "Stripe", "payment", "high"),
    (r'paypal\.com', "PayPal", "payment", "high"),
]


URL_SIGNATURES = {
    "/wp-admin": ("WordPress", "cms"),
    "/wp-login.php": ("WordPress", "cms"),
    "/administrator": ("Joomla", "cms"),
    "/user/login": ("Drupal", "cms"),
    "/rails/info": ("Ruby on Rails", "backend"),
    "/django-admin": ("Django", "backend"),
    "/elmah.axd": ("ASP.NET", "backend"),
    "/phpMyAdmin": ("phpMyAdmin", "tool"),
    "/adminer.php": ("Adminer", "tool"),
}


class TechnologyFingerprinter:
    """Identifies technologies used by a web application."""

    def __init__(self):
        """Initialize the fingerprinter."""
        self.detected: Dict[str, TechnologyInfo] = {}

    def analyze_headers(self, headers: Dict[str, str]) -> List[TechnologyInfo]:
        """
        Analyze HTTP headers for technology signatures.
        
        Args:
            headers: Dictionary of HTTP response headers
            
        Returns:
            List of detected technologies
        """
        detected = []
        
        for header_name, signatures in HEADER_SIGNATURES.items():
            header_value = headers.get(header_name, "")
            if header_value:
                for pattern, (name, category) in signatures.items():
                    if pattern == "" or pattern.lower() in header_value.lower():
                        version = self._extract_version(header_value)
                        tech = TechnologyInfo(
                            name=name,
                            category=category,
                            version=version,
                            confidence="high",
                            evidence=f"{header_name}: {header_value}"
                        )
                        detected.append(tech)
                        self.detected[name] = tech

        set_cookie = headers.get("Set-Cookie", "")
        for cookie_name, (name, category) in COOKIE_SIGNATURES.items():
            if cookie_name.lower() in set_cookie.lower():
                tech = TechnologyInfo(
                    name=name,
                    category=category,
                    confidence="medium",
                    evidence=f"Cookie: {cookie_name}"
                )
                if name not in self.detected:
                    detected.append(tech)
                    self.detected[name] = tech

        return detected

    def analyze_html(self, html_content: str) -> List[TechnologyInfo]:
        """
        Analyze HTML content for technology signatures.
        
        Args:
            html_content: Raw HTML content
            
        Returns:
            List of detected technologies
        """
        detected = []
        html_lower = html_content.lower()

        for pattern, name, category, confidence in HTML_SIGNATURES:
            if re.search(pattern, html_content, re.IGNORECASE):
                if name not in self.detected:
                    version = None
                    if name in ["jQuery", "Bootstrap", "Vue.js", "React", "Angular"]:
                        version = self._extract_library_version(html_content, name)
                    
                    tech = TechnologyInfo(
                        name=name,
                        category=category,
                        version=version,
                        confidence=confidence,
                        evidence=f"HTML pattern: {pattern[:50]}"
                    )
                    detected.append(tech)
                    self.detected[name] = tech

        return detected

    def analyze_url(self, url: str, status_code: int) -> Optional[TechnologyInfo]:
        """
        Analyze a URL and its response for technology hints.
        
        Args:
            url: The URL that was accessed
            status_code: HTTP status code received
            
        Returns:
            Detected technology if any
        """
        if status_code not in (200, 301, 302, 403):
            return None

        for path, (name, category) in URL_SIGNATURES.items():
            if path.lower() in url.lower():
                if name not in self.detected:
                    tech = TechnologyInfo(
                        name=name,
                        category=category,
                        confidence="high",
                        evidence=f"URL: {url}"
                    )
                    self.detected[name] = tech
                    return tech
        
        return None

    def _extract_version(self, text: str) -> Optional[str]:
        """Extract version number from text."""
        version_pattern = r'[\d]+\.[\d]+(?:\.[\d]+)?'
        match = re.search(version_pattern, text)
        return match.group(0) if match else None

    def _extract_library_version(self, html: str, library: str) -> Optional[str]:
        """Extract version of a JavaScript library from HTML."""
        patterns = {
            "jQuery": r'jquery[.-]?(\d+\.\d+(?:\.\d+)?)',
            "Bootstrap": r'bootstrap[.-]?(\d+\.\d+(?:\.\d+)?)',
            "Vue.js": r'vue[.-]?(\d+\.\d+(?:\.\d+)?)',
            "React": r'react[.-]?(\d+\.\d+(?:\.\d+)?)',
            "Angular": r'angular[.-]?(\d+\.\d+(?:\.\d+)?)',
        }
        
        if library in patterns:
            match = re.search(patterns[library], html, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None

    def get_summary(self) -> Dict[str, List[Dict]]:
        """
        Get a summary of all detected technologies grouped by category.
        
        Returns:
            Dictionary with categories as keys and lists of technologies
        """
        summary = {}
        
        for tech in self.detected.values():
            if tech.category not in summary:
                summary[tech.category] = []
            summary[tech.category].append(tech.to_dict())
        
        return summary

    def get_all_detected(self) -> List[Dict]:
        """Get all detected technologies as a list."""
        return [tech.to_dict() for tech in self.detected.values()]

    def clear(self):
        """Clear all detected technologies."""
        self.detected.clear()
