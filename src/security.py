"""
Security Header Analysis Module
Analyzes HTTP response headers for security best practices and vulnerabilities.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import re


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections",
        "severity": "high",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'"
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and data injection attacks",
        "severity": "high",
        "recommendation": "Implement a Content-Security-Policy header"
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "severity": "medium",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "severity": "medium",
        "recommendation": "Add 'X-Content-Type-Options: nosniff'"
    },
    "X-XSS-Protection": {
        "description": "Enables browser XSS filtering",
        "severity": "low",
        "recommendation": "Add 'X-XSS-Protection: 1; mode=block'"
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leakage",
        "severity": "low",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'"
    },
    "Permissions-Policy": {
        "description": "Controls browser feature permissions",
        "severity": "low",
        "recommendation": "Add Permissions-Policy to restrict features"
    }
}

DANGEROUS_HEADERS = {
    "Server": {
        "description": "Exposes server software version",
        "severity": "low",
        "recommendation": "Remove or obfuscate the Server header"
    },
    "X-Powered-By": {
        "description": "Exposes backend technology",
        "severity": "low",
        "recommendation": "Remove the X-Powered-By header"
    },
    "X-AspNet-Version": {
        "description": "Exposes ASP.NET version",
        "severity": "medium",
        "recommendation": "Remove the X-AspNet-Version header"
    },
    "X-AspNetMvc-Version": {
        "description": "Exposes ASP.NET MVC version",
        "severity": "medium",
        "recommendation": "Remove the X-AspNetMvc-Version header"
    }
}

DIRECTORY_LISTING_PATTERNS = [
    r"Index of /",
    r"Directory listing for",
    r"<title>Index of",
    r"Parent Directory</a>",
    r"\[To Parent Directory\]",
    r"<h1>Directory listing",
    r"mod_autoindex",
    r"<pre><a href=\"\?",
    r"<address>Apache/",
    r"lighttpd/",
    r"nginx/\d"
]


@dataclass
class SecurityIssue:
    """Represents a security issue found during analysis."""
    header: str
    issue_type: str
    severity: str
    description: str
    recommendation: str
    value: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "header": self.header,
            "issue_type": self.issue_type,
            "severity": self.severity,
            "description": self.description,
            "recommendation": self.recommendation,
            "value": self.value
        }


@dataclass
class SecurityAnalysis:
    """Complete security analysis result."""
    missing_headers: List[SecurityIssue] = field(default_factory=list)
    dangerous_headers: List[SecurityIssue] = field(default_factory=list)
    directory_listings: List[str] = field(default_factory=list)
    score: int = 100
    grade: str = "A+"

    def to_dict(self) -> dict:
        return {
            "missing_headers": [h.to_dict() for h in self.missing_headers],
            "dangerous_headers": [h.to_dict() for h in self.dangerous_headers],
            "directory_listings": self.directory_listings,
            "score": self.score,
            "grade": self.grade,
            "total_issues": len(self.missing_headers) + len(self.dangerous_headers) + len(self.directory_listings)
        }


class SecurityAnalyzer:
    """Analyzes security aspects of HTTP responses."""

    def __init__(self):
        self.issues: List[SecurityIssue] = []
        self.directory_listings: List[str] = []
        self.analyzed_urls: set = set()

    def analyze_headers(self, headers: Dict[str, str], url: str = "") -> List[SecurityIssue]:
        """
        Analyze HTTP headers for security issues.
        
        Args:
            headers: Dictionary of HTTP response headers
            url: URL being analyzed (for context)
            
        Returns:
            List of security issues found
        """
        issues = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header, info in SECURITY_HEADERS.items():
            if header.lower() not in headers_lower:
                issue = SecurityIssue(
                    header=header,
                    issue_type="missing",
                    severity=info["severity"],
                    description=info["description"],
                    recommendation=info["recommendation"]
                )
                issues.append(issue)

        for header, info in DANGEROUS_HEADERS.items():
            if header.lower() in headers_lower:
                issue = SecurityIssue(
                    header=header,
                    issue_type="exposed",
                    severity=info["severity"],
                    description=info["description"],
                    recommendation=info["recommendation"],
                    value=headers_lower[header.lower()]
                )
                issues.append(issue)

        for issue in issues:
            if issue.header not in [i.header for i in self.issues]:
                self.issues.append(issue)

        return issues

    def check_directory_listing(self, content: str, url: str) -> bool:
        """
        Check if content appears to be a directory listing.
        
        Args:
            content: HTML content to analyze
            url: URL of the page
            
        Returns:
            True if directory listing detected
        """
        if url in self.analyzed_urls:
            return False
        self.analyzed_urls.add(url)

        for pattern in DIRECTORY_LISTING_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                if url not in self.directory_listings:
                    self.directory_listings.append(url)
                return True
        return False

    def calculate_score(self) -> Tuple[int, str]:
        """
        Calculate security score based on issues found.
        
        Returns:
            Tuple of (score, grade)
        """
        score = 100
        
        for issue in self.issues:
            if issue.issue_type == "missing":
                if issue.severity == "high":
                    score -= 15
                elif issue.severity == "medium":
                    score -= 10
                else:
                    score -= 5
            elif issue.issue_type == "exposed":
                if issue.severity == "high":
                    score -= 10
                elif issue.severity == "medium":
                    score -= 7
                else:
                    score -= 3

        score -= len(self.directory_listings) * 20

        score = max(0, min(100, score))

        if score >= 90:
            grade = "A+"
        elif score >= 80:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 50:
            grade = "D"
        else:
            grade = "F"

        return score, grade

    def get_analysis(self) -> SecurityAnalysis:
        """
        Get complete security analysis results.
        
        Returns:
            SecurityAnalysis object with all findings
        """
        score, grade = self.calculate_score()
        
        missing = [i for i in self.issues if i.issue_type == "missing"]
        dangerous = [i for i in self.issues if i.issue_type == "exposed"]

        return SecurityAnalysis(
            missing_headers=missing,
            dangerous_headers=dangerous,
            directory_listings=self.directory_listings,
            score=score,
            grade=grade
        )

    def reset(self):
        """Reset the analyzer for a new scan."""
        self.issues = []
        self.directory_listings = []
        self.analyzed_urls = set()


def analyze_security_headers(headers: Dict[str, str]) -> Dict[str, any]:
    """
    Convenience function to analyze headers and return results dict.
    
    Args:
        headers: HTTP response headers
        
    Returns:
        Dictionary with security analysis
    """
    analyzer = SecurityAnalyzer()
    analyzer.analyze_headers(headers)
    analysis = analyzer.get_analysis()
    return analysis.to_dict()
