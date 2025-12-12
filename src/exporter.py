"""
Export Module
Handles exporting scan results to various formats (JSON, CSV, TXT).
"""

import json
import csv
import io
from typing import List, Dict, Any
from datetime import datetime
from src.scanner import ScanResult


class ResultExporter:
    """Exports scan results to different file formats."""

    def __init__(self, results: List[ScanResult], metadata: Dict[str, Any] = None):
        """
        Initialize the exporter with scan results.
        
        Args:
            results: List of ScanResult objects from the scan
            metadata: Optional metadata about the scan (domain, options, etc.)
        """
        self.results = results
        self.metadata = metadata or {}

    def to_json(self, include_metadata: bool = True, pretty: bool = True) -> str:
        """
        Export results to JSON format.
        
        Args:
            include_metadata: Whether to include scan metadata
            pretty: Whether to format with indentation
            
        Returns:
            JSON string of results
        """
        data = {
            "scan_date": datetime.now().isoformat(),
            "total_urls": len(self.results),
            "results": [r.to_dict() for r in self.results]
        }
        
        if include_metadata:
            data["metadata"] = self.metadata
            
        success_count = sum(1 for r in self.results 
                          if 200 <= r.status_code < 300 and not r.is_soft_404)
        data["summary"] = {
            "total_scanned": len(self.results),
            "successful": success_count,
            "redirects": sum(1 for r in self.results if 300 <= r.status_code < 400),
            "client_errors": sum(1 for r in self.results if 400 <= r.status_code < 500),
            "server_errors": sum(1 for r in self.results if r.status_code >= 500),
            "errors": sum(1 for r in self.results if r.error)
        }

        indent = 2 if pretty else None
        return json.dumps(data, indent=indent, default=str)

    def to_csv(self, include_headers: bool = True) -> str:
        """
        Export results to CSV format.
        
        Args:
            include_headers: Whether to include column headers
            
        Returns:
            CSV string of results
        """
        output = io.StringIO()
        
        fieldnames = [
            'url', 'status_code', 'content_length', 'redirect_url',
            'is_soft_404', 'response_time', 'error'
        ]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        
        if include_headers:
            writer.writeheader()
        
        for result in self.results:
            writer.writerow(result.to_dict())
        
        return output.getvalue()

    def to_txt(self, format_type: str = "simple") -> str:
        """
        Export results to plain text format.
        
        Args:
            format_type: 'simple' for URLs only, 'detailed' for full info
            
        Returns:
            Plain text string of results
        """
        lines = []
        
        if format_type == "simple":
            for result in self.results:
                if 200 <= result.status_code < 300 and not result.is_soft_404:
                    lines.append(result.url)
        
        elif format_type == "detailed":
            lines.append(f"Scan Date: {datetime.now().isoformat()}")
            lines.append(f"Total URLs Scanned: {len(self.results)}")
            lines.append("=" * 60)
            lines.append("")
            
            for result in self.results:
                status_indicator = self._get_status_indicator(result)
                lines.append(f"[{result.status_code}] {status_indicator} {result.url}")
                
                if result.redirect_url:
                    lines.append(f"    -> Redirects to: {result.redirect_url}")
                if result.error:
                    lines.append(f"    ! Error: {result.error}")
                if result.is_soft_404:
                    lines.append(f"    * Soft 404 detected")
        
        elif format_type == "urls_with_status":
            for result in self.results:
                lines.append(f"{result.status_code}\t{result.url}")
        
        return "\n".join(lines)

    def to_txt_filtered(self, status_codes: List[int] = None) -> str:
        """
        Export filtered URLs to plain text.
        
        Args:
            status_codes: List of status codes to include (default: 200-299)
            
        Returns:
            Plain text string of filtered URLs
        """
        if status_codes is None:
            status_codes = list(range(200, 300))
        
        lines = []
        for result in self.results:
            if result.status_code in status_codes and not result.is_soft_404:
                lines.append(result.url)
        
        return "\n".join(lines)

    def _get_status_indicator(self, result: ScanResult) -> str:
        """Get a text indicator for the status code."""
        if result.error:
            return "ERROR"
        elif result.is_soft_404:
            return "SOFT404"
        elif 200 <= result.status_code < 300:
            return "OK"
        elif 300 <= result.status_code < 400:
            return "REDIRECT"
        elif result.status_code == 403:
            return "FORBIDDEN"
        elif result.status_code == 404:
            return "NOT_FOUND"
        elif 400 <= result.status_code < 500:
            return "CLIENT_ERR"
        elif result.status_code >= 500:
            return "SERVER_ERR"
        return "UNKNOWN"

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the scan results.
        
        Returns:
            Dictionary with scan statistics
        """
        status_counts = {}
        for result in self.results:
            code = result.status_code
            status_counts[code] = status_counts.get(code, 0) + 1

        response_times = [r.response_time for r in self.results if r.response_time > 0]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0

        return {
            "total_urls": len(self.results),
            "successful_urls": sum(1 for r in self.results 
                                  if 200 <= r.status_code < 300 and not r.is_soft_404),
            "redirects": sum(1 for r in self.results if 300 <= r.status_code < 400),
            "forbidden": sum(1 for r in self.results if r.status_code == 403),
            "not_found": sum(1 for r in self.results if r.status_code == 404),
            "server_errors": sum(1 for r in self.results if r.status_code >= 500),
            "connection_errors": sum(1 for r in self.results if r.error),
            "soft_404s": sum(1 for r in self.results if r.is_soft_404),
            "status_code_distribution": status_counts,
            "average_response_time": round(avg_response_time, 3),
            "fastest_response": round(min(response_times), 3) if response_times else 0,
            "slowest_response": round(max(response_times), 3) if response_times else 0
        }


def export_results(
    results: List[ScanResult],
    format: str = "json",
    metadata: Dict[str, Any] = None,
    **kwargs
) -> str:
    """
    Convenience function to export results in a specified format.
    
    Args:
        results: List of ScanResult objects
        format: Output format ('json', 'csv', 'txt', 'txt_detailed')
        metadata: Optional scan metadata
        **kwargs: Additional arguments for specific formats
        
    Returns:
        Formatted string output
    """
    exporter = ResultExporter(results, metadata)
    
    if format == "json":
        return exporter.to_json(**kwargs)
    elif format == "csv":
        return exporter.to_csv(**kwargs)
    elif format == "txt":
        return exporter.to_txt(format_type="simple", **kwargs)
    elif format == "txt_detailed":
        return exporter.to_txt(format_type="detailed", **kwargs)
    elif format == "txt_status":
        return exporter.to_txt(format_type="urls_with_status", **kwargs)
    else:
        raise ValueError(f"Unknown format: {format}")
