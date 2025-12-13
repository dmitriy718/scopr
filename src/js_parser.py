import re
from dataclasses import dataclass, field
from typing import List, Set
from urllib.parse import urljoin, urlparse


@dataclass
class JSEndpoint:
    url: str
    source_file: str
    endpoint_type: str
    context: str = ""


class JSEndpointExtractor:
    ENDPOINT_PATTERNS = [
        (r'["\'](/api/[^"\'<>\s]+)["\']', 'api'),
        (r'["\'](/v\d+/[^"\'<>\s]+)["\']', 'versioned_api'),
        (r'["\'](/rest/[^"\'<>\s]+)["\']', 'rest'),
        (r'["\'](/graphql[^"\'<>\s]*)["\']', 'graphql'),
        (r'["\'](/ws[^"\'<>\s]*)["\']', 'websocket'),
        (r'["\'](/socket[^"\'<>\s]*)["\']', 'websocket'),
        (r'fetch\s*\(\s*["\']([^"\'<>\s]+)["\']', 'fetch'),
        (r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\'<>\s]+)["\']', 'axios'),
        (r'\$\.(?:ajax|get|post)\s*\(\s*["\']([^"\'<>\s]+)["\']', 'jquery'),
        (r'XMLHttpRequest.*?open\s*\(\s*["\'][^"\']+["\']\s*,\s*["\']([^"\'<>\s]+)["\']', 'xhr'),
        (r'url\s*[:=]\s*["\']([^"\'<>\s]+)["\']', 'url_assignment'),
        (r'endpoint\s*[:=]\s*["\']([^"\'<>\s]+)["\']', 'endpoint_assignment'),
        (r'path\s*[:=]\s*["\']([^"\'<>\s]+)["\']', 'path_assignment'),
        (r'href\s*[:=]\s*["\']([^"\'<>\s]+)["\']', 'href'),
        (r'src\s*[:=]\s*["\']([^"\'<>\s]+)["\']', 'src'),
        (r'action\s*[:=]\s*["\']([^"\'<>\s]+)["\']', 'form_action'),
        (r'["\']https?://[^"\'<>\s]+["\']', 'absolute_url'),
        (r'["\']wss?://[^"\'<>\s]+["\']', 'websocket_url'),
        (r'route\s*\(\s*["\']([^"\']+)["\']', 'route'),
        (r'router\s*\.\s*(?:get|post|put|delete|patch|use)\s*\(\s*["\']([^"\']+)["\']', 'router'),
        (r'app\s*\.\s*(?:get|post|put|delete|patch|use)\s*\(\s*["\']([^"\']+)["\']', 'express_route'),
    ]
    
    EXCLUDED_EXTENSIONS = {
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp',
        '.css', '.scss', '.less', '.sass',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.mp3', '.mp4', '.wav', '.avi', '.mov', '.webm',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx',
        '.zip', '.tar', '.gz', '.rar',
    }
    
    EXCLUDED_PATTERNS = [
        r'^data:',
        r'^javascript:',
        r'^mailto:',
        r'^tel:',
        r'^#',
        r'^\$\{',
        r'^{{',
        r'^\[',
        r'^undefined$',
        r'^null$',
        r'^true$',
        r'^false$',
    ]

    def __init__(self, base_url: str = ""):
        self.base_url = base_url
        self.endpoints: List[JSEndpoint] = []
        self.seen_urls: Set[str] = set()

    def extract_from_js(self, js_content: str, source_file: str = "unknown") -> List[JSEndpoint]:
        found_endpoints = []
        
        for pattern, endpoint_type in self.ENDPOINT_PATTERNS:
            try:
                matches = re.finditer(pattern, js_content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    url = match.group(1) if match.lastindex else match.group(0)
                    url = url.strip('"\'')
                    
                    if self._is_valid_endpoint(url):
                        normalized_url = self._normalize_url(url)
                        if normalized_url and normalized_url not in self.seen_urls:
                            self.seen_urls.add(normalized_url)
                            
                            start = max(0, match.start() - 50)
                            end = min(len(js_content), match.end() + 50)
                            context = js_content[start:end].replace('\n', ' ').strip()
                            
                            endpoint = JSEndpoint(
                                url=normalized_url,
                                source_file=source_file,
                                endpoint_type=endpoint_type,
                                context=context[:150] + "..." if len(context) > 150 else context
                            )
                            found_endpoints.append(endpoint)
                            self.endpoints.append(endpoint)
            except re.error:
                continue
        
        return found_endpoints

    def _is_valid_endpoint(self, url: str) -> bool:
        if not url or len(url) < 2:
            return False
            
        for pattern in self.EXCLUDED_PATTERNS:
            if re.match(pattern, url, re.IGNORECASE):
                return False
        
        parsed = urlparse(url)
        ext = parsed.path.lower()
        for excluded_ext in self.EXCLUDED_EXTENSIONS:
            if ext.endswith(excluded_ext):
                return False
        
        if url.startswith('/') or url.startswith('http'):
            return True
            
        if '/api/' in url or '/v1/' in url or '/v2/' in url:
            return True
            
        return False

    def _normalize_url(self, url: str) -> str:
        url = url.strip('"\'')
        
        url = re.sub(r'\$\{[^}]+\}', '{param}', url)
        url = re.sub(r'{{[^}]+}}', '{param}', url)
        
        url = re.sub(r'/:\w+', '/{param}', url)
        
        url = re.sub(r'\?.*$', '', url)
        
        url = url.rstrip('/')
        
        if self.base_url and not url.startswith('http'):
            url = urljoin(self.base_url, url)
        
        return url

    def get_all_endpoints(self) -> List[dict]:
        return [
            {
                'url': ep.url,
                'source': ep.source_file,
                'type': ep.endpoint_type,
                'context': ep.context
            }
            for ep in self.endpoints
        ]

    def get_unique_paths(self) -> List[str]:
        paths = set()
        for ep in self.endpoints:
            parsed = urlparse(ep.url)
            if parsed.path:
                paths.add(parsed.path)
        return sorted(list(paths))

    def clear(self):
        self.endpoints = []
        self.seen_urls = set()
