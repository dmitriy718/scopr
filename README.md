# Web Folder & Endpoint Discovery Tool

A production-ready, security-focused web application for discovering accessible folders, endpoints, and technologies on web servers. Built to run seamlessly on Replit.

## Features

### Core Functionality
- **Domain Scanning**: Accept any domain and discover all accessible folders and endpoints
- **HTTP Response Analysis**: Detect and categorize responses by status codes (200, 301, 403, 404, 500, etc.)
- **Soft 404 Detection**: Identify pages that return 200 but are actually "not found" pages
- **Redirect Handling**: Follow and track redirect chains

### Advanced Features (10+ Implemented)

1. **Asynchronous Scanning** - Uses asyncio + aiohttp for high-performance concurrent requests
2. **Custom Wordlist Support** - Upload your own wordlists or select from built-in categories
3. **Recursive Discovery** - Automatically discover subfolders with configurable depth
4. **Subdomain Enumeration** - DNS-based subdomain discovery using common subdomain lists
5. **Technology Fingerprinting** - Identify CMS, frameworks, servers, and JavaScript libraries
6. **Status Code Categorization** - Color-coded output for easy visual analysis
7. **Multiple Export Formats** - Download results as JSON, CSV, or TXT
8. **robots.txt Analysis** - Auto-parse robots.txt for additional paths
9. **sitemap.xml Parsing** - Extract URLs from sitemaps for comprehensive coverage
10. **Authentication Support** - Optional Basic Auth and Bearer Token authentication
11. **Parameter Discovery** - Built-in wordlist for common URL parameters
12. **Real-time Progress** - Live progress tracking during scans

## How to Run

### On Replit

1. **Click the Run button** - The application will start automatically on port 5000
2. **Open the Webview** - Access the web interface through Replit's webview panel
3. **Enter a domain** - Type the target domain (e.g., `example.com`)
4. **Configure options** - Select wordlist type and enable/disable features
5. **Start scanning** - Click "Start Scan" and watch the results appear

### Configuration

The tool can be configured via environment variables. Copy `.env.example` to `.env`:

```bash
# Scan Settings
SCAN_TIMEOUT=10          # Request timeout in seconds
MAX_CONCURRENT=20        # Maximum concurrent requests
MAX_URLS=1000           # Maximum URLs to scan
RECURSIVE_DEPTH=2       # Depth for recursive scanning

# HTTP Settings
USER_AGENT=Mozilla/5.0...  # Custom user agent string
VERIFY_SSL=false           # SSL certificate verification
```

### Required Secrets

- `SESSION_SECRET` - Flask session secret (auto-generated if not set)

## Usage Examples

### Basic Scan
1. Enter domain: `example.com`
2. Select wordlist: "All Paths (Comprehensive)"
3. Leave default options checked
4. Click "Start Scan"

### API Endpoint Discovery
1. Enter domain: `api.example.com`
2. Select wordlist: "API Endpoints"
3. Enable "Recursive Discovery"
4. Click "Start Scan"

### Security Audit
1. Enter domain: `target.com`
2. Select wordlist: "Hidden/Sensitive Files"
3. Enable all parsing options
4. Enable "Enumerate Subdomains"
5. Click "Start Scan"

### With Authentication
1. Enter domain: `protected.example.com`
2. Expand "Authentication (Optional)"
3. Select "Bearer Token" or "Basic Auth"
4. Enter your credentials
5. Click "Start Scan"

## Output Formats

### JSON Export
```json
{
  "scan_date": "2024-01-15T10:30:00",
  "total_urls": 150,
  "results": [
    {
      "url": "https://example.com/admin/",
      "status_code": 200,
      "content_length": 5432,
      "response_time": 0.234
    }
  ],
  "summary": {
    "successful": 45,
    "redirects": 12,
    "client_errors": 93
  }
}
```

### CSV Export
```
url,status_code,content_length,redirect_url,is_soft_404,response_time,error
https://example.com/admin/,200,5432,,false,0.234,
https://example.com/api/,301,,https://example.com/api/v2/,false,0.156,
```

### TXT Export
```
[200] OK https://example.com/admin/
[301] REDIRECT https://example.com/api/
    -> Redirects to: https://example.com/api/v2/
[403] FORBIDDEN https://example.com/config/
[404] NOT_FOUND https://example.com/test/
```

## Project Structure

```
.
├── app.py                 # Main Flask application
├── src/
│   ├── __init__.py       # Package initialization
│   ├── scanner.py        # Async HTTP scanner core
│   ├── wordlists.py      # Wordlist management
│   ├── parsers.py        # robots.txt/sitemap parsers
│   ├── fingerprint.py    # Technology detection
│   ├── subdomain.py      # Subdomain enumeration
│   └── exporter.py       # Export functionality
├── templates/
│   └── index.html        # Web UI template
├── wordlists/            # Custom wordlist storage
├── .env.example          # Configuration template
└── README.md             # This file
```

## Built-in Wordlists

| Category | Count | Description |
|----------|-------|-------------|
| All | ~300 | Comprehensive list of all paths |
| Directories | ~150 | Common folder names |
| API | ~50 | REST API endpoints |
| Hidden | ~50 | Hidden/sensitive files |
| Files | ~50 | Common file names |
| Backup | ~20 | Backup file patterns |
| Subdomains | ~100 | Common subdomain prefixes |

## Technology Detection

The tool can identify:
- **Servers**: Nginx, Apache, IIS, LiteSpeed, Cloudflare
- **Frameworks**: WordPress, Drupal, Joomla, Laravel, Django, Rails
- **Frontend**: React, Vue.js, Angular, Next.js, Nuxt.js
- **Libraries**: jQuery, Bootstrap, Tailwind CSS
- **Services**: Google Analytics, Stripe, Cloudflare CDN
- **And more...**

## Replit-Specific Notes

- The tool is optimized for Replit's resource limits
- Maximum concurrent requests are capped to prevent rate limiting
- All file operations respect Replit's sandbox environment
- No external installation required - runs entirely on Replit

## Ethical Use

This tool is intended for:
- Security professionals testing their own systems
- Penetration testers with proper authorization
- Developers auditing their web applications

**Always obtain proper authorization before scanning any system you do not own.**

## License

MIT License - See LICENSE file for details.
