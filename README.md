# Scopr - Web Recon Tool

The ultimate reconnaissance platform for security researchers and bug bounty hunters. Discover hidden endpoints, exposed secrets, vulnerable subdomains, and security misconfigurations - all from your browser.

## Features (21 Implemented)

### Core Scanning
- **Endpoint Discovery** - Async scanning with 20 concurrent requests
- **Custom Wordlists** - 6 built-in categories or upload your own
- **Recursive Discovery** - Configurable depth subfolder scanning
- **Soft 404 Detection** - Identify false positives automatically

### Subdomain & Takeover
- **Subdomain Enumeration** - DNS-based discovery using common prefixes
- **Subdomain Takeover Detection** - Checks 20+ vulnerable services (S3, Heroku, Azure, Netlify, etc.)

### JavaScript & Secrets
- **JS Endpoint Extraction** - Parse JS files for hidden API routes, fetch calls, axios requests
- **Secrets Scanner** - Detect 25+ types of exposed credentials (AWS, GitHub, Stripe, OpenAI, etc.)

### Security Analysis
- **Security Header Analysis** - Grade targets A+ to F, identify missing protections
- **Directory Listing Detection** - Find exposed directory indexes
- **Technology Fingerprinting** - Detect CMS, frameworks, servers, libraries

### Automation & Visualization
- **Scan Workflows** - 5 pre-built workflows (Quick Recon, Full Recon, API Recon, Subdomain Takeover Hunt, Secrets Hunt)
- **Visual Asset Map** - Interactive graph visualization of discovered assets
- **Export Formats** - JSON, CSV, TXT downloads

### Additional Features
- **robots.txt Analysis** - Auto-parse for additional paths
- **sitemap.xml Parsing** - Extract URLs for comprehensive coverage
- **Authentication Support** - Basic Auth and Bearer Token
- **Parameter Discovery** - Test URLs with common query parameters
- **Real-time Progress** - Live scanning statistics
- **Scan History** - Browser localStorage persistence
- **Result Filtering & Sorting** - By status, response time, size

## Quick Start

1. **Enter a domain** - Type the target (e.g., `example.com`)
2. **Select a workflow** - Choose Quick Recon, Full Recon, or another preset
3. **Start scanning** - Click "Start Scan" and watch results appear
4. **Analyze results** - View endpoints, secrets, technologies, and the asset map

## Workflows

| Workflow | Description |
|----------|-------------|
| **Quick Recon** | Fast scan with endpoint discovery and technology fingerprinting |
| **Full Recon** | Comprehensive scan including subdomains, JS parsing, and secrets |
| **API Recon** | Focused on API endpoints, parameters, and sensitive data |
| **Subdomain Takeover Hunt** | Find dangling DNS and takeover vulnerabilities |
| **Secrets Hunt** | Deep scan for exposed API keys and credentials |

## Configuration

Environment variables (optional):
```bash
SCAN_TIMEOUT=10          # Request timeout in seconds
MAX_CONCURRENT=20        # Maximum concurrent requests
MAX_URLS=300            # Maximum URLs to scan
SESSION_SECRET=...       # Flask session secret
```

## Built-in Wordlists

| Category | Description |
|----------|-------------|
| All | Comprehensive list of all paths |
| Directories | Common folder names |
| API | REST API endpoints |
| Hidden | Hidden/sensitive files |
| Files | Common file names |
| Backup | Backup file patterns |

## Technology Stack

- **Backend**: Python 3.11, Flask, aiohttp, asyncio
- **Frontend**: Bootstrap 5, vanilla JavaScript
- **Visualization**: vis.js for asset mapping
- **DNS**: dnspython for subdomain enumeration
- **Parsing**: BeautifulSoup, lxml

## Ethical Use

Scopr is intended for:
- Security professionals testing their own systems
- Bug bounty hunters with authorized targets
- Penetration testers with proper authorization
- Developers auditing their web applications

**Always obtain proper authorization before scanning any system you do not own.**

## License

MIT License
