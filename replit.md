# Scopr - Web Recon Tool

## Overview
A production-ready web reconnaissance platform for security professionals and bug bounty hunters. Built with Flask and async Python for high-performance scanning. Features JS endpoint extraction, secrets scanning, security header analysis, and more.

## Project Structure
```
.
├── app.py                 # Main Flask application (entry point)
├── src/
│   ├── scanner.py        # Async HTTP scanner with aiohttp
│   ├── wordlists.py      # Built-in and custom wordlist management
│   ├── parsers.py        # robots.txt/sitemap.xml parsers
│   ├── fingerprint.py    # Technology detection module
│   ├── subdomain.py      # DNS-based subdomain enumeration
│   ├── exporter.py       # JSON/CSV/TXT export functionality
│   ├── parameters.py     # Parameter discovery module
│   ├── security.py       # Security header analysis module
│   ├── js_parser.py      # JavaScript endpoint extraction
│   ├── secrets_scanner.py # Exposed secrets/API key detection
│   ├── takeover.py       # Subdomain takeover detection
│   └── workflows.py      # Scan workflow management (5 presets)
├── templates/
│   └── index.html        # Bootstrap 5 web interface with glassmorphism design
├── wordlists/            # Custom wordlist storage directory
└── static/               # Static assets (if needed)
```

## Key Technologies
- **Backend**: Python 3.11, Flask, aiohttp, asyncio
- **Frontend**: Bootstrap 5, vanilla JavaScript, vis.js
- **DNS**: dnspython for subdomain enumeration
- **Parsing**: BeautifulSoup, lxml for HTML/XML parsing
- **Visualization**: vis.js for interactive asset maps

## Running the Application
- The app runs on port 5000 with Flask
- Access via the Replit webview
- All configuration via environment variables

## Configuration
Environment variables (set in Secrets or .env):
- `SCAN_TIMEOUT`: Request timeout (default: 10s)
- `MAX_CONCURRENT`: Concurrent connections (default: 20)
- `MAX_URLS`: Maximum URLs to scan (default: 300)
- `SESSION_SECRET`: Flask session secret

## Recent Changes (December 2025)
- Added Subdomain Takeover Detection (src/takeover.py) - 20+ vulnerable services
- Added JavaScript Endpoint Extraction (src/js_parser.py)
- Added Secrets Scanner with 25+ patterns (src/secrets_scanner.py)
- Added Security Header Analysis with grade scoring (A+ to F)
- Added Directory Listing Detection for exposed directories
- Added Scan Statistics Dashboard (requests/sec, duration, avg time)
- Added Result Sorting (by status, response time, size)
- Added Scan History with localStorage persistence
- Fixed scan config card centering (centered initially, side-by-side after scan)
- Modern UI with glassmorphism, gradients, and animations

## Features (21 Implemented)
1. Asynchronous Scanning - High-performance concurrent requests
2. Custom Wordlist Support - Upload or select built-in categories
3. Recursive Discovery - Configurable depth subfolder scanning
4. Subdomain Enumeration - DNS-based discovery
5. Technology Fingerprinting - CMS, frameworks, servers detection
6. Status Code Categorization - Color-coded visual analysis
7. Multiple Export Formats - JSON, CSV, TXT downloads
8. robots.txt Analysis - Auto-parse for additional paths
9. sitemap.xml Parsing - Extract URLs for coverage
10. Authentication Support - Basic Auth and Bearer Token
11. Parameter Discovery - Tests URLs with common query params
12. Security Header Analysis - Missing headers, grade scoring
13. Directory Listing Detection - Exposed directory identification
14. Scan Statistics - Performance metrics dashboard
15. Result Filtering & Sorting - By status, time, size
16. Scan History - Browser localStorage persistence
17. JavaScript Endpoint Extraction - Parse JS for hidden APIs
18. Secrets Scanner - Detect exposed API keys, tokens, credentials
19. Subdomain Takeover Detection - Dangling DNS to 20+ vulnerable services
20. Scan Chaining/Workflows - 5 preset workflows for automated multi-stage recon
21. Visual Asset Map - Interactive graph visualization of discovered assets using vis.js

## Remaining Tasks
- All 21 features completed!

## Architecture Decisions
- Async scanning for performance within Replit limits
- In-memory scan storage (no database needed)
- Built-in wordlists to avoid external dependencies
- Soft 404 detection using baseline comparison
- Security scoring based on header presence/exposure
- JS parsing extracts endpoints from fetch, axios, XMLHttpRequest, etc.
- Secrets scanner detects AWS, GitHub, Stripe, OpenAI keys and more
- Takeover detection checks CNAME records against known vulnerable services (AWS S3, Heroku, GitHub Pages, Azure, Netlify, Vercel, etc.)
- Workflow system with 5 presets (Quick Recon, Full Recon, API Recon, Subdomain Takeover Hunt, Secrets Hunt)
