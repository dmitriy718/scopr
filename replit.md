# Web Endpoint Discovery Tool

## Overview
A production-ready web folder and endpoint discovery tool for security professionals. Built with Flask and async Python for high-performance scanning.

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
│   └── security.py       # Security header analysis module
├── templates/
│   └── index.html        # Bootstrap 5 web interface with glassmorphism design
├── wordlists/            # Custom wordlist storage directory
└── static/               # Static assets (if needed)
```

## Key Technologies
- **Backend**: Python 3.11, Flask, aiohttp, asyncio
- **Frontend**: Bootstrap 5, vanilla JavaScript
- **DNS**: dnspython for subdomain enumeration
- **Parsing**: BeautifulSoup, lxml for HTML/XML parsing

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
- Added Security Header Analysis with grade scoring (A+ to F)
- Added Directory Listing Detection for exposed directories
- Added Scan Statistics Dashboard (requests/sec, duration, avg time)
- Added Result Sorting (by status, response time, size)
- Added Scan History with localStorage persistence
- Added Response Time display for each result
- Fixed concurrent scanning for faster performance
- Modern UI with glassmorphism, gradients, and animations

## Features (15+ Implemented)
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

## Architecture Decisions
- Async scanning for performance within Replit limits
- In-memory scan storage (no database needed)
- Built-in wordlists to avoid external dependencies
- Soft 404 detection using baseline comparison
- Security scoring based on header presence/exposure
