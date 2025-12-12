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
│   └── exporter.py       # JSON/CSV/TXT export functionality
├── templates/
│   └── index.html        # Bootstrap 5 web interface
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
- `MAX_URLS`: Maximum URLs to scan (default: 1000)
- `SESSION_SECRET`: Flask session secret

## Recent Changes
- Initial implementation with all 10+ advanced features
- Flask web UI with real-time progress
- Export to JSON, CSV, TXT formats
- Technology fingerprinting
- Subdomain enumeration

## Architecture Decisions
- Async scanning for performance within Replit limits
- In-memory scan storage (no database needed)
- Built-in wordlists to avoid external dependencies
- Soft 404 detection using baseline comparison
