"""
Web Folder & Endpoint Discovery Tool - Main Flask Application
A production-ready security tool for discovering accessible folders and endpoints.
"""

import os
import asyncio
import json
import uuid
import logging
from datetime import datetime
from typing import Dict, List, Optional
from flask import Flask, render_template, request, jsonify, Response, send_file
from dotenv import load_dotenv
import io

from src.scanner import AsyncScanner, ScanConfig, ScanResult, normalize_url
from src.wordlists import WordlistManager, get_default_wordlist
from src.parsers import parse_all_sources, HTMLLinkParser
from src.fingerprint import TechnologyFingerprinter
from src.subdomain import SubdomainEnumerator
from src.exporter import ResultExporter, export_results
from src.parameters import ParameterScanner, discover_parameters
from src.security import SecurityAnalyzer
from src.js_parser import JSEndpointExtractor
from src.secrets_scanner import SecretsScanner
from src.takeover import TakeoverDetector
from src.workflows import workflow_manager, StageType

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", os.urandom(24).hex())

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

active_scans: Dict[str, dict] = {}


def get_config() -> dict:
    """Load configuration from environment variables."""
    return {
        "timeout": int(os.environ.get("SCAN_TIMEOUT", "10")),
        "max_concurrent": int(os.environ.get("MAX_CONCURRENT", "20")),
        "user_agent": os.environ.get(
            "USER_AGENT",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ),
        "verify_ssl": os.environ.get("VERIFY_SSL", "false").lower() == "true",
        "max_urls": int(os.environ.get("MAX_URLS", "300")),
        "recursive_depth": int(os.environ.get("RECURSIVE_DEPTH", "2"))
    }


@app.route('/')
def index():
    """Render the main scanning interface."""
    config = get_config()
    return render_template('index.html', config=config)


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """
    Start a new scan job.
    
    Expected JSON body:
    {
        "domain": "example.com",
        "options": {
            "scan_subdomains": false,
            "parse_robots": true,
            "parse_sitemap": true,
            "recursive": true,
            "recursive_depth": 2,
            "wordlist": "all",
            "custom_wordlist": [],
            "auth_type": null,
            "auth_value": null
        }
    }
    """
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        if not domain:
            return jsonify({"error": "Domain is required"}), 400

        options = data.get('options', {})
        scan_id = str(uuid.uuid4())

        active_scans[scan_id] = {
            "id": scan_id,
            "domain": domain,
            "status": "pending",
            "progress": 0,
            "total": 0,
            "results": [],
            "technologies": [],
            "subdomains": [],
            "parameters": [],
            "started_at": datetime.now().isoformat(),
            "completed_at": None,
            "error": None,
            "options": options
        }

        return jsonify({
            "scan_id": scan_id,
            "status": "pending",
            "message": "Scan initiated"
        })

    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/scan/<scan_id>/execute', methods=['POST'])
def execute_scan(scan_id: str):
    """Execute the scan synchronously and return results."""
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404

    scan_data = active_scans[scan_id]
    
    try:
        scan_data["status"] = "running"
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            results = loop.run_until_complete(
                run_scan(scan_data)
            )
            scan_data["results"] = results
            scan_data["status"] = "completed"
            scan_data["completed_at"] = datetime.now().isoformat()
        finally:
            loop.close()

        return jsonify({
            "scan_id": scan_id,
            "status": "completed",
            "total_found": len([r for r in results if 200 <= r.get("status_code", 0) < 300]),
            "total_scanned": len(results)
        })

    except Exception as e:
        logger.error(f"Scan error: {e}")
        scan_data["status"] = "error"
        scan_data["error"] = str(e)
        return jsonify({"error": str(e)}), 500


async def run_scan(scan_data: dict) -> List[dict]:
    """
    Execute the full scanning workflow.
    
    Args:
        scan_data: Dictionary with scan configuration
        
    Returns:
        List of result dictionaries
    """
    domain = scan_data["domain"]
    options = scan_data.get("options", {})
    config = get_config()

    base_url = normalize_url(domain)
    scan_data["base_url"] = base_url

    scan_config = ScanConfig(
        timeout=config["timeout"],
        max_concurrent=config["max_concurrent"],
        user_agent=config["user_agent"],
        verify_ssl=config["verify_ssl"],
        auth_type=options.get("auth_type"),
        auth_value=options.get("auth_value")
    )

    wordlist_manager = WordlistManager()
    fingerprinter = TechnologyFingerprinter()
    security_analyzer = SecurityAnalyzer()
    js_extractor = JSEndpointExtractor(base_url)
    secrets_scanner = SecretsScanner()

    wordlist_type = options.get("wordlist", "all")
    paths = wordlist_manager.get_builtin_wordlist(wordlist_type)

    custom_words = options.get("custom_wordlist", [])
    if custom_words:
        paths = wordlist_manager.merge_wordlists(paths, custom_words)

    async with AsyncScanner(scan_config) as scanner:
        await scanner.establish_baseline(base_url)

        if options.get("parse_robots", True) or options.get("parse_sitemap", True):
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    parsed_data = await parse_all_sources(base_url, session)
                    
                    for path in parsed_data.get("robots_paths", []):
                        if path.startswith(base_url):
                            paths.append(path.replace(base_url, "").lstrip("/"))
                    
                    for url in parsed_data.get("sitemap_urls", [])[:100]:
                        if url.startswith(base_url):
                            paths.append(url.replace(base_url, "").lstrip("/"))
            except Exception as e:
                logger.warning(f"Error parsing robots/sitemap: {e}")

        if options.get("recursive", False):
            depth = options.get("recursive_depth", 2)
            paths = wordlist_manager.get_recursive_paths(paths, depth)

        paths = list(set(paths))[:config["max_urls"]]
        urls = wordlist_manager.generate_urls(base_url, paths)

        scan_data["total"] = len(urls)

        def progress_callback(completed, total, result):
            scan_data["progress"] = completed
            if result and result.status_code == 200:
                fingerprinter.analyze_headers(result.headers)
                fingerprinter.analyze_url(result.url, result.status_code)

        results = await scanner.scan_urls(urls, progress_callback)

        for result in results:
            if result.headers:
                security_analyzer.analyze_headers(result.headers, result.url)
            if result.is_directory_listing and result.url not in security_analyzer.directory_listings:
                security_analyzer.directory_listings.append(result.url)
            if result.content:
                secrets_scanner.scan_content(result.content, result.url)

        scan_data["technologies"] = fingerprinter.get_all_detected()
        scan_data["security"] = security_analyzer.get_analysis().to_dict()
        scan_data["secrets"] = secrets_scanner.get_findings()
        scan_data["secrets_stats"] = secrets_scanner.get_stats()

        js_urls = [r.url for r in results if r.url.endswith('.js') and r.status_code == 200]
        html_results = [r for r in results if r.status_code == 200 and r.content and not r.url.endswith('.js')]
        
        for html_result in html_results:
            if html_result.content:
                import re
                js_refs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', html_result.content, re.IGNORECASE)
                for js_ref in js_refs:
                    from urllib.parse import urljoin
                    full_js_url = urljoin(html_result.url, js_ref)
                    if full_js_url not in js_urls:
                        js_urls.append(full_js_url)

        if js_urls:
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    for js_url in js_urls[:20]:
                        try:
                            async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                                if resp.status == 200:
                                    js_content = await resp.text()
                                    js_extractor.extract_from_js(js_content, js_url)
                                    secrets_scanner.scan_content(js_content, js_url)
                        except:
                            pass
            except Exception as e:
                logger.warning(f"JS parsing error: {e}")

        scan_data["js_endpoints"] = js_extractor.get_all_endpoints()
        scan_data["secrets"] = secrets_scanner.get_findings()
        scan_data["secrets_stats"] = secrets_scanner.get_stats()

    if options.get("scan_subdomains", False):
        try:
            from urllib.parse import urlparse
            parsed = urlparse(base_url)
            domain_only = parsed.netloc
            
            enumerator = SubdomainEnumerator(domain_only, max_concurrent=10)
            await enumerator.enumerate()
            scan_data["subdomains"] = enumerator.get_results_as_dict()
            
            if options.get("check_takeover", True) and scan_data["subdomains"]:
                takeover_detector = TakeoverDetector()
                await takeover_detector.scan_subdomains(scan_data["subdomains"])
                scan_data["takeover"] = takeover_detector.get_vulnerable_as_dict()
                scan_data["takeover_stats"] = takeover_detector.get_stats()
        except Exception as e:
            logger.warning(f"Subdomain enumeration error: {e}")

    if options.get("scan_parameters", False):
        try:
            import aiohttp
            successful_urls = [r.url for r in results if r.status_code == 200 and not r.is_soft_404]
            if successful_urls:
                async with aiohttp.ClientSession() as session:
                    param_results = await discover_parameters(session, successful_urls, max_urls=10)
                    scan_data["parameters"] = param_results
        except Exception as e:
            logger.warning(f"Parameter discovery error: {e}")

    return [r.to_dict() for r in results]


@app.route('/api/scan/<scan_id>/status')
def get_scan_status(scan_id: str):
    """Get the current status of a scan."""
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404

    scan_data = active_scans[scan_id]
    
    return jsonify({
        "scan_id": scan_id,
        "status": scan_data["status"],
        "progress": scan_data["progress"],
        "total": scan_data["total"],
        "started_at": scan_data["started_at"],
        "completed_at": scan_data["completed_at"],
        "error": scan_data["error"]
    })


@app.route('/api/scan/<scan_id>/results')
def get_scan_results(scan_id: str):
    """Get the full results of a completed scan."""
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404

    scan_data = active_scans[scan_id]
    
    filter_status = request.args.get('status', None)
    results = scan_data["results"]
    
    if filter_status:
        if filter_status == "success":
            results = [r for r in results if 200 <= r.get("status_code", 0) < 300 
                      and not r.get("is_soft_404", False)]
        elif filter_status == "redirect":
            results = [r for r in results if 300 <= r.get("status_code", 0) < 400]
        elif filter_status == "forbidden":
            results = [r for r in results if r.get("status_code") == 403]
        elif filter_status == "error":
            results = [r for r in results if r.get("error")]

    return jsonify({
        "scan_id": scan_id,
        "domain": scan_data["domain"],
        "status": scan_data["status"],
        "results": results,
        "technologies": scan_data.get("technologies", []),
        "subdomains": scan_data.get("subdomains", []),
        "parameters": scan_data.get("parameters", []),
        "security": scan_data.get("security", {}),
        "js_endpoints": scan_data.get("js_endpoints", []),
        "secrets": scan_data.get("secrets", []),
        "secrets_stats": scan_data.get("secrets_stats", {}),
        "takeover": scan_data.get("takeover", []),
        "takeover_stats": scan_data.get("takeover_stats", {}),
        "total": len(results)
    })


@app.route('/api/scan/<scan_id>/export/<format>')
def export_scan_results(scan_id: str, format: str):
    """
    Export scan results in specified format.
    
    Formats: json, csv, txt
    """
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404

    if format not in ('json', 'csv', 'txt'):
        return jsonify({"error": "Invalid format"}), 400

    scan_data = active_scans[scan_id]
    
    results = []
    for r in scan_data["results"]:
        results.append(ScanResult(
            url=r["url"],
            status_code=r["status_code"],
            content_length=r.get("content_length", 0),
            redirect_url=r.get("redirect_url"),
            is_soft_404=r.get("is_soft_404", False),
            response_time=r.get("response_time", 0),
            error=r.get("error")
        ))

    metadata = {
        "domain": scan_data["domain"],
        "scan_id": scan_id,
        "started_at": scan_data["started_at"],
        "completed_at": scan_data["completed_at"]
    }

    exporter = ResultExporter(results, metadata)

    if format == "json":
        content = exporter.to_json()
        mimetype = "application/json"
        filename = f"scan_{scan_id[:8]}.json"
    elif format == "csv":
        content = exporter.to_csv()
        mimetype = "text/csv"
        filename = f"scan_{scan_id[:8]}.csv"
    else:
        content = exporter.to_txt(format_type="detailed")
        mimetype = "text/plain"
        filename = f"scan_{scan_id[:8]}.txt"

    return Response(
        content,
        mimetype=mimetype,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route('/api/wordlists')
def list_wordlists():
    """List available wordlist categories and custom wordlists."""
    manager = WordlistManager()
    
    categories = {
        "all": len(manager.get_builtin_wordlist("all")),
        "directories": len(manager.get_builtin_wordlist("directories")),
        "api": len(manager.get_builtin_wordlist("api")),
        "hidden": len(manager.get_builtin_wordlist("hidden")),
        "files": len(manager.get_builtin_wordlist("files")),
        "backup": len(manager.get_builtin_wordlist("backup"))
    }
    
    custom = manager.list_custom_wordlists()
    
    return jsonify({
        "builtin": categories,
        "custom": custom
    })


@app.route('/api/wordlists/upload', methods=['POST'])
def upload_wordlist():
    """Upload a custom wordlist file."""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    manager = WordlistManager()
    
    content = file.read().decode('utf-8', errors='ignore')
    words = [line.strip() for line in content.split('\n') if line.strip()]
    
    filename = file.filename
    if not filename.endswith('.txt'):
        filename += '.txt'
    
    filepath = manager.save_custom_wordlist(filename, words)
    
    return jsonify({
        "filename": filename,
        "words_count": len(words),
        "path": filepath
    })


@app.route('/api/config')
def get_app_config():
    """Get current application configuration."""
    return jsonify(get_config())


@app.route('/api/workflows')
def list_workflows():
    """List all available workflows (presets and custom)."""
    return jsonify({
        "presets": workflow_manager.get_presets(),
        "custom": workflow_manager.get_custom_workflows(),
        "stage_types": [
            {"value": st.value, "info": workflow_manager.get_stage_options(st)}
            for st in StageType
        ]
    })


@app.route('/api/workflows/<workflow_id>')
def get_workflow(workflow_id: str):
    """Get a specific workflow by ID."""
    workflow = workflow_manager.get_workflow(workflow_id)
    if not workflow:
        return jsonify({"error": "Workflow not found"}), 404
    return jsonify(workflow.to_dict())


@app.route('/api/workflows', methods=['POST'])
def create_workflow():
    """Create a new custom workflow."""
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        stages = data.get('stages', [])
        
        if not name:
            return jsonify({"error": "Workflow name is required"}), 400
        if not stages:
            return jsonify({"error": "At least one stage is required"}), 400
        
        workflow = workflow_manager.create_workflow(name, description, stages)
        return jsonify(workflow.to_dict())
    except Exception as e:
        logger.error(f"Error creating workflow: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/workflows/<workflow_id>', methods=['DELETE'])
def delete_workflow(workflow_id: str):
    """Delete a custom workflow."""
    if workflow_manager.delete_workflow(workflow_id):
        return jsonify({"success": True})
    return jsonify({"error": "Cannot delete preset or non-existent workflow"}), 400


@app.route('/api/workflows/<workflow_id>/execute', methods=['POST'])
def execute_workflow(workflow_id: str):
    """Execute a workflow on a domain."""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        if not domain:
            return jsonify({"error": "Domain is required"}), 400
        
        workflow = workflow_manager.get_workflow(workflow_id)
        if not workflow:
            return jsonify({"error": "Workflow not found"}), 404
        
        execution = workflow_manager.create_execution(workflow_id, domain)
        if not execution:
            return jsonify({"error": "Failed to create execution"}), 500
        
        enabled_stages = [s for s in workflow.stages if s.enabled]
        options = {
            "scan_subdomains": any(s.stage_type == StageType.SUBDOMAIN_ENUM for s in enabled_stages),
            "check_takeover": any(s.stage_type == StageType.TAKEOVER_CHECK for s in enabled_stages),
            "parse_robots": True,
            "parse_sitemap": True,
            "scan_parameters": any(s.stage_type == StageType.PARAMETER_DISCOVERY for s in enabled_stages),
        }
        
        for stage in enabled_stages:
            if stage.stage_type == StageType.ENDPOINT_SCAN and stage.config:
                options["wordlist"] = stage.config.get("wordlist", "all")
                options["recursive"] = stage.config.get("recursive", False)
                options["recursive_depth"] = stage.config.get("recursive_depth", 2)
        
        scan_id = str(uuid.uuid4())
        active_scans[scan_id] = {
            "id": scan_id,
            "domain": domain,
            "status": "pending",
            "progress": 0,
            "total": 0,
            "results": [],
            "technologies": [],
            "subdomains": [],
            "parameters": [],
            "started_at": datetime.now().isoformat(),
            "completed_at": None,
            "error": None,
            "options": options,
            "workflow_id": workflow_id,
            "workflow_name": workflow.name,
            "execution_id": execution.id
        }
        
        return jsonify({
            "scan_id": scan_id,
            "execution_id": execution.id,
            "workflow": workflow.to_dict(),
            "status": "pending",
            "message": f"Workflow '{workflow.name}' initiated"
        })
    except Exception as e:
        logger.error(f"Error executing workflow: {e}")
        return jsonify({"error": str(e)}), 500


@app.after_request
def add_cache_headers(response):
    """Add cache control headers to prevent caching issues."""
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
