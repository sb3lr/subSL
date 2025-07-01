#!/usr/bin/env python3
import asyncio
import aiohttp
import aiodns
import json
import csv
import os
import sys
import socket
import logging
import re
import itertools
import hashlib
import time
import yaml
import traceback
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime
from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
import threading
import httpx

# Load environment variables
load_dotenv()

# --- Terminal Colors ---
class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format=f'{Colors.BLUE}[%(asctime)s]{Colors.RESET} %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler("subSL.log"),
        logging.StreamHandler(sys.stdout) # Ensure logs go to stdout for colored output
    ]
)
logger = logging.getLogger("SubSL")

# --- General Settings ---
CONFIG_FILE = "config.yaml"
WORDLIST_FILE = "wordlists.txt"
DEFAULT_CONFIG = {
    "concurrent_dns": 300,
    "concurrent_http": 100, # New: Concurrency for HTTP checks
    "timeout": 15,
    "http_timeout": 10,    # New: Timeout for HTTP requests
    "rate_limit_pause": 1,
    "max_retries": 3,
    "api_keys": {
        "securitytrails": os.getenv("SECURITYTRAILS_API_KEY"),
        "github": os.getenv("GITHUB_TOKEN"),
        "shodan": os.getenv("SHODAN_API_KEY"),
    }
}

# --- Load Configuration ---
def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                user_conf = yaml.safe_load(f)
                cfg = DEFAULT_CONFIG.copy()
                cfg.update(user_conf or {})
                return cfg
        except yaml.YAMLError as e:
            logger.error(f"{Colors.RED}Error loading config.yaml: {e}{Colors.RESET}")
            logger.warning(f"{Colors.YELLOW}Using default configuration.{Colors.RESET}")
            return DEFAULT_CONFIG
    logger.info(f"{Colors.YELLOW}Config file '{CONFIG_FILE}' not found. Using default configuration.{Colors.RESET}")
    return DEFAULT_CONFIG

config = load_config()

# --- Storage Management ---
def read_wordlist(filename=WORDLIST_FILE):
    if not os.path.exists(filename):
        logger.warning(f"{Colors.YELLOW}Wordlist file '{filename}' not found! Using an empty list.{Colors.RESET}")
        return [] # Return empty list if file not found
    with open(filename, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

# --- Helpers ---
def sanitize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.rstrip("/")
    return domain

def extract_title(html_content: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html_content, re.IGNORECASE | re.DOTALL)
    if match:
        title = match.group(1).strip()
        from html import unescape
        return unescape(title)
    return ""

# --- OSINT Sources (No changes needed for this section) ---
class OSINTCollector:
    def __init__(self, domain: str, session: aiohttp.ClientSession, config: dict):
        self.domain = domain
        self.session = session
        self.config = config
        self.api_keys = config.get("api_keys", {})

        self.takeover_providers = {
            "herokudns.com": "Heroku", "s3-website-us-east-1.amazonaws.com": "AWS S3",
            "s3-website.eu-central-1.amazonaws.com": "AWS S3", "s3-website-ap-northeast-1.amazonaws.com": "AWS S3",
            "gh-pages.github.io": "GitHub Pages", "works.intercom.io": "Intercom",
            "proxy.webflow.com": "Webflow", "myshopify.com": "Shopify",
            "squarespace.com": "Squarespace", "domains.tumblr.com": "Tumblr",
            "helpscoutdocs.com": "Help Scout", "desk.com": "Desk.com",
            "zendesk.com": "Zendesk", "read.the-docs.io": "Read the Docs",
            "cname.bitly.com": "Bitly", "cname.wishpond.com": "Wishpond",
            "cname.helpscout.com": "Help Scout", "unbouncepages.com": "Unbounce",
            "createsend.com": "Campaign Monitor", "hosting.intercom.com": "Intercom",
            "custom.cname.is": "CloudFlare", "readthedocs.io": "Read the Docs",
            "azurewebsites.net": "Microsoft Azure", "cloudapp.net": "Microsoft Azure",
            "trafficmanager.net": "Microsoft Azure", "elasticbeanstalk.com": "AWS Elastic Beanstalk",
            "wpengine.com": "WP Engine", "surge.sh": "Surge.sh",
            "feedpress.me": "FeedPress", "netlify.com": "Netlify",
            "apigee.net": "Apigee", "fastly.net": "Fastly",
            "ghost.io": "Ghost", "strikingly.com": "Strikingly",
            "dotcloud.com": "DotCloud", "withgoogle.com": "Google Sites",
            "github.io": "GitHub Pages", "readthedocs.org": "Read the Docs",
            "amazonaws.com": "Amazon AWS (Generic S3)", "storage.googleapis.com": "Google Cloud Storage",
            "wixsite.com": "Wix", "statuspage.io": "StatusPage.io",
            "appspot.com": "Google App Engine", "azureedge.net": "Azure CDN",
            "cdn.amplifyapp.com": "AWS Amplify", "us-east-1.elasticbeanstalk.com": "AWS Elastic Beanstalk (Region specific)",
            "pageclip.co": "Pageclip", "readmessg.me": "MessageBird",
            "domains.tilda.ws": "Tilda", "pagemodo.com": "Pagemodo",
            "relay-publishing.com": "Relay Publishing", "landing.ly": "Landingi",
            "flywheelsites.com": "Flywheel", "kinsta.com": "Kinsta",
            "pantheonsite.io": "Pantheon", "webhosting.net": "Web Hosting (Generic)",
            "hosting-cloud.net": "OVHCloud", "hubspot.com": "HubSpot",
            "redirect.g.doubleclick.net": "Google Redirect", "azurefd.net": "Azure Front Door",
            "customer-app.io": "Intercom", "webflow.io": "Webflow",
        }
        self.subdomains: Set[str] = set()

    async def from_crtsh(self) -> Set[str]:
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        results = set()
        try:
            async with self.session.get(url, timeout=self.config["timeout"]) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    for item in data:
                        names = item.get("name_value","").split("\n")
                        for n in names:
                            if "*" not in n and self.domain in n:
                                results.add(n.lower())
                else:
                    logger.warning(f"{Colors.YELLOW}crt.sh response status: {resp.status}{Colors.RESET}")
        except Exception as e:
            logger.error(f"{Colors.RED}Error fetching crt.sh data: {e}{Colors.RESET}")
        return results

    async def from_securitytrails(self) -> Set[str]:
        api_key = self.api_keys.get("securitytrails")
        if not api_key:
            logger.warning(f"{Colors.YELLOW}SecurityTrails API key missing!{Colors.RESET}")
            return set()
        url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
        headers = {"APIKEY": api_key}
        results = set()
        try:
            async with self.session.get(url, headers=headers, timeout=self.config["timeout"]) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    subs = data.get("subdomains", [])
                    for s in subs:
                        results.add(f"{s}.{self.domain}".lower())
                else:
                    logger.warning(f"{Colors.YELLOW}SecurityTrails response status: {resp.status}{Colors.RESET}")
        except Exception as e:
            logger.error(f"{Colors.RED}Error fetching SecurityTrails data: {e}{Colors.RESET}")
        return results

    async def from_github(self) -> Set[str]:
        token = self.api_keys.get("github")
        if not token:
            logger.warning(f"{Colors.YELLOW}GitHub token missing!{Colors.RESET}")
            return set()
        url = f"https://api.github.com/search/code?q={self.domain}+extension:yaml"
        headers = {"Authorization": f"token {token}"}
        results = set()
        try:
            async with self.session.get(url, headers=headers, timeout=self.config["timeout"]) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get("items", []):
                        path = item.get("path", "")
                        if self.domain in path:
                            results.add(path.lower())
                else:
                    logger.warning(f"{Colors.YELLOW}GitHub response status: {resp.status}{Colors.RESET}")
        except Exception as e:
            logger.error(f"{Colors.RED}Error fetching GitHub data: {e}{Colors.RESET}")
        return results

    async def from_alienvault(self) -> Set[str]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        results = set()
        try:
            async with self.session.get(url, timeout=self.config["timeout"]) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for record in data.get("passive_dns", []):
                        hostname = record.get("hostname", "").lower()
                        if hostname.endswith(self.domain):
                            results.add(hostname)
                else:
                    logger.warning(f"{Colors.YELLOW}AlienVault response status: {resp.status}{Colors.RESET}")
        except Exception as e:
            logger.error(f"{Colors.RED}Error fetching AlienVault data: {e}{Colors.RESET}")
        return results

    async def from_shodan(self) -> Set[str]:
        key = self.api_keys.get("shodan")
        if not key:
            logger.warning(f"{Colors.YELLOW}Shodan API key missing!{Colors.RESET}")
            return set()
        url = f"https://api.shodan.io/dns/domain/{self.domain}"
        results = set()
        try:
            async with self.session.get(url, params={"key": key}, timeout=self.config["timeout"]) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for s in data.get("subdomains", []):
                        results.add(f"{s}.{self.domain}".lower())
                else:
                    logger.warning(f"{Colors.YELLOW}Shodan response status: {resp.status}{Colors.RESET}")
        except Exception as e:
            logger.error(f"{Colors.RED}Error fetching Shodan data: {e}{Colors.RESET}")
        return results

    async def gather_all(self) -> Set[str]:
        results = set()
        coros = [
            self.from_crtsh(),
            self.from_securitytrails(),
            self.from_github(),
            self.from_alienvault(),
            self.from_shodan(),
        ]
        gathered = await asyncio.gather(*coros, return_exceptions=True)
        for result in gathered:
            if isinstance(result, Exception):
                logger.error(f"{Colors.RED}Error in OSINT source gathering: {result}{Colors.RESET}")
            else:
                results.update(result)
        return results

# --- Brute-force Subdomain Generation ---
def generate_bruteforce(wordlist: List[str], domain: str) -> Set[str]:
    results = set()
    for word in wordlist:
        results.add(f"{word}.{domain}")
    return results

# --- DNS Resolver + Cache + Takeover Detector ---
class DNSResolver:
    def __init__(self, concurrency: int):
        self.resolver = aiodns.DNSResolver()
        self.semaphore = asyncio.Semaphore(concurrency)
        self.cache_ip = {}
        self.cache_cname = {}

    async def resolve(self, subdomain: str) -> Optional[str]:
        if subdomain in self.cache_ip:
            return self.cache_ip[subdomain]
        async with self.semaphore:
            try:
                res = await self.resolver.gethostbyname(subdomain, socket.AF_INET)
                if res and res.addresses:
                    self.cache_ip[subdomain] = res.addresses[0]
                    return res.addresses[0]
            except Exception:
                self.cache_ip[subdomain] = None
        return None

    async def get_cname(self, subdomain: str) -> Optional[str]:
        if subdomain in self.cache_cname:
            return self.cache_cname[subdomain]
        async with self.semaphore:
            try:
                res = await self.resolver.query(subdomain, 'CNAME')
                if res:
                    cname = res[0].host.lower()
                    self.cache_cname[subdomain] = cname
                    return cname
            except Exception:
                self.cache_cname[subdomain] = None
        return None

    async def check_takeover(self, subdomain: str, takeover_providers: Dict[str, str]) -> Optional[Dict]:
        cname = await self.get_cname(subdomain)
        if not cname:
            return None
        for pattern, provider in takeover_providers.items():
            if pattern in cname:
                return {"subdomain": subdomain, "cname": cname, "provider": provider}
        return None

# --- HTTP / HTTPS Reachability Check ---
async def fetch_http_status(
    session: httpx.AsyncClient, url: str, http_timeout: int
) -> Dict[str, any]:
    """
    Checks HTTP/HTTPS status and extracts title. Prioritizes HTTPS.
    Returns a dictionary with 'status_code', 'title', 'url', 'reachable'.
    """
    # Try HTTPS first
    full_url_https = f"https://{url}"
    try:
        resp = await session.get(full_url_https, timeout=http_timeout, follow_redirects=True)
        if 200 <= resp.status_code < 400: # Success or redirect
            title = extract_title(resp.text)
            return {"status_code": resp.status_code, "title": title, "url": str(resp.url), "reachable": True}
        else:
            return {"status_code": resp.status_code, "title": "", "url": full_url_https, "reachable": False}
    except (httpx.RequestError, httpx.TimeoutException, httpx.ConnectError):
        pass # Fallback to HTTP if HTTPS fails

    # If HTTPS failed, try HTTP
    full_url_http = f"http://{url}"
    try:
        resp = await session.get(full_url_http, timeout=http_timeout, follow_redirects=True)
        if 200 <= resp.status_code < 400: # Success or redirect
            title = extract_title(resp.text)
            return {"status_code": resp.status_code, "title": title, "url": str(resp.url), "reachable": True}
        else:
            return {"status_code": resp.status_code, "title": "", "url": full_url_http, "reachable": False}
    except (httpx.RequestError, httpx.TimeoutException, httpx.ConnectError) as e:
        return {"status_code": None, "title": "", "url": "", "reachable": False}
    except Exception as e:
        logger.error(f"{Colors.RED}Unexpected error during HTTP check for {url}: {e}{Colors.RESET}")
        return {"status_code": None, "title": "", "url": "", "reachable": False}

# --- Reporting ---
def save_json_report(data: dict, filename: str):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    logger.info(f"{Colors.GREEN}JSON report saved to {filename}{Colors.RESET}")

def save_csv_report(data: dict, filename: str):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Subdomain", "IP Address", "CNAME", "Takeover Provider", "HTTP Status", "HTTP Title", "Final URL", "Status"])
        for sub, info in data["all_resolved_subdomains"].items(): # Use all_resolved_subdomains
            status_text = "HTTP OK" if info.get("http_reachable", False) else "DNS Only"
            if info.get("takeover_provider"):
                status_text += f" (Potential Takeover: {info['takeover_provider']})"

            writer.writerow([
                sub,
                info.get("ip", ""),
                info.get("cname", ""),
                info.get("takeover_provider", ""),
                info.get("http_status", ""),
                info.get("http_title", ""),
                info.get("http_url", ""),
                status_text
            ])
    logger.info(f"{Colors.GREEN}CSV report saved to {filename}{Colors.RESET}")

def generate_html_report(data: dict, filename: str):
    live_rows = ""
    dns_only_rows = ""

    # Sort subdomains for consistent report generation (optional but good practice)
    sorted_subdomains = sorted(data["all_resolved_subdomains"].items())

    for sub, info in sorted_subdomains:
        # Prepare data for display
        ip_display = info.get('ip', 'N/A')
        cname_display = info.get('cname', 'N/A')
        takeover_display = info.get('takeover_provider', 'No')
        http_status_display = info.get('http_status', 'N/A')
        title_display = info.get('http_title', 'N/A')
        final_url_display = info.get('http_url', '#')

        # Truncate title and URL for cleaner display
        if title_display and len(title_display) > 80:
            title_display = title_display[:77] + "..."
        if final_url_display and len(final_url_display) > 60 and final_url_display != '#':
            final_url_display_short = final_url_display.replace('http://', '').replace('https://', '')
            if len(final_url_display_short) > 57:
                final_url_display_short = final_url_display_short[:57] + "..."
            final_url_link = f'<a href="{final_url_display}" target="_blank">{final_url_display_short}</a>'
        elif final_url_display == '#':
            final_url_link = 'N/A'
        else:
            final_url_link = f'<a href="{final_url_display}" target="_blank">{final_url_display.replace("http://", "").replace("https://", "")}</a>'

        # Determine row class based on status for styling
        row_class = ""
        status_note = ""
        if info.get('http_reachable', False):
            row_class = "live-ok"
            status_note = "HTTP OK"
            if info.get('takeover_provider'):
                row_class = "live-takeover"
                status_note = f"HTTP OK (Potential Takeover: {takeover_display})"
        elif info.get('ip'): # DNS resolved but not HTTP reachable
            row_class = "dns-only"
            status_note = "DNS Resolved, HTTP Unreachable"
            if info.get('takeover_provider'):
                row_class = "dns-takeover"
                status_note = f"DNS Only (Potential Takeover: {takeover_display})"
        else: # Should not happen if data filtered for resolved, but as fallback
            row_class = "not-resolved"
            status_note = "Not Resolved"


        row_html = f"""<tr class="{row_class}">
            <td>{sub}</td>
            <td>{ip_display}</td>
            <td>{cname_display}</td>
            <td>{takeover_display}</td>
            <td>{http_status_display}</td>
            <td>{title_display}</td>
            <td>{final_url_link}</td>
            <td>{status_note}</td>
        </tr>\n"""

        if info.get('http_reachable', False):
            live_rows += row_html
        elif info.get('ip'): # Only add to DNS only if DNS resolved but HTTP unreachable
            dns_only_rows += row_html

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SubSL Scan Report for {data['domain']}</title>
    <style>
    body {{font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 20px; background:#f0f2f5; color: #333;}}
    .container {{max-width: 1200px; margin: 30px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.08);}}
    h1, h2 {{color: #0056b3; text-align: center; margin-bottom: 25px;}}
    h2 {{margin-top: 40px; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px;}}
    .summary {{background: #e9f5ff; padding: 20px; border-radius: 8px; margin-bottom: 35px; display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; border: 1px solid #cce0ff;}}
    .summary div {{padding: 10px; border-left: 4px solid #007bff; background: #ffffff; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.05);}}
    .summary div strong {{display: block; font-size: 0.9em; color: #555; margin-bottom: 5px;}}
    .summary div span {{font-size: 1.6em; font-weight: bold; color: #007bff; display: block;}}
    table {{border-collapse: collapse; width: 100%; margin-top: 25px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); border-radius: 8px; overflow: hidden;}}
    th, td {{border: 1px solid #e0e0e0; padding: 14px; text-align: left; vertical-align: top; font-size: 0.95em;}}
    th {{background-color: #007bff; color: white; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px;}}
    tr.live-ok {{background-color: #e6ffe6;}} /* Light green for live & http ok */
    tr.live-takeover {{background-color: #ffcccc; font-weight: bold;}} /* Light red for live & takeover */
    tr.dns-only {{background-color: #fff8e1;}} /* Light yellow for DNS resolved but HTTP failed */
    tr.dns-takeover {{background-color: #ffb3b3; font-weight: bold;}} /* Lighter red for DNS resolved & takeover */
    tr:nth-child(even):not(.live-ok):not(.live-takeover):not(.dns-only):not(.dns-takeover) {{background-color: #f8f8f8;}}
    tr:hover {{background-color: #e2e6ea; cursor: pointer;}}
    a {{color: #007bff; text-decoration: none;}}
    a:hover {{text-decoration: underline;}}
    .no-results {{text-align: center; color: #666; padding: 20px; background: #f9f9f9; border: 1px solid #eee; border-radius: 5px; margin-top: 20px;}}
    </style>
    </head>
    <body>
    <div class="container">
        <h1>SubSL Scan Report for {data['domain']}</h1>
        <div class="summary">
            <div><strong>Total Candidates:</strong> <span>{data['total_candidates']}</span></div>
            <div><strong>DNS Resolved Subdomains:</strong> <span>{data['dns_resolved_count']}</span></div>
            <div><strong>HTTP Reachable Subdomains:</strong> <span>{data['live_count']}</span></div>
            <div><strong>Potential Takeovers:</strong> <span>{data['takeover_count']}</span></div>
            <div><strong>Scan Timestamp:</strong> <span>{data['timestamp']}</span></div>
        </div>

        <h2>Live & HTTP Reachable Subdomains</h2>
        {'' if live_rows else '<p class="no-results">No HTTP reachable subdomains found.</p>'}
        <table>
            <thead>
                <tr>
                    <th>Subdomain</th>
                    <th>IP Address</th>
                    <th>CNAME</th>
                    <th>Takeover Provider</th>
                    <th>HTTP Status</th>
                    <th>HTTP Title</th>
                    <th>Final URL</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {live_rows}
            </tbody>
        </table>

        <h2>DNS Resolved but HTTP Unreachable Subdomains</h2>
        {'' if dns_only_rows else '<p class="no-results">No DNS resolved subdomains without HTTP reachability found.</p>'}
        <table>
            <thead>
                <tr>
                    <th>Subdomain</th>
                    <th>IP Address</th>
                    <th>CNAME</th>
                    <th>Takeover Provider</th>
                    <th>HTTP Status</th>
                    <th>HTTP Title</th>
                    <th>Final URL</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {dns_only_rows}
            </tbody>
        </table>
    </div>
    </body>
    </html>
    """
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    logger.info(f"{Colors.GREEN}HTML report saved to {filename}{Colors.RESET}")


# --- CLI + Web API (No changes needed for this section) ---
app = FastAPI()
connected_clients = set()
progress_status = {
    "stage": "Idle",
    "total_subs": 0,
    "checked": 0,
    "dns_resolved": 0, # New: Count for DNS resolved
    "http_reachable": 0, # New: Count for HTTP reachable
    "takeovers": 0
}

@app.get("/")
async def home():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SubSL Dashboard</title>
        <style>
            body { font-family: sans-serif; margin: 20px; background: #f4f7f6; color: #333; }
            .container { max-width: 900px; margin: auto; background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #007bff; text-align: center; margin-bottom: 30px; }
            .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; margin-bottom: 30px; }
            .status-item { background: #e9ecef; padding: 15px; border-radius: 5px; text-align: center; }
            .status-item h2 { margin-top: 0; color: #555; font-size: 1.1em; }
            .status-item p { font-size: 1.6em; font-weight: bold; color: #007bff; margin: 0; }
            .log-box { background: #343a40; color: #e9ecef; padding: 15px; border-radius: 5px; height: 350px; overflow-y: scroll; font-family: monospace; font-size: 0.85em; white-space: pre-wrap; margin-top: 20px; }
            .log-box div { margin-bottom: 5px; }
            .log-info { color: #87ceeb; }
            .log-warning { color: #ffeb3b; }
            .log-error { color: #ff4d4d; }
            .log-success { color: #72ec72; }
            .stage-label { color: #ffc107; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>SubSL Subdomain Scanner Dashboard</h1>
            <div class="status-grid">
                <div class="status-item"><h2>Current Stage</h2><p id="stage">Idle</p></div>
                <div class="status-item"><h2>Total Candidates</h2><p id="total_subs">0</p></div>
                <div class="status-item"><h2>Subdomains Checked</h2><p id="checked">0</p></div>
                <div class="status-item"><h2>DNS Resolved</h2><p id="dns_resolved">0</p></div>
                <div class="status-item"><h2>HTTP Reachable</h2><p id="http_reachable">0</p></div>
                <div class="status-item"><h2>Potential Takeovers</h2><p id="takeovers">0</p></div>
            </div>
            <h2>Live Updates</h2>
            <div id="log-output" class="log-box"></div>
        </div>

        <script>
            var ws = new WebSocket("ws://localhost:8000/ws");
            var logOutput = document.getElementById("log-output");

            ws.onmessage = function(event) {
                var data = JSON.parse(event.data);
                document.getElementById("stage").innerText = data.stage;
                document.getElementById("total_subs").innerText = data.total_subs;
                document.getElementById("checked").innerText = data.checked;
                document.getElementById("dns_resolved").innerText = data.dns_resolved;
                document.getElementById("http_reachable").innerText = data.http_reachable;
                document.getElementById("takeovers").innerText = data.takeovers;

                var logMsg = data.last_log_message || '';
                if (logMsg) {
                    var logDiv = document.createElement('div');
                    if (logMsg.includes('[LIVE')) {
                        logDiv.className = 'log-success';
                    } else if (logMsg.includes('[NOT LIVE') || logMsg.includes('[DNS Resolved')) {
                        logDiv.className = 'log-warning';
                    } else if (logMsg.includes('ERROR')) {
                        logDiv.className = 'log-error';
                    } else {
                        logDiv.className = 'log-info';
                    }
                    logDiv.innerText = logMsg;
                    logOutput.appendChild(logDiv);
                    logOutput.scrollTop = logOutput.scrollHeight;
                }
            };

            ws.onclose = function(event) {
                console.log('WebSocket closed, attempting to reconnect...');
                setTimeout(function() {
                    ws = new WebSocket("ws://localhost:8000/ws");
                }, 1000);
            };
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.add(websocket)
    try:
        while True:
            current_status = progress_status.copy()
            current_status['last_log_message'] = None
            await websocket.send_json(current_status)
            await asyncio.sleep(0.5)
    except Exception as e:
        logger.debug(f"WebSocket disconnected: {e}")
    finally:
        connected_clients.remove(websocket)

def start_web_server():
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")

# --- Main Program ---
async def scan_domain(domain: str):
    domain = sanitize_domain(domain)
    logger.info(f"{Colors.BOLD}{Colors.BLUE}[*] Starting scan for: {domain}{Colors.RESET}")

    async with aiohttp.ClientSession() as osint_session, httpx.AsyncClient() as http_session:
        collector = OSINTCollector(domain, osint_session, config)

        logger.info(f"{Colors.CYAN}[*] Gathering subdomains from OSINT sources...{Colors.RESET}")
        osint_subs = await collector.gather_all()
        logger.info(f"{Colors.GREEN}Found {len(osint_subs)} subdomains from OSINT sources.{Colors.RESET}")

        wordlist = read_wordlist()
        logger.info(f"{Colors.CYAN}[*] Loading brute-force wordlist with {len(wordlist)} words.{Colors.RESET}")
        brute_force_subs = generate_bruteforce(wordlist, domain)
        logger.info(f"{Colors.GREEN}Generated {len(brute_force_subs)} subdomains for brute-force.{Colors.RESET}")

        all_candidates = osint_subs.union(brute_force_subs)
        logger.info(f"{Colors.BOLD}{Colors.MAGENTA}[*] Total unique candidates for DNS/HTTP checks: {len(all_candidates)}{Colors.RESET}")

        dns_resolver = DNSResolver(config["concurrent_dns"])
        http_semaphore = asyncio.Semaphore(config["concurrent_http"])

        all_resolved_subdomains_info = {} # Stores info for all DNS resolved subdomains
        live_http_subdomains_count = 0
        dns_resolved_count = 0
        takeover_found = 0
        checked_count = 0
        total_candidates_to_check = len(all_candidates)

        async def check_single_subdomain(sub: str):
            nonlocal live_http_subdomains_count, dns_resolved_count, takeover_found, checked_count

            sub_info = {
                "ip": None, "cname": None, "takeover_provider": None,
                "http_status": None, "http_title": None, "http_url": None, "http_reachable": False
            }
            status_log_msg = ""

            # --- DNS Resolution ---
            ip = await dns_resolver.resolve(sub)
            if ip:
                sub_info["ip"] = ip
                dns_resolved_count += 1

                # --- Takeover Check ---
                takeover_info = await dns_resolver.check_takeover(sub, collector.takeover_providers)
                if takeover_info:
                    sub_info.update({"cname": takeover_info["cname"], "takeover_provider": takeover_info["provider"]})
                    takeover_found += 1

                # --- HTTP/HTTPS Check ---
                async with http_semaphore:
                    http_check_result = await fetch_http_status(http_session, sub, config["http_timeout"])
                    sub_info.update({
                        "http_status": http_check_result["status_code"],
                        "http_title": http_check_result["title"],
                        "http_url": http_check_result["url"],
                        "http_reachable": http_check_result["reachable"]
                    })

                if sub_info["http_reachable"]:
                    live_http_subdomains_count += 1
                    status_color = Colors.GREEN
                    status_prefix = "[LIVE - HTTP OK]"
                else:
                    status_color = Colors.YELLOW
                    status_prefix = "[DNS Resolved - HTTP Unreachable]"

                status_log_msg = (
                    f"{status_color}{status_prefix}{Colors.RESET} {sub} -> IP: {ip} "
                    f"(HTTP: {sub_info['http_status'] or 'N/A'}"
                    f"{', Title: ' + sub_info['http_title'][:50] + '...' if sub_info['http_title'] and sub_info['http_title'] != 'N/A' else ''}"
                    f")"
                )
                if sub_info["takeover_provider"]:
                    status_log_msg += f" | {Colors.RED}{Colors.BOLD}Takeover Potential: {sub_info['takeover_provider']}{Colors.RESET}"
            else:
                status_color = Colors.YELLOW
                status_prefix = "[NOT LIVE - DNS Failed]"
                status_log_msg = f"{status_color}{status_prefix}{Colors.RESET} {sub}"

            logger.info(status_log_msg)

            # Store results for reporting
            if ip: # Only store if DNS resolved
                all_resolved_subdomains_info[sub] = sub_info
            checked_count += 1

            # Update global progress status for WebSocket
            progress_status.update({
                "stage": "Scanning DNS & HTTP",
                "total_subs": total_candidates_to_check,
                "checked": checked_count,
                "dns_resolved": dns_resolved_count,
                "http_reachable": live_http_subdomains_count,
                "takeovers": takeover_found,
                "last_log_message": status_log_msg
            })

        logger.info(f"{Colors.CYAN}[*] Starting DNS and HTTP checks. This might take a while...{Colors.RESET}")
        tasks = [check_single_subdomain(sub) for sub in all_candidates]
        await asyncio.gather(*tasks)

        report_data = {
            "domain": domain,
            "total_candidates": total_candidates_to_check,
            "dns_resolved_count": dns_resolved_count,
            "live_count": live_http_subdomains_count,
            "all_resolved_subdomains": all_resolved_subdomains_info, # Now contains ALL DNS resolved, with HTTP details
            "takeover_count": takeover_found,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        # Save reports
        report_timestamp = int(time.time())
        json_file = f"report_{domain}_{report_timestamp}.json"
        csv_file = f"report_{domain}_{report_timestamp}.csv"
        html_file = f"report_{domain}_{report_timestamp}.html"

        save_json_report(report_data, json_file)
        save_csv_report(report_data, csv_file)
        generate_html_report(report_data, html_file)

        logger.info(f"{Colors.BOLD}{Colors.GREEN}Scan completed successfully!{Colors.RESET}")
        logger.info(f"{Colors.GREEN}Summary for {domain}:{Colors.RESET}")
        logger.info(f"{Colors.GREEN}  - Total Candidates: {total_candidates_to_check}{Colors.RESET}")
        logger.info(f"{Colors.GREEN}  - DNS Resolved Subdomains: {dns_resolved_count}{Colors.RESET}")
        logger.info(f"{Colors.GREEN}  - HTTP Reachable Subdomains: {live_http_subdomains_count}{Colors.RESET}")
        logger.info(f"{Colors.GREEN}  - Potential Takeovers: {takeover_found}{Colors.RESET}")
        logger.info(f"{Colors.GREEN}Reports saved to: {os.path.abspath('.')}{Colors.RESET}")

        progress_status["stage"] = "Completed"

# --- CLI Entry Point ---
def run_cli():
    if len(sys.argv) < 2:
        print(f"{Colors.BOLD}{Colors.RED}Usage: python3 subSL.py <domain> [--web]{Colors.RESET}")
        sys.exit(1)

    domain = sys.argv[1]
    start_web = "--web" in sys.argv

    if start_web:
        logger.info(f"{Colors.BLUE}[*] Starting web dashboard on http://localhost:8000{Colors.RESET}")
        t = threading.Thread(target=start_web_server, daemon=True)
        t.start()
        time.sleep(1)

    try:
        asyncio.run(scan_domain(domain))
    except KeyboardInterrupt:
        logger.info(f"{Colors.YELLOW}Scan interrupted by user.{Colors.RESET}")
    except Exception as e:
        logger.error(f"{Colors.RED}An unexpected error occurred: {e}{Colors.RESET}")
        traceback.print_exc()
    finally:
        logger.info(f"{Colors.BLUE}Exiting SubSL.{Colors.RESET}")
        progress_status["stage"] = "Terminated"

if __name__ == "__main__":
    run_cli()
