# ========================================
# File: tools.py
# ========================================
import os
import re
import tldextract
import validators
from typing import Dict, List
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from crewai_tools import BaseTool
from config import Config
from datetime import datetime
import whois
from config import Config
from util_funcs import is_exact_legitimate_domain, flatten_legitimate_domains

def get_domain_age_days(domain: str):
    """
    Returns domain age in days or None if unavailable.
    """
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return None

        return (datetime.utcnow() - creation_date).days

    except Exception:
        return None

class URLAnalysisTool(BaseTool):
    name: str = "URL Analysis Tool"
    description: str = "Analyzes URLs for phishing indicators including domain reputation, typosquatting, and suspicious patterns"
    
    def _run(self, url: str) -> str:
        """Comprehensive URL analysis"""
        results = {
            'is_valid': False,
            'domain': '',
            'tld': '',
            'subdomain': '',
            'suspicious_patterns': [],
            'risk_score': 0
        }
        
        if not validators.url(url):
            results['suspicious_patterns'].append('Invalid URL format')
            results['risk_score'] += 30
            return self._format_results(results)
        
        results['is_valid'] = True
        
        # Extract URL components
        extracted = tldextract.extract(url)
        results['domain'] = extracted.domain
        results['tld'] = extracted.suffix
        results['subdomain'] = extracted.subdomain
        
        # -------------------------
        # WHOIS domain age analysis
        # -------------------------
        domain_age_days = get_domain_age_days(
            f"{results['domain']}.{results['tld']}"
        )

        if domain_age_days is not None:
            if domain_age_days < 7:
                results['suspicious_patterns'].append(
                    f"Very new domain ({domain_age_days} days old)"
                )
                results['risk_score'] += 40
            elif domain_age_days < 30:
                results['suspicious_patterns'].append(
                    f"Newly registered domain ({domain_age_days} days old)"
                )
                results['risk_score'] += 30
            elif domain_age_days < 90:
                results['suspicious_patterns'].append(
                    f"Recently registered domain ({domain_age_days} days old)"
                )
                results['risk_score'] += 15
        else:
            results['suspicious_patterns'].append(
                "Domain age unavailable (WHOIS lookup failed)"
            )
            
        if is_exact_legitimate_domain(
            f"{results['domain']}.{results['tld']}",
            flatten_legitimate_domains(Config.LEGITIMATE_DOMAINS)
        ):
            domain_age_days = None
        
        # Check for suspicious TLD
        if f".{results['tld']}" in Config.SUSPICIOUS_TLDS:
            results['suspicious_patterns'].append(f"Suspicious TLD: .{results['tld']}")
            results['risk_score'] += 25
            
        # Reserved TLD check (test / non-routable)
        if f".{results['tld']}" in Config.RESERVED_TLDS:
            results['suspicious_patterns'].append("Reserved / non-routable TLD (testing or example domain)")
            results['risk_score'] += 0
            
        # Shortened-looking paths
        if len(urlparse(url).path.strip("/")) <= 8:
            results['suspicious_patterns'].append("Shortened or opaque URL path")
            results['risk_score'] += 10
        
        # Check for IP address instead of domain
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', results['domain']):
            results['suspicious_patterns'].append('IP address used instead of domain')
            results['risk_score'] += 40
        
        # Check for excessive subdomains
        if results['subdomain'] and results['subdomain'].count('.') > 2:
            results['suspicious_patterns'].append('Multiple suspicious subdomains')
            results['risk_score'] += 20
        
        # Check for typosquatting of popular brands
        for brand, legit_domain in Config.LEGITIMATE_DOMAINS.items():
            if isinstance(legit_domain, list):
                if brand in results['domain'].lower() and results['domain'].lower() not in [ld.split('.')[0] for ld in legit_domain]:
                    results['suspicious_patterns'].append(f"Possible {brand} typosquatting")
                    results['risk_score'] += 35
            else:
                if brand in results['domain'].lower() and results['domain'].lower() != legit_domain.split('.')[0]:
                    results['suspicious_patterns'].append(f"Possible {brand} typosquatting")
                    results['risk_score'] += 35
        
        # Check for suspicious characters
        if any(char in url for char in ['@', '..']):
            results['suspicious_patterns'].append('Suspicious characters in URL')
            results['risk_score'] += 15
        
        # Check URL length
        if len(url) > 75:
            results['suspicious_patterns'].append('Unusually long URL')
            results['risk_score'] += 10
        
        return self._format_results(results)
    
    def _format_results(self, results: Dict) -> str:
        """Format results as a string for the agent"""
        output = f"URL Analysis Results:\n"
        output += f"Valid URL: {results['is_valid']}\n"
        output += f"Domain: {results['domain']}\n"
        output += f"TLD: {results['tld']}\n"
        output += f"Subdomain: {results['subdomain']}\n"
        output += f"Risk Score: {results['risk_score']}/100\n"
        output += f"Suspicious Patterns Found: {len(results['suspicious_patterns'])}\n"
        for pattern in results['suspicious_patterns']:
            output += f"  - {pattern}\n"
        output += "\nEnd of URL Analysis.\n"
        return output

class ContentAnalysisTool(BaseTool):
    name: str = "Content Analysis Tool"
    description: str = "Analyzes text content for phishing indicators including social engineering tactics and suspicious keywords"
    
    def _run(self, content: str) -> str:
        """Analyze text content for phishing patterns"""
        results = {
            'suspicious_keywords_found': [],
            'urgency_level': 'low',
            'contains_threats': False,
            'grammar_issues': 0,
            'risk_score': 0
        }
        
        content_lower = content.lower()
        
        # Check for suspicious keywords
        for keyword in Config.SUSPICIOUS_KEYWORDS:
            if keyword in content_lower:
                results['suspicious_keywords_found'].append(keyword)
                results['risk_score'] += 8
        
        # Check for urgency indicators
        urgency_words = ['urgent', 'immediate', 'now', 'today', 'within 24 hours']
        urgency_count = sum(1 for word in urgency_words if word in content_lower)
        
        if urgency_count >= 3:
            results['urgency_level'] = 'high'
            results['risk_score'] += 25
        elif urgency_count >= 1:
            results['urgency_level'] = 'medium'
            results['risk_score'] += 15
        
        # Check for threats
        threat_words = ['suspend', 'terminate', 'close your account', 'legal action']
        if any(word in content_lower for word in threat_words):
            results['contains_threats'] = True
            results['risk_score'] += 30
        
        # Simple grammar check
        grammar_patterns = [
            r'\s+[a-z]',
            r'[.!?]\s*[a-z]',
        ]
        for pattern in grammar_patterns:
            results['grammar_issues'] += len(re.findall(pattern, content))
        
        if results['grammar_issues'] > 3:
            results['risk_score'] += 15
        
        # Check for generic greetings
        if re.search(r'\b(dear (customer|user|member|valued))\b', content_lower):
            results['suspicious_keywords_found'].append('generic greeting')
            results['risk_score'] += 10
        
        return self._format_results(results)
    
    def _format_results(self, results: Dict) -> str:
        """Format results as a string for the agent"""
        output = f"Content Analysis Results:\n"
        output += f"Risk Score: {results['risk_score']}/100\n"
        output += f"Urgency Level: {results['urgency_level']}\n"
        output += f"Contains Threats: {results['contains_threats']}\n"
        output += f"Grammar Issues: {results['grammar_issues']}\n"
        output += f"Suspicious Keywords Found ({len(results['suspicious_keywords_found'])}):\n"
        for keyword in results['suspicious_keywords_found']:
            output += f"  - {keyword}\n"
        output += "\nEnd of Content Analysis.\n"
        return output

class VisualAnalysisTool(BaseTool):
    name: str = "Visual Analysis Tool"
    description: str = "Analyzes visual and structural indicators of phishing including brand impersonation and suspicious forms"
    
    def _run(self, url: str) -> str:
        """Analyze visual phishing indicators"""
        results = {
            'brand_impersonation': [],
            'suspicious_forms': False,
            'external_resources': 0,
            'risk_score': 0
        }
        
        try:
            response = requests.get(url, timeout=5, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            html_content = response.text
        except:
            results['risk_score'] += 20
            return self._format_results(results, error=True)
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Check for password inputs
        password_inputs = soup.find_all('input', {'type': 'password'})
        if password_inputs:
            results['suspicious_forms'] = True
            results['risk_score'] += 20
        
        # Check for external resources
        images = soup.find_all('img', src=True)
        scripts = soup.find_all('script', src=True)
        
        external_count = 0
        for element in images + scripts:
            src = element.get('src', '')
            if src.startswith('http') and url and urlparse(src).netloc != urlparse(url).netloc:
                external_count += 1
        
        results['external_resources'] = external_count
        if external_count > 10:
            results['risk_score'] += 15
        
        # Check for brand keywords
        page_text = soup.get_text().lower()
        for brand in Config.LEGITIMATE_DOMAINS.keys():
            if brand in page_text:
                results['brand_impersonation'].append(brand)
                results['risk_score'] += 12
        
        return self._format_results(results)
    
    def _format_results(self, results: Dict, error: bool = False) -> str:
        """Format results as a string for the agent"""
        if error:
            return f"Visual Analysis Results:\nError fetching page content.\nRisk Score: {results['risk_score']}/100\n"
        
        output = f"Visual Analysis Results:\n"
        output += f"Risk Score: {results['risk_score']}/100\n"
        output += f"Suspicious Forms: {results['suspicious_forms']}\n"
        output += f"External Resources: {results['external_resources']}\n"
        output += f"Brand Impersonation Detected: {len(results['brand_impersonation'])}\n"
        for brand in results['brand_impersonation']:
            output += f"  - {brand}\n"
        output += "\nEnd of Visual Analysis.\n"
        return output

class VirusTotalTool(BaseTool):
    name: str = "VirusTotal Reputation Tool"
    description: str = "Checks URL or domain reputation using VirusTotal"

    def _run(self, indicator: str) -> str:
        import os
        import requests
        import time

        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            return "VirusTotal: API key not configured"

        headers = {
            "x-apikey": api_key,
            "Content-Type": "application/x-www-form-urlencoded"
        }

        # STEP 1 — Submit URL
        submit_resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": indicator},
            timeout=10
        )

        if submit_resp.status_code != 200:
            return "VirusTotal: URL submission failed"

        submit_data = submit_resp.json()
        analysis_id = submit_data.get("data", {}).get("id")

        if not analysis_id:
            return "VirusTotal: Failed to obtain analysis ID"

        # STEP 2 — Fetch analysis result
        time.sleep(1.5)

        analysis_resp = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers={"x-apikey": api_key},
            timeout=10
        )

        if analysis_resp.status_code != 200:
            return "VirusTotal: Failed to retrieve analysis"

        analysis_data = analysis_resp.json()
        stats = (
            analysis_data
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats")
        )

        if not stats:
            return "VirusTotal: Analysis pending — no verdict available"

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        total_engines = malicious + suspicious + harmless + undetected

        evidence = []

        if malicious > 0:
            evidence.append(
                f"VirusTotal: {malicious}/{total_engines} security engines flagged this indicator as malicious"
            )

        if suspicious > 0:
            evidence.append(
                f"VirusTotal: {suspicious}/{total_engines} security engines flagged this indicator as suspicious"
            )

        if not evidence:
            evidence.append(
                "VirusTotal: No security engines flagged this indicator as malicious"
            )

        return "\n".join(evidence)
