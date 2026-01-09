# ========================================
# File: util_funcs.py
# ========================================
import json
import re
from urllib.parse import urlparse
from config import Config

def extract_url_risk_score(text: str) -> int:
    """
    Extracts URL risk score from URL Analysis Tool output.
    Expected format: 'Risk Score: XX/100'
    """
    if not text:
        return 0

    match = re.search(r"Risk Score:\s*(\d+)\s*/\s*100", text)
    return int(match.group(1)) if match else 0

def parse_coordinator_json(
    output: str,
    full_report: str = "",
    input_url: str = ""):
    """
    Parses coordinator JSON output and applies SOC-grade deterministic logic:
    - Risk floors
    - Benign overrides
    - Verdict classification
    - Narrative correction
    """

    # -------------------------
    # Validation
    # -------------------------
    if not isinstance(output, str):
        raise RuntimeError(f"Unexpected coordinator output type: {type(output)}")

    output = output.strip()
    if not output:
        raise RuntimeError("Coordinator returned empty output")

    try:
        result = json.loads(output)
    except json.JSONDecodeError:
        raise RuntimeError(
            "Coordinator did not return valid JSON.\n\n"
            f"Raw output:\n{output}"
        )

    # -------------------------
    # Base fields from coordinator
    # -------------------------
    phishing_probability = int(result.get("phishing_probability", 0))
    brand_impersonation = bool(result.get("brand_impersonation_detected", False))
    ti_confirmed = bool(result.get("ti_confirmed", False))
    evidence = result.get("evidence", [])

    # -------------------------
    # Combined report (tools + coordinator)
    # -------------------------
    combined_report = (full_report or "") + "\n" + output

    # -------------------------
    # URL risk extraction
    # -------------------------
    url_risk_score = extract_url_risk_score(combined_report)
    
    # -------------------------
    # Deterministic confidence calculation (AUTHORITATIVE)
    # -------------------------
    confidence = 0

    # URL analysis strength (PRIMARY for phishing)
    if url_risk_score >= 70:
        confidence += 45
    elif url_risk_score >= 50:
        confidence += 35
    elif url_risk_score >= 30:
        confidence += 25

    # Brand impersonation
    if brand_impersonation:
        confidence += 25

    # Phishing language indicators
    if any(
        kw in combined_report.lower()
        for kw in ["verify", "login", "confirm", "account", "secure"]
    ):
        confidence += 20

    # Threat intelligence confirmation (BOOSTER, not gate)
    if ti_confirmed:
        confidence += 15

    # Cap confidence
    confidence = min(confidence, 95)

    # Floor
    confidence = max(confidence, 30)
    
    # -------------------------
    # Deterministic risk floors (ANTI false-negative)
    # -------------------------
    if phishing_probability == 0:
        phishing_probability = 30

    phishing_probability = max(
        phishing_probability,
        url_risk_score,
        30
    )
    phishing_probability = min(phishing_probability, 100)

    # =========================================================
    # Benign override (ANTI false-positive)
    # =========================================================
    legit_domain_set = flatten_legitimate_domains(Config.LEGITIMATE_DOMAINS)

    benign_override_applied = False
    if (
        input_url
        and not ti_confirmed
        and is_exact_legitimate_domain(input_url, legit_domain_set)
    ):
        phishing_probability = min(phishing_probability, 10)
        confidence = max(confidence, 70)
        benign_override_applied = True

    # -------------------------
    # Verdict (human-readable)
    # -------------------------
    if ti_confirmed:
        verdict = "malicious"
    elif phishing_probability >= 50:
        verdict = "suspicious"
    else:
        verdict = "likely_benign"
    
    # -------------------------
    # Threat level (system severity)
    # -------------------------
    threat_level = compute_threat_level(
        phishing_probability,
        brand_impersonation
    )

    # -------------------------
    # Confidence source
    # -------------------------
    confidence_source = "heuristic"
    if ti_confirmed:
        confidence_source = "threat_intelligence"
    elif url_risk_score >= 50:
        confidence_source = "url_analysis"

    # =========================================================
    # Narrative correction (CRITICAL FIX)
    # =========================================================
    # Remove misleading TI-only findings when heuristics detect risk
    top_findings = result.get("top_findings", [])

    if verdict == "suspicious" and not ti_confirmed:
        top_findings = [
            f for f in top_findings
            if "no confirmed" not in f.lower()
        ]

        # Promote heuristic evidence
        top_findings.insert(
            0,
            "URL exhibits phishing indicators (suspicious TLD and brand impersonation)."
        )

    # -------------------------
    # Summary correction
    # -------------------------
    summary = result.get("summary", "")

    if verdict == "suspicious" and not ti_confirmed:
        summary = (
            "Suspicious phishing indicators detected based on URL analysis. "
            "External threat intelligence has not yet confirmed this threat."
        )

    if verdict == "likely_benign" and benign_override_applied:
        summary = (
            "The URL belongs to a known legitimate domain. "
            "No phishing indicators were detected."
        )

    # -------------------------
    # Return final SOC-grade result
    # -------------------------
    return {
        "verdict": verdict,
        "threat_level": threat_level,
        "phishing_probability": phishing_probability,
        "confidence": confidence,
        "confidence_source": confidence_source,
        "ti_confirmed": ti_confirmed,
        "evidence": evidence,
        "top_findings": top_findings,
        "summary": summary,
        "recommendations": result.get("recommendations", []),
        "full_report": combined_report.strip()
    }

def compute_threat_level(phishing_probability: int, brand_impersonation: bool) -> str:
    """
    Deterministic SOC-style threat classification
    """
    if phishing_probability >= 60:
        return "high"
    elif phishing_probability >= 30:
        return "medium"
    elif brand_impersonation:
        return "medium"
    else:
        return "low"
        
def get_coordinator_output(crew_result):
    if isinstance(crew_result, str):
        return crew_result
    if hasattr(crew_result, "tasks_output"):
        return crew_result.tasks_output[-1].raw_output
    raise RuntimeError("Unknown CrewAI result format")
    
def flatten_legitimate_domains(legit_domains: dict) -> set:
    """
    Flattens LEGITIMATE_DOMAINS into a set of exact domains.
    """
    domains = set()

    for value in legit_domains.values():
        if isinstance(value, list):
            domains.update(value)
        else:
            domains.add(value)

    return domains
    
def is_exact_legitimate_domain(url: str, legit_domain_set: set) -> bool:
    """
    Checks if the URL hostname exactly matches or is a subdomain
    of a known legitimate domain.
    """
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False

        hostname = hostname.lower()

        for legit_domain in legit_domain_set:
            legit_domain = legit_domain.lower()
            if hostname == legit_domain or hostname.endswith("." + legit_domain):
                return True

        return False
    except Exception:
        return False
