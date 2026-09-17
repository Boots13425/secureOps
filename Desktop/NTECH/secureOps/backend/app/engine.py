# secureOps/backend/app/engine.py
from typing import Dict, Any, List, Optional

EXPOSURE_WEIGHTS = {
    "isolated": 20,
    "restricted": 30,
    "internal_protected": 50,
    "general_staff": 65,
    "guest": 80,
    "internet_facing": 100
}

CRITICALITY_WEIGHTS = {
    "test_device": 20,
    "printer": 30,
    "workstation": 50,
    "admin_workstation": 70,
    "server": 85,
    "core_identity_finance": 100
}

def calculate_eari(
    cvss_score: Optional[float],
    epss_score: Optional[float],
    in_kev: bool,
    exposure_context: str = "general_staff",
    criticality: str = "workstation"
) -> Dict[str, Any]:
    """
    Calculates the ETSNTECH Asset Risk Index (EARI) prioritizing heuristic.
    """
    # 1. Normalize variables to 0 - 100 scale
    norm_severity = (cvss_score or 0.0) * 10.0
    norm_epss = (epss_score or 0.0) * 100.0
    norm_kev = 100.0 if in_kev else 0.0
    norm_exposure = float(EXPOSURE_WEIGHTS.get(exposure_context, 65))
    norm_criticality = float(CRITICALITY_WEIGHTS.get(criticality, 50))

    # 2. Weighted calculation
    score = (
        (0.30 * norm_severity) +
        (0.20 * norm_epss) +
        (0.20 * norm_kev) +
        (0.15 * norm_exposure) +
        (0.15 * norm_criticality)
    )

    # 3. KEV Precedence Rule: Minimum priority score of 80
    if in_kev and score < 80.0:
        score = 80.0

    score = round(score, 1)

    # 4. Priority tier assignment
    if score >= 85:
        tier = "Critical"
    elif score >= 70:
        tier = "High"
    elif score >= 50:
        tier = "Elevated"
    elif score >= 30:
        tier = "Moderate"
    else:
        tier = "Low"

    return {
        "eari_score": score,
        "priority_tier": tier,
        "is_kev": in_kev,
        "breakdown": {
            "severity": norm_severity,
            "epss": norm_epss,
            "kev": norm_kev,
            "exposure": norm_exposure,
            "criticality": norm_criticality
        }
    }

def generate_business_recommendation(finding_type: str, details: Dict[str, Any]) -> Dict[str, str]:
    """
    Translates technical exposure checks and vulnerabilities into 
    manager-friendly action directives.
    """
    if details.get("in_kev"):
        return {
            "summary": "Actively Exploited Threat Detected",
            "impact": "Criminals are actively weaponizing this exact vulnerability in real-world attacks.",
            "action": "Prioritize immediate software update or isolate this device until patched."
        }
    
    mapping = {
        "smb-protocols": {
            "summary": "Obsolete Windows File-Sharing Protocol (SMBv1)",
            "impact": "SMBv1 is an insecure legacy protocol vulnerable to widespread network ransomware.",
            "action": "Disable SMBv1 in Windows Features or server settings, then rescan."
        },
        "ftp-anon": {
            "summary": "Unsecured Public File Server (Anonymous FTP)",
            "impact": "Anyone on the local network can view or download files without a password.",
            "action": "Disable anonymous access and enforce credential-based login."
        },
        "rdp-enum-encryption": {
            "summary": "Exposed Remote Desktop Access (RDP)",
            "impact": "Exposed administrative remote desktop ports invite credential brute-force attacks.",
            "action": "Restrict RDP access behind an internal VPN and enforce two-factor authentication."
        },
        "ssl-cert": {
            "summary": "Expired or Invalid Security Certificate",
            "impact": "Encrypted communication trust is broken; connections may be intercepted or untrusted.",
            "action": "Renew and bind a valid TLS certificate to this web service."
        },
        "new_port": {
            "summary": "New Network Service Appeared",
            "impact": "A previously closed communication channel is now reachable, expanding the attack surface.",
            "action": "Identify the application owner and shut down the port if not explicitly required."
        }
    }
    
    return mapping.get(finding_type, {
        "summary": "Software Weakness Identified",
        "impact": "Identified product version contains known security bugs.",
        "action": "Validate product version and apply the latest official vendor security patches."
    })