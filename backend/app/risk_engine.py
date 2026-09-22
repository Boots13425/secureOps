from __future__ import annotations

from ipaddress import ip_address, ip_network


CRITICALITY_VALUES = {"low": 20, "normal": 50, "high": 70, "critical": 100}
NETWORK_CONTEXT_VALUES = {
    "Isolated lab/test network": 20,
    "Management-only/restricted segment": 30,
    "Server/internal protected VLAN": 50,
    "General staff/user network": 65,
    "Guest or broadly reachable internal": 80,
    "Internet-facing/reachable": 100,
}

LABELS = ((85, "Critical"), (70, "High"), (50, "Elevated"), (30, "Moderate"), (0, "Low"))


def score_label(score: float) -> str:
    return next(label for minimum, label in LABELS if score >= minimum)


def score_asset(severity_normalized, epss_normalized, kev_normalized, exposure, asset_criticality):
    weighted = (
        0.30 * severity_normalized
        + 0.20 * epss_normalized
        + 0.20 * kev_normalized
        + 0.15 * exposure
        + 0.15 * asset_criticality
    )
    score = max(weighted, 80 if kev_normalized == 100 else 0)
    score = round(min(score, 100), 1)
    return score, score_label(score)


def policy_exposure(ip, policies):
    address = ip_address(str(ip))
    matches = [policy for policy in policies if address in policy["network"]]
    if not matches:
        return 50, True, None
    selected = min(matches, key=lambda policy: policy["network"].prefixlen)
    return NETWORK_CONTEXT_VALUES[selected["context_label"]], False, selected["context_label"]


def _canonicalize_identifier(identifier):
    if identifier is None:
        return ""
    value = str(identifier).strip().lower()
    if not value:
        return ""
    value = value.replace("-", ":")
    return value


def policy_criticality(values, identifiers):
    normalized_values = { _canonicalize_identifier(key): value for key, value in values.items() }
    for identifier in identifiers:
        canon = _canonicalize_identifier(identifier)
        if canon and (value := normalized_values.get(canon)):
            return CRITICALITY_VALUES[value], value
    return 50, "normal"


def recommendations(asset):
    services = asset.get("services") or []
    findings = asset.get("findings") or []
    recommendations = []

    if asset.get("kev_normalized") == 100:
        recommendations.append("Prioritize vendor-supported remediation/mitigation; verify exposure and rescan after action.")
    service_text = " ".join(str(service.get("name") or "") + " " + str(service.get("product") or "") for service in services).lower()
    finding_text = " ".join(str(finding.get(key) or "") for finding in findings for key in ("title", "check_id", "evidence", "why_it_matters")).lower()
    combined = service_text + " " + finding_text
    if "smbv1" in combined or "smb-protocols" in combined or "nt lm 0.12" in combined:
        recommendations.append("Validate legacy dependency, disable SMBv1 where feasible, then rescan.")
    if "anonymous ftp" in combined or "ftp-anon" in combined:
        recommendations.append("Disable anonymous access unless explicitly required; restrict writable areas and network reachability.")
    if any(str(service.get("port")) == "3389" or "rdp" in str(service.get("name") or "").lower() for service in services):
        recommendations.append("Restrict RDP to approved management sources/VPN and enforce strong authentication policy.")
    if "certificate" in combined and ("expired" in combined or "near expiry" in combined or "expir" in combined):
        recommendations.append("Renew/replace certificate and verify service continuity.")
    if any(finding.get("check_id") in {"unexpected-port", "new-unexpected-port"} for finding in findings):
        recommendations.append("Identify process/owner, validate business need, close/restrict service if unauthorized.")
    if asset.get("severity_normalized", 0) >= 70 and asset.get("epss_normalized", 0) >= 50:
        recommendations.append("Prioritize validation and vendor remediation because both impact and exploitation likelihood are elevated.")
    return recommendations