from __future__ import annotations

from ipaddress import ip_address


CRITICALITY_VALUES = {
    "test_temporary": 20,
    "peripheral": 30,
    "standard_workstation": 50,
    "privileged_workstation": 70,
    "business_server": 85,
    "critical_service": 100,
}
CRITICALITY_LABELS = {
    "test_temporary": "Test/temporary device",
    "peripheral": "Printer/non-critical peripheral",
    "standard_workstation": "Standard staff workstation",
    "privileged_workstation": "Administration/privileged workstation",
    "business_server": "Business application/server",
    "critical_service": "Identity, finance, student/medical records, critical core service",
}
# The exact strings an asset document may use, mapped to the 0-100 criticality
# value they feed into the Layer 8 formula (weight 0.15).
CRITICALITY_CATEGORY_VALUES = {
    "Test/temporary device": 20,
    "Printer/non-critical peripheral": 30,
    "Standard staff workstation": 50,
    "Administration/privileged workstation": 70,
    "Business application/server": 85,
    "Identity, finance, student/medical records, critical core service": 100,
}

# Spec 12.3 exposure table, kept for reference/UI copy only. The network is
# flat, so scoring uses one network-wide value (settings.network_exposure_value)
# for every asset rather than looking a subnet up.
NETWORK_CONTEXT_VALUES = {
    "Isolated lab/test network": 20,
    "Management-only/restricted segment": 30,
    "Server/internal protected VLAN": 50,
    "General staff/user network": 65,
    "Guest or broadly reachable internal": 80,
    "Internet-facing/reachable": 100,
}

# Scanned devices that no document row matched are still ranked, using the
# standard-workstation criticality rather than being hidden.
DEFAULT_CRITICALITY_VALUE = CRITICALITY_VALUES["standard_workstation"]
DEFAULT_CRITICALITY_CATEGORY = CRITICALITY_LABELS["standard_workstation"]

ASSET_DOCUMENT_COLUMNS = ("device_name", "ip_address", "purpose", "criticality_category")
NOT_IN_DOCUMENT_NOTE = "Not in your document - default value used"
MISSING_FROM_SCAN_NOTE = "Listed in your document but not detected on the network in the last 24 hours"

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


# --- Asset document --------------------------------------------------------
def _normalize_header(name) -> str:
    return str(name or "").strip().lower()


def _category_lookup() -> dict[str, tuple[str, int]]:
    """Category label -> (canonical label, value), case/space insensitive."""
    return {_normalize_header(label): (label, value) for label, value in CRITICALITY_CATEGORY_VALUES.items()}


def parse_asset_document(raw_rows) -> tuple[list[dict], list[dict]]:
    """Validate an uploaded asset document.

    Returns (valid_rows, errors). Every failure is reported rather than the
    first one, so the admin sees the whole list and can fix the file in one
    pass. Each error carries row, column, problem and expectation.
    """
    rows = [row for row in raw_rows if any(str(cell or "").strip() for cell in row)]
    if not rows:
        return [], [{"row": 0, "column": "-", "problem": "The document is empty",
                     "expected": "At least one device row"}]

    headers = [_normalize_header(cell) for cell in rows[0]]
    missing = [column for column in ASSET_DOCUMENT_COLUMNS if column not in headers]
    if missing:
        return [], [{
            "row": 1,
            "column": ", ".join(missing),
            "problem": "Required column(s) not found in the header row",
            "expected": "Header must contain: " + ", ".join(ASSET_DOCUMENT_COLUMNS),
        }]

    categories = _category_lookup()
    if len(rows) < 2:
        return [], [{"row": 1, "column": "-", "problem": "The document has a header row but no device rows",
                     "expected": "At least one device row under the header"}]
    lookup = {column: headers.index(column) for column in ASSET_DOCUMENT_COLUMNS}
    valid, errors = [], []
    seen_ips: dict[str, int] = {}
    seen_names: dict[str, int] = {}

    for offset, row in enumerate(rows[1:], start=2):
        def cell(column: str) -> str:
            index = lookup[column]
            return str(row[index] if index < len(row) else "").strip()

        device_name = cell("device_name")
        raw_ip = cell("ip_address")
        purpose = cell("purpose")
        raw_category = cell("criticality_category")
        row_errors = []

        parsed_ip = None
        if raw_ip:
            try:
                candidate = ip_address(raw_ip)
                if candidate.version != 4:
                    row_errors.append({
                        "row": offset, "column": "ip_address",
                        "problem": f"'{raw_ip}' is not an IPv4 address",
                        "expected": "An IPv4 address such as 192.168.1.10",
                    })
                else:
                    parsed_ip = str(candidate)
            except ValueError:
                row_errors.append({
                    "row": offset, "column": "ip_address",
                    "problem": f"'{raw_ip}' is not a valid IP address",
                    "expected": "An IPv4 address such as 192.168.1.10",
                })

        if not parsed_ip and not device_name:
            row_errors.append({
                "row": offset, "column": "ip_address / device_name",
                "problem": "A row needs an ip_address or a device_name, and this row has neither",
                "expected": "A valid ip_address, or a non-empty device_name, or both",
            })

        category_match = categories.get(_normalize_header(raw_category))
        if not raw_category:
            row_errors.append({
                "row": offset, "column": "criticality_category",
                "problem": "The criticality_category is empty",
                "expected": "One of: " + " | ".join(CRITICALITY_CATEGORY_VALUES),
            })
        elif not category_match:
            row_errors.append({
                "row": offset, "column": "criticality_category",
                "problem": f"'{raw_category}' is not an allowed criticality_category",
                "expected": "One of: " + " | ".join(CRITICALITY_CATEGORY_VALUES),
            })

        if parsed_ip:
            key = str(ip_address(parsed_ip))
            if key in seen_ips:
                row_errors.append({
                    "row": offset, "column": "ip_address",
                    "problem": f"Duplicate ip_address '{parsed_ip}', already used on row {seen_ips[key]}",
                    "expected": "Each ip_address may appear only once in the document",
                })
            else:
                seen_ips[key] = offset

        name_key = normalize_hostname(device_name) if device_name else ""
        if name_key:
            if name_key in seen_names:
                row_errors.append({
                    "row": offset, "column": "device_name",
                    "problem": f"Duplicate device_name '{device_name}', already used on row {seen_names[name_key]}",
                    "expected": "Each device_name may appear only once in the document",
                })
            else:
                seen_names[name_key] = offset

        errors.extend(row_errors)
        if row_errors:
            continue
        category_label, category_value = category_match
        valid.append({
            "row_number": offset,
            "device_name": device_name or None,
            "ip_address": parsed_ip,
            "purpose": purpose,
            "criticality_category": category_label,
            "criticality_value": category_value,
        })
    return valid, errors


def normalize_hostname(hostname) -> str:
    """Case-insensitive host key with any domain suffix dropped.

    'SW-NTECHCENTRAL.ntech.com' and 'sw-ntechcentral' both become
    'sw-ntechcentral', so a document can list a short name and still match a
    fully qualified one from a scan.
    """
    if not hostname:
        return ""
    return str(hostname).strip().lower().split(".")[0]


def match_document_to_assets(document_rows, assets) -> tuple[dict, dict]:
    """Match scanned assets to document rows.

    IP wins over hostname. When an asset's IP points at one row while its
    hostname points at a different row, the IP match is used and flagged as a
    conflict so an administrator can correct the document.

    Returns (matches, unmatched) where matches maps asset key -> match dict and
    unmatched lists document rows that no active asset claimed.
    """
    by_ip = {row["ip_address"]: row for row in document_rows if row.get("ip_address")}
    by_name = {
        normalize_hostname(row["device_name"]): row
        for row in document_rows if normalize_hostname(row.get("device_name"))
    }
    matches, claimed = {}, set()
    for asset in assets:
        asset_ip = str(asset.get("ip_address") or "")
        asset_name = normalize_hostname(asset.get("hostname"))
        ip_row = by_ip.get(asset_ip)
        name_row = by_name.get(asset_name) if asset_name else None

        row, flag = None, None
        if ip_row:
            row = ip_row
            flag = "conflict" if name_row and name_row["row_number"] != ip_row["row_number"] else "ip"
        elif name_row:
            row, flag = name_row, "hostname"
        if row is None:
            continue
        claimed.add(row["row_number"])
        matches[asset.get("asset_id")] = {"row": row, "flag": flag}
    unmatched = [row for row in document_rows if row["row_number"] not in claimed]
    return matches, unmatched


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