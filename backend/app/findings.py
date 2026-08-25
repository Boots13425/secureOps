import re
from dataclasses import dataclass
from datetime import datetime, timezone

from .scanner import HostObservation, ServiceObservation


@dataclass
class FindingCandidate:
    key: str
    asset_id: str
    service_id: str | None
    check_id: str
    title: str
    evidence: str
    severity: str
    confidence: str
    why_it_matters: str
    recommendation: str
    check_run_id: str | None = None


def _service(host: HostObservation, port: int | None) -> ServiceObservation | None:
    return next((service for service in host.services if service.port == port), None)


def _candidate(host, suffix, service, check_id, title, evidence, severity, confidence, why, recommendation, check_run_id=None):
    return FindingCandidate(
        key=f"{host.asset_id}:{suffix}", asset_id=host.asset_id, service_id=service.service_id if service else None,
        check_id=check_id, title=title, evidence=evidence[:4000], severity=severity, confidence=confidence,
        why_it_matters=why, recommendation=recommendation, check_run_id=check_run_id,
    )


def _certificate_expiry(output: str | None) -> datetime | None:
    match = re.search(r"(?:Not valid after|notAfter)\s*:\s*([^\r\n]+)", output or "", re.IGNORECASE)
    if not match:
        return None
    value = match.group(1).strip().replace("Z", "+00:00")
    for parser in (
        lambda: datetime.fromisoformat(value),
        lambda: datetime.strptime(value, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc),
        lambda: datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc),
    ):
        try:
            parsed = parser()
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def evaluate_host(host: HostObservation, now: datetime | None = None) -> list[FindingCandidate]:
    if not host.asset_id:
        return []
    now = now or datetime.now(timezone.utc)
    findings = []

    for check in host.exposure_checks:
        if check.status != "completed":
            continue
        output = check.output or ""
        lowered = output.lower()
        service = _service(host, check.port)
        if check.check_id == "smb-protocols" and ("nt lm 0.12" in lowered or "smbv1" in lowered):
            findings.append(_candidate(
                host, "legacy-smbv1", service, check.check_id, "Legacy SMB protocol detected",
                f"SMBv1 dialect reported by approved smb-protocols check on {check.port}/tcp. {output}", "high", "high",
                "Legacy SMB increases the attack surface and is commonly targeted for lateral movement.",
                "Disable SMBv1 after validating business dependencies, then rescan.", check.check_run_id,
            ))
        elif check.check_id == "ftp-anon" and "anonymous ftp login allowed" in lowered:
            findings.append(_candidate(
                host, f"anonymous-ftp:{check.port}", service, check.check_id, "Anonymous FTP access accepted",
                f"The approved ftp-anon check accepted anonymous authentication on {check.port}/tcp. {output}", "high", "high",
                "Anonymous FTP can expose or permit modification of files without an accountable identity.",
                "Disable anonymous FTP access or restrict it to a documented, isolated business requirement, then rescan.", check.check_run_id,
            ))
        elif check.check_id == "ssl-cert":
            expiry = _certificate_expiry(output)
            if expiry and expiry <= now:
                findings.append(_candidate(
                    host, f"expired-certificate:{check.port}", service, check.check_id, "Expired TLS certificate detected",
                    f"The approved ssl-cert check reports certificate expiry {expiry.isoformat()} on {check.port}/tcp.", "high", "high",
                    "Expired certificates undermine trust decisions and can interrupt secure services.",
                    "Replace the expired certificate, validate the complete certificate chain, and rescan.", check.check_run_id,
                ))
            elif expiry and (expiry - now).days <= 30:
                findings.append(_candidate(
                    host, f"expiring-certificate:{check.port}", service, check.check_id, "TLS certificate expires soon",
                    f"The approved ssl-cert check reports certificate expiry {expiry.isoformat()} on {check.port}/tcp.", "medium", "high",
                    "A certificate approaching expiry can create an avoidable service outage or emergency change.",
                    "Renew and deploy the certificate before expiry, validate the chain, and rescan.", check.check_run_id,
                ))
        elif check.check_id == "rdp-enum-encryption":
            findings.append(_candidate(
                host, f"rdp-exposure:{check.port}", service, check.check_id, "Remote Desktop service exposed",
                f"RDP is reachable on {check.port}/tcp. Approved rdp-enum-encryption evidence: {output}", "medium", "medium",
                "Broad RDP exposure increases remote-access attack surface even when no specific vulnerability is asserted.",
                "Confirm the exposure is required, restrict source networks, require NLA and strong authentication, then rescan.", check.check_run_id,
            ))

    telnet = next((service for service in host.services if service.port == 23 or (service.name or "").lower() == "telnet"), None)
    if telnet:
        findings.append(_candidate(
            host, f"cleartext-telnet:{telnet.port}", telnet, "service-observation", "Clear-text Telnet administration exposed",
            f"Service fingerprinting observed Telnet on {telnet.port}/{telnet.protocol}.", "high", "high",
            "Telnet transmits administrative credentials and session content without transport encryption.",
            "Replace Telnet with SSH or another encrypted management protocol and restrict administrative access.",
        ))

    rdp = next((service for service in host.services if service.port == 3389 or (service.name or "").lower() in {"ms-wbt-server", "rdp"}), None)
    rdp_already_reported = any(finding.check_id == "rdp-enum-encryption" for finding in findings)
    if rdp and not rdp_already_reported:
        check = next((item for item in host.exposure_checks if item.check_id == "rdp-enum-encryption" and item.port == rdp.port), None)
        findings.append(_candidate(
            host, f"rdp-exposure:{rdp.port}", rdp, "service-observation", "Remote Desktop service exposed",
            f"Service fingerprinting observed RDP on {rdp.port}/{rdp.protocol}. " + ((check.output or "The approved encryption check returned no additional evidence.") if check else "The approved encryption check returned no additional evidence."),
            "medium", "high", "Broad RDP exposure increases remote-access attack surface even when no specific vulnerability is asserted.",
            "Confirm the exposure is required, restrict source networks, require NLA and strong authentication, then rescan.",
            check.check_run_id if check else None,
        ))

    http = next((service for service in host.services if (service.name or "").lower() == "http" or service.port in {80, 8080, 8000}), None)
    has_tls = any((service.name or "").lower() in {"https", "ssl", "ssl/http", "https-alt"} or service.port in {443, 8443, 9443} for service in host.services)
    if http and not has_tls:
        findings.append(_candidate(
            host, "http-without-https", http, "service-observation", "HTTP service exposed without observed HTTPS",
            f"HTTP is exposed on {http.port}/{http.protocol}; no HTTPS service was observed in the approved scan profile.", "medium", "high",
            "Unencrypted HTTP may expose credentials or business data, depending on the service purpose; this finding does not assume sensitive content.",
            "Confirm the service purpose, enable TLS where sensitive or authenticated traffic is possible, and redirect HTTP to HTTPS.",
        ))

    administrative_ports = {22, 23, 445, 3389, 5900, 5985, 5986}
    for service in host.services:
        if service.is_new and not host.is_new_asset and service.port in administrative_ports:
            findings.append(_candidate(
                host, f"new-admin-exposure:{service.port}:{service.protocol}", service, "historical-comparison",
                "New administrative service exposure observed",
                f"{service.port}/{service.protocol} ({service.name or 'unidentified service'}) was not present in prior observations for this asset.",
                "medium", "high", "A newly exposed management service can indicate configuration drift or an unauthorized change even without a CVE.",
                "Validate the change owner and business need, restrict access to management networks, and remove the exposure if unapproved.",
            ))
    return findings
