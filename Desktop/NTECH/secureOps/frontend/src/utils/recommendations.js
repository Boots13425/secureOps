// frontend/src/utils/recommendations.js

export function getActionableAdvice(asset) {
  if (asset.has_kev) {
    return {
      severity: "CRITICAL",
      title: "Actively Exploited Threat Detected",
      reason: "This machine runs software known to be exploited in active cyberattacks.",
      action: "Prioritize vendor patch immediately or temporarily disconnect this device."
    };
  }

  if (asset.critical_finding_count > 0 || asset.high_finding_count > 0) {
    return {
      severity: "HIGH",
      title: "Insecure Service Configuration",
      reason: "Exposed legacy or cleartext services (such as SMBv1, FTP, or remote desktop) were detected.",
      action: "Disable unused legacy features and restrict remote administration to VPN only."
    };
  }

  if (asset.max_epss > 0.3) {
    return {
      severity: "ELEVATED",
      title: "High Exploit Probability",
      reason: "Public exploit prediction models estimate a high probability of weaponization.",
      action: "Verify current version with the application vendor and schedule software updates."
    };
  }

  return {
    severity: "LOW",
    title: "Routine Baseline Maintenance",
    reason: "No active critical exploits detected. Normal maintenance profile.",
    action: "Keep operating system and business tools set to automated security updates."
  };
}