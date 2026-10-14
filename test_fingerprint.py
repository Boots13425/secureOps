import sys
sys.path.insert(0, r'C:\Users\PAD-MARKET\secureOps\backend')

from app.scanner import HostObservation, fingerprint_hosts
import threading

# Create a test host from SNMP ARP
hosts = [
    HostObservation(
        ip_address="172.16.2.3",
        mac_address="f4:3b:d8:d1:60:14",
        vendor=None,
        hostname=None,
        device_type="unknown",
        discovery_sources=["snmp_arp"],
    ),
]

stop_event = threading.Event()
print("Starting fingerprint_hosts...")
try:
    result = fingerprint_hosts(hosts, stop_event)
    print(f"Completed: {len(result)} hosts")
    for h in result:
        print(f"  {h.ip_address}: {h.services}")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()