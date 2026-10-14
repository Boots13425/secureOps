import sys
sys.path.insert(0, '.')
from app import snmp
from app.config import settings

ip = '172.16.1.10'
community = settings.snmp_community
timeout = settings.snmp_timeout_seconds

print('Testing MAC tables for switch...')
macs_by_vlan = snmp.collect_fdb_entries(ip, community, timeout)
print('FDB entries (dot1q/dot1d):', macs_by_vlan)

# Try with community@vlan for VLAN 2
print('Trying community@vlan for VLAN 2...')
macs_vlan2 = snmp.collect_fdb_entries_vlan(ip, 2, community, timeout)
print('VLAN 2 MACs:', macs_vlan2)

# Try VLAN 1
macs_vlan1 = snmp.collect_fdb_entries_vlan(ip, 1, community, timeout)
print('VLAN 1 MACs:', macs_vlan1)

# Try dot1dTpFdbPort per VLAN
print('FDB ports...')
fdb_ports = snmp.collect_fdb_ports(ip, community, timeout)
print('FDB ports:', fdb_ports)