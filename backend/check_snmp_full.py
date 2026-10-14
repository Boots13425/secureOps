import sys
sys.path.insert(0, '.')
from app import snmp
from app.config import settings
from app.snmp import walk_table

for ip in ['172.16.1.1', '172.16.1.10']:
    print('Testing {}...'.format(ip))
    community = settings.snmp_community
    timeout = settings.snmp_timeout_seconds
    
    # Test ipAddrTable with full walk
    print('  ipAddrTable (full walk):')
    IP_ADDR_TABLE = (1, 3, 6, 1, 2, 1, 4, 7, 1, 1)
    for suffix, tag, value in walk_table(IP_ADDR_TABLE, ip, community, timeout, max_entries=100):
        print('    suffix={} tag={} value={}'.format(suffix, tag, value))
    
    # Test ipAddressTable with full walk
    print('  ipAddressTable (full walk):')
    IP_ADDRESS_TABLE = (1, 3, 6, 1, 2, 1, 4, 20, 1, 1, 1)
    for suffix, tag, value in walk_table(IP_ADDRESS_TABLE, ip, community, timeout, max_entries=100):
        print('    suffix={} tag={} value={}'.format(suffix, tag, value))
    
    # Test VLAN FDB (MAC addresses per VLAN)
    print('  VLAN FDB (dot1qTpFdbAddress):')
    DOT1Q_TP_FDB_ADDRESS = (1, 3, 6, 1, 2, 1, 17, 4, 3, 2, 2, 1, 1)
    for suffix, tag, value in walk_table(DOT1Q_TP_FDB_ADDRESS, ip, community, timeout, max_entries=20):
        print('    suffix={} tag={} value={}'.format(suffix, tag, value))
    
    # Test ipCidrRouteTable with full walk
    print('  ipCidrRouteTable (full walk):')
    IP_CIDR_ROUTE_TABLE = (1, 3, 6, 1, 2, 1, 4, 24, 7, 1, 7, 1)
    for suffix, tag, value in walk_table(IP_CIDR_ROUTE_TABLE, ip, community, timeout, max_entries=50):
        print('    suffix={} tag={} value={}'.format(suffix, tag, value))
    
    print()