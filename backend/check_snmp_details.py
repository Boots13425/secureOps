import sys
sys.path.insert(0, '.')
from app import snmp
from app.config import settings

# Test the specific OIDs
for ip in ['172.16.1.1', '172.16.1.10']:
    print('Testing {}...'.format(ip))
    community = settings.snmp_community
    timeout = settings.snmp_timeout_seconds
    
    # Test VLAN table
    print('  VLAN table (dot1qVlanCurrentName):')
    vlans = snmp.collect_vlans(ip, community, timeout)
    print('    Result: {}'.format(vlans))
    
    # Test ipAddressTable
    print('  Interface addresses (ipAddressTable):')
    interfaces = snmp.collect_interface_addresses(ip, community, timeout)
    print('    Result: {}'.format(interfaces))
    
    # Test ipAddrTable
    print('  Interface addresses (ipAddrTable):')
    from app.snmp import IP_ADDR_TABLE, COL_IPADENT_IF_INDEX, COL_IPADENT_ADDR, COL_IPADENT_NETMASK
    from app.snmp import walk_columns
    for row in walk_columns(IP_ADDR_TABLE, {COL_IPADENT_IF_INDEX: 'if_index', COL_IPADENT_ADDR: 'addr', COL_IPADENT_NETMASK: 'netmask'}, ip, community, timeout):
        print('    {}'.format(row))
    
    # Test ipCidrRouteTable
    print('  Routes (ipCidrRouteTable):')
    routes = snmp.collect_routes(ip, community, timeout)
    print('    Count: {}'.format(len(routes)))
    for r in routes[:5]:
        print('    {}'.format(r))
    
    # Test inetCidrRouteTable
    print('  Routes (inetCidrRouteTable):')
    from app.snmp import INET_CIDR_ROUTE_TABLE, COL_INET_ROUTE_TYPE, COL_INET_ROUTE_DEST, COL_INET_ROUTE_PFX_LEN, COL_INET_ROUTE_NEXT_HOP
    for row in walk_columns(INET_CIDR_ROUTE_TABLE, {COL_INET_ROUTE_TYPE: 'route_type', COL_INET_ROUTE_DEST: 'dest', COL_INET_ROUTE_PFX_LEN: 'pfx_len', COL_INET_ROUTE_NEXT_HOP: 'next_hop'}, ip, community, timeout):
        print('    {}'.format(row))
    
    # Test ifDescr to see interface names
    print('  Interface descriptions (ifDescr):')
    from app.snmp import walk_table
    IF_DESCR = (1, 3, 6, 1, 2, 1, 2, 2, 1, 2)
    for suffix, tag, value in walk_table(IF_DESCR, ip, community, timeout, max_entries=50):
        if tag == snmp.TAG_OCTET_STRING:
            if_index = suffix[0] if suffix else '?'
            descr = value.decode('utf-8', errors='replace')
            print('    ifIndex {}: {}'.format(if_index, descr))
    
    print()