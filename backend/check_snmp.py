import sys
sys.path.insert(0, '.')
from app import snmp

for ip in ['172.16.1.1', '172.16.1.10', '192.168.100.15']:
    print('Testing {}...'.format(ip))
    reachable = snmp.reachable(ip)
    print('  reachable: {}'.format(reachable))
    if reachable:
        identity = snmp.collect_identity(ip)
        print('  identity: {}'.format(identity))
        vlans = snmp.collect_vlans(ip)
        print('  vlans: {}'.format(vlans))
        routes = snmp.collect_routes(ip)
        print('  routes count: {}'.format(len(routes)))
        for r in routes[:10]:
            print('    {}'.format(r))
        interfaces = snmp.collect_interface_addresses(ip)
        print('  interfaces: {}'.format(interfaces))
    print()