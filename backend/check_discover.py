import sys
sys.path.insert(0, '.')
from app import cross_network

result = cross_network.discover_networks('172.16.1.10')
print('Discovered networks from switch:')
for n in result:
    print('  CIDR: {} | VLAN: {} | name: {} | routed: {} | scannable: {} | path: {} | evidence: {} | mac_count: {}'.format(
        n.get('subnet'), n.get('vlan_id'), n.get('name'), n.get('routed'), n.get('scannable'), n.get('reachability_path'), n.get('subnet_evidence'), n.get('mac_count')
    ))
print()
print('Total:', len(result))