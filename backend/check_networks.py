import sys
sys.path.insert(0, '.')
from app import cross_network

result = cross_network.detect_all()
print('=== DETECTED NETWORKS ===')
for n in result.get('networks', []):
    cidr = n.get('cidr')
    vlan = n.get('vlan_id')
    routed = n.get('routed')
    scannable = n.get('scannable')
    path = n.get('reachability_path')
    hops = len(n.get('reachability_hops', []))
    mac_count = n.get('mac_count')
    reason = n.get('unscannable_reason')
    print('  CIDR: {} | VLAN: {} | routed: {} | scannable: {} | path: {} | hops: {} | mac_count: {} | reason: {}'.format(cidr, vlan, routed, scannable, path, hops, mac_count, reason))
print()
print('=== ROUTED NETWORKS ===')
for n in result.get('routed_networks', []):
    print('  CIDR: {} | hops: {} | scannable: {}'.format(n.get('subnet'), len(n.get('reachability_hops', [])), n.get('scannable')))
print()
print('=== QUERIED ===')
for q in result.get('queried', []):
    print('  {}'.format(q))
print()
print('=== TRAVERSAL ===')
t = result.get('traversal', {})
print('  queried: {}'.format(t.get('queried', [])))
print('  unqueryable: {}'.format(t.get('unqueryable', [])))
print('  routed_networks: {}'.format(len(t.get('routed_networks', []))))
for rn in t.get('routed_networks', []):
    print('    {} | hops: {} | via: {} | scannable: {}'.format(rn.get('subnet'), rn.get('hop_count'), rn.get('via_router'), rn.get('scannable')))
print()
print('Report:', result.get('report'))