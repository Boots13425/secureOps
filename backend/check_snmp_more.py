import sys
sys.path.insert(0, '.')
from app import snmp
from app.config import settings
from app.snmp import walk_table

for ip in ['172.16.1.1', '172.16.1.10']:
    print('Testing {}...'.format(ip))
    community = settings.snmp_community
    timeout = settings.snmp_timeout_seconds
    
    # Test ifTable (interface table)
    print('  ifTable (ifDescr, ifType, ifPhysAddress):')
    IF_DESCR = (1, 3, 6, 1, 2, 1, 2, 2, 1, 2)
    IF_TYPE = (1, 3, 6, 1, 2, 1, 2, 2, 1, 3)
    IF_PHYS = (1, 3, 6, 1, 2, 1, 2, 2, 1, 6)
    
    for suffix, tag, value in walk_table(IF_DESCR, ip, community, timeout, max_entries=50):
        if_index = suffix[0] if suffix else '?'
        descr = value.decode('utf-8', errors='replace')
        print('    ifDescr[{}]: {}'.format(if_index, descr))
    
    print('  ifPhysAddress (MAC):')
    for suffix, tag, value in walk_table(IF_PHYS, ip, community, timeout, max_entries=50):
        if tag == snmp.TAG_OCTET_STRING and len(value) == 6:
            if_index = suffix[0] if suffix else '?'
            mac = ':'.join('{:02x}'.format(b) for b in value)
            print('    ifPhys[{}]: {}'.format(if_index, mac))
    
    # Test ipNetToMedia (ARP table)
    print('  ipNetToMediaPhysAddress (ARP):')
    IPNETTOMEDIA_PHYS = (1, 3, 6, 1, 2, 1, 4, 22, 1, 2)
    for suffix, tag, value in walk_table(IPNETTOMEDIA_PHYS, ip, community, timeout, max_entries=20):
        if tag == snmp.TAG_OCTET_STRING and len(value) == 6:
            mac = ':'.join('{:02x}'.format(b) for b in value)
            print('    {}: {}'.format('.'.join(str(x) for x in suffix[-4:]), mac))
    
    # Test BRIDGE-MIB
    print('  dot1dTpFdbAddress (Bridge FDB):')
    DOT1D_TP_FDB_ADDRESS = (1, 3, 6, 1, 2, 1, 17, 2, 2, 2, 1, 2)
    for suffix, tag, value in walk_table(DOT1D_TP_FDB_ADDRESS, ip, community, timeout, max_entries=20):
        if tag == snmp.TAG_OCTET_STRING and len(value) == 6:
            mac = ':'.join('{:02x}'.format(b) for b in value)
            print('    {}: {}'.format(suffix, mac))
    
    print()