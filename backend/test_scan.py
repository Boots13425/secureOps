import sys
sys.path.insert(0, '.')
from app import repository, cross_network
from app.main import scan_network_by_id
from app.scan_service import ScanCoordinator
from fastapi import HTTPException

# Simulate the scan request
network_id = 'f2d8a0df-5358-4cea-a3f5-3307beeae258'  # 172.16.2.0/24
network = repository.get_network(network_id)
print('Network:', network)

if network:
    scannable, reason = cross_network.network_is_scannable(network)
    print('Scannable:', scannable, 'Reason:', reason)
    
    if scannable:
        cidr = cross_network.record_cidr(network)
        print('CIDR for scan:', cidr)
        
        # Try to create a session
        from app.repository import create_session
        session = create_session(cidr, 10, source="cross_network", network_id=network_id)
        print('Session created:', session)
    else:
        print('NOT SCANNABLE:', reason)