import requests
r = requests.get("http://localhost:8007/api/v1/devices?scan_id=960ab483-96f0-4c9f-9312-86d5853fc0b5")
data = r.json()
for d in data['data']:
    print(f"{d['ip']} | MAC: {d['mac_address']} | Host: {d['hostname']} | Type: {d['device_type']} | Discovery: {d.get('discovery_source', 'N/A')}")