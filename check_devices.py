import sys, json, requests
r = requests.get("http://localhost:8007/api/v1/devices?scan_id=155e1347-6923-477d-a8a7-c99b5e1befac")
data = r.json()
for d in data['data']:
    print(f"{d['ip']} | MAC: {d['mac_address']} | Host: {d['hostname']} | Type: {d['device_type']}")