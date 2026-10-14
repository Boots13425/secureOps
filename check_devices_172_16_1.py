import requests
r = requests.get("http://localhost:8007/api/v1/devices?scan_id=17096827-fadd-40b9-b8ba-6a514ec247a5")
data = r.json()
for d in data['data']:
    print(f'{d["ip"]} | MAC: {d["mac_address"]} | Host: {d["hostname"]} | Type: {d["device_type"]} | Discovery: {d.get("discovery_source", "N/A")}')