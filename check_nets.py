import requests
r = requests.get("http://localhost:8007/api/v1/networks")
data = r.json()
for n in data['data']['networks']:
    print(f'{n["network_id"]} | {n["cidr_text"]} | local={n["is_local"]} | scannable={n["is_scannable"]} | reason={n.get("reachability_reason")}')