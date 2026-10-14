import requests
r = requests.get("http://localhost:8007/api/v1/networks")
data = r.json()
import json
print(json.dumps(data['data']['networks'], indent=2))