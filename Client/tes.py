import requests
resp = requests.get("http://localhost:5000")
print(resp.status_code,"1", resp.text)