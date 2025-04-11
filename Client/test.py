import config
import json

with open("keypair.json",'r') as file:
    kp = json.load(file)
    print(type(kp['metadata']))