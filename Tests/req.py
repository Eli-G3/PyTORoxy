import requests
from requests_toolbelt.utils import dump

resp = requests.get('https://www.facebook.com')
data = dump.dump_all(resp)
print(data)