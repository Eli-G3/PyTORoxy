import requests


proxies = {
    "https": "127.0.0.1:9150",
    "http": "127.0.0.1:9150"
}

url = " http://www.ucla.edu"

r = requests.get(url, proxies=proxies)

print(r.text)