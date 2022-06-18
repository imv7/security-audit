import re
from random import randint
from time import sleep
import os
import json
import requests

try:
    with open('/Users/imv7/Documents/trabaio/Code/hosts.txt') as wordlist:
        for keyword in wordlist:
            username = 'imv7'
            token = ''
            url = 'https://api.github.com/search/code?q=' + keyword + '&page=1&per_page=1'
            r = requests.get(''+ url +'', auth=(username,token))
            pretty_json = json.loads(r.text)
            pretty_servidor = json.dumps(pretty_json, indent=2)
            print(json.dumps(pretty_json, indent=2))
            start = url.find("q=") + len("q=")
            end = url.find("&page")
            substring = url[start:end]
          #  print(substring)
            #j = json.loads(r.text)["items"][0]["html_url"]
            #print(j)
            print(url)
           #with open('/Users/imv7/Documents/trabaio/Code/results/%s.json' % substring, 'a+') as file:
#          #     #file.write(url)
           #    file.write(pretty_servidor)
           #    file.close()
           #    sleep(randint(1,3))

except:
    print("Deu um erro aqui", url)