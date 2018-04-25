# Created by Andrew Angrisani -- aangrisa@cisco.com
#
#
# Meant as a tool to help compare the efficacy of Umbrella vs Quad9
# PLEASE NOTE: Must have a restrictive policy created in Umbrella for the device or VM you intend to use.
# For more information on my DNSSEC validation check, see here: https://docs.menandmice.com/display/MM/How+to+test+DNSSEC+validation
#
# Tested in Python 2.7.x

import subprocess
import os
import signal
import csv
import re
import dns
import shlex
import urllib
import time
import json
from urllib2 import Request, urlopen, URLError, HTTPError

token = '' # Investigate API key

headers = {
    'Authorization': 'Bearer ' + token
}

print "Welcome to the Quad9 vs. Umbrella Domain Checker! This script will query Umbrella and Quad9's AnyCast addresses and determine whether either solution has blocked a given domain."
print "For Umbrella, please ensure you are using a device or VM that is tied to a restrictive Umbrella policy with the Intelligent Proxy enabled and all security categories enabled"

response = raw_input('Do you have multiple domains you would like to query? [Yes or No] ')

results = open("results.txt","w")

if response.lower() == "yes":
    log_file = raw_input('Enter the filename & extension: ') # Ask for the input filename

    input_file = open(log_file,"r") # designate the file to be parsed

    reader = csv.reader(input_file, delimiter=",")

    output = open("results.txt", "w")
    n = 1
    for row in reader:
        for domain in row:
            domain = domain.rstrip()
            
            print n,"- Domain: " , domain
            
            #Start Umbrella Domain Check
            process = subprocess.Popen(["nslookup", "-type=a", domain, "208.67.222.222"], stdout=subprocess.PIPE, shell=False)
            output = process.communicate()[0].split('\n')
            ip_arr = []
            for data in output:
                if 'Address' in data:
                    ip_arr.append(data.replace('Address: ',''))
            ip_arr.pop(0)
            results.write("%s - Domain: %s" % (n,domain) + '\n')
            if any("146.112" in s for s in ip_arr):
                print "    Umbrella Response: Blocked"
                results.write("    Umbrella Response: Blocked" + '\n')
                n = n + 1
                request = Request('https://investigate.api.umbrella.com/domains/categorization/' + domain + '?showLabels', headers=headers)
                fetch = urlopen(request)
                data = json.load(fetch)
                if data[domain]['security_categories']:
                    categories = '|'.join(data[domain]['security_categories'])
                    print "        Security Categories :: " , categories
                    results.write("        Security Categories :: %s" % categories + '\n')
                else:
                    print "        No Umbrella categories found."
                    results.write("        No Umbrella categories found." + '\n')
            elif any("185.60.84" in s for s in ip_arr):
                print "    Umbrella Response: Blocked"
                results.write("    Umbrella Response: Blocked" + '\n')
                n = n + 1
                request = Request('https://investigate.api.umbrella.com/domains/categorization/' + domain + '?showLabels', headers=headers)
                fetch = urlopen(request)
                data = json.load(fetch)
                if data[domain]['security_categories']:
                    categories = '|'.join(data[domain]['security_categories'])
                    print "        Security Categories :: " , categories
                    results.write("        Security Categories :: %s" % categories + '\n')
                else:
                    print "        No Umbrella categories found."
                    results.write("        No Umbrella categories found." + '\n')
            elif any("208.69.32" in s for s in ip_arr):
                print "    Umbrella Response: Blocked"
                results.write("    Umbrella Response: Blocked" + '\n')
                n = n + 1
                request = Request('https://investigate.api.umbrella.com/domains/categorization/' + domain + '?showLabels', headers=headers)
                fetch = urlopen(request)
                data = json.load(fetch)
                if data[domain]['security_categories']:
                    categories = '|'.join(data[domain]['security_categories'])
                    print "        Security Categories :: " , categories
                    results.write("        Security Categories :: %s" % categories + '\n')
                else:
                    print "        No Umbrella categories found."
                    results.write("        No Umbrella categories found." + '\n')
            elif any("208.67.216" in s for s in ip_arr):
                print "    Umbrella Response: Blocked"
                results.write("    Umbrella Response: Blocked" + '\n')
                n = n + 1
                request = Request('https://investigate.api.umbrella.com/domains/categorization/' + domain + '?showLabels', headers=headers)
                fetch = urlopen(request)
                data = json.load(fetch)
                if data[domain]['security_categories']:
                    categories = '|'.join(data[domain]['security_categories'])
                    print "        Security Categories :: " , categories
                    results.write("        Security Categories :: %s" % categories + '\n')
                else:
                    print "        No Umbrella categories found."
                    results.write("        No Umbrella categories found." + '\n')
            elif any("204.194.232" in s for s in ip_arr):
                print "    Umbrella Response: Blocked"
                results.write("    Umbrella Response: Blocked" + '\n')
                n = n + 1
                request = Request('https://investigate.api.umbrella.com/domains/categorization/' + domain + '?showLabels', headers=headers)
                fetch = urlopen(request)
                data = json.load(fetch)
                if data[domain]['security_categories']:
                    categories = '|'.join(data[domain]['security_categories'])
                    print "        Security Categories :: " , categories
                    results.write("        Security Categories :: %s" % categories + '\n')
                else:
                    print "        No Umbrella categories found."
                    results.write("        No Umbrella categories found." + '\n')
            elif any("67.215.64" in s for s in ip_arr):
                print "    Umbrella Response: Blocked"
                results.write("    Umbrella Response: Blocked" + '\n')
                n = n + 1
                request = Request('https://investigate.api.umbrella.com/domains/categorization/' + domain + '?showLabels', headers=headers)
                fetch = urlopen(request)
                data = json.load(fetch)
                if data[domain]['security_categories']:
                    categories = '|'.join(data[domain]['security_categories'])
                    print "        Security Categories :: " , categories
                    results.write("        Security Categories :: %s" % categories + '\n')
                else:
                    print "        No Umbrella categories found."
                    results.write("        No Umbrella categories found." + '\n')
            else:
                print "    Umbrella Response: Allowed"
                results.write("    Umbrella Response: Allowed" + '\n')
                n = n + 1

            #Start Quad9 Domain Check
            quad9 = urllib.urlopen("https://api.quad9.net/search/%s" % domain).read()
            blocked = re.findall('"blocked":true', quad9)
            time.sleep(0.5)
            if any('"blocked":true' in j for j in blocked):
                print "    Quad9 Response: Blocked"
                results.write("    Quad9 Response: Blocked" + '\n')
                attack = re.findall(r'"blocked_by":(.*?)}]}',quad9)
                print "        Quad9 Threat Information :: ", attack
                results.write("        Quad9 Threat Information :: %s" % attack + '\n')
            else:
                print "    Quad9 Response: Allowed"
                results.write("    Quad9 Response: Allowed" + '\n')
                
            # Start Norton ConnectSafe Domain Check
            output = []
            process = subprocess.Popen(["nslookup", "-type=a", domain, "199.85.126.10"], stdout=subprocess.PIPE)
            output = process.communicate()[0].split('\n')
            nip_arr = []
            for data in output:
                if 'Address' in data:
                    nip_arr.append(data.replace('Address: ',''))
                else:
                    nip_arr.append(data.replace(';; connection timed out;','No Server Found'))
            nip_arr.pop(0)
            if any("34.234.89" in s for s in nip_arr):
                print "    Norton ConnectSafe Response: Blocked"
                results.write("    Norton ConnectSafe Response: Blocked" + '\n')
            elif any("No Server Found" in s for s in nip_arr):
                print "    Norton ConnectSafe Response: No Server Found"
                results.write("    Norton ConnectSafe Response: No Server Found" + '\n')
            else:
                print "    Norton ConnectSafe Response: Allowed"
                results.write("    Norton ConnectSafe Response: Allowed" + '\n')

            # Check for DNSSEC Validation on domain
            cmd='dig @9.9.9.9 %s +dnssec' % domain
            proc=subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE)
            out,err=proc.communicate()
            dnssec = re.findall(r';; flags:(.*?);',out)
            if any("ad" in m for m in dnssec):
                print ""
                print "    **DNSSEC Validation Confirmed**"  + '\n'
                results.write('\n')
                results.write("    **DNSSEC Validation Confirmed**" + '\n' + '\n')
            else:
                print ""
                print"    **No DNSSEC Validation**"  + '\n'
                results.write('\n')
                results.write("    **No DNSSEC Validation**" + '\n' + '\n')

else:
    dm = raw_input('What domain would you like to query? ')
    
    print "Domain: ",dm
    
    process = subprocess.Popen(["nslookup", dm, "208.67.222.222"], stdout=subprocess.PIPE)
    output = process.communicate()[0].split('\n')
    ip_arr = []
    for data in output:
        if 'Address' in data:
            ip_arr.append(data.replace('Address: ',''))
    ip_arr.pop(0)

    if any("146.112" in s for s in ip_arr):
        print "    Umbrella Response: Blocked"
        request = Request('https://investigate.api.umbrella.com/domains/categorization/' + dm + '?showLabels', headers=headers)
        fetch = urlopen(request)
        data = json.load(fetch)
        if data[dm]['security_categories']:
            categories = '|'.join(data[dm]['security_categories'])
            print "        Security Categories :: " , categories
        else:
            print "        No Umbrella categories found."
    elif any("185.60.84" in s for s in ip_arr):
        print "    Umbrella Response: Blocked"
        request = Request('https://investigate.api.umbrella.com/domains/categorization/' + dm + '?showLabels', headers=headers)
        fetch = urlopen(request)
        data = json.load(fetch)
        if data[dm]['security_categories']:
            categories = '|'.join(data[dm]['security_categories'])
            print "        Security Categories :: " , categories
        else:
            print "        No Umbrella categories found."
    elif any("208.69.32" in s for s in ip_arr):
        print "    Umbrella Response: Blocked"
        request = Request('https://investigate.api.umbrella.com/domains/categorization/' + dm + '?showLabels', headers=headers)
        fetch = urlopen(request)
        data = json.load(fetch)
        if data[dm]['security_categories']:
            categories = '|'.join(data[dm]['security_categories'])
            print "        Security Categories :: " , categories
        else:
            print "        No Umbrella categories found."
    elif any("208.67.216" in s for s in ip_arr):
        print "    Umbrella Response: Blocked"
        request = Request('https://investigate.api.umbrella.com/domains/categorization/' + dm + '?showLabels', headers=headers)
        fetch = urlopen(request)
        data = json.load(fetch)
        if data[dm]['security_categories']:
            categories = '|'.join(data[dm]['security_categories'])
            print "        Security Categories :: " , categories
        else:
            print "        No Umbrella categories found."
    elif any("204.194.232" in s for s in ip_arr):
        print "    Umbrella Response: Blocked"
        request = Request('https://investigate.api.umbrella.com/domains/categorization/' + dm + '?showLabels', headers=headers)
        fetch = urlopen(request)
        data = json.load(fetch)
        if data[dm]['security_categories']:
            categories = '|'.join(data[dm]['security_categories'])
            print "        Security Categories :: " , categories
        else:
            print "        No Umbrella categories found."
    elif any("67.215.64" in s for s in ip_arr):
        print "    Umbrella Response: Blocked"
        request = Request('https://investigate.api.umbrella.com/domains/categorization/' + dm + '?showLabels', headers=headers)
        fetch = urlopen(request)
        data = json.load(fetch)
        if data[dm]['security_categories']:
            categories = '|'.join(data[dm]['security_categories'])
            print "        Security Categories :: " , categories
        else:
            print "        No Umbrella categories found."
    else:
        print "    Umbrella Response: Allowed"

    # Start Quad9 Domain Check
    quad9 = urllib.urlopen("https://api.quad9.net/search/%s" % dm).read()
    blocked = re.findall('"blocked":true', quad9)
    time.sleep(05) #Pause for X seconds so as not to overload Quad9 API
    if any('"blocked":true' in j for j in blocked):
        print "    Quad9 Response: Blocked"
        attack = re.findall(r'"blocked_by":(.*?)}]}',quad9)
        print "        Quad9 Threat Information :: ", attack
    else:
        print "    Quad9 Response: Allowed"
        results.write("    Quad9 Response: Allowed" + '\n')

    # Start Norton ConnectSafe Domain Check
    output = []
    process = subprocess.Popen(["nslookup", "-type=a", dm, "199.85.126.10"], stdout=subprocess.PIPE)
    output = process.communicate()[0].split('\n')
    ip_arr = []
    for data in output:
        if 'Address' in data:
            ip_arr.append(data.replace('Address: ',''))
        ip_arr.pop(0)
    if any("34.234.89" in s for s in ip_arr):
        print "    Norton ConnectSafe Response: Blocked"
        results.write("    Norton ConnectSafe Response: Blocked" + '\n')
    else:
        print "    Norton ConnectSafe Response: Allowed"
        results.write("    Norton ConnectSafe Response: Allowed" + '\n')

    # Check for DNSSEC Validation on domain
    cmd='dig @9.9.9.9 %s +dnssec' % dm
    proc=subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE)
    out,err=proc.communicate()
    dnssec = re.findall(r';; flags:(.*?);',out)
    if any("ad" in m for m in dnssec):
        print ""
        print "    **DNSSEC Validation Confirmed**"
    else:
        print ""
        print"    **No DNSSEC Validation**"

quit()