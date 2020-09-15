# -*- coding: utf-8 -*-
"""
Created on Mon Jan 23 11:05:01 2017

@author: MJS
updated by: mb
"""

import sys
import urllib, json
import time

if (len(sys.argv) < 2):
    print("")
    print("")
    print("This script loads an IP file with one IP address per line and searches Shodan IO")
    print("for Open Ports and IP location. ")
    print("Copy results by highligting the table, pressing ctrl-c, and then pasting into Word using Keep Source Formating.")
    print("")
    print("NOTE: Run this script from the director with the .nessus file")
    print("")
    print("Use:  python c:\<path>\ShodanLookup.py <IPfile.txt>")
    print("")
    print("The script will create <IPfiletxt.html> and then try to open the new file in IE.")
    sys.exit()

inputfile = sys.argv[1]
outputfile = "ShodanIO"+ sys.argv[1].replace(".","")+".html"

with open(inputfile) as f:
    lines = f.readlines()

IPs = []
for line in lines:
    line = line.strip()
    if line.find("-")>0 :
        (startingip, lastoct) = line.split("-")
        (firstoct, secondoct, thirdoct, fourthoct) = startingip.split(".")
        for fourthoct in range(int(fourthoct),int(lastoct)+1):
            IPs.append(firstoct+"."+secondoct+"."+thirdoct+"."+str(fourthoct))
    else:
        IPs.append(line)
    
    
fout = open(outputfile,"w")
fout.write("<p> </p>\n")
fout.write("<h1>Shodan Scan</h1>\n")
fout.write("<table>\n")
fout.write("<tr><th>IP</th><th>Open Ports</th><th>City</th><th>Country</th><th>isp</th></tr>\n")


dataStr = ""
for line in IPs:
    try:
        line = line.strip()
        
        url = "https://api.shodan.io/shodan/host/"+line+"?key=Z6vlj0sfFPV95tcAp1d00WCmhxmtPxDg"
        response = urllib.urlopen(url)
        data = json.loads(response.read())
        
        
        print(line)
        print json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))
        dataStr = dataStr + "<br><p><b>"+line+"</b></p><p>" + json.dumps(data, sort_keys=True, indent=4, separators=(',', ': ')).replace("<","&lt;").replace(">","&gt;").replace(" ","&nbsp;").replace("\n","<br>") + "</p>"
        print("")
        print("")
        
        if (data.has_key("ip_str")):
            fout.write("<tr><td>"+data["ip_str"]+"</td>")
        else:
            fout.write("<tr><td>"+line+"</td>")
        
        if (data.has_key("ports")):
            fout.write("<td>")
            for item in sorted(data["ports"]):
                fout.write(str(item)+", ")
            fout.write("</td>")
        else:
            fout.write("<td></td>")
            
        if (data.has_key("city")):
            fout.write("<td>"+data["city"]+"</td>")
        else:
            fout.write("<td></td>")
            
        if (data.has_key("country_code")):
            fout.write("<td>"+data["country_code"]+"</td>")
        else:
            fout.write("<td></td>")
        
        if (data.has_key("isp")):
            fout.write("<td>"+data["isp"]+"</td></tr>")
        else:
            fout.write("<td></td></tr>\n")
            
        time.sleep(10)
    except:
        e = sys.exc_info()[0]
        print ("ERROR OCCURED - skipping "+line)
        print (e)
        
    
        
fout.write("</table>\n")
fout.write(dataStr)
 
fout.close()

print("")
print("File saved: "+outputfile)
print("")
print("Opening IE to display file")

import os
directory = os.getcwd()
import webbrowser
ie = webbrowser.get(webbrowser.iexplore)
ie.open(directory+'\\'+outputfile)