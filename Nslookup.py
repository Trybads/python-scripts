# Updated 12/20/2019
# author: mbland
'''
This script takes a text file of domains and runs nslookup, pulls MX and SPF records, and then checks for common subdomains(mail./vpn./ftp.).
Remove any subdomains or www., http://, or https:// from the begining of the domains in the file.

File should look like: lookup.txt
google.com
github.com

Usage:
Enter a filename: <enter file name>
Do you want to search for common subdomains? <Enter y or n>

The search for common subdomain runs nslookup on about 60 subdomains and returns found results.
Note: Some domains redirect all traffic, so sometimes it will find results for every subdomain, but they will all have the same ip.

Outputs to html file.
'''
import os
import re
import time

while True:
    file = input("Enter a filename: ")
    try:
        file = open(file,'r')
        break
    except FileNotFoundError:
        print("File by that name not found.")
    
start = time.time()

file = file.readlines()
file = [j.strip() for j in file]
l = len(file) - 1
i = 0
output = open("NslookupMXspf.html","w+")
counter = 0

while True:
    subdomain = input("Do you want to search for common subdomains?")
    subdomain = subdomain.lower()
    if subdomain == 'y':
        break
    elif subdomain == 'n':
        break
    print("Enter 'y' or 'n'")

sub = ["autodiscover", "remote", "blog", "autodetect", "webmail", "email", "mail", "mail1", "mail2", "mail3", "mail4", "mail5", "owa", "secure", "vpn", "sslvpn", "ns", "ns1", "ns2", "ns3", "ns4", "server", "smtp", "m", "shop", "ftp", "test", "host", "support", "dev", "mx", "cloud", "forum", "admin", "store", "exchange", "news", "abc", "access360", "360", "365", "office", "access", "afs", "applications", "auth", "wp", "wpex", "login", "home", "loan", "apply", "cardfinder", "homeloan", "carloan", "onlinebanking", "mobile", "mobileapp", "mobilemail", "ms", "vsp", "online", "mac", "conf", "conf1", "conf2", "awc", "vsg", "fact", "public", "private", "info"]

output.write("<p> </p>\n")
output.write("<style>")
output.write("table, th, td {border: 1px solid black; border-collapse: collapse;}")
output.write("</style>")
output.write("<html>\n<body>\n")

while i <= l: #loops through domains
    print("1") #testing exe
    op = []
    op2 = []
    op3 = []
    domain = file[i]
    print("2") #testing exe
    result = os.popen('nslookup ' + domain).read()#runs nslookup command
    print("3") #testing exe
    op = result.split()
    spf = os.popen('nslookup -type=TXT ' + domain).read()#spf lookup command
    op2 = spf.splitlines()    
    z = 0  
    found = False
    second = False
    output.write("<h2>"+domain+"</h2>\n<table>\n") #prints domain name
    mx = os.popen('nslookup -q=MX ' + domain).read() #MX lookup command
    op3 = mx.splitlines()#start MX Record
    output.write("<tr><th bgcolor=\"#B7CEEC\">MX Record</th></tr>") #mx table heading
    for x in op3: 
        if domain in x:
            output.write("<tr><td>" + str(x) + "\n</td></tr>") #end MX Record   
    output.write("<tr><th bgcolor=\"#B7CEEC\">SPF Record</th></tr>") #SPF table heading
    for x in op2: #start finding spf record
        if len(x) >= 3:
            if x[2] == 'v' or x[2] == 'V': #Edited to accept capital and lower......................
                output.write("<tr><td>" + str(x) + "\n</td>")
                if x[-5] == '-':
                    output.write("<tr><td>Set to -all : Fail\n</td></tr>")
                if x[-5] == '~':
                    output.write("<tr><td>Set to ~all : Soft Fail\n</td></tr>")   
                if x[-5] == '+':
                    output.write("<tr><td>Set to +all : Pass\n</td></tr>")#ends finding spf record
    output.write("</table>\n</br>")
    output.write("<table>\n")
    output.write("<tr><th bgcolor=\"#B7CEEC\">Domain/Subdomain</th><th bgcolor=\"#B7CEEC\">IP/Alias</th></tr>") #domain table headings
    for x in op: #finding IPs from nslookup
        if found == False and second == True:
            train = str(op[z+1:])
            train = re.sub('\'', '', train)
            train = re.sub('\[', '', train)
            train = re.sub('\]', '', train)
            if x == "Address:":
                output.write("<tr><td>"+domain+"</td><td>"+ train+"</td></tr>\n")
                counter += 1
                found = True
            elif x == "Addresses:":
                output.write("<tr><td>" + domain + "</td><td>"+ train +"</td></tr>\n") 
                counter += 1
                found = True
        if x == "Address:":
            second = True            
        z += 1 #ends main domain nslookup
    if subdomain == 'y':
        for m in sub: #start sub domains
            op = []
            check = []
            result = os.popen('nslookup ' + m + "." + domain).read()
            op = result.split()
            z = 0
            found = False
            second = False
            for v in op:          
                if found == False and second == True:
                    if v == "Address:":
                        check.extend(op[z+1:])
                        counter += 1
                        found = True                  
                    elif v == "Addresses:":
                        check.extend(op[z+1:])
                        counter += 1
                        found = True               
                if v == "Address:":
                    second = True            
                z += 1 #end sub domains
            for w in check:
                pos = check.index(w) #
                checking = check[pos].split('.') #removes periods from IPs
                checking[:] = [''.join(checking[:])] #joins numbers together to be checked
                try:
                    int(checking[0]) #checks if string is int
                except:
                    check.remove(w) #removes non int strings
            if check != []:
                car = str(check)
                car = re.sub('\'', '', car)
                car = re.sub('\[', '', car)
                car = re.sub('\]', '', car)                 
                output.write("<tr><td>" + m + "." + domain + "</td><td>"+ car + "</td></tr>\n")
    i += 1
    output.write("</table>\n")
output.write("</body>\n</html>")
output.close()
end = time.time()
print("DONE!")
print("Found", counter,"sub/domains in", end - start, "seconds.")

directory = os.getcwd()
import webbrowser
ie = webbrowser.get(webbrowser.iexplore)
ie.open(directory+'\\NslookupMXspf.html')