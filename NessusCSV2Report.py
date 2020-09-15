#updated by: mb

import sys

if (len(sys.argv) < 2):
    print("")
    print("")
    print("Usage: python NessusCSV2Report.py {NessusCSVfile.csv}")
    print("")
    print("This script will create Open Port Tables and convert any vulnerability with a Risk != None into a format that can be copied into an Exit Meeting or Report and then EDITED.")
	
import csv
import re

PluginID = 0
CVE = 1
CVSS = 2
Risk = 3
Host = 4
Protocol = 5
Port = 6
Name = 7 
Synopsis = 8
Description = 9 
Solution = 10 
PluginOutput = 12

inputfile = sys.argv[1]
outputhtml = sys.argv[1].replace(".","")+".html"

f = open(inputfile, 'rb')
reader = csv.reader(f)
vuls = []
TCPdict = {}   # Dictionary Key = host Value = List of Ports (strings)
SYNdict = {}
Servicedict = {}
HOSTdict = {}
skip = reader.next()
#vuls[0][CVE]=''
#print vuls[0]
for row in reader:
    row[CVE] = ''  # Remove CVEs
    if row[Risk] != 'None' :            # Build vulnerability List vuls
        skip = False
        for vul in vuls:
            if row == vul : skip = True   # Skip duplicates
        if skip == False : vuls.append(row)
    if row[PluginID] == '10335' :        # Build TCP Scanner Open Port Dictionary
        if TCPdict.has_key(row[Host]) :  # Add another port to an existing IP address in TCPdict
            TCPdict[row[Host]].append(int(row[Port]))
        else :
            TCPdict[row[Host]] = [int(row[Port])]  #Create a new IP in TCPdict and add open port
    if row[PluginID] == '11935' :        # ADD UDP 500 to TCP SCAN dict
        if TCPdict.has_key(row[Host]) :  # Add another port to an existing IP address in TCPdict
            TCPdict[row[Host]].append(int(row[Port]))
        else :
            TCPdict[row[Host]] = [int(row[Port])]  #Create a new IP in TCPdict and add open port    
    if row[PluginID] == '11219' :        # Build SYN Scanner Open Port Dictionary
        if SYNdict.has_key(row[Host]) :  # Add another port to an existing IP address in SYNdict
            SYNdict[row[Host]].append(int(row[Port]))
        else :
            SYNdict[row[Host]] = [row[Port]]  #Create a new IP in SYNdict and add open port            
    if row[PluginID] == '22964' :        # Build Service Scanner Open Port Dictionary
        if Servicedict.has_key(row[Host]) :  # Add another port to an existing IP address in Servicedict
            Servicedict[row[Host]].append(int(row[Port]))
        else :
            Servicedict[row[Host]] = [int(row[Port])]  #Create a new IP in Servicedict and add open port          
    if row[PluginID] == '46180' :        # Build TCP Scanner Open Port Dictionary
        if HOSTdict.has_key(row[Host]) :  # Add another port to an existing IP address in TCPdict
            Descrip = row[PluginOutput].split("point to the remote host :\n  -",1)[1]  # Keep lines after "point to the remote host :"
            Descrip = Descrip.replace("\n  -","<br>",99)
            Descrip = Descrip.replace("\n","<br>",99)
            HOSTdict[row[Host]].append(Descrip)
        else :
            Descrip = row[PluginOutput].split("point to the remote host :\n  -",1)[1]  # Keep lines after "point to the remote host :"
            Descrip = Descrip.replace("\n  -","<br>",99)
            Descrip = Descrip.replace("\n","<br>",99)
            HOSTdict[row[Host]] = [Descrip]  #Create a new IP in TCPdict and add open port




            
IPs = 0
Text = 1
Output = 2
Rec = 3
Plugin = 4
CVS = 5
dict = {}
for vul in vuls:
    if dict.has_key(vul[Name]) : 
        dict[vul[Name]][IPs].append(vul[Host] + ':' + vul[Port])
        dict[vul[Name]][Output].append(vul[Host] + ':' + vul[Port] + '<br>' + vul[PluginOutput])
    else :
        dict[vul[Name]] = [[vul[Host] + ':' + vul[Port]], vul[Description], [vul[Host] + ':' + vul[Port] +'<br> '+vul[PluginOutput]+'<br>'], vul[Solution], vul[PluginID], vul[CVSS]]

    
 
# Replace Contents of Text based on Plugin Number
for issue in dict:
    if dict[issue][Plugin] == "62694" :   # IKE Aggressive Mode
        dict[issue][Rec] = """Disable Aggressive Mode.
        Do not use Pre-Shared key for authentication.
        If using Pre-Shared key cannot be avoided, use very strong keys.
        If possible, only allow VPN connections from approved IP addresses."""
    if dict[issue][Plugin] == "51192" :   # SSL Certificate Cannot Be Trusted
        dict[issue][Text] = """The server's X.509 certificate does not have a signature from a known public certificate authority.
        This makes it more difficult for users to verify the authenticity and identity of the web server and could make it easier to carry out man-in-the-middle attacks."""
    if dict[issue][Plugin] == "42873" :   # SSL Medium Strength Cipher Suites Supported
        dict[issue][Text] = """The remote host supports the use of SSL ciphers that offer medium strength encryption.  Medium strength encryption includes key lengths between 64 bits and 112 bits, or the use of the 3DES encryption suite."""
    if dict[issue][Plugin] == "94437" :   # SSL 64-bit Block Size Cipher Suites Supported (SWEET32)
        dict[issue][Text] = """The remote host supports the use of a block cipher with 64-bit blocks in one or more cipher suites.  A man-in-the-middle attacker who has sufficient resources can exploit this vulnerability, via a 'birthday' attack, to detect a collision that leaks the XOR between the fixed secret and a known plaintext, allowing the disclosure of the secret text, such as secure HTTPS cookies, and possibly resulting in the hijacking of an authenticated session."""
    if dict[issue][Plugin] == "58751" :   # SSL/TLS Protocol Initialization Vector... BEAST
        dict[issue][Text] = """A vulnerability exists in SSL 3.0 and TLS 1.0 that could allow information disclosure if an attacker intercepts encrypted traffic served from an affected system.
        This test tries to establish an SSL/TLS remote connection using an affected SSL version and cipher suite and then solicits return data.  If returned application data is not fragmented with an empty or one-byte record, it is likely vulnerable."""
        dict[issue][Rec] = """Configure SSL/TLS servers to only use TLS 1.1 or TLS 1.2. \nConfigure SSL/TLS servers to only support cipher suites that do not use block ciphers."""
    if dict[issue][Plugin] == "10759" :   # Web Server HTTP Header Internal IP Disclosure
        dict[issue][Text] = """This may expose internal IP addresses that are usually hidden or masked behind a Network Address Translation (NAT) Firewall or proxy server. """
        dict[issue][Rec] = """Configure the web server so that it does not leak its internal IP address."""
    if dict[issue][Plugin] == "94437" or dict[issue][Plugin] == "42873" or dict[issue][Plugin] == "65821":  # Remove extra content from SSL 64-bit Block Size Cipher Suites or Medium Strength Output
        for i in range(0,len(dict[issue][Output])) :
            print dict[issue][Output][i]
            print " ------------- "
            dict[issue][Output][i] = re.sub("The fields above are :","",dict[issue][Output][i])
            dict[issue][Output][i] = re.sub("{OpenSSL ciphername}","",dict[issue][Output][i])
            dict[issue][Output][i] = re.sub("Kx={key exchange}","",dict[issue][Output][i])
            dict[issue][Output][i] = re.sub("Au={authentication}","",dict[issue][Output][i])
            dict[issue][Output][i] = re.sub("Enc={symmetric encryption method}","",dict[issue][Output][i])
            dict[issue][Output][i] = re.sub("Mac={message authentication code}","",dict[issue][Output][i])
            dict[issue][Output][i] = re.sub("{export flag}","",dict[issue][Output][i])
    
from collections import OrderedDict
dict = OrderedDict(sorted(dict.items(), key=lambda (k,v):v[CVS], reverse=True))    
 
fout = open(outputhtml,"w")
fout.write("""<html>
<head>
<style>
p {
    font-family:Cambria;
    margin: 0;
    padding: 0;
} 
</style>
</head>""")

# Print out Open Port Tables

fout.write("<h1>Open Ports</h1>\n")
fout.write("<div style='font-family:Cambria'>")

# Print TCP Table
fout.write("<h1>TCP Table - use this for report, but compare to others</h1>")
fout.write("<table style='width:600px;border: 1px solid black;border-collapse: collapse;font-family: cambria;'>")
fout.write("<tr style='background-color:darkorange;width:180px;'><th  style='border: 1px solid black;'>Live Hosts</th><th  style='border: 1px solid black;'>Detected Hostnames</th><th  style='border: 1px solid black;'>Open Ports</th></tr>")

# Sort the Dictiary
hosts = {}  #dictionary of IPvalue : key
count = 0
for key in TCPdict:
    IPvalue = key
    IPvalue = IPvalue.split('.')      # Use split to test for IP Address
    if len(IPvalue)==4 and int(IPvalue[0])<257:   #Test for IP Address    
        IPvalue = int(IPvalue[0])*16777216+int(IPvalue[1])*65536+int(IPvalue[2])*256+int(IPvalue[3])  #Convert IP to integer equivalent
        hosts[IPvalue]=key
    else:
        hosts[key]=key    # If not an IP create dictionary entry based on hostname

for sortedkey in sorted(hosts):
    key = hosts[sortedkey]
    if count%2 == 1 : style='background-color:#fbd4b4;'
    else : style='background-color:white;'
    fout.write("<tr style='"+style+"'>")    
    fout.write("<td style='border: 1px solid black;'>"+key+"</td>")
    if key in HOSTdict :
        fout.write("<td style='border: 1px solid black;'>"+HOSTdict[key][0]+"</td><td style='border: 1px solid black;'>")
    else : fout.write("<td style='border: 1px solid black;'>&nbsp;</td><td style='border: 1px solid black;'>") 
    #fout.write("<tr><td>"+key+"</td><td>")
    commalen = len(sorted(TCPdict[key]))
    commacount = 0
    for port in sorted(TCPdict[key]):
        fout.write(str(port))
        if commacount < commalen - 1 : fout.write(", ")
        commacount = commacount + 1
    fout.write("</td></tr>\n")
    count = count + 1
fout.write("</table>")
fout.write("<p>&nbsp; </p>")


# Print SYN Table
fout.write("<h1>SYN Table</h1>")
fout.write("<table style='width:600px;border: 1px solid black;border-collapse: collapse;font-family: cambria;'>")
fout.write("<tr style='background-color:darkorange;width:180px;'><th  style='border: 1px solid black;'>Live Hosts</th><th  style='border: 1px solid black;'>Open Ports</th></tr>")

# Sort the Dictiary
hosts = {}  #dictionary of IPvalue : key
count = 0
for key in SYNdict:
    IPvalue = key
    IPvalue = IPvalue.split('.')      # Use split to test for IP Address
    if len(IPvalue)==4 and int(IPvalue[0])<257:   #Test for IP Address    
        IPvalue = int(IPvalue[0])*16777216+int(IPvalue[1])*65536+int(IPvalue[2])*256+int(IPvalue[3])  #Convert IP to integer equivalent
        hosts[IPvalue]=key
    else:
        hosts[key]=key    # If not an IP create dictionary entry based on hostname

for sortedkey in sorted(hosts):
    key = hosts[sortedkey]
    if count%2 == 1 : style='background-color:#fbd4b4;'
    else : style='background-color:white;'
    fout.write("<tr style='"+style+"'>")    
    fout.write("<td style='border: 1px solid black;'>"+key+"</td><td style='border: 1px solid black;'>") 
    #fout.write("<tr><td>"+key+"</td><td>")
    commalen = len(sorted(SYNdict[key]))
    commacount = 0
    for port in sorted(SYNdict[key]):
        fout.write(str(port))
        if commacount < commalen - 1 : fout.write(", ")
        commacount = commacount + 1
    fout.write("</td></tr>\n")
    count = count + 1
fout.write("</table>")
fout.write("<p>&nbsp; </p>")


# Print Service Table
fout.write("<h1>Service Table</h1>")
fout.write("<table style='width:600px;border: 1px solid black;border-collapse: collapse;font-family: cambria;'>")
fout.write("<tr style='background-color:darkorange;width:180px;'><th  style='border: 1px solid black;'>Live Hosts</th><th  style='border: 1px solid black;'>Open Ports</th></tr>")

# Sort the Dictiary
hosts = {}  #dictionary of IPvalue : key
count = 0
for key in Servicedict:
    IPvalue = key
    IPvalue = IPvalue.split('.')      # Use split to test for IP Address
    if len(IPvalue)==4 and int(IPvalue[0])<257:   #Test for IP Address    
        IPvalue = int(IPvalue[0])*16777216+int(IPvalue[1])*65536+int(IPvalue[2])*256+int(IPvalue[3])  #Convert IP to integer equivalent
        hosts[IPvalue]=key
    else:
        hosts[key]=key    # If not an IP create dictionary entry based on hostname

for sortedkey in sorted(hosts):
    key = hosts[sortedkey]
    if count%2 == 1 : style='background-color:#fbd4b4;'
    else : style='background-color:white;'
    fout.write("<tr style='"+style+"'>")    
    fout.write("<td style='border: 1px solid black;'>"+key+"</td><td style='border: 1px solid black;'>") 
    #fout.write("<tr><td>"+key+"</td><td>")
    commalen = len(sorted(Servicedict[key]))
    commacount = 0
    for port in sorted(Servicedict[key]):
        fout.write(str(port))
        if commacount < commalen - 1 : fout.write(", ")
        commacount = commacount + 1
    fout.write("</td></tr>\n")
    count = count + 1
fout.write("</table>")
fout.write("<p>&nbsp; </p>")


# Print Hostname Table
fout.write("<h1>Hostname Table</h1>")
fout.write("<table style='width:600px;border: 1px solid black;border-collapse: collapse;font-family: cambria;'>")
fout.write("<tr style='background-color:darkorange;width:180px;'><th  style='border: 1px solid black;'>Live Hosts</th><th  style='border: 1px solid black;'>Open Ports</th></tr>")

# Sort the Dictiary
hosts = {}  #dictionary of IPvalue : key
count = 0
for key in HOSTdict:
    fout.write("<tr><td>"+key+"</td><td>"+str(HOSTdict[key])+"</td></tr>\n")
# for key in HOSTdict:
    # IPvalue = key
    # IPvalue = IPvalue.split('.')      # Use split to test for IP Address
    # if len(IPvalue)==4 and int(IPvalue[0])<257:   #Test for IP Address    
        # IPvalue = int(IPvalue[0])*16777216+int(IPvalue[1])*65536+int(IPvalue[2])*256+int(IPvalue[3])  #Convert IP to integer equivalent
        # hosts[IPvalue]=key
    # else:
        # hosts[key]=key    # If not an IP create dictionary entry based on hostname

# for sortedkey in sorted(hosts):
    # key = hosts[sortedkey]
    # if count%2 == 1 : style='background-color:#fbd4b4;'
    # else : style='background-color:white;'
    # fout.write("<tr style='"+style+"'>")    
    # fout.write("<td style='border: 1px solid black;'>"+key+"</td><td style='border: 1px solid black;'>") 
    # #fout.write("<tr><td>"+key+"</td><td>")
    # commalen = len(sorted(HOSTdict[key]))
    # commacount = 0
    # for port in sorted(HOSTdict[key]):
        # fout.write(str(port))
        # if commacount < commalen - 1 : fout.write(", ")
        # commacount = commacount + 1
    # fout.write("</td></tr>\n")
    # count = count + 1
fout.write("</table>")
fout.write("<p>&nbsp; </p>")

fout.write("<h1>Exit Meeting Bullets - Edit as required</h1>\n")
fout.write("<div style='font-family:Cambria'>")
for issue in dict:
    fout.write ("<p>"+issue + "</p>\n")
fout.write("<br><br></div>")
    
fout.write("<h1>Report Text</h1>\n")
fout.write("<div style='font-family:Cambria;'>")

for issue in dict:
    if len(dict[issue][IPs]) > 1 : fout.write ("<p><b>Hosts:</b> ")
    else : fout.write("<p><b>Host:</b> ")
    count = 1
    for host in dict[issue][IPs]:
        fout.write (host)
        if count < len(dict[issue][IPs]) : fout.write (", ")
        count = count + 1
    fout.write ("</p>\n")
    fout.write ("<p><b>Issue:</b> " + issue +"</p>\n<p>&nbsp; </p>\n")
    fout.write ("<p>"+dict[issue][Text].replace('\n','</p><p>&nbsp;</p><p>') + "</p>\n<p>&nbsp;</p>\n")
    fout.write ("<p><b>Output:</b></p>\n<p>")
    for out in dict[issue][Output]:
        out = out.replace('\n','</p><p>')
        fout.write (out+ "</p>\n<p>&nbsp;</p>\n")
    fout.write("</p>\n")
    if dict[issue][Rec].count('\n') < 1 :
        fout.write ("<p><b>Recommendation:</b> " + dict[issue][Rec].replace('\n','</p><p>') + "</p>\n<p>&nbsp;</p>\n<p>&nbsp;</p>\n<p>&nbsp;</p>\n")
    else :
        fout.write ("<p><b>Recommendations:</b></p>\n<p>" + dict[issue][Rec].replace('\n','</p><p>') + "</p>\n<p>&nbsp;</p>\n<p>&nbsp;</p>\n<p>&nbsp;</p>\n")
fout.write("<p> </p><p> </p>")
fout.write("</div>")

fout.write("<div style='font-family:Cambria'>")
fout.write("<h1>Sample Website Vulnerability Language - Use if non Nessus Tests warrant this language.</h1>\n")
fout.write("<p><b>Issue:</b> The {{website.com}} website does not have cache-control and pragma HTTP headers set to prevent browsers and proxies from caching content.(Low Risk)</p>\n<p>&nbsp;</p>\n")
fout.write("<p><b>Recommendation:</b> Whenever possible ensure the cache-control HTTP header is set with no-cache, no-store, must-revalidate, private; and that the pragma HTTP header is set with no-cache.</p>\n")
fout.write("<p>")


fout.write("<p><b>Issue:</b> The {{website.com}} website does not enable Web Browser Cross Site Scripting (XSS) Protection.(Low Risk)</p>\n<p>&nbsp;</p>\n")
fout.write("<p><b>Recommendation:</b> Ensure that the web browser's XSS filter is enabled, by setting the X-XSS-Protection HTTP response header to '1'.</p><p>&nbsp;</p>\n<p>&nbsp;</p>\n\n")
fout.write("<p>&nbsp;</p>\n")
fout.write("<p><b>Issue:</b> The {{website.com}} website does not set the HttpOnly flag for or secure flag for cookies.(Low Risk)</p>\n<p>&nbsp;</p>\n")
fout.write("<p><b>Recommendation:</b> Ensure that the HttpOnly flag and secure flag are set for all cookies.</p>\n<p>&nbsp;</p>\n")
fout.write("<p>&nbsp;</p>\n")

fout.write("<p><b>Issue:</b> The {{website.com}} website does not support https validation and encryption by default.(High Risk)</p><p>&nbsp;</p>\n")
fout.write("""<p>The Bank's website is not encrypted by default.  Although the user login form information may be transmitted securely to the online banking system, without the browser validation (green lock symbol near the URL) users have no way to validate that the website is truly the Bank's website and that the user login information is truly going to be encrypted without looking at the source code of the page.
Fraudsters could send emails to bank customers pointing to a malicious website that looks identical to the Bank's website.  Because the Bank's customers are not accustomed to validating the Bank's website via the green lock symbol next to the URL in the browser, they may not be able to spot the fraudulent site and may provide their online banking credentials.</p><p>&nbsp;</p>\n""")
fout.write("<p><b>Recommendation:</b> The Bank's website should automatically redirect from http:// to https:// with a valid SSL certificate and secure encryption protocols.</p><p>&nbsp;</p>\n")


fout.write("</div>")



fout.close()

print("")
print("File saved: "+outputhtml)
print("")
print("Opening IE to display file")

import os
directory = os.getcwd()
import webbrowser
ie = webbrowser.get(webbrowser.iexplore)
ie.open(directory+'\\'+outputhtml)
        
