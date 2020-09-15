#!/usr/bin/env python
# Libtest Nessus File Helper 3.0
# Install: python -m pip install python-libnessus
# https://github.com/bmx0r/python-libnessus/
# To run: libtest.py --filename somefile.nessus > myresults.txt
# version 3.0   - Print out Authentication Failure Errors
#               - Print out SNMP found
#               - Print the top 10 High and Critical for the Report
# version 2.9   - Added Signature (Vista, SuperMicro)
# version 2.8   - Added Signature (Server 2016)
# version 2.7   - Added a function to create a summary of Local Admin accounts to speed up reviews
# version 2.6   - Added a function to do all the file cleanup, removed those from the other functions
# version 2.5   - Added Signatures(IBMi OS V7R3M0,FortiOS on Fortinet FortiGate,NetApp, HP 2424M Switch (J4093A) with software revision C.08.22)
# Version 2.4   - Added some Verbiage from Exit Document with Counts
# Version 2.3   - Added Credentialed Devices Count
# Version 2.2   - Added Citrix NetScaler to Signatures
# Version 2.1   - Added total Critical and High Counts for easier reporting
# Version 2.00  - Updated to Python 3.x
# Version 1.17  - Added Signatures (Linux Kernel 3, AXIS Network Camera, VxWorks)
# Version 1.16  - Added Total Device Count (hasn't been test much)
# Version 1.15  - Added Signatures (CISCO IP Telephone, HP 2848 Switch, HP OfficeJet Pro Printer, HP 2524 Switch)
# Version 1.14  - Added Signatures (HP Switch, AIX, None-Unknown)
# Version 1.13  - Fixed and Issue where if no Users in Admin group would break the script
# Version 1.12  - Fixed and Issue where a Scan with No Highs broke the script
# Version 1.11  - Added Signatures (NetBSD, Dell PowerConnect Switch, HP Integrated Lights Out,RICOH Printer)
# Version 1.10  - Added Signatures (Unix, Barracuda Spam)
# Version 1.9   - Fixed an Issue where a scan with NO CRITS (I know!) broke the script
# Version 1.8   - Fixed an Issue where some Items used commas and broke the script
# Version 1.7   - Added Signatures (IBMi OS V7R1M0, Buffalo TeraStation NAS, Linux Kernel 4.4 on Ubuntu 16.04 (xenial))
# Version 1.6   - Added Signature (NEC UNIVERGE)
# Version 1.5   -  Code Cleaup and Documented some areas
# Version 1.4   - Added More Signatures (SonicWALL, Cisco IOS 15)
# Version 1.3   - Added additional Signatures
# Version 1.2   - Added filtering to not sure OS's with 0
# Version 1.1   - Added additional Signatures

from libnessus.parser import NessusParser
from libnessus.plugins.backendpluginFactory import BackendPluginFactory
import glob
import argparse
from datetime import datetime
import operator
import csv
from collections import defaultdict
import os
import re
import fileinput

glob_Total_Devices         = 0
glob_Total_Windows_Systems = 0
glob_total_crit_vuln       = 0
glob_total_crit_hosts      = 0
glob_total_high_vuln       = 0
glob_total_high_hosts      = 0
glob_total_crit_high_hosts = 0
glob_Critial_Exploit_count = 0
glob_High_Exploit_count    = 0

parser = argparse.ArgumentParser(
    description='This script will work with .nessus')
parser.add_argument('--filename',
                    default="../libnessus/test/files/nessus*",
                    help="path or pattern to a nessusV2 xml")
args = parser.parse_args()

# Parse_nessus - Process the Operating Systems and Total Device Count
def parse_nessus(filename):
  index_settings = {u'mappings': {u'vulnerability': {u'properties': {u'host-fqdn': {u'type': u'string'},
      u'host_ip': {u'type': 'ip', "index" : "not_analyzed","doc_values": "true"},
      u'host_name': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'operating-system': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'scantime': {u'format': u'dateOptionalTime', u'type': u'date'},
      u'system-type': {u'type': u'string'},
      u'vulninfo': {u'properties': {u'apple-sa': {u'type': u'string'},
        u'bid': {u'type': u'string'},
        u'canvas_package': {u'type': u'string'},
        u'cert': {u'type': u'string'},
        u'cpe': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
        u'cve': {u'type': u'string'},
        u'cvss_base_score': {u'type': u'float'},
        u'cvss_temporal_score': {u'type': u'string'},
        u'cvss_temporal_vector': {u'type': u'string'},
        u'cvss_vector': {u'type': u'string'},
        u'cwe': {u'type': u'string'},
        u'd2_elliot_name': {u'type': u'string'},
        u'description': {u'type': u'string'},
        u'edb-id': {u'type': u'string'},
        u'exploit_available': {u'type': u'boolean'},
        u'exploit_framework_canvas': {u'type': u'string'},
        u'exploit_framework_core': {u'type': u'string'},
        u'exploit_framework_d2_elliot': {u'type': u'string'},
        u'exploit_framework_metasploit': {u'type': u'string'},
        u'exploitability_ease': {u'type': u'string'},
        u'exploited_by_malware': {u'type': u'string'},
        u'fname': {u'type': u'string'},
        u'iava': {u'type': u'string'},
        u'iavb': {u'type': u'string'},
        u'metasploit_name': {u'type': u'string'},
        u'osvdb': {u'type': u'string'},
        u'owasp': {u'type': u'string'},
        u'patch_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'pluginFamily': {u'type': u'string'},
        u'pluginID': {u'type': u'string'},
        u'pluginName': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
        u'plugin_modification_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'plugin_name': {u'type': u'string'},
        u'plugin_output': {u'type': u'string'},
        u'plugin_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'plugin_type': {u'type': u'string'},
        u'port': {u'type': u'string'},
        u'protocol': {u'type': u'string'},
        u'rhsa': {u'type': u'string'},
        u'risk_factor': {u'type': u'string'},
        u'script_version': {u'type': u'string'},
        u'secunia': {u'type': u'string'},
        u'see_also': {u'type': u'string'},
        u'severity': {u'type': u'integer'},
        u'solution': {u'type': u'string'},
        u'stig_severity': {u'type': u'string'},
        u'svc_name': {u'type': u'string'},
        u'synopsis': {u'type': u'string'},
        u'vuln_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'xref': {u'type': u'string'}}}}}}} 
  listfiles = args.filename

  Total_count = 0
  Total_WindowsSystems_count = 0
  Windows7_count = 0
  Windows_server_2008_count = 0
  Windows_xp_count = 0
  Windows_8_count = 0
  Windows_8_1_count = 0
  Windows_storage_server_count = 0
  Windows_server_2012_count = 0
  Windows_server_2003_count = 0
  Windows_xp_embedded_count = 0
  Microsoft_Windows_10_count = 0
  AXIS_Network_Camera_count = 0
  VMware_ESXi_count = 0
  Mac_OS_X_10_10_count = 0
  AppleTV_count = 0
  FortiOS_count = 0
  Linux_2_6_count = 0
  Linux_2_4_count = 0
  SBS_2011_count = 0
  OILOM_count = 0 #Oracle Integrated Lights Out Manager
  Solaris10_count = 0 #Solaris 10 (sparc)
  NortelSwitch_count = 0 #Nortel Switch
  CISCO_ASA_5500_count = 0
  CISCO_IPS_count = 0
  CISCO_IOS_12_4_count = 0
  CISCO_IOS_15_count = 0
  SonicWALL_count = 0
  NEC_UNIVERGE_count = 0
  IBMi_OS_V7R1M0_count = 0
  Buffalo_TeraStation_NAS_count = 0
  Linux_Ubuntu_1604_count = 0
  Unix_count = 0
  Barracuda_Spam_count = 0
  NetBSD_count = 0
  Dell_powerConnect_Switch_count = 0
  HP_Integrated_Lights_Out_count = 0
  RICOH_Printer_count = 0
  HP_Switch_count = 0
  AIX_count = 0
  None_count = 0
  CISCO_IP_Telephone_count = 0
  HP_2848_Switch_count = 0
  HP_OfficeJet_Pro_Printer_count = 0
  HP_2524_Switch_count = 0
  KYOCERA_Printer_count = 0
  ExtremeXOS_count = 0
  MSWindowsEmbedded_7_count = 0
  AXIS_count = 0
  Linux_3_count = 0
  VxWorks_count = 0
  Citrix_NetScaler_count = 0
  IBMi_count = 0
  FortiOS_count = 0
  NetApp_count = 0
  HP_2424M_count = 0
  Microsoft_Windows_Server_2016_Standard_count = 0
  Super_Micro_count = 0
  Windows_Vista_count = 0

  files = glob.glob(listfiles)
  for file in files:
      try:
          nessus_obj_list = NessusParser.parse_fromfile(file)
      except:
          print("file cannot be imported : %s" % file)
          continue
      for i in nessus_obj_list.hosts:
          docu = {}
          #docu['scantime'] = nessus_obj_list.endtime
          #docu['host_ip'] = i.ip
          #docu['host_name'] = i.name
          #docu['host-fqdn'] = i.get_host_property('host-fqdn')
          docu['operating-system'] = i.get_host_property('operating-system')
          #docu['system-type'] = i.get_host_property('system-type')
          # UNCOMMENT the line below to search for undocumented OS
          #print (str(docu['operating-system']) + ",1")
          #first_list = open('first_list3.csv', 'a').writelines(str(docu['operating-system']) + ",1\n")
          Total_count += 1
          if  'Microsoft Windows XP' in str(docu['operating-system']):
            if 'Microsoft Windows XP for Embedded Systems' in str(docu['operating-system']):
              Windows_xp_embedded_count +=1
            else:
              Windows_xp_count += 1
              Total_WindowsSystems_count += 1
          if 'Microsoft Windows 7' in str(docu['operating-system']):
            Windows7_count += 1
            Total_WindowsSystems_count += 1
          if 'Windows 8.0' in str(docu['operating-system']):
            Windows_8_count += 1
            Total_WindowsSystems_count += 1
          if 'Windows 8.1' in str(docu['operating-system']):
            Windows_8_1_count += 1
            Total_WindowsSystems_count += 1
          #Microsoft Windows 10 Pro
          if 'Microsoft Windows 10' in str(docu['operating-system']):
            Microsoft_Windows_10_count += 1
            Total_WindowsSystems_count += 1
          #Microsoft Windows Server 2008 R2 Standard Service Pack 1
          if 'Microsoft Windows Server 2008' in str(docu['operating-system']):
            Windows_server_2008_count += 1
            Total_WindowsSystems_count += 1
            #Microsoft Windows XP Professional Service Pack 3 (English)
                      #Microsoft Windows Storage Server 2008 Standard Service Pack 2
          if 'Microsoft Windows Storage Server' in str(docu['operating-system']):
            Windows_storage_server_count += 1
            Total_WindowsSystems_count += 1
            #Microsoft Windows Server 2012 Standard
          if 'Microsoft Windows Server 2012' in str(docu['operating-system']):
            Windows_server_2012_count += 1
            Total_WindowsSystems_count += 1 
            #Microsoft Windows Server 2003
          if 'Microsoft Windows Server 2003' in str(docu['operating-system']):
            Windows_server_2003_count += 1
            Total_WindowsSystems_count += 1  
          if 'Microsoft Windows Server 2016 Standard' in str(docu['operating-system']):
            Microsoft_Windows_Server_2016_Standard_count += 1
            Total_WindowsSystems_count += 1                   
          #AXIS Network Camera
          if 'AXIS Network Camera' in str(docu['operating-system']):
            AXIS_Network_Camera_count += 1
          #VMware ESXi
          if 'VMware ESXi' in str(docu['operating-system']):
            VMware_ESXi_count += 1
          #Mac OS X 10.10
          if 'Mac OS X 10.10' in str(docu['operating-system']):
            Mac_OS_X_10_10_count += 1
          #AppleTV (2nd or 3rd Generation)
          if 'AppleTV' in str(docu['operating-system']):
            AppleTV_count += 1
          #FortiOS on Fortinet FortiGate,1
          if 'FortiOS' in str(docu['operating-system']):
            FortiOS_count += 1
          #Linux Kernel 2.6,1
          if 'Linux Kernel 2.6' in str(docu['operating-system']):
            Linux_2_6_count += 1
          #Linux Kernel 2.4
          if 'Linux Kernel 2.4' in str(docu['operating-system']):
            Linux_2_4_count += 1
          if 'Microsoft Windows Small Business Server 2011' in str(docu['operating-system']):
            SBS_2011_count += 1
            Total_WindowsSystems_count += 1
          if 'Oracle Integrated Lights Out Manager' in str(docu['operating-system']):
            OILOM_count += 1
          if 'Solaris 10 (sparc)' in str(docu['operating-system']):
            Solaris10_count += 1
          if 'Nortel Switch' in str(docu['operating-system']):
            NortelSwitch_count += 1
          if 'CISCO ASA 5500' in str(docu['operating-system']):
            CISCO_ASA_5500_count += 1
          if 'CISCO IPS' in str(docu['operating-system']):
            CISCO_IPS_count += 1
          if 'CISCO IOS 12' in str(docu['operating-system']):
            CISCO_IOS_12_4_count += 1
          if 'CISCO IOS 15' in str(docu['operating-system']):
            CISCO_IOS_15_count += 1
          if 'SonicWALL' in str(docu['operating-system']):
            SonicWALL_count += 1
          if 'NEC UNIVERGE' in str(docu['operating-system']):
            NEC_UNIVERGE_count += 1
          if 'IBMi OS V7R1M0' in str(docu['operating-system']):
            IBMi_OS_V7R1M0_count += 1
          if 'Buffalo TeraStation NAS' in str(docu['operating-system']):
            Buffalo_TeraStation_NAS_count += 1
          if 'Linux Kernel 4.4 on Ubuntu 16.04 (xenial)' in str(docu['operating-system']):
            Linux_Ubuntu_1604_count += 1
          if 'Unix' in str(docu['operating-system']):
            Unix_count += 1
          if 'Barracuda Spam' in str(docu['operating-system']):
            Barracuda_Spam_count += 1
          if 'NetBSD' in str(docu['operating-system']):
            NetBSD_count += 1
          if 'Dell Powerconnect Switch' in str(docu['operating-system']):
            Dell_powerConnect_Switch_count += 1
          if 'HP Integrated Lights Out' in str(docu['operating-system']):
            HP_Integrated_Lights_Out_count += 1
          if 'RICOH Printer' in str(docu['operating-system']):
            RICOH_Printer_count += 1
          if 'HP Switch' in str(docu['operating-system']):
            HP_Switch_count += 1
          if 'AIX' in str(docu['operating-system']):
            AIX_count += 1
          if 'CISCO IP Telephone' in str(docu['operating-system']):
            CISCO_IP_Telephone_count += 1
          if 'HP 2848 Switch' in str(docu['operating-system']):
            HP_2848_Switch_count += 1
          if 'HP OfficeJet Pro Printer' in str(docu['operating-system']):
            HP_OfficeJet_Pro_Printer_count += 1
          if 'HP 2524 Switch' in str(docu['operating-system']):
            HP_2524_Switch_count += 1
          if 'KYOCERA Printer' in str(docu['operating-system']):
            KYOCERA_Printer_count += 1
          if 'ExtremeXOS' in str(docu['operating-system']):
            ExtremeXOS_count += 1
          if 'Microsoft Windows Embedded Standard 7' in str(docu['operating-system']):
            MSWindowsEmbedded_7_count += 1
          if 'AXIS' in str(docu['operating-system']):
            AXIS_count += 1
          if 'Linux Kernel 3.' in str(docu['operating-system']):
            Linux_3_count += 1
          if 'VxWorks' in str(docu['operating-system']):
            VxWorks_count += 1
          if 'Citrix NetScaler'in str(docu['operating-system']):
            Citrix_NetScaler_count += 1
          if 'IBMi OS'in str(docu['operating-system']):
            IBMi_count += 1
          if 'FortiOS'in str(docu['operating-system']):
            FortiOS_count += 1
          if 'NetApp'in str(docu['operating-system']):
            NetApp_count += 1
          if 'HP 2424M Switch'in str(docu['operating-system']):
            HP_2424M_count += 1 
          if 'Super Micro'in str(docu['operating-system']):
            Super_Micro_count += 1
          if 'Microsoft Windows Vista'in str(docu['operating-system']):
            Windows_Vista_count += 1
            Total_WindowsSystems_count += 1  
          if 'None' in str(docu['operating-system']):
            None_count += 1

  print ("-------------------------")
  print (" Total Devices:         " + str(Total_count))
  print (" Total Windows Devices: " + str(Total_WindowsSystems_count))
  global glob_Total_Devices,glob_Total_Windows_Systems
  glob_Total_Devices = Total_count
  glob_Total_Windows_Systems = Total_WindowsSystems_count
  print ("-------------------------")
  if Windows_xp_count > 0:
    print ("Windows XP:             "             + str(Windows_xp_count))
  if Windows_xp_embedded_count > 0:
    print ("Windows XP Embedded:    "    + str(Windows_xp_embedded_count))
  if  Windows_Vista_count > 0:
    print ("Windows Vista :         "           + str(Windows_Vista_count))
  if  Windows7_count > 0:
    print ("Windows 7:              "              + str(Windows7_count))
  if  Windows_8_count > 0:
    print ("Windows 8:              "              + str(Windows_8_count))
  if  Windows_8_1_count > 0:
    print ("Windows 8.1:            "            + str(Windows_8_1_count))
  if  Microsoft_Windows_10_count > 0:
    print ("Windows 10:             "             + str(Microsoft_Windows_10_count))
  if  Windows_server_2003_count > 0:
    print ("Windows Server 2003:    "    + str(Windows_server_2003_count))
  if  Windows_server_2008_count> 0:
    print ("Windows Server 2008:    "    + str(Windows_server_2008_count))
  if  Windows_storage_server_count > 0:
    print ("Windows Storage Server: " + str(Windows_storage_server_count))
  if  Windows_server_2012_count > 0:
    print ("Windows Server 2012:    "    + str(Windows_server_2012_count))
  if  SBS_2011_count > 0:
    print ("Windows SBS 2011:       "       + str(SBS_2011_count))
  if  Microsoft_Windows_Server_2016_Standard_count > 0:
    print ("Windows Server 2016 Standard: "       + str(Microsoft_Windows_Server_2016_Standard_count))
  if  AXIS_Network_Camera_count > 0:
    print ("AXIS Network Camera: "    + str(AXIS_Network_Camera_count))
  if  VMware_ESXi_count > 0:
    print ("VMware ESXi: "            + str(VMware_ESXi_count))
  if  Mac_OS_X_10_10_count > 0:
    print ("Mac OS X 10.10: "         + str(Mac_OS_X_10_10_count))
  if  AppleTV_count > 0:
    print ("AppleTV: "                + str(AppleTV_count))
  if  FortiOS_count > 0:
    print ("FortiOS: "                + str(FortiOS_count))
  if  Linux_2_6_count > 0:
    print ("Linux Kernel 2.6: "       + str(Linux_2_6_count))
  if  Linux_2_4_count > 0:
    print ("Linux Kernel 2.4: "       + str(Linux_2_4_count))
  if  Linux_3_count > 0:
    print ("Linux Kernal 3.x : "           + str(Linux_3_count))
  if  Linux_Ubuntu_1604_count > 0:
    print ("Linux Kernel 4.4 on Ubuntu 16.04 (xenial): "           + str(Linux_Ubuntu_1604_count))
  if  OILOM_count > 0:
    print ("Oracle Integrated Lights Out Manager: "       + str(OILOM_count))
  if  Solaris10_count > 0:
    print ("Solaris 10 (sparc): "     + str(Solaris10_count))
  if  NortelSwitch_count > 0:
    print ("Nortel Switch: "          + str(NortelSwitch_count))
  if  CISCO_ASA_5500_count > 0:  
    print ("CISCO ASA 5500: "         + str(CISCO_ASA_5500_count))
  if  CISCO_IPS_count > 0:
    print ("CISCO IPS: "              + str(CISCO_IPS_count))
  if  CISCO_IOS_12_4_count > 0:
    print ("CISCO IOS 12.x: "         + str(CISCO_IOS_12_4_count))
  if  CISCO_IOS_15_count > 0:
    print ("CISCO IOS 15: "           + str(CISCO_IOS_15_count))
  if  SonicWALL_count > 0:
    print ("SonicWALL: "              + str(SonicWALL_count))
  if  NEC_UNIVERGE_count > 0:
    print ("NEC UNIVERGE: "           + str(NEC_UNIVERGE_count))
  if  IBMi_OS_V7R1M0_count > 0:
    print ("IBMi OS V7R1M0: "           + str(IBMi_OS_V7R1M0_count))
  if  Buffalo_TeraStation_NAS_count > 0:
    print ("Buffalo TeraStation NAS: "           + str(Buffalo_TeraStation_NAS_count))
  if  Unix_count > 0:
    print ("Unix: "           + str(Unix_count))
  if  Barracuda_Spam_count > 0:
    print ("Barracuda Spam and Virus Firewall: "           + str(Barracuda_Spam_count))
  if  NetBSD_count > 0:
    print ("NetBSD: "           + str(NetBSD_count))
  if  Dell_powerConnect_Switch_count > 0:
    print ("Dell PowerConnect Switch: "           + str(Dell_powerConnect_Switch_count))
  if  HP_Integrated_Lights_Out_count > 0:
    print ("HP Integrated Lights Out: "           + str(HP_Integrated_Lights_Out_count))
  if  RICOH_Printer_count > 0:
    print ("RICOH Printer: "           + str(RICOH_Printer_count))
  if  HP_Switch_count > 0:
    print ("HP Switch: "           + str(HP_Switch_count))
  if  AIX_count > 0:
    print ("AIX : "           + str(AIX_count))
  if  CISCO_IP_Telephone_count > 0:
    print ("CISCO IP Telephone : "           + str(CISCO_IP_Telephone_count))
  if  HP_2848_Switch_count > 0:
    print ("HP 2848 Switch : "           + str(HP_2848_Switch_count))
  if  HP_OfficeJet_Pro_Printer_count > 0:
    print ("HP OfficeJet Pro Printer : "           + str(HP_OfficeJet_Pro_Printer_count))
  if  HP_2524_Switch_count > 0:
    print ("HP 2524 Switch : "           + str(HP_2524_Switch_count))
  if  KYOCERA_Printer_count > 0:
    print ("KYOCERA Printer : "           + str(KYOCERA_Printer_count))
  if  ExtremeXOS_count > 0:
    print ("ExtremeXOS Network Operating System : "           + str(ExtremeXOS_count))
  if  MSWindowsEmbedded_7_count > 0:
    print ("Microsoft Windows Embedded Standard 7 : "           + str(MSWindowsEmbedded_7_count))
  if  AXIS_count > 0:
    print ("AXIS Network Camera : "           + str(AXIS_count))
  if  VxWorks_count > 0:
    print ("VxWorks : "           + str(VxWorks_count))
  if  Citrix_NetScaler_count > 0:
    print ("Citrix NetScaler : "           + str(Citrix_NetScaler_count))
  if  IBMi_count > 0:
    print ("IBMi : "           + str(IBMi_count))
  if  FortiOS_count > 0:
    print ("FortiOS : "           + str(FortiOS_count))
  if  NetApp_count > 0:
    print ("NetApp : "           + str(NetApp_count))
  if  Super_Micro_count > 0:
    print ("Super Micro : "           + str(Super_Micro_count)) 
  if  HP_2424M_count > 0:
    print ("HP 2424M Switch : "           + str(HP_2424M_count))            
  if  None_count > 0:
    print ("None - Unknown : "           + str(None_count))
  print ("-------------------------")  
# Parse_nessus2 - Process the Critcal and High Rated
def parse_nessus2(filename):
  #print "Starting Total Crit Vuln: " + str(total_crit_vuln)
  index_settings = {u'mappings': {u'vulnerability': {u'properties': {u'host-fqdn': {u'type': u'string'},
      u'host_ip': {u'type': 'ip', "index" : "not_analyzed","doc_values": "true"},
      u'host_name': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'operating-system': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'scantime': {u'format': u'dateOptionalTime', u'type': u'date'},
      u'system-type': {u'type': u'string'},
      u'vulninfo': {u'properties': {u'apple-sa': {u'type': u'string'},
        u'bid': {u'type': u'string'},
        u'canvas_package': {u'type': u'string'},
        u'cert': {u'type': u'string'},
        u'cpe': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
        u'cve': {u'type': u'string'},
        u'cvss_base_score': {u'type': u'float'},
        u'cvss_temporal_score': {u'type': u'string'},
        u'cvss_temporal_vector': {u'type': u'string'},
        u'cvss_vector': {u'type': u'string'},
        u'cwe': {u'type': u'string'},
        u'd2_elliot_name': {u'type': u'string'},
        u'description': {u'type': u'string'},
        u'edb-id': {u'type': u'string'},
        u'exploit_available': {u'type': u'boolean'},
        u'exploit_framework_canvas': {u'type': u'string'},
        u'exploit_framework_core': {u'type': u'string'},
        u'exploit_framework_d2_elliot': {u'type': u'string'},
        u'exploit_framework_metasploit': {u'type': u'string'},
        u'exploitability_ease': {u'type': u'string'},
        u'exploited_by_malware': {u'type': u'string'},
        u'fname': {u'type': u'string'},
        u'iava': {u'type': u'string'},
        u'iavb': {u'type': u'string'},
        u'metasploit_name': {u'type': u'string'},
        u'osvdb': {u'type': u'string'},
        u'owasp': {u'type': u'string'},
        u'patch_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'pluginFamily': {u'type': u'string'},
        u'pluginID': {u'type': u'string'},
        u'pluginName': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
        u'plugin_modification_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'plugin_name': {u'type': u'string'},
        u'plugin_output': {u'type': u'string'},
        u'plugin_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'plugin_type': {u'type': u'string'},
        u'port': {u'type': u'string'},
        u'protocol': {u'type': u'string'},
        u'rhsa': {u'type': u'string'},
        u'risk_factor': {u'type': u'string'},
        u'script_version': {u'type': u'string'},
        u'secunia': {u'type': u'string'},
        u'see_also': {u'type': u'string'},
        u'severity': {u'type': u'integer'},
        u'solution': {u'type': u'string'},
        u'stig_severity': {u'type': u'string'},
        u'svc_name': {u'type': u'string'},
        u'synopsis': {u'type': u'string'},
        u'vuln_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'xref': {u'type': u'string'}}}}}}} 
  total_crit_hosts = 0
  total_crit_vuln = 0
  total_high_hosts = 0
  total_high_vuln = 0
  total_crit_high_hosts = 0
  listfiles = args.filename
  files = glob.glob(listfiles)
  for file in files:
      try:
          nessus_obj_list = NessusParser.parse_fromfile(file)
      except:
          print("file cannot be imported : %s" % file)
          continue
      for i in nessus_obj_list.hosts:
          docu = {}
          for v in i.get_report_items:
              docu['host_ip'] = i.ip
              docu['vulninfo'] = v.get_vuln_info
              docu['risk_factor'] = v.get_vuln_info[('risk_factor')]
              docu['plugin_name'] = v.get_vuln_info[('plugin_name')]
              docu['plugin_name'] = docu['plugin_name'].replace(",", " ")
              #Critical
              if 'Critical' in str(docu['risk_factor']):
                 crit_list = open('crit_list.csv', 'a').writelines(str(docu['plugin_name']) + ",1\n")
                 crit_host_list = open('crit_host_list.csv', 'a').writelines(str(docu['host_ip']) + ",1\n")
                 crit_high_host_list = open('crit_high_host_list.csv', 'a').writelines(str(docu['host_ip']) + ",1\n")
              #High
              if 'High' in str(docu['risk_factor']):
                 high_list = open('high_list.csv', 'a').writelines(str(docu['plugin_name']) + ",1\n")
                 high_host_list = open('high_host_list.csv', 'a').writelines(str(docu['host_ip']) + ",1\n")
                 crit_high_host_list = open('crit_high_host_list.csv', 'a').writelines(str(docu['host_ip']) + ",1\n")
  if os.path.isfile('crit_list.csv'):
    print ("----------Critical-----------")
    data = defaultdict(list)
    for i, row in enumerate(csv.reader(open('crit_list.csv', 'r'))): #changed rb to r
        plugin_name, crit_count = row
        data[plugin_name].append(float(crit_count))   
    for plugin_name, crit_count in data.items(): #dict.iteritems -> dict.items
        #crit_list2.csv Contains Total Number of Items
        crit_list2 = open('crit_list2.csv', 'a').writelines(str(int(sum(crit_count))) + ","+str(plugin_name)+"\n")
        total_crit_vuln +=1
        reader = csv.reader(open("crit_list2.csv"), delimiter=",")
        sorted_lines = sorted(reader,key=lambda x: int(x[0]), reverse=True)
    for x in sorted_lines:
      print (x[0] + " Instances of " + x[1])
      with open('crit_list3.csv', 'w') as myfile: #change wb to w
        wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)
        wr.writerow(x)
    #print ("-------Total Unique Critical Vuln: " + str(total_crit_vuln) + "-------"  )
  else:
    print ("-------No Critical-------")
  #----START Calculate Total Crit Hosts and Vulns
  if os.path.isfile('crit_host_list.csv'):
    data = defaultdict(list)
    for i, row in enumerate(csv.reader(open('crit_host_list.csv', 'r'))): #changed rb to r
        plugin_name, crit_count = row
        data[plugin_name].append(float(crit_count))   
    for plugin_name, crit_count in data.items(): #dict.iteritems -> dict.items
        #crit_list2.csv Contains Total Number of Items
        crit_list2 = open('crit_host_list2.csv', 'a').writelines(str(int(sum(crit_count))) + ","+str(plugin_name)+"\n")
        total_crit_hosts +=1
        reader = csv.reader(open("crit_host_list2.csv"), delimiter=",")
        sorted_lines = sorted(reader,key=lambda x: int(x[0]), reverse=True)
    print ("-------Total Critical Hosts:       " + str(total_crit_hosts) + "-------"  ) 
    print ("-------Total Unique Critical Vuln: " + str(total_crit_vuln) + "-------"  )
    global glob_total_crit_vuln, glob_total_crit_hosts
    glob_total_crit_vuln = str(total_crit_vuln)
    glob_total_crit_hosts = total_crit_hosts
  else:
    print ("\n")
  #----END Calculate Total Crit Hosts and Vulns
  if os.path.isfile('high_list.csv'):
    print   ("----------HIGH-----------")
    data = defaultdict(list)
    for i, row in enumerate(csv.reader(open('high_list.csv', 'r'))): #rb to r
      plugin_name, high_count = row
      data[plugin_name].append(float(high_count))   
    for plugin_name, high_count in data.items():#items
      high_list2 = open('high_list2.csv', 'a').writelines(str(int(sum(high_count))) + ","+str(plugin_name)+"\n")
      total_high_vuln +=1
      reader = csv.reader(open('high_list2.csv'), delimiter=",")
      sorted_lines = sorted(reader,key=lambda x: int(x[0]), reverse=True)
    for x in sorted_lines:
      print (x[0] + " Instances of " + x[1])
      with open('high_list3.csv', 'w') as myfile: #wb to w
        wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)
        wr.writerow(x)
    os.remove('high_list.csv')
    os.rename('high_list3.csv', 'high_list.csv')
  else:
    print ("-------No HIGH-----------")
  #----START Calculate Total High Hosts and Vulns
  if os.path.isfile('high_host_list.csv'):
    data = defaultdict(list)
    for i, row in enumerate(csv.reader(open('high_host_list.csv', 'r'))): #changed rb to r
        plugin_name, high_count = row
        data[plugin_name].append(float(high_count))   
    for plugin_name, high_count in data.items(): #dict.iteritems -> dict.items
        #crit_list2.csv Contains Total Number of Items
        high_list2 = open('high_host_list2.csv', 'a').writelines(str(int(sum(high_count))) + ","+str(plugin_name)+"\n")
        total_high_hosts +=1
        reader = csv.reader(open("high_host_list2.csv"), delimiter=",")
        sorted_lines = sorted(reader,key=lambda x: int(x[0]), reverse=True)
    print ("-------Total High Hosts:       " + str(total_high_hosts) + "-------"  ) 
    print ("-------Total Unique High Vuln: " + str(total_high_vuln) + "-------"  )
    global glob_total_high_vuln, glob_total_high_hosts
    glob_total_high_vuln = str(total_high_vuln)
    glob_total_high_hosts = total_high_hosts
  else:
    print ("\n")
  #----END Calculate Total High Hosts and Vulns
  #----START Calculate Total Crit + High Hosts
  if os.path.isfile('crit_high_host_list.csv'):
    data = defaultdict(list)
    for i, row in enumerate(csv.reader(open('crit_high_host_list.csv', 'r'))): #changed rb to r
        plugin_name, high_count = row
        data[plugin_name].append(float(high_count))   
    for plugin_name, high_count in data.items(): #dict.iteritems -> dict.items
        crit_high_list2 = open('crit_high_host_list2.csv', 'a').writelines(str(int(sum(high_count))) + ","+str(plugin_name)+"\n")
        total_crit_high_hosts +=1
    print ("-------Total Crit + High Hosts:       " + str(total_crit_high_hosts) + "-------"  )
    global glob_total_crit_high_hosts
    glob_total_crit_high_hosts = str(total_crit_high_hosts) 
  else:
    print ("\n")
  #----END Calculate Total Crit + High Hosts
# Parse_nessus3 - Process the Local Windows Administators
def parse_nessus3(filename):
  #################################################################
  # a_list.csv - Starts as the full Admin block of TXT from Nessus
  # The following users are members of the 'Administrators' group :
  #  - SARA-PC\Administrator (User)
  #- SARA-PC\Comproom (User)
  #
  # admin_list.csv - Temp List of Admin Users - With Blank Lines
  # Used as a holder before it gets cleaned up
  #################################################################
  index_settings = {u'mappings': {u'vulnerability': {u'properties': {u'host-fqdn': {u'type': u'string'},
      u'host_ip': {u'type': 'ip', "index" : "not_analyzed","doc_values": "true"},
      u'host_name': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'operating-system': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'scantime': {u'format': u'dateOptionalTime', u'type': u'date'},
      u'system-type': {u'type': u'string'},
      u'vulninfo': {u'properties': {u'apple-sa': {u'type': u'string'},
        u'bid': {u'type': u'string'},
        u'canvas_package': {u'type': u'string'},
        u'cert': {u'type': u'string'},
        u'cpe': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
        u'cve': {u'type': u'string'},
        u'cvss_base_score': {u'type': u'float'},
        u'cvss_temporal_score': {u'type': u'string'},
        u'cvss_temporal_vector': {u'type': u'string'},
        u'cvss_vector': {u'type': u'string'},
        u'cwe': {u'type': u'string'},
        u'd2_elliot_name': {u'type': u'string'},
        u'description': {u'type': u'string'},
        u'edb-id': {u'type': u'string'},
        u'exploit_available': {u'type': u'boolean'},
        u'exploit_framework_canvas': {u'type': u'string'},
        u'exploit_framework_core': {u'type': u'string'},
        u'exploit_framework_d2_elliot': {u'type': u'string'},
        u'exploit_framework_metasploit': {u'type': u'string'},
        u'exploitability_ease': {u'type': u'string'},
        u'exploited_by_malware': {u'type': u'string'},
        u'fname': {u'type': u'string'},
        u'iava': {u'type': u'string'},
        u'iavb': {u'type': u'string'},
        u'metasploit_name': {u'type': u'string'},
        u'osvdb': {u'type': u'string'},
        u'owasp': {u'type': u'string'},
        u'patch_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'pluginFamily': {u'type': u'string'},
        u'pluginID': {u'type': u'string'},
        u'pluginName': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
        u'plugin_modification_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'plugin_name': {u'type': u'string'},
        u'plugin_output': {u'type': u'string'},
        u'plugin_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'plugin_type': {u'type': u'string'},
        u'port': {u'type': u'string'},
        u'protocol': {u'type': u'string'},
        u'rhsa': {u'type': u'string'},
        u'risk_factor': {u'type': u'string'},
        u'script_version': {u'type': u'string'},
        u'secunia': {u'type': u'string'},
        u'see_also': {u'type': u'string'},
        u'severity': {u'type': u'integer'},
        u'solution': {u'type': u'string'},
        u'stig_severity': {u'type': u'string'},
        u'svc_name': {u'type': u'string'},
        u'synopsis': {u'type': u'string'},
        u'vuln_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'xref': {u'type': u'string'}}}}}}} 
  listfiles = args.filename
  files = glob.glob(listfiles)
         
  for file in files:
      try:
          nessus_obj_list = NessusParser.parse_fromfile(file)
      except:
          print("file cannot be imported : %s" % file)
          continue
      for i in nessus_obj_list.hosts:
          docu = {}
          docu2 = {}
          docu2['host_ip'] = i.ip
          docu3 = {}
          docu3['host-fqdn'] = i.name
          for v in i.get_report_items:
              docu['vulninfo'] = v.get_vuln_info
              docu['risk_factor'] =   v.get_vuln_info[('risk_factor')]
              docu['plugin_name'] =   v.get_vuln_info[('plugin_name')]
              # In Nessus - Microsoft Windows 'Administrators' Group User List
              if "Microsoft Windows 'Administrators'" in str(docu['plugin_name']):
                a_list = open('a_list.csv', 'a').writelines(str(v.get_vuln_info[('plugin_output')]))
                # if you need to print an ip address to link ot admin accounts you can uncomment this
                # NOTE: You'll need to manually process your results
                #print (str(v.get_vuln_info[('plugin_output')]) + str(docu2['host_ip']))
                #print (str(v.get_vuln_info[('plugin_output')]) + str(docu2['host_ip']) + ' ' + str(docu3['host-fqdn']))
  if os.path.isfile('a_list.csv'):
    print ("-The following users are members of the 'Administrators' group-")
    data = defaultdict(list)
    #################################
    # open the csv file and iterate over its rows. the enumerate()
    # Then Remove text that isn't needed
    # close the csv file
    # Write the txt to a new CSV file
    # close the new csv file
    cvs_file = open('a_list.csv', 'r')
    cvs_line = cvs_file.read()
    cvs_line_sub = re.sub("The following users are members of the 'Administrators' group :", "", cvs_line, count=0, flags=0)
    cvs_file.close()
    cvs_file_new = open('admin_list.csv','a') #ab to b
    cvs_file_new.write(cvs_line_sub)
    cvs_file_new.close()
    #################################
    # Still processing out un needed info
    cvs_file = open('admin_list.csv', 'r')
    cvs_line = cvs_file.read()
    cvs_line_sub = re.sub("\n", ",1\n", cvs_line, count=0, flags=0)
    cvs_file.close()
    cvs_file_new = open('a_list.csv','w')
    cvs_file_new.write(cvs_line_sub)
    #print cvs_line_sub # Uncomment for Debug Help
    cvs_file_new.close()
    ##################################
    # Cleanup the CVS lines Mess
    for i, row in enumerate(csv.reader(open('a_list.csv', 'r'))):#rb to r
      # unpack the columns into local variables
      plugin_name, crit_count = row
      # for each adminaccount, add the level the list
      data[plugin_name].append(float(crit_count))   
    for plugin_name, crit_count in data.items():#change
      a_list2 = open('a_list2.csv', 'a').writelines(str(int(sum(crit_count))) + ","+str(plugin_name)+"\n")
    reader = csv.reader(open("a_list2.csv"), delimiter=",")    
    sorted_lines = sorted(reader,key=lambda x: int(x[0]), reverse=True)
    for x in sorted_lines:
      print (x[1])
      with open('crit_list3.csv', 'w') as cvs_file: #wb to b
        wr = csv.writer(cvs_file, quoting=csv.QUOTE_ALL)
        wr.writerow(x)
  else:
    print ("-- No users are members of the 'Administrators' group --")
# Parse_nessus4 - Process the Number of Credentialed Checks
def parse_nessus4(filename):
  index_settings = {u'mappings': {u'vulnerability': {u'properties': {u'host-fqdn': {u'type': u'string'},
      u'host_ip': {u'type': 'ip', "index" : "not_analyzed","doc_values": "true"},
      u'host_name': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'operating-system': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'scantime': {u'format': u'dateOptionalTime', u'type': u'date'},
      u'system-type': {u'type': u'string'},
      u'vulninfo': {u'properties': {u'apple-sa': {u'type': u'string'},
        u'bid': {u'type': u'string'},
        u'canvas_package': {u'type': u'string'},
        u'cert': {u'type': u'string'},
        u'cpe': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
        u'cve': {u'type': u'string'},
        u'cvss_base_score': {u'type': u'float'},
        u'cvss_temporal_score': {u'type': u'string'},
        u'cvss_temporal_vector': {u'type': u'string'},
        u'cvss_vector': {u'type': u'string'},
        u'cwe': {u'type': u'string'},
        u'd2_elliot_name': {u'type': u'string'},
        u'description': {u'type': u'string'},
        u'edb-id': {u'type': u'string'},
        u'exploit_available': {u'type': u'boolean'},
        u'exploit_framework_canvas': {u'type': u'string'},
        u'exploit_framework_core': {u'type': u'string'},
        u'exploit_framework_d2_elliot': {u'type': u'string'},
        u'exploit_framework_metasploit': {u'type': u'string'},
        u'exploitability_ease': {u'type': u'string'},
        u'exploited_by_malware': {u'type': u'string'},
        u'fname': {u'type': u'string'},
        u'iava': {u'type': u'string'},
        u'iavb': {u'type': u'string'},
        u'metasploit_name': {u'type': u'string'},
        u'osvdb': {u'type': u'string'},
        u'owasp': {u'type': u'string'},
        u'patch_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'pluginFamily': {u'type': u'string'},
        u'pluginID': {u'type': u'string'},
        u'pluginName': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
        u'plugin_modification_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'plugin_name': {u'type': u'string'},
        u'plugin_output': {u'type': u'string'},
        u'plugin_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'plugin_type': {u'type': u'string'},
        u'port': {u'type': u'string'},
        u'protocol': {u'type': u'string'},
        u'rhsa': {u'type': u'string'},
        u'risk_factor': {u'type': u'string'},
        u'script_version': {u'type': u'string'},
        u'secunia': {u'type': u'string'},
        u'see_also': {u'type': u'string'},
        u'severity': {u'type': u'integer'},
        u'solution': {u'type': u'string'},
        u'stig_severity': {u'type': u'string'},
        u'svc_name': {u'type': u'string'},
        u'synopsis': {u'type': u'string'},
        u'vuln_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'xref': {u'type': u'string'}}}}}}} 
  listfiles = args.filename

  Total_count = 0 # Total Devices Scaned
  True_count  = 0 # Devices Scanned with Credentials
  False_count = 0 # Devices Scanned without Credentials

  files = glob.glob(listfiles)
  for file in files:
      try:
          nessus_obj_list = NessusParser.parse_fromfile(file)
      except:
          print("file cannot be imported : %s" % file)
          continue
      for i in nessus_obj_list.hosts:
          docu = {}
          docu['Credentialed_Scan'] = i.get_host_property('Credentialed_Scan')    
          if 'true' in str(docu['Credentialed_Scan']):
                 #print(str(docu['Credentialed_Scan']) + "\n")
                 True_count +=1
          else:
            False_count += 1
          Total_count += 1     
  print ("---------------------------")
  print (" Total Devices:          " + str(Total_count))
  print (" Total Windows Devices:  " + str(glob_Total_Windows_Systems))
  print (" Credentialed Count:     " + str(True_count))
  print (" Non-Credentialed Count: " + str(False_count))
  print ("---------------------------")
# Parse_nessus5 - Process the Number of Critical Rated with Exploits
def parse_nessus5(filename):
  index_settings = {u'mappings': {u'vulnerability': {u'properties': {u'host-fqdn': {u'type': u'string'},
      u'host_ip': {u'type': 'ip', "index" : "not_analyzed","doc_values": "true"},
      u'host_name': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'operating-system': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'scantime': {u'format': u'dateOptionalTime', u'type': u'date'},
      u'system-type': {u'type': u'string'},
      u'vulninfo': {u'properties': {u'apple-sa': {u'type': u'string'},
        u'bid': {u'type': u'string'},
        u'canvas_package': {u'type': u'string'},
        u'cert': {u'type': u'string'},
        u'cpe': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
        u'cve': {u'type': u'string'},
        u'cvss_base_score': {u'type': u'float'},
        u'cvss_temporal_score': {u'type': u'string'},
        u'cvss_temporal_vector': {u'type': u'string'},
        u'cvss_vector': {u'type': u'string'},
        u'cwe': {u'type': u'string'},
        u'd2_elliot_name': {u'type': u'string'},
        u'description': {u'type': u'string'},
        u'edb-id': {u'type': u'string'},
        u'exploit_available': {u'type': u'boolean'},
        u'exploit_framework_canvas': {u'type': u'string'},
        u'exploit_framework_core': {u'type': u'string'},
        u'exploit_framework_d2_elliot': {u'type': u'string'},
        u'exploit_framework_metasploit': {u'type': u'string'},
        u'exploitability_ease': {u'type': u'string'},
        u'exploited_by_malware': {u'type': u'string'},
        u'fname': {u'type': u'string'},
        u'iava': {u'type': u'string'},
        u'iavb': {u'type': u'string'},
        u'metasploit_name': {u'type': u'string'},
        u'osvdb': {u'type': u'string'},
        u'owasp': {u'type': u'string'},
        u'patch_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'pluginFamily': {u'type': u'string'},
        u'pluginID': {u'type': u'string'},
        u'pluginName': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
        u'plugin_modification_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'plugin_name': {u'type': u'string'},
        u'plugin_output': {u'type': u'string'},
        u'plugin_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'plugin_type': {u'type': u'string'},
        u'port': {u'type': u'string'},
        u'protocol': {u'type': u'string'},
        u'rhsa': {u'type': u'string'},
        u'risk_factor': {u'type': u'string'},
        u'script_version': {u'type': u'string'},
        u'secunia': {u'type': u'string'},
        u'see_also': {u'type': u'string'},
        u'severity': {u'type': u'integer'},
        u'solution': {u'type': u'string'},
        u'stig_severity': {u'type': u'string'},
        u'svc_name': {u'type': u'string'},
        u'synopsis': {u'type': u'string'},
        u'vuln_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'xref': {u'type': u'string'}}}}}}} 
  listfiles = args.filename
  Critial_Exploit_count = 0 # Total Devices Scaned
  if os.path.exists('crit_exploit_list.csv'):
        os.remove('crit_exploit_list.csv')
  files = glob.glob(listfiles)
  for file in files:
      try:
          nessus_obj_list = NessusParser.parse_fromfile(file)
      except:
          print("file cannot be imported : %s" % file)
          continue
      # exploit_available

      for i in nessus_obj_list.hosts: # 
          docu = {}     
          for v in i.get_report_items:
               if 'exploit_available' in v.get_vuln_info:
                if 'true' in v.get_vuln_info[('exploit_available')]:
                  docu['exploit_available']       = v.get_vuln_info[('exploit_available')]
                  if 'Critical' in v.get_vuln_info[('risk_factor')]:                   
                    docu['plugin_name'] = v.get_vuln_info[('plugin_name')]
                    docu['plugin_name'] = docu['plugin_name'].replace(",", " ")
                    crit_exploit_list = open('crit_exploit_list.csv', 'a').writelines(str(docu['plugin_name']) + ",1\n")
  if os.path.isfile('crit_exploit_list.csv'):
    print ("----------Critical With Exploit-----------")
    data = defaultdict(list)
    for i, row in enumerate(csv.reader(open('crit_exploit_list.csv', 'r'))):
        plugin_name, crit_count = row
        data[plugin_name].append(float(crit_count))   
    for plugin_name, crit_count in data.items():
        crit_list2 = open('crit_exploit_list2.csv', 'a').writelines(str(int(sum(crit_count))) + ","+str(plugin_name)+"\n")
        reader = csv.reader(open("crit_exploit_list2.csv"), delimiter=",")
        sorted_lines = sorted(reader,key=lambda x: int(x[0]), reverse=True)
    for x in sorted_lines:
      Critial_Exploit_count += 1
      print (x[0] + " Instances of " + x[1])
      with open('crit_exploit_list3.csv', 'w') as myfile:
        wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)
        wr.writerow(x) 
  global glob_Critial_Exploit_count
  glob_Critial_Exploit_count = Critial_Exploit_count
  print ("---------------------------")
  print (" Critical w Exploit: " + str(Critial_Exploit_count))
  print ("---------------------------")
  # End Process the Number of Critical Rated with Exploits ###
# Parse_nessus6 - Process the Number of High Rated with Exploits
def parse_nessus6(filename):
  index_settings = {u'mappings': {u'vulnerability': {u'properties': {u'host-fqdn': {u'type': u'string'},
      u'host_ip': {u'type': 'ip', "index" : "not_analyzed","doc_values": "true"},
      u'host_name': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'operating-system': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'scantime': {u'format': u'dateOptionalTime', u'type': u'date'},
      u'system-type': {u'type': u'string'},
      u'vulninfo': {u'properties': {u'apple-sa': {u'type': u'string'},
        u'bid': {u'type': u'string'},
        u'canvas_package': {u'type': u'string'},
        u'cert': {u'type': u'string'},
        u'cpe': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
        u'cve': {u'type': u'string'},
        u'cvss_base_score': {u'type': u'float'},
        u'cvss_temporal_score': {u'type': u'string'},
        u'cvss_temporal_vector': {u'type': u'string'},
        u'cvss_vector': {u'type': u'string'},
        u'cwe': {u'type': u'string'},
        u'd2_elliot_name': {u'type': u'string'},
        u'description': {u'type': u'string'},
        u'edb-id': {u'type': u'string'},
        u'exploit_available': {u'type': u'boolean'},
        u'exploit_framework_canvas': {u'type': u'string'},
        u'exploit_framework_core': {u'type': u'string'},
        u'exploit_framework_d2_elliot': {u'type': u'string'},
        u'exploit_framework_metasploit': {u'type': u'string'},
        u'exploitability_ease': {u'type': u'string'},
        u'exploited_by_malware': {u'type': u'string'},
        u'fname': {u'type': u'string'},
        u'iava': {u'type': u'string'},
        u'iavb': {u'type': u'string'},
        u'metasploit_name': {u'type': u'string'},
        u'osvdb': {u'type': u'string'},
        u'owasp': {u'type': u'string'},
        u'patch_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'pluginFamily': {u'type': u'string'},
        u'pluginID': {u'type': u'string'},
        u'pluginName': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
        u'plugin_modification_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'plugin_name': {u'type': u'string'},
        u'plugin_output': {u'type': u'string'},
        u'plugin_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'plugin_type': {u'type': u'string'},
        u'port': {u'type': u'string'},
        u'protocol': {u'type': u'string'},
        u'rhsa': {u'type': u'string'},
        u'risk_factor': {u'type': u'string'},
        u'script_version': {u'type': u'string'},
        u'secunia': {u'type': u'string'},
        u'see_also': {u'type': u'string'},
        u'severity': {u'type': u'integer'},
        u'solution': {u'type': u'string'},
        u'stig_severity': {u'type': u'string'},
        u'svc_name': {u'type': u'string'},
        u'synopsis': {u'type': u'string'},
        u'vuln_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'xref': {u'type': u'string'}}}}}}} 
  listfiles = args.filename
  High_Exploit_count = 0 # Total Devices Scaned
  if os.path.exists('high_exploit_list.csv'):
        os.remove('high_exploit_list.csv')
  files = glob.glob(listfiles)
  for file in files:
      try:
          nessus_obj_list = NessusParser.parse_fromfile(file)
      except:
          print("file cannot be imported : %s" % file)
          continue
      # exploit_available

      for i in nessus_obj_list.hosts: # 
          docu = {}     
          for v in i.get_report_items:
               if 'exploit_available' in v.get_vuln_info:
                if 'true' in v.get_vuln_info[('exploit_available')]:
                  docu['exploit_available']       = v.get_vuln_info[('exploit_available')]
                  if 'High' in v.get_vuln_info[('risk_factor')]:
                    docu['plugin_name'] = v.get_vuln_info[('plugin_name')]
                    docu['plugin_name'] = docu['plugin_name'].replace(",", " ")
                    crit_exploit_list = open('high_exploit_list.csv', 'a').writelines(str(docu['plugin_name']) + ",1\n")
  if os.path.isfile('high_exploit_list.csv'):
    print ("----------High With Exploit-----------")
    data = defaultdict(list)
    for i, row in enumerate(csv.reader(open('high_exploit_list.csv', 'r'))):
        plugin_name, high_count = row
        data[plugin_name].append(float(high_count))   
    for plugin_name, high_count in data.items():
        high_list2 = open('high_exploit_list2.csv', 'a').writelines(str(int(sum(high_count))) + ","+str(plugin_name)+"\n")
        reader = csv.reader(open("high_exploit_list2.csv"), delimiter=",")
        sorted_lines = sorted(reader,key=lambda x: int(x[0]), reverse=True)
    for x in sorted_lines:
      High_Exploit_count += 1
      print (x[0] + " Instances of " + x[1])
      with open('high_exploit_list3.csv', 'w') as myfile:
        wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)
        wr.writerow(x) 
  global glob_High_Exploit_count
  glob_High_Exploit_count = High_Exploit_count
  print ("---------------------------")
  print (" High w Exploit: " + str(High_Exploit_count))
  print ("---------------------------")
  # End Process the Number of High Rated with Exploits ###
# Parse_nessus7 - Process the Local Windows Administators - Summarized
def parse_nessus7(filename):
  #################################################################
  # a_list.csv - Starts as the full Admin block of TXT from Nessus
  # The following users are members of the 'Administrators' group :
  #  - SARA-PC\Administrator (User)
  #- SARA-PC\Comproom (User)
  #
  # admin_list.csv - Temp List of Admin Users - With Blank Lines
  # Used as a holder before it gets cleaned up
  #################################################################
  index_settings = {u'mappings': {u'vulnerability': {u'properties': {u'host-fqdn': {u'type': u'string'},
      u'host_ip': {u'type': 'ip', "index" : "not_analyzed","doc_values": "true"},
      u'host_name': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'operating-system': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'scantime': {u'format': u'dateOptionalTime', u'type': u'date'},
      u'system-type': {u'type': u'string'},
      u'vulninfo': {u'properties': {u'apple-sa': {u'type': u'string'},
        u'bid': {u'type': u'string'},
        u'canvas_package': {u'type': u'string'},
        u'cert': {u'type': u'string'},
        u'cpe': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
        u'cve': {u'type': u'string'},
        u'cvss_base_score': {u'type': u'float'},
        u'cvss_temporal_score': {u'type': u'string'},
        u'cvss_temporal_vector': {u'type': u'string'},
        u'cvss_vector': {u'type': u'string'},
        u'cwe': {u'type': u'string'},
        u'd2_elliot_name': {u'type': u'string'},
        u'description': {u'type': u'string'},
        u'edb-id': {u'type': u'string'},
        u'exploit_available': {u'type': u'boolean'},
        u'exploit_framework_canvas': {u'type': u'string'},
        u'exploit_framework_core': {u'type': u'string'},
        u'exploit_framework_d2_elliot': {u'type': u'string'},
        u'exploit_framework_metasploit': {u'type': u'string'},
        u'exploitability_ease': {u'type': u'string'},
        u'exploited_by_malware': {u'type': u'string'},
        u'fname': {u'type': u'string'},
        u'iava': {u'type': u'string'},
        u'iavb': {u'type': u'string'},
        u'metasploit_name': {u'type': u'string'},
        u'osvdb': {u'type': u'string'},
        u'owasp': {u'type': u'string'},
        u'patch_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'pluginFamily': {u'type': u'string'},
        u'pluginID': {u'type': u'string'},
        u'pluginName': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
        u'plugin_modification_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'plugin_name': {u'type': u'string'},
        u'plugin_output': {u'type': u'string'},
        u'plugin_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'plugin_type': {u'type': u'string'},
        u'port': {u'type': u'string'},
        u'protocol': {u'type': u'string'},
        u'rhsa': {u'type': u'string'},
        u'risk_factor': {u'type': u'string'},
        u'script_version': {u'type': u'string'},
        u'secunia': {u'type': u'string'},
        u'see_also': {u'type': u'string'},
        u'severity': {u'type': u'integer'},
        u'solution': {u'type': u'string'},
        u'stig_severity': {u'type': u'string'},
        u'svc_name': {u'type': u'string'},
        u'synopsis': {u'type': u'string'},
        u'vuln_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'xref': {u'type': u'string'}}}}}}} 
  listfiles = args.filename
  files = glob.glob(listfiles)
         
  for file in files:
      try:
          nessus_obj_list = NessusParser.parse_fromfile(file)
      except:
          print("file cannot be imported : %s" % file)
          continue
      for i in nessus_obj_list.hosts:
          docu = {}
          for v in i.get_report_items:
              docu['vulninfo'] = v.get_vuln_info
              docu['plugin_name'] =   v.get_vuln_info[('plugin_name')]
              # In Nessus - Microsoft Windows 'Administrators' Group User List
              if "Microsoft Windows 'Administrators'" in str(docu['plugin_name']):
                # a_list33.csv -   - FARMERS\administrator (User),1
                a_list = open('summary_admin_list_1.csv', 'a').writelines(str(v.get_vuln_info[('plugin_output')]))
  if os.path.isfile('summary_admin_list_1.csv'):
    data = defaultdict(list)
    #################################
    # open the csv file and iterate over its rows. the enumerate()
    # Then Remove text that isn't needed
    # close the csv file
    # Write the txt to a new CSV file
    # close the new csv file
    cvs_file = open('summary_admin_list_1.csv', 'r')
    cvs_line = cvs_file.read()
    cvs_line_sub = re.sub("The following users are members of the 'Administrators' group :", "", cvs_line, count=0, flags=0)
    cvs_line_sub = re.sub(".*?\\\\", "", cvs_line, count=0, flags=0)
    cvs_file.close()
    ### admin_list33.csv   - FARMERS\administrator (User) - Also Includes Blank Lines
    cvs_file_new = open('summary_admin_list_2.csv','a') #ab to b
    cvs_file_new.write(cvs_line_sub)
    cvs_file_new.close()
    #################################
    # Still processing out un needed info
    cvs_file = open('summary_admin_list_2.csv', 'r')
    cvs_line = cvs_file.read()
    cvs_line_sub = re.sub("\n", ",1\n", cvs_line, count=0, flags=0)
    cvs_file.close()
    cvs_file_new = open('summary_admin_list_1.csv','w')
    cvs_file_new.write(cvs_line_sub)
    #print cvs_line_sub # Uncomment for Debug Help
    cvs_file_new.close()
    ##################################
    # Cleanup the CVS lines Mess
    for i, row in enumerate(csv.reader(open('summary_admin_list_1.csv', 'r'))):#rb to r
      # unpack the columns into local variables
      plugin_name, crit_count = row
      # for each adminaccount, add the level the list
      data[plugin_name].append(float(crit_count))   
    for plugin_name, crit_count in data.items():#change
      ## a_list233.csv - 2    - FARMERS\administrator (User)
      a_list2 = open('summary_admin_list_3.csv', 'a').writelines(str(int(sum(crit_count))) + ","+str(plugin_name)+"\n")
    reader = csv.reader(open("summary_admin_list_3.csv"), delimiter=",")    
    sorted_lines = sorted(reader,key=lambda x: int(x[0]), reverse=True)
    ### Print Admin List On The Screen ###
    print ("--------------------------------------------------------")
    print ("-Summary of members of the Local 'Administrators' group-")
    for x in sorted_lines:
      print (x[1])
    print ("--------------------------------------------------------")
    ### End Print Admin List On The Screen ###
  else:
    print ("--------------------------------------------------------")
    print ("--   No Summary of the Local 'Administrators' group   --")
    print ("--------------------------------------------------------")
# Parse_nessus8 - Authentication Failure - Local Checks Not Run
def parse_nessus8(filename):
  #################################################################
  # a_list.csv - Starts as the full Admin block of TXT from Nessus
  # The following users are members of the 'Administrators' group :
  #  - SARA-PC\Administrator (User)
  #- SARA-PC\Comproom (User)
  #
  # admin_list.csv - Temp List of Admin Users - With Blank Lines
  # Used as a holder before it gets cleaned up
  #################################################################
  index_settings = {u'mappings': {u'vulnerability': {u'properties': {u'host-fqdn': {u'type': u'string'},
      u'host_ip': {u'type': 'ip', "index" : "not_analyzed","doc_values": "true"},
      u'host_name': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'operating-system': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'scantime': {u'format': u'dateOptionalTime', u'type': u'date'},
      u'system-type': {u'type': u'string'},
      u'vulninfo': {u'properties': {u'apple-sa': {u'type': u'string'},
        u'bid': {u'type': u'string'},
        u'canvas_package': {u'type': u'string'},
        u'cert': {u'type': u'string'},
        u'cpe': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
        u'cve': {u'type': u'string'},
        u'cvss_base_score': {u'type': u'float'},
        u'cvss_temporal_score': {u'type': u'string'},
        u'cvss_temporal_vector': {u'type': u'string'},
        u'cvss_vector': {u'type': u'string'},
        u'cwe': {u'type': u'string'},
        u'd2_elliot_name': {u'type': u'string'},
        u'description': {u'type': u'string'},
        u'edb-id': {u'type': u'string'},
        u'exploit_available': {u'type': u'boolean'},
        u'exploit_framework_canvas': {u'type': u'string'},
        u'exploit_framework_core': {u'type': u'string'},
        u'exploit_framework_d2_elliot': {u'type': u'string'},
        u'exploit_framework_metasploit': {u'type': u'string'},
        u'exploitability_ease': {u'type': u'string'},
        u'exploited_by_malware': {u'type': u'string'},
        u'fname': {u'type': u'string'},
        u'iava': {u'type': u'string'},
        u'iavb': {u'type': u'string'},
        u'metasploit_name': {u'type': u'string'},
        u'osvdb': {u'type': u'string'},
        u'owasp': {u'type': u'string'},
        u'patch_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'pluginFamily': {u'type': u'string'},
        u'pluginID': {u'type': u'string'},
        u'pluginName': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
        u'plugin_modification_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'plugin_name': {u'type': u'string'},
        u'plugin_output': {u'type': u'string'},
        u'plugin_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'plugin_type': {u'type': u'string'},
        u'port': {u'type': u'string'},
        u'protocol': {u'type': u'string'},
        u'rhsa': {u'type': u'string'},
        u'risk_factor': {u'type': u'string'},
        u'script_version': {u'type': u'string'},
        u'secunia': {u'type': u'string'},
        u'see_also': {u'type': u'string'},
        u'severity': {u'type': u'integer'},
        u'solution': {u'type': u'string'},
        u'stig_severity': {u'type': u'string'},
        u'svc_name': {u'type': u'string'},
        u'synopsis': {u'type': u'string'},
        u'vuln_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'xref': {u'type': u'string'}}}}}}} 
  listfiles = args.filename
  files = glob.glob(listfiles)
         
  for file in files:
      try:
          nessus_obj_list = NessusParser.parse_fromfile(file)
      except:
          print("file cannot be imported : %s" % file)
          continue
      print ("\n\n")
      print ("--------------------------------------------------------")
      print ("--   Authentication Failure - Local Checks Not Run    --")
      print ("--------------------------------------------------------")
      for i in nessus_obj_list.hosts:
          docu  = {}
          docu2 = {}
          docu3 = {}
          docu4 = {}
          docu2['host_ip'] = i.ip
          docu3['host-fqdn'] = i.name
          docu4['operating-system'] = i.get_host_property('operating-system')
          for v in i.get_report_items:
              docu['vulninfo'] = v.get_vuln_info
              docu['plugin_name'] =   v.get_vuln_info[('plugin_name')]
              
              if "Authentication Failure - Local Checks Not Run" in str(docu['plugin_name']):
                # a_list33.csv -   - FARMERS\administrator (User),1
                print(str(docu2['host_ip']))
                #print(str(docu2['host_ip']) + " " + docu4['operating-system'])
      print ("--------------------------------------------------------")
      # Nessus Windows Scan Not Performed with Admin Privileges
      print ("--------------------------------------------------------")
      print ("Nessus Windows Scan Not Performed with Admin Privileges ")
      print ("--------------------------------------------------------")
      for i in nessus_obj_list.hosts:
          docu  = {}
          docu2 = {}
          docu3 = {}
          docu4 = {}
          docu2['host_ip'] = i.ip
          docu3['host-fqdn'] = i.name
          docu4['operating-system'] = i.get_host_property('operating-system')
          for v in i.get_report_items:
              docu['vulninfo'] = v.get_vuln_info
              docu['plugin_name'] =   v.get_vuln_info[('plugin_name')]
              
              if "Nessus Windows Scan Not Performed with Admin Privileges" in str(docu['plugin_name']):
                # a_list33.csv -   - FARMERS\administrator (User),1
                print(str(docu2['host_ip']))
                #print(str(docu2['host_ip']) + " " + docu4['operating-system'])
      print ("--------------------------------------------------------")
# Parse_nessus9 - SNMP Agent Default Community Name (public)
def parse_nessus9(filename):
  #################################################################
  # a_list.csv - Starts as the full Admin block of TXT from Nessus
  # The following users are members of the 'Administrators' group :
  #  - SARA-PC\Administrator (User)
  #- SARA-PC\Comproom (User)
  #
  # admin_list.csv - Temp List of Admin Users - With Blank Lines
  # Used as a holder before it gets cleaned up
  #################################################################
  index_settings = {u'mappings': {u'vulnerability': {u'properties': {u'host-fqdn': {u'type': u'string'},
      u'host_ip': {u'type': 'ip', "index" : "not_analyzed","doc_values": "true"},
      u'host_name': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'operating-system': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
      u'scantime': {u'format': u'dateOptionalTime', u'type': u'date'},
      u'system-type': {u'type': u'string'},
      u'vulninfo': {u'properties': {u'apple-sa': {u'type': u'string'},
        u'bid': {u'type': u'string'},
        u'canvas_package': {u'type': u'string'},
        u'cert': {u'type': u'string'},
        u'cpe': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
        u'cve': {u'type': u'string'},
        u'cvss_base_score': {u'type': u'float'},
        u'cvss_temporal_score': {u'type': u'string'},
        u'cvss_temporal_vector': {u'type': u'string'},
        u'cvss_vector': {u'type': u'string'},
        u'cwe': {u'type': u'string'},
        u'd2_elliot_name': {u'type': u'string'},
        u'description': {u'type': u'string'},
        u'edb-id': {u'type': u'string'},
        u'exploit_available': {u'type': u'boolean'},
        u'exploit_framework_canvas': {u'type': u'string'},
        u'exploit_framework_core': {u'type': u'string'},
        u'exploit_framework_d2_elliot': {u'type': u'string'},
        u'exploit_framework_metasploit': {u'type': u'string'},
        u'exploitability_ease': {u'type': u'string'},
        u'exploited_by_malware': {u'type': u'string'},
        u'fname': {u'type': u'string'},
        u'iava': {u'type': u'string'},
        u'iavb': {u'type': u'string'},
        u'metasploit_name': {u'type': u'string'},
        u'osvdb': {u'type': u'string'},
        u'owasp': {u'type': u'string'},
        u'patch_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'pluginFamily': {u'type': u'string'},
        u'pluginID': {u'type': u'string'},
        u'pluginName': {u'type': u'string', "index" : "not_analyzed","doc_values": "true"},
        u'plugin_modification_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'plugin_name': {u'type': u'string'},
        u'plugin_output': {u'type': u'string'},
        u'plugin_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'plugin_type': {u'type': u'string'},
        u'port': {u'type': u'string'},
        u'protocol': {u'type': u'string'},
        u'rhsa': {u'type': u'string'},
        u'risk_factor': {u'type': u'string'},
        u'script_version': {u'type': u'string'},
        u'secunia': {u'type': u'string'},
        u'see_also': {u'type': u'string'},
        u'severity': {u'type': u'integer'},
        u'solution': {u'type': u'string'},
        u'stig_severity': {u'type': u'string'},
        u'svc_name': {u'type': u'string'},
        u'synopsis': {u'type': u'string'},
        u'vuln_publication_date': {u'format': u'yyyy/MM/dd HH:mm:ss||yyyy/MM/dd',
         u'type': u'date'},
        u'xref': {u'type': u'string'}}}}}}} 
  listfiles = args.filename
  files = glob.glob(listfiles)
         
  for file in files:
      try:
          nessus_obj_list = NessusParser.parse_fromfile(file)
      except:
          print("file cannot be imported : %s" % file)
          continue
      print ("\n\n")
      print ("--------------------------------------------------------")
      print ("--   SNMP Agent Default Community Name (public)       --")
      print ("--------------------------------------------------------")
      for i in nessus_obj_list.hosts:
          docu  = {}
          docu2 = {}
          docu3 = {}
          docu4 = {}
          docu2['host_ip'] = i.ip
          docu3['host-fqdn'] = i.name
          docu4['operating-system'] = i.get_host_property('operating-system')
          for v in i.get_report_items:
              docu['vulninfo'] = v.get_vuln_info
              docu['plugin_name'] =   v.get_vuln_info[('plugin_name')]
              
              if "SNMP Agent Default Community Name (public)" in str(docu['plugin_name']):
                # a_list33.csv -   - FARMERS\administrator (User),1
                print(str(docu2['host_ip']))
                #print(str(docu2['host_ip']) + " " + docu4['operating-system'])
      print ("--------------------------------------------------------")
# Parse_nessus10 - Print the Number of Critical Rated with Exploits
def parse_nessus10(filename):
  listfiles = args.filename
  files = glob.glob(listfiles)
  if os.path.isfile('crit_exploit_list2.csv'):
    print ("Critical with Exploit")
    reader = csv.reader(open("crit_exploit_list2.csv"), delimiter=",")
    sorted_lines = sorted(reader,key=lambda x: int(x[0]), reverse=True)
    for x in sorted_lines:
      print (x[0] + " Instances of " + str(x[1]))
  print ("\n")
  if os.path.isfile('high_exploit_list2.csv'):
    print ("High with Exploit")
    reader = csv.reader(open("high_exploit_list2.csv"), delimiter=",")
    sorted_lines = sorted(reader,key=lambda x: int(x[0]), reverse=True)
    sorted_lines = sorted_lines[:10]
    for x in sorted_lines:
        print (x[0] + " Instances of " + str(x[1]))
  # End Print Critical Rated with Exploits ###
# Cleanup
def cleanup():
  filelist =['high_exploit_list2.csv','high_exploit_list3.csv','high_exploit_list.csv',
             'crit_exploit_list.csv','crit_exploit_list2.csv','crit_exploit_list3.csv',
             'a_list.csv','a_list2.csv',
             'crit_high_host_list2.csv','high_host_list2.csv','high_list.csv',
             'high_list2.csv','crit_high_host_list.csv','crit_host_list.csv',
             'crit_host_list2.csv', 'crit_list.csv','crit_list2.csv',
             'high_host_list.csv','admin_list.csv','crit_list3.csv',
             'summary_admin_list_3.csv','summary_admin_list_2.csv','summary_admin_list_1.csv']
  for x in filelist:
    if os.path.exists(x):
        os.remove(x)
  # End Cleanup ###
# Print out Josh's Standard Nessus Output for reports
def printit():
  print ("\n" + "A total of " + str(glob_Total_Devices) + " computers, servers and network devices on the network were scanned for vulnerabilities. " +
       "There were " + str(glob_total_crit_vuln) + " unique Critical Rated Vulnerabilities affecting " +
       str(glob_total_crit_hosts) + " hosts and " +
       str(glob_total_high_vuln) + " unique High Rated Vulnerabilities affecting " + 
       str(glob_total_high_hosts) + " Hosts." +
       "The total number of combined hosts affected is " + str(glob_total_crit_high_hosts) + ". " +
       str(glob_Critial_Exploit_count) + " of the Critical rated and " + str(glob_High_Exploit_count) + 
       " of the High rated vulnerabilities have exploits available." +
       " Compared to other environments your size you are in the xxth percentile range for patching. " +
       "Key examples include but are not limited to the following:" + "\n")
# Make the Magic Happen
parse_nessus(args)   # Process the Operating Systems and Total Device Count
parse_nessus2(args)  # Process Critical and High Rated
parse_nessus3(args)  # Process the Local Windows Administators
parse_nessus7(args)  # Process the Local Windows Administators - Summarized
parse_nessus4(args)  # Process the Number of Credentialed Devices
parse_nessus5(args)  # Process the Number of Critical Rated with Exploits
parse_nessus6(args)  # Process the Number of High Rated with Exploits
parse_nessus8(args)  # Print out Authentication Failure Errors
parse_nessus9(args)  # Print out SNMP found
printit()            # Print out standard report informaiton
parse_nessus10(args) # Print the top 10 High and Critical for the Report
cleanup()            # Cleanup all files generated by this script