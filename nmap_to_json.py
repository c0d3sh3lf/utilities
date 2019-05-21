#!/usr/bin/python

__author__ = "Sumit Shrivastava"
__version__ = "1.0.0"
__description__ = """
Author: Sumit Shrivasava
Version 1.0.0

Creates nmap xml output to sqlite database 

"""

from xml.dom.minidom import *
import sqlite3, sys, optparse, json, re


def readXMLFile(inputfilename):
    print "[+] Parsing the XML File\r",
    DOMTree = parse(inputfilename)
    return DOMTree


def parseXMLFile(DOMTree):
    global total_count
    portscan_dict = {}
    portscan = DOMTree.documentElement
    hosts = portscan.getElementsByTagName('host')
    read = 1
    total = len(hosts)
    for host in hosts:
        print "[+] Reading", read, "of", total, "host(s)\r",
        read += 1
        ip_addr = host.getElementsByTagName('address')[0].getAttribute('addr')
        ports = host.getElementsByTagName('ports')[0].getElementsByTagName('port')
        port_list = []
        if len(ports) > 0:
            for port in ports:
                if port.getElementsByTagName('state')[0].getAttribute('state') == "open":
                    protocol = port.getAttribute('protocol')
                    port_num = port.getAttribute('portid')
                    service = port.getElementsByTagName('service')[0].getAttribute('name')
                    port_list.append((str(protocol), str(port_num), str(service)))
        if len(port_list) > 0:
            portscan_dict[str(ip_addr)] = port_list
    print " "*79,"\r",
    print "[+] Found ", len(portscan_dict.keys()), "IP address(es) with open port(s)"
    return portscan_dict


def write_to_json(portscan_dict = {}, project_name = ""):

    json_filename = project_name + ".json"

    with open(json_filename, 'w') as json_file:
        json.dump(portscan_dict, json_file)

    print "[+] JSON File '%s' written."%(json_filename)


def main():
    parser = optparse.OptionParser("python nmap_to_sqlite.py -x NMAP_XML -p PROJECT_NAME\n" + __description__)
    parser.add_option("-x", "--xml", dest="nmap_xml", help="NMAP XML output file")
    parser.add_option("-p", "--project", dest="project_name", default="default", help="Project Name. Default is 'default'.")
    options, args = parser.parse_args()
    if not (options.nmap_xml):
        print "[-] XML File is required"
        parser.print_help()
        sys.exit(1)
    else:
        port_scan = parseXMLFile(readXMLFile(options.nmap_xml))
        write_to_json(port_scan, options.project_name)


if __name__ == "__main__":
    main()

