#!/usr/bin/python

__author__ = "Sumit Shrivastava"
__version__ = "1.0.0"
__description__ = """
Author: Sumit Shrivasava
Version 1.0.0

Creates nmap xml output to sqlite database 

"""

from xml.dom.minidom import *
import sqlite3, sys, optparse


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
    conn = sqlite3.connect(project_name+".db")
    conn.execute('''
        CREATE TABLE IF NOT EXISTS port_scan
        (
            ID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            HOST TEXT,
            PROTOCOL TEXT,
            PORT TEXT,
            SERVICE TEXT
        );
    ''')
    counter = 1
    for ip_addr in portscan_dict.keys():
        for port in portscan_dict[ip_addr]:
            protocol, port_num, service = port
            insert_statement = "INSERT INTO port_scan (HOST, PROTOCOL, PORT, SERVICE) VALUES('"
            insert_statement += ip_addr + "','"
            insert_statement += protocol + "','"
            insert_statement += port_num + "','"
            insert_statement += service + "');"
            try:
                conn.execute(insert_statement)
            except Exception, e:
                print e.args
                break
            if counter % 100 == 0:
                conn.commit()
            print "[+] Inserted", counter, "record(s)\r",
            counter += 1
    conn.commit()
    conn.close()


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
        write_to_database(port_scan, options.project_name)


if __name__ == "__main__":
    main()

