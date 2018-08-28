from xml.dom.minidom import *
import time, sys, optparse, re

# Class Output Sample
# 
# {
#     'nmap': {
#         'endtime': '16-08-2017 16:59:32 +0000', 
#         'command': 'nmap -sT -Pn -p- -A -iL ip_list_05.txt -T4 -oA nmap_output/ip_list_05_tcp_scan_full_port_aggr_T4 -vv', 
#         'summary': 'Nmap done at Wed Aug 16 20:59:32 2017; 2 IP addresses (2 hosts up) scanned in 4817.09 seconds', 
#         'starttime': '16-08-2017 15:39:15 +0000', 
#         'elapsed': '4817.09'
#     }, 
#     'os': {
#         '10.11.1.31': {
#             'Microsoft Windows XP SP2': '89', 
#             'Microsoft Windows XP SP3': '93', 
#             'Cisco SA520 firewall (Linux 2.6)': '93', 
#             'Linux 2.6.9 (CentOS 4.4)': '93', 
#             'Motorola VIP1216 digital set top box (Windows CE 5.0)': '89', 
#             'Linux 2.6.9 - 2.6.27': '93', 
#             'Microsoft Windows Server 2003': '90', 
#             'Ruckus 7363 WAP': '92', 
#             'Microsoft Windows Server 2003 SP1 or SP2': '91', 
#             'Linux 2.6.9': '91', 
#             'Microsoft Windows Server 2003 SP0 - SP2': '91', 
#             'Linux 2.6.11': '90', 
#             'Riverbed Steelhead 200 proxy server': '93', 
#             'Microsoft Windows Server 2003 SP1': '90', 
#             'Linux 2.6.28': '91', 
#             'Linux 2.6.18': '91', 
#             'Linux 2.6.30': '93', 
#             'Microsoft Windows Server 2003 SP0 or Windows XP SP2': '89', 
#             'Microsoft Windows Server 2003 SP2': '94', 
#             'Microsoft Windows 2003': '90'
#         }, 
#         '10.11.1.35': {
#             'Microsoft Windows XP SP2': '89', 
#             'Microsoft Windows XP SP3': '93', 
#             'Cisco SA520 firewall (Linux 2.6)': '93', 
#             'Linux 2.6.9 (CentOS 4.4)': '93', 
#             'Motorola VIP1216 digital set top box (Windows CE 5.0)': '89', 
#             'Linux 2.6.9 - 2.6.27': '93', 
#             'Microsoft Windows Server 2003': '90', 
#             'Ruckus 7363 WAP': '92', 
#             'Microsoft Windows Server 2003 SP1 or SP2': '91', 
#             'Linux 2.6.9': '91', 
#             'Microsoft Windows Server 2003 SP0 - SP2': '91', 
#             'Linux 2.6.11': '90', 
#             'Riverbed Steelhead 200 proxy server': '93', 
#             'Microsoft Windows Server 2003 SP1': '90', 
#             'Linux 2.6.28': '91', 
#             'Linux 2.6.18': '91', 
#             'Linux 2.6.30': '93', 
#             'Microsoft Windows Server 2003 SP0 or Windows XP SP2': '89', 
#             'Microsoft Windows Server 2003 SP2': '94', 
#             'Microsoft Windows 2003': '90'
#         }
#     }, 
#     'details': {
#         '10.11.1.31': {
#             'hostnames': {}, 
#             'vendor': 'VMware', 
#             'mac_addr': '00:50:56:B8:E1:C9', 
#             'ipv6': ''
#         }, 
#         '10.11.1.35': {
#             'hostnames': {}, 
#             'vendor': 'VMware', 
#             'mac_addr': '00:50:56:B8:C2:C0', 
#             'ipv6': ''
#         }
#     }, 
#     'portscan': {
#         '10.11.1.31': [('tcp', '80', 'http', 'Microsoft IIS httpd'), ('tcp', '135', 'msrpc', 'Microsoft Windows RPC'), ('tcp', '139', 'netbios-ssn', 'Microsoft Windows netbios-ssn'), ('tcp', '445', 'microsoft-ds', 'Windows Server 2003 3790 Service Pack 1 microsoft-ds'), ('tcp', '1025', 'msrpc', 'Microsoft Windows RPC'), ('tcp', '1433', 'ms-sql-s', 'Microsoft SQL Server 2000'), ('tcp', '3384', 'http', 'Microsoft IIS httpd'), ('tcp', '3389', 'ms-wbt-server', 'Microsoft Terminal Service')], 
#         '10.11.1.35': [('tcp', '22', 'ssh', 'OpenSSH'), ('tcp', '443', 'https', '')]
#     }
# }
# 

class nmap:
    
    __nmap_filename__ = ""

    def __init__(self, filename):
        self.__nmap_filename__ = filename


    def __covn_time__(self, epoch = 0):
        return time.strftime('%d-%m-%Y %H:%M:%S %z', time.localtime(epoch))


    def parseDict(self):
        try:
            DOMTree = parse(self.__nmap_filename__)
            portscan_dict = {}
            os_dict = {}
            details_dict = {}
            nmap_dict = {}
            portscan = DOMTree.documentElement
            nmap_command = str(DOMTree.getElementsByTagName('nmaprun')[0].getAttribute('args'))
            starttime = self.__covn_time__(int(DOMTree.getElementsByTagName('nmaprun')[0].getAttribute('start')))
            endtime = self.__covn_time__(int(DOMTree.getElementsByTagName('nmaprun')[0].getElementsByTagName('runstats')[0].getElementsByTagName('finished')[0].getAttribute('time')))
            elapsed = str(DOMTree.getElementsByTagName('nmaprun')[0].getElementsByTagName('runstats')[0].getElementsByTagName('finished')[0].getAttribute('elapsed'))
            summary = str(DOMTree.getElementsByTagName('nmaprun')[0].getElementsByTagName('runstats')[0].getElementsByTagName('finished')[0].getAttribute('summary'))
            hosts = portscan.getElementsByTagName('host')

            #Adding scan details to the dictonary
            nmap_dict["command"] = nmap_command
            nmap_dict["starttime"] = starttime
            nmap_dict["endtime"] = endtime
            nmap_dict["elapsed"] = elapsed
            nmap_dict["summary"] = summary

            temp_details_dict = {}
            temp_os_dict = {}
            read = 1
            total = len(hosts)
            for host in hosts:
                read += 1

                #Fetch IP Address Details
                addresses = host.getElementsByTagName('address')
                ip_addr, ip_addr_6, mac_addr, vendor = "", "", "", ""
                for address in addresses:
                    if address.getAttribute('addrtype') == "ipv4":
                        ip_addr = str(address.getAttribute('addr'))
                    if address.getAttribute('addrtype') == "ipv6":
                        ip_addr_6 = str(address.getAttribute('addr'))
                    if address.getAttribute('addrtype') == "mac":
                        mac_addr = str(address.getAttribute('addr'))
                        vendor = str(address.getAttribute('vendor'))

                hostnames = host.getElementsByTagName('hostnames')
                records = {}
                try:
                    for hostname in hostnames:
                        records[str(hostname.getElementsByTagName(hostname)[0].getAttribute('name'))] = str(hostname.getElementsByTagName('hostname')[0].getAttribute('type'))
                except:
                    records = {}
                temp_details_dict["ipv6"] = ip_addr_6
                temp_details_dict["mac_addr"] = mac_addr
                temp_details_dict["vendor"] = vendor
                temp_details_dict["hostnames"] = records
                details_dict[ip_addr] = temp_details_dict
                temp_details_dict = {}

                #Fetch Port Details
                ports = host.getElementsByTagName('ports')[0].getElementsByTagName('port')
                port_list = []
                if len(ports) > 0:
                    for port in ports:
                        if port.getElementsByTagName('state')[0].getAttribute('state') == "open":
                            protocol = port.getAttribute('protocol')
                            port_num = port.getAttribute('portid')
                            try:
                                service = port.getElementsByTagName('service')[0].getAttribute('name')
                            except:
                                service = ""
                            try:
                                service_details = port.getElementsByTagName('service')[0].getAttribute('product')
                            except:
                                service_details = ""
                            port_list.append((str(protocol), str(port_num), str(service), str(service_details)))
                if len(port_list) > 0:
                    portscan_dict[str(ip_addr)] = port_list

                #Fetch OS Details
                oses = host.getElementsByTagName('os')[0].getElementsByTagName('osmatch')
                for os in oses:
                    temp_os_dict[str(os.getAttribute('name'))] = str(os.getAttribute('accuracy'))

                os_dict[ip_addr] = temp_os_dict
            
            scan_dict = {"portscan":portscan_dict, "os":os_dict, "details":details_dict, "nmap":nmap_dict}
            return scan_dict
        except:
            raise NmapException("Unable to parse the nmap output.")


class NmapException(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


def conv_to_csv(filename):
    nmap_obj = nmap(filename)
    try:
        output_dict = nmap_obj.parseDict()
        portscan = output_dict["portscan"]
        csv_data = "IP Address, Protocol, Port Number, Service, Description\n\r"
        for ip_address in portscan.keys():
            port_list = portscan[ip_address]
            for port in port_list:
                (protocol, port_num, service, desc) = port
                csv_data += ip_address + "," + protocol + "," + port_num + "," + service + "," + desc + "\n\r"
        xml_re = re.compile(r"\.xml")
        csv_filename = xml_re.sub(".csv", filename)
        csv_file = open(csv_filename, "w")
        csv_file.write(csv_data)
        csv_file.close()
        print "[+] CSV File '%s' written."%(csv_Filename)
    except Exception, e:
        print e



def main():
    parser = optparse.OptionParser(usage="python" + str(sys.argv[1]) + " -r <NMAP_XML_REPORT>")
    parser.add_option("-r", "--report", type=str, dest="nmap_xml", help="Nmap XML Report file")
    (options, args) = parser.parse_args()

    if options.nmap_xml:
        conv_to_csv(options.nmap_xml)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()