from xml.dom.minidom import *
import sys, optparse, re


class nmap:
    
    __nmap_filename__ = ""

    def __init__(self, filename):
        self.__nmap_filename__ = filename

    def parseDict(self):
        try:
            DOMTree = parse(self.__nmap_filename__)
            avail_dict = {}
            portscan = DOMTree.documentElement
            hosts = portscan.getElementsByTagName('host')

            read = 1
            total = len(hosts)
            for host in hosts:
                print "\r[+] Reading host", read, "of", total,
                read += 1

                addresses = host.getElementsByTagName('address')
                hostname = ""
                for address in addresses:
                    if address.getAttribute('addrtype') == "ipv4":
                        hostname = str(address.getAttribute('addr'))
                
                #Check Availability Details
                ports = host.getElementsByTagName('ports')[0].getElementsByTagName('port')
                port_list = []
                up = False
                if len(ports) > 0:
                    for port in ports:
                        if port.getElementsByTagName('state')[0].getAttribute('state') == "open":
                            up = True
                            break
                if up:
                    avail_dict[hostname] = "Up"
                else:
                    avail_dict[hostname] = "Down"
                
            return avail_dict
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
        csv_data = "IP Address, Status\n\r"
        for ip_address in output_dict.keys():
            csv_data += ip_address + "," + output_dict[ip_address] + "\n\r"
        xml_re = re.compile(r"\.xml")
        csv_filename = xml_re.sub(".csv", filename)
        csv_file = open(csv_filename, "w")
        csv_file.write(csv_data)
        csv_file.close()
        print "[+] CSV File '%s' written."%(csv_filename)
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