#!/usr/bin/python

__author__ = "Sumit Shrivastava"
__version__ = "1.0.0"
__description__ = """
Author: Sumit Shrivasava
Version 1.0.0
Parses sslscan xml output and identifies the SSL / TLS version being used 
"""

from xml.dom.minidom import *
import sys, optparse, re

sslv2_re = re.compile(r"SSLv2")
sslv3_re = re.compile(r"SSLv3")
tls10_re = re.compile(r"TLSv1.0")
tls11_re = re.compile(r"TLSv1.1")
tls12_re = re.compile(r"TLSv1.2")

def readXMLFile(inputfilename):
	print "[+] Parsing output XML"
	DOMTree = parse(inputfilename)
	return DOMTree
	
def parseXMLFile(DOMTree):
	version_dict = {}
	sslscan = DOMTree.documentElement
	host_list = sslscan.getElementsByTagName('ssltest')
	for host in host_list:
		hostname = host.getAttribute('host')
		ciphers = host.getElementsByTagName('cipher')
		tls12 = False
		tls11 = False
		tls10 = False
		sslv3 = False
		sslv2 = False
		for cipher in ciphers:
			if sslv2_re.match(cipher.getAttribute('sslversion')):
				sslv2 = True
			if sslv3_re.match(cipher.getAttribute('sslversion')):
				sslv3 = True
			if tls10_re.match(cipher.getAttribute('sslversion')):
				tls10 = True
			if tls11_re.match(cipher.getAttribute('sslversion')):
				tls11 = True
			if tls12_re.match(cipher.getAttribute('sslversion')):
				tls12 = True
		version_dict[hostname] = {"sslv2":sslv2, "sslv3":sslv3, "tls10":tls10, "tls11":tls11, "tls12":tls12}
	return version_dict

def dict2csv(version_dict, csvfilename, urllistfilename):
	csvfile = open(csvfilename, "w")
	urllistfile = open(urllistfilename, "r")
	urllist = urllistfile.readlines()
	urllistfile.close()
	csv_data = "Sr.No.,URL,SSLv2,SSLv3,TLS1.0,TLS1.1,TLS1.2,Not Reachable\n"
	srno = 1
	for url in urllist:
		url = url.strip()
		try:
			versions = version_dict[url]
			csv_data += str(srno) + "," + url + ","
			if versions["sslv2"]:
				csv_data += "*,"
			else:
				csv_data += ","
			if versions["sslv3"]:
				csv_data += "*,"
			else:
				csv_data += ","
			if versions["tls10"]:
				csv_data += "*,"
			else:
				csv_data += ","
			if versions["tls11"]:
				csv_data += "*,"
			else:
				csv_data += ","
			if versions["tls12"]:
				csv_data += "*,"
			else:
				csv_data += ","
			csv_data += "\n"
		except KeyError:
			csv_data += str(srno) + "," + url + ",,,,,,*\n"
		except:
			csv_data += str(srno) + "," + url + ",,,,,,ERROR OCCURED\n"
		srno += 1
	csvfile.write(csv_data)
	csvfile.close()
	
def main():
	parser = optparse.OptionParser("python parse_output.py -x SSLSCAN_XML -u URLLISTFILE -c CSVFILE\n" + __description__)
	parser.add_option("-x", "--xml", dest="sslscan_xml", help="SSLSCAN XML output file")
	parser.add_option("-u", "--url-list", dest="urllist", help="URL List file with each URL separated by a new line")
	parser.add_option("-c", "--csv-file", dest="csvfile", help="CSV Output File")
	options, args = parser.parse_args()
	if not (options.sslscan_xml):
		print "[-] XML File is required"
		parser.print_help()
		sys.exit(1)
	elif not (options.urllist):
		print "[-] URL List File is required"
		parser.print_help()
		sys.exit(1)
	elif not (options.csvfile):
		print "[-] CSV Filename is required"
		parser.print_help()
		sys.exit(1)
	else:
		version_details = parseXMLFile(readXMLFile(options.sslscan_xml))
		dict2csv(version_details, options.csvfile, options.urllist)


if __name__ == "__main__":
	main()