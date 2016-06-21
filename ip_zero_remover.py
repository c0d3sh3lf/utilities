#!/usr/bin/python

__author__ = "Sumit Shrivastava (@invad3rsam)"
__version__ = "v1.0.0"

import re

inputfilename = raw_input("Enter the input file : ")
inputfile = open(inputfilename, "r")
inputfile_data = inputfile.readlines()
output_data = ""

ip_re = re.compile(r"([0-9]{1,3}.){3}([0-9]{1,3})")

for ip in inputfile_data:
    if ip_re.match(ip):
        ip_octate = ip.split(".")
        for i in range(0, len(ip_octate)):
            ip_octate[i] = int(ip_octate[i])
            ip_octate[i] = str(ip_octate[i])
        new_ip = ip_octate[0] + "." + ip_octate[1] + "." + ip_octate[2] + "." + ip_octate[3]+"\n"
        output_data += new_ip
        print "Processed", new_ip
inputfile.close()
outputfile = open(inputfilename, "w")
outputfile.write(output_data)
outputfile.close()
