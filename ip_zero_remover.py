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
        ip_octate[0] = int(ip_octate[0])
        ip_octate[0] = str(ip_octate[0])
        ip_octate[1] = int(ip_octate[1])
        ip_octate[1] = str(ip_octate[1])
        ip_octate[2] = int(ip_octate[2])
        ip_octate[2] = str(ip_octate[2])
        ip_octate[3] = int(ip_octate[3])
        ip_octate[3] = str(ip_octate[3])
        output_data += ip_octate[0] + "." + ip_octate[1] + "." + ip_octate[2] + "." + ip_octate[3] + "\n"
inputfile.close()
outputfile = open(inputfilename, "w")
outputfile.write(output_data)
outputfile.close()