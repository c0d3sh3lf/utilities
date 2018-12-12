#!/usr/bin/python

### This script requires responder to be installed on your system

import subprocess, sys, re

non_error_line = re.compile(r"^\[")

if len(sys.argv) > 1:
	range_file_name = str(sys.argv[1])
else:
	print "[-] Error. Filename is required. Run program as python", str(sys.argv[0]), "<RANGE_FILENAME>"
	sys.exit(1)

range_file = open(range_file_name, "r")
ranges = range_file.readlines()
range_file.close()

print "[+] Looking for hosts vulnerable to MS17-010"

for range in ranges:
	try:
		finger_process = subprocess.Popen(['responder-RunFinger', '-i', range, '-g'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		result = finger_process.communicate()[0].split('\n')
		for line in result:
			if non_error_line.match(line):
				try:
					line_split = line.strip()[1:-1].split(",")
					if (line_split[len(line_split)-1].split(":")[1] == " True"):
						ip_address = str(line_split[0])[1:-1]
						os = str(line_split[1].split(":")[1])[1:-1]
						domain = str(line_split[2].split(":")[1])
						print "[+] Found %s (%s on %s domain)"%(ip_address, os, domain)
				except:
					pass
	except OSError as e:
		print "[-] Error. You need to have responder installed to run this tool."
		sys.exit(1)
	except KeyboardInterrupt as e:
		print "[!] Exiting.\a.\a."
		sys.exit(1)