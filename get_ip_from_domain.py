#!/usr/bin/python3

import socket

domain_list_file_path = "domain_list.txt"
domain_list_file = open(domain_list_file_path, "r")
domain_list = domain_list_file.readlines()
domain_list_file.close()

mapping = {}

for domain in domain_list:
    domain = domain.strip()
    try:
        ip_address = socket.gethostbyname(domain)
        print("{} -> {}".format(domain, ip_address))
        mapping[domain] = ip_address
    except:
        print("{} -> ERROR". format(domain))
        mapping[domain] = ""

#Write output to mapping.csv

output_file = open("mapping.csv", "w")
output_data = "Domain,IP Address\n"
for domain_name in mapping.keys():
    output_data += domain_name + "," + mapping[domain_name] + "\n"

output_file.write(output_data)
output_file.close()
print("Ouptut written to mapping.csv")
