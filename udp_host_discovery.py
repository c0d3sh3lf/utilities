#!/usr/bin/python

import socket, os, re

ip_re = re.compile(r"((\d{1,3}\.){3}\d{1,3})")
ip_list = []

def extract_ip(received_data):
    match = ip_re.search(received_data)
    if match:
        push_to_list(match.group(1))


def push_to_list(ip_address):
    if not(ip_address in ip_list):
        ip_list.append(ip_address)


# host to listen on
host = "192.168.140.1"  #Enter your IP address here

#Create raw socket and bind it to the public interface
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))

# We want the IP headers included in the capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# if we're using Windows, we need to send an IOCTL
# to set up promiscious mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

#read in a single packet
for i in range(0, 10):
    extract_ip(str(sniffer.recvfrom(65565)))
    

#If we are using Windows, turn off promiscious mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


for ip in ip_list:
    print ip