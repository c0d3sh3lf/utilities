#!/usr/bin/python

import socket, os, struct
from ctypes import *

#Host to listen on
host = "192.168.140.1" #Enter your IP address

#Our IP Header
class IP(Structure):
    _fields_ = [
        ("ihl",             c_ubyte, 4),
        ("version",         c_ubyte, 4),
        ("tos",             c_ubyte),
        ("len",             c_ushort),
        ("id",              c_ushort),
        ("offset",          c_ushort),
        ("ttl",             c_ubyte),
        ("protocol_num",    c_ubyte),
        ("sum",             c_ushort),
        ("src",             c_ulong),
        ("dst",             c_ulong)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # Map protocol constants to their name
        self.protocol_map = {
            0:"HOPOPT", 1:"ICMP", 2:"IGMP", 3:"GGP", 4:"IP-in-IP", 5:"ST", 6:"TCP", 7:"CBT", 8:"EGP", 9:"IGP", 10:"BBN-RCC-MON", 11:"NVP-II", 12:"PUP", 13:"ARGUS", 14:"EMCON", 15:"XNET", 
            16:"CHAOS", 17:"UDP", 18:"MUX", 19:"DCN-MEAS", 20:"HMP", 21:"PRM", 22:"XNS-IDP", 23:"TRUNK-1", 24:"TRUNK-2", 25:"LEAF-1", 26:"LEAF-2", 27:"RDP", 28:"IRTP", 29:"ISO-TP4", 30:"NETBLT", 31:"MFE-NSP"
            }

        # Human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        # Human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

print "[+] Booting Script"
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP


sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

print "[+] Initiating the sniffer"
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

print "[+] Looking for packets"
try:
    while True:
            #read a packet
            raw_buffer = sniffer.recvfrom(65565)[0]

            #create an IP header
            ip_header = IP(raw_buffer[0:20])

            #print out the protocol that was detected
            print "[*] Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)

#handle Ctrl + C
except KeyboardInterrupt:
    print "[-] Received Interrupt"
    print "[+] Initiating script shutdown procedure"
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)