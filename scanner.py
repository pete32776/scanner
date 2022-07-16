#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    #arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #broadcast.show()
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    #print(answered_list.summary())
    print("*"*75)
    print("IP\t\t\tMac Address")
    print("*"*75)
    for item in answered_list:
        print(item[1].psrc,"\t\t", end="")
        print(item[1].hwsrc)
        print("....................................")
    #arp_request_broadcast.show()
    #scapy.ls(scapy.Ether)
    #print(arp_request.summary())
    #scapy.ls(scapy.ARP())

scan("192.168.52.0/24")

