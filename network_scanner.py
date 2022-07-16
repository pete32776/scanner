#!/usr/bin/env python

import scapy.all as scapy
import argparse



#parses arguments provided by user at the command line
def parse_input():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip_range", dest="ip", help="ip range to scan"),
    parser.add_argument("-b", "--beginning", dest="beginning_address", help="first address in range to scan")
    parser.add_argument("-e", "--ending", dest="ending_address", help="last address in range to scan")
    return parser.parse_args()


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    #arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #broadcast.show()
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    #print(answered_list.summary())
    client_list = []
    for item in answered_list:
        client_dict = {"ip":item[1].psrc,"mac":item[1].hwsrc}
        client_list.append(client_dict)
    return client_list



def print_client_list(client_list):
    print("*"*75)
    print("IP\t\t\tMac Address")
    print("*"*75)
    for item in client_list:
        print(item["ip"],"\t\t", end="")
        print(item["mac"])
        print("....................................")
    #arp_request_broadcast.show()
    #scapy.ls(scapy.Ether)
    #print(arp_request.summary())
    #scapy.ls(scapy.ARP())
args = parse_input()
print(args.ip)
scan_result = scan(args.ip)
print_client_list(scan_result)

