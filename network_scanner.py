#!/usr/bin/env python

import scapy.all as scapy
import argparse



#parses arguments provided by user at the command line
def parse_input():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ip", help="ip range to scan")
    return parser.parse_args()


#scan ip or ip range and returns dictionary of ip addresses and associated mac addresses
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    client_list = []
    for item in answered_list:
        client_dict = {"ip":item[1].psrc,"mac":item[1].hwsrc}
        client_list.append(client_dict)
    return client_list


#print client list ip/mac
def print_client_list(client_list):
    print("*"*75)
    print("IP\t\t\tMac Address")
    print("*"*75)
    for item in client_list:
        print(item["ip"],"\t\t", end="")
        print(item["mac"])
        print("....................................")


#main
args = parse_input()
scan_result = scan(args.ip)
print_client_list(scan_result)

