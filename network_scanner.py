#!/usr/bin/env python3

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast/arp_request
    answered_list = scapy.srp(packet, timeout=1, verbose=False)[0]

    print("IP\t\t\tMAC Address\n---------------------------------------------------")
    for element in answered_list:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)
        print("---------------------------------------------------")


scan("192.168.226.0/24")
