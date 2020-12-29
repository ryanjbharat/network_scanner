#!/usr/bin/env python3

import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser(description="Scan the IP range.")
    parser.add_argument("-t", "--target", dest="target", help="Target IP range to scan. /8, /16, /24 only.")
    args = parser.parse_args()
    if not args.target:
        parser.error("Please specify an IP range, use --help for more help.")
    return args


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered_list = scapy.srp(packet, timeout=1, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_result(results_list):
    print("IP\t\t\tMAC Address\n---------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

args = get_arguments()

scan_result = scan(args.target)
print_result(scan_result)