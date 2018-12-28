#!/usr/bin/env python3
from scapy.all import IP,sr1,ICMP,conf
import random
import netifaces
import argparse


end_text = "\033[0m"
yellow_text = "\033[93m"
green_text = "\033[92m"
red_text = "\033[91m"


def send_packet(dst_ip,payload):
	try:
		scapypkt = IP(dst=dst_ip)/ICMP()/payload
		send_packet = sr1(scapypkt,timeout=timeout,verbose=False)
		print("{0}[+] Payload sent!{1}".format(green_text,end_text))
		if send_packet.summary():
			print("{0}[+] Response: {1}{2}".format(green_text,send_packet.summary(),end_text))
		else:
			print("{0}[-] Sent packet, but no response received.{1}".format(red_text,end_text))
	except:
		print("{0}[-] Couldn't send packet to {1} via {2}{3}".format(red_text,dst_ip,conf.iface,
																	end_text))


def auto_int_select(dst_ip,payload):
	print("{0}[+] Automatically detecting interface...{1}".format(green_text,end_text))
	for interface in netifaces.interfaces():
		conf.iface = interface
		try:
			ipassigned = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
		except:
			continue
		test_wan = IP(dst="8.8.8.8")/ICMP()
		run_test = sr1(test_wan, timeout=timeout,verbose=False)
		if run_test:
			print("{0}[!] {1} auto-selected!{2}".format(yellow_text,interface,end_text))
			conf.iface = interface
			break
	try:
		print("{0}[+] Sending Packet...{1}".format(green_text,end_text))
		send_packet(dst_ip,payload)

	except:
		print("{0}[-] Something went wrong!{1}".format(red_text,end_text))


description = "Simple program to send an ICMP packet with a payload via Python/Scapy."
parser = argparse.ArgumentParser(description=description)
parser.add_argument('-i',help='IP Address of the target',required=True)
parser.add_argument('-p',default="",help='The payload to include in the packet')
parser.add_argument('-t',default=2,help='Network Timeout')
parser.add_argument('-n',default='eth0',help='Network Interface"')
parser.add_argument('-a',action="store_true",
						help='Auto-Detect Network Interface')
args = parser.parse_args()

if args.i:
	dst_ip = args.i

if args.p:
	payload = args.p

if args.t:
	timeout = args.t

if args.n:
	conf.iface = args.n

if args.a:
	auto_int_select(dst_ip,payload)

if not args.a:
	send_packet(dst_ip,payload)