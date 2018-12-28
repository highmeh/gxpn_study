#!/usr/bin/env python3
from scapy.all import *

icmp_packets = sniff(filter="icmp",count=1)
for packet in icmp_packets:
	if packet.haslayer(ICMP):
		print((packet[Raw].load).decode('utf-8'))
