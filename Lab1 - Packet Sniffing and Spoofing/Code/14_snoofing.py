#!/usr/bin/python

from scapy.all import *

def send_pkt(pkt):
	p = copy.deepcopy(pkt[IP])
	p.src = pkt[IP].dst
	p.dst = pkt[IP].src
	p[ICMP].type = 0
	send(p)

pkt = sniff(filter='icmp',prn=send_pkt) 
