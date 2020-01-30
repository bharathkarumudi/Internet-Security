#!/usr/bin/python
from scapy.all import *

def print_pkt(pkt):
 pkt.show()

pkt = sniff(filter='tcp port telnet and src host 10.0.2.4',prn=print_pkt)
