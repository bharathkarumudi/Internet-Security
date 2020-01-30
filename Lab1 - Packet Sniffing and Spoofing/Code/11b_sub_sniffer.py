#!/usr/bin/python
from scapy.all import *

def print_pkt(pkt):
 pkt.show()

pkt = sniff(filter='net 216.58.0.0/16 ',prn=print_pkt)
