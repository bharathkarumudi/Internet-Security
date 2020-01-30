#! /usr/bin/python

from scapy.all import *
a = IP()
a.src = '1.2.3.4'
a.dst = '10.0.2.4'
ls(a)
b = ICMP()
p = a/b
send(p)

