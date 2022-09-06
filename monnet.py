#!/usr/bin/env python3
import dashing
from dashing import *
import os
import math
import time
import pyshark
import argparse
import netifaces as ni


parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', help='interface to listen to', default='any')
parser.add_argument('ports', help='ports to listen to, comma separated')

args = parser.parse_args()

iface = args.interface

if iface == "any":
    dsts = [ni.ifaddresses(i)[ni.AF_INET][0]['addr'] for i in ni.interfaces() if ni.AF_INET in ni.ifaddresses(i)]
else:
    dsts = [ni.ifaddresses(iface)[ni.AF_INET][0]['addr']]

icmp = False


ports = [int(p) for p in args.ports.split(",") if p.lower() != 'icmp']
if 'icmp' in [p.lower() for p in args.ports.split(",")]:
    ports.append('icmp')


portcharts = {}
ui = VSplit()

# textbox
textbox = dashing.Text("    --- MONNET port monitoring ---", color=10, border_color=0)
ui.items +=(textbox,)

colour = 1
for i,port in enumerate(ports):
    colour = colour+1 % 20

    new = HSplit(HChart(title=f'{port}', border_color=7, color=colour))
    portcharts[port] = new.items[0]
    ui.items+=(new,)

try:
    # display/refresh the ui
    while True:

        capture = pyshark.LiveCapture(interface=iface)
        # capture.set_debug()
        capture.sniff(timeout=2)
        packets = [pkt for pkt in capture._packets]
        capture.close()

        counts = {p:0 for p in ports}
        
        for packet in packets:
            if 'ip' in packet and packet['ip'].dst in dsts:
                if 'tcp' in packet:
                    for port in ports:
                        if port == int(packet['tcp'].dstport):
                            counts[port] += 1
            elif 'ICMP' in packet:
                counts['icmp'] += 1

        for port in ports:
            portcharts[port].append((counts[port]*5))

        ui.display()

except KeyboardInterrupt:
    exit()
