#!/usr/bin/env python3
import dashing
from dashing import *
import os
import math
import time
import pyshark
import argparse
import netifaces


parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', help='interface to listen to')
parser.add_argument('ports', help='ports to listen to, comma separated')

args = parser.parse_args()

iface = args.interface
dst = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']

ports = [int(p) for p in args.ports.split(",")]

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
        capture.sniff(timeout=1)
        packets = [pkt for pkt in capture._packets]
        capture.close()

        counts = {p:0 for p in ports}

        for packet in packets:
            if 'ip' in packet and packet['ip'].dst == dst:
                if 'tcp' in packet:
                    for port in ports:
                        if port == int(packet['tcp'].dstport):
                            counts[port] += 1

        for port in ports:
            portcharts[port].append((counts[port]*5))

        ui.display()

except KeyboardInterrupt:
    exit()
