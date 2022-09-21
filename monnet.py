#!/usr/bin/env python3
import dashing
from dashing import *
import os
import math
import time
import pyshark
import argparse
import netifaces as ni

class CustomHChart(HChart):
    """Horizontal chart. Values must be between 0 and 100 and can be float.
    """
    def __init__(self, val=100, *args, **kw):
        super(CustomHChart, self).__init__(**kw)
        self.value = val
        self.datapoints = deque(maxlen=500)
        

    def _display(self, tbox, parent):
        tbox = self._draw_borders_and_title(tbox)
        print(tbox.t.color(self.color))

        flags = {}
        for dx in range(tbox.w):
            dp_index = -tbox.w + dx
            try:
                dp = self.datapoints[dp_index]
                    
                if type(dp) in [str]:
                    flags[dp_index] = [x for x in dp if x.isdigit() ==False]
            except (IndexError,KeyError):
                pass

        for dy in range(tbox.h):
            bar = ""
            for dx in range(tbox.w):
                dp_index = -tbox.w + dx
                try:
                    dp = self.datapoints[dp_index]
                    if type(dp) in [str]:
                        dp = int(''.join([x for x in dp if x.isdigit()==True]))

                    q = (1 - dp / 100) * tbox.h
                    if dy < int(q):
                        bar += " "
                    else:
                        if flags[dp_index] != []:
                            bar += flags[dp_index][0]
                            if len(flags)>1:
                                flags[dp_index] = flags[dp_index][1:]
                            else:
                                flags[dp_index] = []
                        elif dy == int(q):
                            index = int((int(q) - q) * 8 - 1)
                            bar += vbar_elements[index]
                        else:
                            bar += vbar_elements[-1]
                except (IndexError,KeyError):
                    bar += " "

            # assert len(bar) == tbox.w
            print(tbox.t.move(tbox.x + dy, tbox.y) + bar)

class DataContainer():

    def __init__(self, count=0, flags=''):
        self.count = count
        self.flags = flags


parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', help='interface to listen to', default='any')
parser.add_argument('ports', help='ports to listen to, comma separated')

if os.geteuid() != 0:
    exit("root privileges needed")

args = parser.parse_args()

iface = args.interface

try:
    if iface == "any":
        dsts = [ni.ifaddresses(i)[ni.AF_INET][0]['addr'] for i in ni.interfaces() if ni.AF_INET in ni.ifaddresses(i)]
    else:
        dsts = [ni.ifaddresses(iface)[ni.AF_INET][0]['addr']]
except ValueError:
    print(f"Error: interface {iface} unkown, exiting.")
    exit()

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

    new = HSplit(CustomHChart(title=f'{port}', border_color=7, color=colour))
    portcharts[port] = new.items[0]
    ui.items+=(new,)

try:
    # display/refresh the ui
    while True:
        try:
            capture = pyshark.LiveCapture(interface=iface)
            # capture.set_debug()
            capture.sniff(timeout=2)
            packets = [pkt for pkt in capture._packets]
            capture.close()
        except OSError:
            pass
        counts = {p:DataContainer() for p in ports}
        
        for packet in packets:
            if 'ip' in packet and packet['ip'].dst in dsts:
                if 'tcp' in packet:
                    for port in ports:
                        if port == int(packet['tcp'].dstport):
                            counts[port].count += 1
                            if (packet['tcp'].flags_syn == '1' and 'S' not in counts[port].flags):
                                counts[port].flags += 'S'
                            if (packet['tcp'].flags_res == '1' and 'R' not in counts[port].flags):
                                counts[port].flags += 'R'
            elif 'ICMP' in packet:
                counts['icmp'].count += 1

        for port in ports:
            count = (counts[port].count*5)
            item = count
            if counts[port].flags != '':
                item = counts[port].flags + str(count)

            portcharts[port].append(item)
        
        ui.display()

except KeyboardInterrupt:
    exit()
