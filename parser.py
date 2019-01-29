#!/usr/bin/env python

import os
from scapy.all import *
from scapy.utils import PcapWriter, RawPcapReader

def write_a_packet_to_pcap(pkt, file='test.pcap'):
	pktdump = PcapWriter(file, append=True, sync=True)
	pktdump.write(pkt)
	pktdump.close()

def write_packets_to_pcap(pkts, file='test.pcap'):
	pktdump = PcapWriter(file, append=True, sync=True)
	for pkt in pkts:
		pktdump.write(pkt)
	pktdump.close()

def remove_a_packet_from_pcap(file='test.pcap'):
	# acquire all packets from pcap
	pkts = rdpcap(file)
	# ignore the first packet
	pkts = pkts[1:]
	# recreate pcap
	os.remove(file)
	pktdump = PcapWriter(file, append=True, sync=True)
	# write other packets to pcap
	for pkt in pkts:
		pktdump.write(pkt)
	pktdump.close()

def read_a_packet_from_pacp(file='test.pcap'):
	return rdpcap(file)[0]

def read_packets_from_pacp(number=1, file='test.pcap'):
	return rdpcap(file, number)

def read_all_packets_from_pcap(file='test.pcap'):
	return rdpcap(file)

data=read_all_packets_from_pcap()

#print(type(data))
for p in data:
	if p.haslayer("IP"):
		src = p["IP"].src
		dst = p["IP"].dst
		length = p[IP].len
		print("{}-{} {}" .format( src,dst,length))
		#print("dip: %s" % dst_ip)
