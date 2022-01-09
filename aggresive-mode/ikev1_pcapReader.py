from scapy.all import *
from scapy.layers.isakmp import *

def openPCAPFile(path: str) -> scapy.plist.PacketList:
    #TODO Read a pcap or pcapng file and return a packet list
    res = rdpcap(path)
    return res

def getISAKMPPackets(packets: scapy.plist.PacketList) -> []:
    #TODO returns a list containing only the ISAKMP Layers of the packets in packetList 
    #load_layer("ISAKMP")
    return [p[ISAKMP] for p in packets if p.haslayer(ISAKMP)]
