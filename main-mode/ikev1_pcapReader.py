from scapy.all import *
from scapy.layers.isakmp import *

def openPCAPFile(path):
    #TODO Your Code here
    l =  rdpcap(path)
    return l

# returns only the ISAKMP Layer of the Packet
def getISAKMPPackets(packets):
    return [p[ISAKMP] for p in packets if p.haslayer(ISAKMP)]
