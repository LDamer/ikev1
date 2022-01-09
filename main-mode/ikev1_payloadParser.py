from scapy.all import *
import binascii
from scapy.layers.isakmp import *
from scapy.layers.inet import IP

KEX = ISAKMP_payload_KE
NONCE = ISAKMP_payload_Nonce
SAPAYLOAD = ISAKMP_payload_SA


def getInitiatorIP(packets):
    packet = getIniatorSAPacket(packets)
    return packet[IP].src


def getResponderIP(packets):
    packet = getResponderSAPacket(packets)
    return packet[IP].src


def getIniatorSAPacket(packets):
    for p in packets:
        if p.haslayer(ISAKMP):
            if binascii.hexlify(bytes(p[ISAKMP].resp_cookie)) == b'0000000000000000':
                return p


def getResponderSAPacket(packets):
    for p in packets:
        if p.haslayer(ISAKMP):
            if not binascii.hexlify(bytes(p[ISAKMP].resp_cookie)) == b'0000000000000000':
                return p


def getPayloadFromISAKMP(packet, name):
    return packet[name].load


def getNonce(p):
    return p[ISAKMP_payload_Nonce].fieldval("nonce")


def getCookieFromISAKMP(packet, forResponder):
    if packet.haslayer("ISAKMP"):
        if forResponder:
            return packet.resp_cookie
        else:
            return packet.init_cookie


def getSAPayloadFromInitPacket(packet):
    # TODO Your Code here
    l = packet[ISAKMP_payload_SA].length
    return bytes(packet[ISAKMP_payload_SA])[4:l]  ##skip header


def getResponderIDFromRespPacket(packet):
    # TODO Your Code here
    return (packet[ISAKMP_payload_ID].IDtype.to_bytes(1, "big") + \
            packet[ISAKMP_payload_ID].getfieldval("ProtoID").to_bytes(1, "big") + \
            packet[ISAKMP_payload_ID].getfieldval("Port").to_bytes(2, "big") + \
            (packet[ISAKMP_payload_ID].getfieldval("load")))


def getEncryptedData(packets, senderIP):
    d = []
    for p in packets:
        if p[IP].src == senderIP:
            if p.haslayer('ISAKMP'):
                if p['ISAKMP'].flags == 1:
                    d.append(packet['ISAKMP'].load)
    return d
