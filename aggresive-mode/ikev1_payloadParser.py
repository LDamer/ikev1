from scapy.all import *
from scapy.layers.isakmp import *
from binascii import hexlify
from binascii import unhexlify
import math

ISAKMP_NONCE_NAME = ISAKMP_payload_Nonce
ISAKMP_KEX_NAME = ISAKMP_payload_KE


def getIniatorSAPacket(packets: []) -> scapy.layers.isakmp.ISAKMP:
    # only isakmp packets
    # TODO Get frist initiator SA ISAKMP layer
    for p in packets:
        if p.haslayer(ISAKMP):
            if int(p.getfieldval("resp_cookie").hex(), 16) == 0:
                return p


def getResponderSAPacket(packets: []) -> scapy.layers.isakmp.ISAKMP:
    # TODO Get first responder SA ISAKMP layer
    for p in packets:
        if p.haslayer(ISAKMP):
            if not int(p.getfieldval("resp_cookie").hex(), 16) == 0:
                if len(p.layers()) > 5:
                    return p


def getPayloadFromISAKMP(packet: scapy.layers.isakmp.ISAKMP, name: str) -> bytes:
    # name == payload name
    # TODO Get the corresponding load from the selected (by name) layer
    return packet[name].load


def getCookieFromISAKMP(respPacket: scapy.layers.isakmp.ISAKMP, responderCookie: bool) -> bytes:
    # TODO return corresponding cookie value
    # true -> responder cookie
    # false -> initiator cookie
    if responderCookie:
        return bytes(respPacket.resp_cookie)
    else:
        return bytes(respPacket.init_cookie)
    pass


def getSAPayloadFromInitPacket(packet: scapy.layers.isakmp.ISAKMP) -> bytes:
    l = packet[ISAKMP_payload_SA].length
    return bytes(packet[ISAKMP_payload_SA])[4:l]##skip header

def getResponderIDFromRespPacket(packet: scapy.layers.isakmp.ISAKMP) -> bytes:
    # TODO Return responder ID from ISAKMP layer 
    # Responder ID consist of  IDType||ProtoID||Port||load
    return (packet[ISAKMP_payload_ID].IDtype.to_bytes(1, "big") + \
            packet[ISAKMP_payload_ID].getfieldval("ProtoID").to_bytes(1, "big") + \
            packet[ISAKMP_payload_ID].getfieldval("Port").to_bytes(2, "big") + \
            (packet[ISAKMP_payload_ID].getfieldval("load")))


def getRespHashfromPacket(packet: scapy.layers.isakmp.ISAKMP) -> bytes:
    # pass TODO Get the hash value to compare your computed value against
    return bytes(packet[ISAKMP_payload_Hash].getfieldval("load"))


def getNoncefromPacket(packet: scapy.layers.isakmp.ISAKMP) -> bytes:
    return bytes(packet[ISAKMP_payload_Nonce].getfieldval("load"))


def getKEXvalueFromRespPacket(packet: scapy.layers.isakmp.ISAKMP) -> bytes:
    return packet[ISAKMP_payload_KE].getfieldval("load")


def getKEXvalueFromPacket(packet: scapy.layers.isakmp.ISAKMP) -> bytes:
    return packet[ISAKMP_payload_KE].getfieldval("load")
