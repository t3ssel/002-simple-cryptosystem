#!/usr/bin/env python3

key = b'\
\xb6\x58\x87\x9d\x31\x12\xac\x49\x2f\x4c\xf3\x48\x84\x66\x21\xa1\
\xe3\x28\x72\x9d\x5f\x2f\xa3\x69\xef\xe2\x3c\x9a\x4d\xdf\x23\x92\
\xbd\xe0\x4d\x00\x1c\xcf\x75\x13\x04\x7b\x62\x4d\xcd\xe2\x43\xba\
\x37\x6e\x08\x26\x27\x2b\xc5\x85\xa4\x1c\xab\xd3\xa4\x3c\xc4\xf9\
\x08\x87\xe7\x4f\x46\x6c\x7c\x27\xa2\x43\xab\x5a\x9e\xcf\xa4\x9f\
\x20\x02\x91\x30\xb0\x0e\x9b\x1c\xb1\x1e\x3e\x4d\x38\xea\x76\x18\
\x19\xe1\xcf\xa7\x84\xe4\x49\x06\xe4\xa8\x6a\x2c\x05\x52\x61\x9f\
\x9c\xb0\xa9\x7c\x2c\x76\xa8\xad\x24\xed\x63\x27\x22\x77\x0d\x00\
\xe2\x87\x3b\xf4\xcf\x00\xe0\xbc\x85\x30\x6e\xcf\xa9\xba\x8d\x25\
\x18\x52\xa7\xa3\xd7\xbc\x00\x5f\xdd\x0e\xd3\xd7\x26\x8c\x61\xe0\
\xc0\xf6\x1d\xf8\x48\x22\xd8\xf5\x1f\xc3\xd3\xaf\xea\x9c\x4c\xa3\
\x4f\x9a\xa4\x12\x31\xe9\x28\xd9\xb8\x5e\x90\x3b\xaa\x16\x58\x0e\
\x67\xaf\x35\x47\x2a\x71\x43\xec\x30\xd0\x00\x81\xc2\xb6\xbc\xb0\
\x70\x45\x81\xf8\xbb\xbc\x3a\x67\x63\x46\xd4\x67\xc0\x28\xd4\xcd\
\xee\x1e\x07\x40\xd6\xc8\xac\x6f\x20\x32\x89\x50\xcb\x01\x0d\xec\
\x0b\xef\xde\x7a\x3b\xa6\xca\xd8\x73\x94\x2c\xd4\x19\x16\xc3\x00'

class Crypto:

    last_iterator = 0

    @staticmethod
    def getIterator(distri):
        edx = (Crypto.last_iterator * 0x8088405) & 0xffffffff
        edx = (edx + 1) & 0xffffffff
        Crypto.last_iterator = edx
        edx = ((edx * distri) & 0xffffffff00000000) >> 32
        return (edx)

    #
    # Encrypt a string
    # returns encrypted byte array
    # the byte array is NOT [0xff,0xff] terminated
    #
    @staticmethod
    def encrypt(in_str):
        output = bytearray(len(in_str) + 2)

        ebx = Crypto.getIterator(0xFC) + 1
        edx = (ebx ^ 0x21) & 0xffffffff
        output[0] = (edx & 0xff)

        var_C = Crypto.getIterator(0x14)
        dl = (var_C ^ 0x42) & 0xffffffff
        output[len(in_str) + 1] = dl & 0xff

        in_str = chr(edx) + in_str + chr(dl)

        var_14 = len(in_str) - 2
        var_D = False
        esi = ebx
        edi = 2

        while var_14 != 0:
            if var_D == False:
                dl = ord(in_str[edi - 1]) ^ key[ebx] ^ esi
            else:
                dl = in_str[edi - 1]
            output[edi - 1] = (dl & 0xff)

            var_11 = output[edi - 1] == 0xff

            ebx += var_C
            esi -= var_C
            esi += 3

            if ebx >= 256:
                ebx = 1

            if esi < 1:
                esi = ebx

            edi += 1
            var_14 -= 1

        return (output)

    #
    # Decrypt a network packet
    # returns decrypted byte array
    # indexes and [0xff,0xff] terminations are NOT returned
    #
    @staticmethod
    def decrypt(packet):
        output = bytearray(len(packet))

        esi = packet[0] ^ 0x21
        ebx = esi
        var_10 = packet[len(packet) - 3] ^ 0x42

        var_18 = len(packet) - 4
        edi = 2

        var_11 = packet[edi - 1] == 0xff

        while (edi < len(packet) - 2):
            if var_11 == False:
                dl = (packet[edi - 1] ^ key[esi] ^ ebx) & 0xff
            else:
                dl = packet[edi - 1]
            output[edi - 1] = dl

            var_11 = packet[edi - 1] == 0xff
            esi += var_10
            ebx -= var_10
            ebx += 3

            if esi >= 0x100:
                esi = 1

            if ebx < 1:
                ebx = esi

            edi += 1

        return (output[1:len(packet) - 3])

