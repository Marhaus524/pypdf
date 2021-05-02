import binascii
import zlib
from io import StringIO

from pdfguard.utils import to_bytes


# http://code.google.com/p/pdfminerr/source/browse/trunk/pdfminer/pdfminer/ascii85.py
def ASCII85Decode(data):
    import struct

    n = b = 0
    out = ""
    for c in data:
        if "!" <= c and c <= "u":
            n += 1
            b = b * 85 + (ord(c) - 33)
            if n == 5:
                out += struct.pack(">L", b)
                n = b = 0
        elif c == "z":
            assert n == 0
            out += "\0\0\0\0"
        elif c == "~":
            if n:
                for _ in range(5 - n):
                    b = b * 85 + 84
                out += struct.pack(">L", b)[: n - 1]
            break
    return out


def ASCIIHexDecode(data):
    return binascii.unhexlify(
        "".join([c for c in data if c not in " \t\n\r"]).rstrip(">")
    )


# if inflating fails, we try to inflate byte per byte (sample 4da299d6e52bbb79c0ac00bad6a1d51d4d5fe42965a8d94e88a359e5277117e2)
def FlateDecode(data):
    try:
        return zlib.decompress(to_bytes(data))
    except:
        if len(data) <= 10:
            raise
        oDecompress = zlib.decompressobj()
        oStringIO = StringIO()
        count = 0
        for byte in to_bytes(data):
            try:
                oStringIO.write(oDecompress.decompress(byte))
                count += 1
            except:
                break
        if len(data) - count <= 2:
            return oStringIO.getvalue()
        else:
            raise


def RunLengthDecode(data):
    f = StringIO(data)
    decompressed = ""
    runLength = ord(f.read(1))
    while runLength:
        if runLength < 128:
            decompressed += f.read(runLength + 1)
        if runLength > 128:
            decompressed += f.read(1) * (257 - runLength)
        if runLength == 128:
            break
        runLength = ord(f.read(1))
    #    return sub(r'(\d+)(\D)', lambda m: m.group(2) * int(m.group(1)), data)
    return decompressed


#### LZW code sourced from pdfminer
# Copyright (c) 2004-2009 Yusuke Shinyama <yusuke at cs dot nyu dot edu>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:


class LZWDecoder(object):
    def __init__(self, fp):
        self.fp = fp
        self.buff = 0
        self.bpos = 8
        self.nbits = 9
        self.table = None
        self.prevbuf = None
        return

    def readbits(self, bits):
        v = 0
        while 1:
            # the number of remaining bits we can get from the current buffer.
            r = 8 - self.bpos
            if bits <= r:
                # |-----8-bits-----|
                # |-bpos-|-bits-|  |
                # |      |----r----|
                v = (v << bits) | ((self.buff >> (r - bits)) & ((1 << bits) - 1))
                self.bpos += bits
                break
            else:
                # |-----8-bits-----|
                # |-bpos-|---bits----...
                # |      |----r----|
                v = (v << r) | (self.buff & ((1 << r) - 1))
                bits -= r
                x = self.fp.read(1)
                if not x:
                    raise EOFError
                self.buff = ord(x)
                self.bpos = 0
        return v

    def feed(self, code):
        x = ""
        if code == 256:
            self.table = [chr(c) for c in range(256)]  # 0-255
            self.table.append(None)  # 256
            self.table.append(None)  # 257
            self.prevbuf = ""
            self.nbits = 9
        elif code == 257:
            pass
        elif not self.prevbuf:
            x = self.prevbuf = self.table[code]
        else:
            if code < len(self.table):
                x = self.table[code]
                self.table.append(self.prevbuf + x[0])
            else:
                self.table.append(self.prevbuf + self.prevbuf[0])
                x = self.table[code]
            l = len(self.table)
            if l == 511:
                self.nbits = 10
            elif l == 1023:
                self.nbits = 11
            elif l == 2047:
                self.nbits = 12
            self.prevbuf = x
        return x

    def run(self):
        while 1:
            try:
                code = self.readbits(self.nbits)
            except EOFError:
                break
            x = self.feed(code)
            yield x
        return


####


def LZWDecode(data):
    return "".join(LZWDecoder(StringIO(data)).run())


class cDecoderParent:
    pass


class cIdentity(cDecoderParent):
    name = "Identity function decoder"

    def __init__(self, stream, options):
        self.stream = stream
        self.options = options
        self.available = True

    def Available(self):
        return self.available

    def Decode(self):
        self.available = False
        return self.stream

    def Name(self):
        return ""
