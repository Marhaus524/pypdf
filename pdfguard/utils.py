import re
import time


# string to bytes
def to_bytes(string):
    if type(string) == bytes:
        return string
    else:
        return bytes([ord(x) for x in string])


# bytes to string
def to_string(bytes):
    return "".join([chr(byte) for byte in bytes])


# CIC: Call If Callable
def CIC(expression):
    if callable(expression):
        return expression()
    else:
        return expression


def IIf(expr, truepart, falsepart):
    if expr:
        return truepart
    else:
        return falsepart


# IFF: IF Function
def IFF(expression, valueTrue, valueFalse):
    if expression:
        return CIC(valueTrue)
    else:
        return CIC(valueFalse)


def IsNumeric(str):
    return re.match("^[0-9]+", str)


def Timestamp(epoch=None):
    if epoch == None:
        localTime = time.localtime()
    else:
        localTime = time.localtime(epoch)
    return "%04d%02d%02d-%02d%02d%02d" % localTime[0:6]


def Canonicalize(sIn):
    if sIn == "":
        return sIn
    elif sIn[0] != "/":
        return sIn
    elif sIn.find("#") == -1:
        return sIn
    else:
        i = 0
        iLen = len(sIn)
        sCanonical = ""
        while i < iLen:
            if sIn[i] == "#" and i < iLen - 2:
                try:
                    sCanonical += chr(int(sIn[i + 1: i + 3], 16))
                    i += 2
                except:
                    sCanonical += sIn[i]
            else:
                sCanonical += sIn[i]
            i += 1
        return sCanonical


def EqualCanonical(s1, s2):
    return Canonicalize(s1) == s2


def ConditionalCanonicalize(sIn, nocanonicalizedoutput):
    if nocanonicalizedoutput:
        return sIn
    else:
        return Canonicalize(sIn)
