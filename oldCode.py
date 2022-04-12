from codecs import decode,encode
from opencc import OpenCC

def uuEn(message):
    result = encode(message.encode(), "uu").decode("utf-8")
    start = result.find("<data>")
    end = result.find("\nend\n")
    result = result[start + 7:end - 2]
    return result
def uuDe(message):
    message = "begin 666 <data>\n" + message + " \n \nend\n"
    result = decode(message.encode(), "uu").decode("utf-8")
    return result
def hexEn(message):
    return encode(message.encode(), 'hex_codec').decode("utf-8")
def hexDe(message):
    return decode(message.encode(), 'hex_codec').decode("utf-8")
def binEn(message):
    return " ".join(format(ord(x), 'b') for x in message)
def binDe(binaryString):
    return "".join([chr(int(binary, 2)) for binary in binaryString.split(" ")])
def s2t(val):
    return OpenCC('s2t').convert(val)
def t2s(val):
    return OpenCC('t2s').convert(val)
def s2twp(val):
    return OpenCC('s2twp').convert(val)
def s2hk(val):
    return OpenCC('s2hk').convert(val)