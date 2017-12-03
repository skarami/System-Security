from sha256 import process_chunk
from sha256 import hexdigest
import struct

def create_forgery(oracle):
    
    extension = "y"*50
    msgs = []
    macs = []
    
    msgs.append("x"*10)
    macs.append(oracle(msgs[0]))

    md = []
    for i in range(len(macs[0])/8):
        md.append(int(macs[0][i*8:i*8+8],16))

    msgs.append(pad_message(msgs[0], 16)+extension)
    macs.append(hexdigest(process_chunk(md, pad_message(extension, 64))))
    return (msgs[1], macs[1])

def pad_message(msg, l):
    """ Pad msg appropriately for SHA-256. """
    L = (len(msg)+l)*8
    pad = '1'
    K = 0
    while (L+1+K+64)%512 != 0:
        K += 1
        pad += '0'
    i = 0
    pad += str(format(L,'064b'))
    while i<len(pad):
        msg += chr(int(pad[i:i+8],2))
        i += 8

    return msg
