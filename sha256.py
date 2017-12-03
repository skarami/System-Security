#!/usr/bin/env python2

import struct
from struct import unpack

def pad_message(msg):
    """ Pad msg appropriately for SHA-256. """
    L = len(msg)*8
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

def process_chunk(md, chunk):
    """ Process the next 512-bit chunk, updating the md array. """

    k = [
            0x428a2f98L,0x71374491L,0xb5c0fbcfL,0xe9b5dba5L,0x3956c25bL,0x59f111f1L,0x923f82a4L,0xab1c5ed5L,
            0xd807aa98L,0x12835b01L,0x243185beL,0x550c7dc3L,0x72be5d74L,0x80deb1feL,0x9bdc06a7L,0xc19bf174L,
            0xe49b69c1L,0xefbe4786L,0x0fc19dc6L,0x240ca1ccL,0x2de92c6fL,0x4a7484aaL,0x5cb0a9dcL,0x76f988daL,
            0x983e5152L,0xa831c66dL,0xb00327c8L,0xbf597fc7L,0xc6e00bf3L,0xd5a79147L,0x06ca6351L,0x14292967L,
            0x27b70a85L,0x2e1b2138L,0x4d2c6dfcL,0x53380d13L,0x650a7354L,0x766a0abbL,0x81c2c92eL,0x92722c85L,
            0xa2bfe8a1L,0xa81a664bL,0xc24b8b70L,0xc76c51a3L,0xd192e819L,0xd6990624L,0xf40e3585L,0x106aa070L,
            0x19a4c116L,0x1e376c08L,0x2748774cL,0x34b0bcb5L,0x391c0cb3L,0x4ed8aa4aL,0x5b9cca4fL,0x682e6ff3L,
            0x748f82eeL,0x78a5636fL,0x84c87814L,0x8cc70208L,0x90befffaL,0xa4506cebL,0xbef9a3f7L,0xc67178f2L
        ]
    tmp = unpack('!16L', chunk)
    w = [0]*64
    w[0] = tmp[0]
    w[1] = tmp[1]
    w[2] = tmp[2]
    w[3] = tmp[3]
    w[4] = tmp[4]
    w[5] = tmp[5]
    w[6] = tmp[6]
    w[7] = tmp[7]
    w[8] = tmp[8]
    w[9] = tmp[9]
    w[10] = tmp[10]
    w[11] = tmp[11]
    w[12] = tmp[12]
    w[13] = tmp[13]
    w[14] = tmp[14]
    w[15] = tmp[15]
        
    for i in range(16, 64):
            s0 = rightRotate(w[i-15], 7) ^ rightRotate(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = rightRotate(w[i-2], 17) ^ rightRotate(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFFL
        
    a = md[0]
    b = md[1]
    c = md[2]
    d = md[3]
    e = md[4]
    f = md[5]
    g = md[6]
    h = md[7]
        
    for i in range(64):
            s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = h + s1 + ch + k[i] + w[i]
            s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = s0 + maj
            
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFFL
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFFL
        
    md[0] = (md[0] + a) & 0xFFFFFFFFL
    md[1] = (md[1] + b) & 0xFFFFFFFFL
    md[2] = (md[2] + c) & 0xFFFFFFFFL
    md[3] = (md[3] + d) & 0xFFFFFFFFL
    md[4] = (md[4] + e) & 0xFFFFFFFFL
    md[5] = (md[5] + f) & 0xFFFFFFFFL
    md[6] = (md[6] + g) & 0xFFFFFFFFL
    md[7] = (md[7] + h) & 0xFFFFFFFFL

    return md


def hexdigest(md):
    """ Return the hex digest of the hashed value. """
    digest = ''
    for var in md:
        digest += "{:08x}".format(var)
    return digest

def rightRotate(chunkPart, n):
    v = ((chunkPart >> n) | (chunkPart << (32-n))) & 0xFFFFFFFFL
    return v   

def sha256(md, msg):
    """ Return the SHA-256 hash of msg as a hex string. """
    # Pad the message
    msg = pad_message(msg)
    
    # Break msg into 512-bit chunks
    view = memoryview(msg)
    for chunk_num in range(len(msg)/64):
        chunk_start = 64*chunk_num
        md = process_chunk(md, view[chunk_start:chunk_start+64])
    # Produce the final value
    return hexdigest(md)

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        sys.exit("Usage: {} string".format(sys.argv[0]))
    
    # Initialization vector
    md = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    print sha256(md, sys.argv[1])
