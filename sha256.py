#!/usr/bin/env python2

import struct

def pad_message(msg):
    """ Pad msg appropriately for SHA-256. """
    return msg

def process_chunk(md, chunk):
    """ Process the next 512-bit chunk, updating the md array. """
    pass

def hexdigest(md):
    """ Return the hex digest of the hashed value. """
    digest = ''
    for var in md:
        digest += "{:08x}".format(var)
    return digest


def sha256(msg):
    """ Return the SHA-256 hash of msg as a hex string. """
    # Pad the message
    msg = pad_message(msg)

    # Initialization vector
    md = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

    # Break msg into 512-bit chunks
    view = memoryview(msg)
    for chunk_num in range(0, len(msg), 64):
        chunk_start = 64*chunk_num
        process_chunk(md, view[chunk_start:chunk_start+64])

    # Produce the final value
    return hexdigest(md)

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        sys.exit("Usage: {} string".format(sys.argv[0]))
    print sha256(sys.argv[1])
