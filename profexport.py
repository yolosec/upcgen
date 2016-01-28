#!/usr/bin/env python2
 # -*- coding: utf-8 -*-
'''
Extracts profanities
@author Ph4r05
'''
import os
import sys
import argparse
import codecs
import locale
import struct

# Main executable code
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Export profanity database', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('file', metavar='file', nargs='+', help='file to compute')

    args = parser.parse_args()
    if args.file is None or len(args.file) == 0:
        parser.print_help()
        sys.exit(-1)

    # Wrap sys.stdout into a StreamWriter to allow writing unicode.
    sys.stdout = codecs.getwriter(locale.getpreferredencoding())(sys.stdout)

    for curfile in args.file:
        with open(curfile, 'rb') as f:
            f.seek(0x00040D74)
            for i in range(0,10000):
                buff = f.read(20)
                if not buff[0].isalnum():
                    print "--> finishing: i: %d" % i
                    break
                print buff.strip("\0").strip()
            pass
        pass
    pass
pass