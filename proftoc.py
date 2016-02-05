#!/usr/bin/env python2
 # -*- coding: utf-8 -*-
'''
Profanities file to C
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
    parser = argparse.ArgumentParser(description='Profanities file to C', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('file', metavar='file', nargs='+', help='file to compute')

    args = parser.parse_args()
    if args.file is None or len(args.file) == 0:
        parser.print_help()
        sys.exit(-1)

    # Wrap sys.stdout into a StreamWriter to allow writing unicode.
    sys.stdout = codecs.getwriter(locale.getpreferredencoding())(sys.stdout)

    profans=[]
    for curfile in args.file:
        with open(curfile, 'r') as f:
            lines = f.readlines()
            # print "profanities[] = {"
            for line in lines:
                profans.append(line.strip())
                # print "\"%s\"," % (line.strip())
            # print "};"
        pass
    pass

    padding=14
    online=0
    linebuff=""
    for p in profans:
        if online>8:
            online=0
            print linebuff
            linebuff=""
        nprof='"' + p + '",'
        if (len(nprof)<padding):
            nprof+=(' '*(padding-len(nprof)))
        linebuff+=nprof
        online+=1


pass