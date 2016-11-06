from __future__ import print_function
import sqlite3
import re
import hashlib
import operator
import sys
import unidecode


__author__ = 'dusanklinec'


def get_macs(bssid_suffix):
    macs = []
    hex_num = '0x00' + bssid_suffix
    num = int(hex_num, 0)
    if (num == 0):
        return [(0, '000000')]
    for i in range(-10, 11):
        hex_iterated = hex((num + i))[2:]
        hex_iterated_zfilled = hex_iterated.zfill(6)
        macs.append((i, hex_iterated_zfilled))
    return macs


def macstr2s(m):
    return [m[0:2], m[2:4], m[4:6], m[6:8], m[8:10], m[10:12]]


def compute_ssid(mac):
    '''
    Generates SSID from the MAC - reverse engineered from UBEE
    :param mac:
    :return:
    '''
    m = hashlib.md5()
    m2 = hashlib.md5()
    mac = [int(x,16) for x in mac]

    # MAC+hex(UPCDEAULTSSID)
    inp1 = "%2X%2X%2X%2X%2X%2X555043444541554C5453534944\0" % (mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
    m.update(inp1)
    h1 = [ord(x) for x in m.digest()]

    inp2 = "%.02X%.02X%.02X%.02X%.02X%.02X\0" % (h1[0]&0xf, h1[1]&0xf, h1[2]&0xf, h1[3]&0xf, h1[4]&0xf, h1[5]&0xf)
    m2.update(inp2)
    h2 = [ord(x) for x in m2.digest()]

    return "UPC%d%d%d%d%d%d%d" % (h2[0]%10, h2[1]%10, h2[2]%10, h2[3]%10, h2[4]%10, h2[5]%10, h2[6]%10)


def compute_password(mac):
    '''
    Generates password from the MAC - reverse engineered from UBEE.
    Warning: does not implement profanity detection.
    :param mac:
    :return:
    '''
    m = hashlib.md5()
    m2 = hashlib.md5()
    mac = [int(x,16) for x in mac]

    # MAC+hex(UPCDEAULTPASSPHRASE)
    inp1 = "%2X%2X%2X%2X%2X%2X555043444541554C5450415353504852415345\0" % (mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
    m.update(inp1)
    h1 = [ord(x) for x in m.digest()]

    inp2 = "%.02X%.02X%.02X%.02X%.02X%.02X\0" % (h1[0]&0xf, h1[1]&0xf, h1[2]&0xf, h1[3]&0xf, h1[4]&0xf, h1[5]&0xf)
    m2.update(inp2)
    h2 = [ord(x) for x in m2.digest()]

    return "%c%c%c%c%c%c%c%c" % (
        (0x41 + ((h2[0]+h2[8]) % 0x1A)),
        (0x41 + ((h2[1]+h2[9]) % 0x1A)),
        (0x41 + ((h2[2]+h2[10]) % 0x1A)),
        (0x41 + ((h2[3]+h2[11]) % 0x1A)),
        (0x41 + ((h2[4]+h2[12]) % 0x1A)),
        (0x41 + ((h2[5]+h2[13]) % 0x1A)),
        (0x41 + ((h2[6]+h2[14]) % 0x1A)),
        (0x41 + ((h2[7]+h2[15]) % 0x1A)))


def gen_ssids(s):
    macs = []
    num = int(''.join(s), 16)
    for i in range(-4, 4):
        hex_iterated = hex((num + i))[2:]
        hex_iterated_zfilled = hex_iterated.zfill(12)
        s = macstr2s(hex_iterated_zfilled)
        ssid = compute_ssid(s)
        macs.append((i, hex_iterated_zfilled, ssid))
    return macs


def is_ubee(mac):
    return mac.upper().startswith('64:7C:34')


def is_vuln(mac):
    mac = mac.upper()
    return mac.startswith('64:7C:34') \
           or mac.startswith('88:F7:C7') \
           or mac.startswith('C4:27:95') \
           or mac.startswith('58:23:8C') \
           or mac.startswith('44:32:C8') \
           or mac.startswith('08:95:2A') \
           or mac.startswith('B0:C2:87') \
           or mac.startswith('E0:88:5D')


def is_technicolor(mac):
    mac = mac.upper()
    return mac.startswith('88:F7:C7') \
           or mac.startswith('C4:27:95') \
           or mac.startswith('58:23:8C') \
           or mac.startswith('44:32:C8') \
           or mac.startswith('08:95:2A') \
           or mac.startswith('B0:C2:87') \
           or mac.startswith('E0:88:5D')


def is_upc_mac(mac):
    mac = mac.upper()
    return mac.startswith('64:7C:34') \
           or mac.startswith('88:F7:C7') \
           or mac.startswith('C4:27:95') \
           or mac.startswith('58:23:8C') \
           or mac.startswith('44:32:C8') \
           or mac.startswith('08:95:2A') \
           or mac.startswith('B0:C2:87') \
           or mac.startswith('E0:88:5D') \
           or mac.startswith('54:67:51') \
           or mac.startswith('DC:53:7C')


def is_upc_old(ssid):
    return re.match(r'^UPC[0-9]{6,9}$', ssid) is not None


def is_upc(ssid):
    return re.match(r'^UPC[0-9a-zA-Z]{5,11}$', ssid) is not None and ssid != 'UPC Wi-Free'


def print_max_prefixes(clst, caption, topXmacs=10):
    print(caption)
    sorted_x = sorted(clst, key=operator.itemgetter(1), reverse=True)
    for k in sorted_x:
        print("  %s: %s" % (k[0], k[1]))

    if len(clst) > topXmacs:
        print("Top %d %s" % (topXmacs, caption))
        for k in range(0, topXmacs):
            print("  %s: %s" % (sorted_x[k][0], sorted_x[k][1]))
        print("  rest: %s" % sum([x[1] for x in sorted_x[topXmacs:]]))
    print('')


def binarySearch(data, val):
    highIndex = len(data)-1
    lowIndex = 0
    while highIndex > lowIndex:
            index = (highIndex + lowIndex) / 2
            sub = data[index]
            if data[lowIndex] == val:
                    return [lowIndex, lowIndex]
            elif sub == val:
                    return [index, index]
            elif data[highIndex] == val:
                    return [highIndex, highIndex]
            elif sub > val:
                    if highIndex == index:
                            return sorted([highIndex, lowIndex])
                    highIndex = index
            else:
                    if lowIndex == index:
                            return sorted([highIndex, lowIndex])
                    lowIndex = index
    return sorted([highIndex, lowIndex])

