#
# @author Miroc
#
from __future__ import print_function
import sqlite3
import re

conn1 = sqlite3.connect('/home/miroc/Projects2/Wardriving 2016.2.10/backup-1455138750871.sqlite')
conn2 = sqlite3.connect('/home/miroc/Projects2/ubee_keys.db')


def get_macs(bssid_suffix):
    macs = []
    hex_num = '0x00' + bssid_suffix
    num = int(hex_num, 0)
    for i in range(-10, 11):
        hex_iterated = hex((num + i))[2:]
        hex_iterated_zfilled = hex_iterated.zfill(6)
        macs.append((i, hex_iterated_zfilled))
    return macs


c = conn1.cursor()
ubee_count = 0
collisions_count = 0

res = []

for row in c.execute('select bssid, ssid from network'):
    bssid = row[0]
    ssid = row[1]
    # ssid_no_upc = ssid[3:]
    if re.match(r'^UPC[0-9]{6,9}$', ssid):
        s = bssid.split(':')
        bssid_suffix = s[3] + s[4] + s[5]
        macs = get_macs(bssid_suffix)
        for it, mac in macs:
            c2 = conn2.cursor()
            c2.execute('SELECT mac,ssid from wifi where mac = "' + mac + '"')
            r2 = c2.fetchone()
            if r2 is None:
                print("bad mac", mac, bssid_suffix)
                continue
            gen_mac = r2[0]
            gen_ssid = 'UPC' + r2[1]
            if gen_ssid == ssid:
                # BSSID, it, MAC, SSID
                res.append((bssid, it, mac, gen_ssid, ssid))

                collisions_count += 1

        ubee_count += 1

for r in res:
    print(r)

print(ubee_count)
print(collisions_count)