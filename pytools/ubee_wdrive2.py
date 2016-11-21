#
# @author Miroc
# @author Ph4r05
#

from __future__ import print_function
import sqlite3
import re
import hashlib
import operator
import sys
import unidecode
from functions import *

connWdrive = sqlite3.connect('/Volumes/EXTDATA/backup-1475418391308.sqlite')
connWdrive2 = sqlite3.connect('/Volumes/EXTDATA/kismet.sqlite')

# Statistics
ubee_count = 0
ubee_24 = 0
ubee_5 = 0
ubee_unknown = 0
collisions_count = 0
total_count = 0
huawei_count = 0
upc_any_count = 0
upc_count = 0
upc_free_count = 0
upc_weird_count = 0
upc_vuln_count = 0
upc_vuln_changed_count = 0
upc_changed = 0
upc_technicolor_count = 0
upc_technicolor_changed = 0
ubee_changed_ssid = 0
ubee_no_match = 0
ubee_match = 0
upc_no_match = 0
totalidx = 0
upc_mac_prefixes_counts = {}
upc_ssid_chr_cnt = [0,0,0,0]
upc_ubee_ssid_chr_cnt = [0,0,0,0]
wiggle_added = 0
wiggle_rec = 0
kismet_rec = 0

upc_mac_prefixes_changed = {}
upc_mac_prefixes_weird = {}
upc_mac_prefixes_counts_len = {}
topXmacs = 10

res = []

# joined database
database = {}
database_wiggle = {}
database_kismet = {}

# kismet database
c = connWdrive2.cursor()
for row in c.execute('select bssid, ssid, lasttime from network'):
    bssid = row[0].upper().strip()
    ssid = row[1]
    if bssid in database:
        print("Duplicate BSSID: %s, SSID: %s" % (bssid, ssid))
        continue

    database[bssid] = ssid
    database_kismet[bssid] = row
    kismet_rec += 1

# wigle database
c = connWdrive.cursor()
for row in c.execute('select bssid, ssid, * from network'):
    bssid = row[0].upper().strip()
    ssid = row[1]
    wiggle_rec += 1
    database_wiggle[bssid] = row[2:]

    if bssid in database:
        continue

    database[bssid] = ssid
    wiggle_added += 1

# scan joined database
for bssid in database:
    ssid = database[bssid]

    total_count += 1
    s = bssid.split(':')

    isUbee = (s[0] == '64') and (s[1] == '7C') and (s[2] == '34')
    if isUbee:
        ubee_count += 1

    if len(s) < 6:
        continue

    bssid_prefix = s[0] + s[1] + s[2]
    bssid_suffix = s[3] + s[4] + s[5]

    is_upc_chk = re.match(r'^UPC[0-9]{6,9}$', ssid) is not None
    is_weird_upc = re.match(r'^UPC[0-9A-Za-z]{3,12}$', ssid) is not None and not is_upc_chk
    is_upc_free = ssid == 'UPC Wi-Free'

    if ssid.startswith('UPC') and not is_upc_free:
        upc_any_count += 1

    if is_weird_upc and not is_upc_chk and not is_upc_free:
        upc_weird_count += 1
        if bssid_prefix in upc_mac_prefixes_weird:
            upc_mac_prefixes_weird[bssid_prefix] += 1
        else:
            upc_mac_prefixes_weird[bssid_prefix] = 1

    if is_upc_free:
        upc_free_count += 1

    if ssid.startswith('HUAWEI-'):
        huawei_count += 1

    if is_vuln(bssid) and is_upc_chk:
        upc_vuln_count += 1

    if is_vuln(bssid) and not is_upc_chk:
        upc_vuln_changed_count += 1

    if is_technicolor(bssid) and is_upc_chk:
        upc_technicolor_count += 1

    if is_technicolor(bssid) and not is_upc_chk:
        upc_technicolor_changed += 1

    if is_upc_mac(bssid) and not (is_upc_chk or is_weird_upc):
        upc_changed += 1
        if bssid_prefix in upc_mac_prefixes_changed:
            upc_mac_prefixes_changed[bssid_prefix] += 1
        else:
            upc_mac_prefixes_changed[bssid_prefix] = 1

    # MAC count for all UPC routers
    if is_weird_upc or is_upc_chk:
        if bssid_prefix in upc_mac_prefixes_counts:
            upc_mac_prefixes_counts[bssid_prefix] += 1
        else:
            upc_mac_prefixes_counts[bssid_prefix] = 1

    if is_upc_chk:
        ssidlen = len(ssid)

        upc_ssid_chr_cnt[ssidlen-9] += 1
        if isUbee:
            upc_ubee_ssid_chr_cnt[ssidlen-9] += 1

        upc_count += 1

        macs = get_macs(bssid_suffix)
        itmap = {}
        for it,mac in macs: itmap[str(mac)] = it

        ssiddig = ssidlen-3
        if (ssiddig,bssid_prefix) in upc_mac_prefixes_counts_len:
            upc_mac_prefixes_counts_len[(ssiddig,bssid_prefix)] += 1
        else:
            upc_mac_prefixes_counts_len[(ssiddig,bssid_prefix)] = 1

        upc_matches = 0

        # Generate SSID in python, without lookup
        computed_ssids = gen_ssids(s)
        for cit, cmac, cssid in computed_ssids:
            if cssid == ssid:
                # BSSID, it, MAC, SSID
                shift = cit
                if shift == -3:
                    ubee_24 += 1
                elif shift == -1:
                    ubee_5 += 1
                else:
                    ubee_unknown += 1
                res.append((bssid, shift, cmac, cssid, ssid))
                collisions_count += 1
                upc_matches += 1
                if isUbee:
                    ubee_match += 1
                else:
                    print("Got not of UBEE! ssid: %s bssid: %s" % (ssid, bssid))

        # No match - compute
        if upc_matches == 0:
            upc_no_match += 1
            if isUbee: ubee_no_match += 1

    elif isUbee:
        ubee_changed_ssid += 1


for r in res:
    print(r)

print_max_prefixes(upc_mac_prefixes_counts.items(), 'UPC mac prefixes: ')
for i in range(6,10):
    clst = [(x[1],upc_mac_prefixes_counts_len[x]) for x in upc_mac_prefixes_counts_len if x[0] == i]
    print_max_prefixes(clst, "UPC[0-9]{%d} mac prefixes: " % i)
print_max_prefixes(upc_mac_prefixes_weird.items(), 'UPC weird prefixes: ')
print_max_prefixes(upc_mac_prefixes_changed.items(), 'UPC changed prefixes: ')

# Generate KML map
kml = '<?xml version="1.0" encoding="UTF-8"?>\n' \
      '<kml xmlns="http://www.opengis.net/kml/2.2"><Document>\n' \
      '<Style id="red"><IconStyle><Icon><href>http://i67.tinypic.com/t64076.jpg</href></Icon></IconStyle></Style>\n' \
      '<Style id="yellow"><IconStyle><Icon><href>http://maps.google.com/mapfiles/ms/icons/yellow-dot.png</href></Icon></IconStyle></Style>\n' \
      '<Style id="blue"><IconStyle><Icon><href>http://maps.google.com/mapfiles/ms/icons/blue-dot.png</href></Icon></IconStyle></Style>\n' \
      '<Style id="green"><IconStyle><Icon><href>http://maps.google.com/mapfiles/ms/icons/green-dot.png</href></Icon></IconStyle></Style>\n' \
      '<Folder><name>Wifi Networks</name>\n'

placemarks = []
for bssid in database_wiggle:
    row = database_wiggle[bssid]
    blong = row[-2]
    blat = row[-1]
    ssid = row[1]
    ssid = unidecode.unidecode(ssid)

    style = 'red'
    if is_upc(ssid) and len(ssid) == 10:
        if is_ubee(row[0]):
            style = 'green'
        else:
            style = 'blue'

    pmark = '<Placemark><name><![CDATA[%s]]></name><description><![CDATA[BSSID: %s]]></description>' \
            '<styleUrl>#%s</styleUrl><Point><coordinates>%s,%s</coordinates></Point></Placemark>' \
            % (ssid, bssid[0:8], style, blat, blong)
    placemarks.append(pmark)

# Adding Kismet data to the map - estimation.
# Build location database based on time
# lasttime_db[time] = [loc1, loc2, ..., locN]
lasttime_db = {}
time_diffs = []
for bssid in database_wiggle:
    row = database_wiggle[bssid]
    blong = row[-2]
    blat = row[-1]
    lasttime = row[4]
    if lasttime not in lasttime_db:
        lasttime_db[lasttime] = [(blong, blat)]
    else:
        lasttime_db[lasttime].append((blong, blat))

    # Time sync - if BSSID was caught by both devices, meassure the time difference.
    # Collect time differences to the array for later averaging.
    if bssid in database_kismet and lasttime > 100000:
        kistime = database_kismet[bssid][2]*1000.0
        if kistime > 100000:
            time_diffs.append(long(lasttime - kistime))

time_diffs = sorted(time_diffs)
total_time_diff = sum(time_diffs) / float(len(time_diffs))
print('Total time diff wiggle-kismet: %f mode: %f, total: %d'
      % (total_time_diff, time_diffs[len(time_diffs)/2], len(time_diffs)))

# Average positions on the same time to get the best estimate
lasttime_db_avg = []
for lasttime in lasttime_db:
    positions = lasttime_db[lasttime]
    avg_x = sum([x[0] for x in positions])/float(len(positions))
    avg_y = sum([x[1] for x in positions])/float(len(positions))
    lasttime_db_avg.append((lasttime, avg_x, avg_y))

# Sort wiggle database record based on the time.
# It would be better to do binary search to get the closes point, but... OK later.
lasttime_db_avg = sorted(list(lasttime_db_avg), key=lambda x: x[0])

# Add also Kismet data - based on the wiggle position estimate.
kismet_placemarks_added = 0
for idx, bssid in enumerate(database_kismet):
    if bssid in database_wiggle:
        continue

    cur_time = database_kismet[bssid][2]*1000.0 + total_time_diff
    closest_rec = min(lasttime_db_avg, key=lambda x: abs(x[0] - cur_time))

    # Add as a placemark.
    ssid = database_kismet[bssid][1]
    ssid = unidecode.unidecode(ssid)

    style = 'red'
    if is_upc(ssid) and len(ssid) == 10:
        if is_ubee(bssid):
            style = 'green'
        else:
            style = 'blue'

    pmark = '<Placemark><name><![CDATA[%s]]></name><description><![CDATA[BSSID: %s<br/>Estimate]]></description>' \
            '<styleUrl>#%s</styleUrl><Point><coordinates>%s,%s</coordinates></Point></Placemark>' \
            % (ssid, bssid[0:8], style, closest_rec[2], closest_rec[1])
    placemarks.append(pmark)
    kismet_placemarks_added += 1

kml += '\n'.join(placemarks)
kml += '</Folder></Document></kml>\n'
with open('wdriving2.kml', 'w') as kml_file:
    kml_file.write(kml)


# Other statistics
print("\n* Statistics: ")
print("Total count: ", total_count)
print("UPC any: %d (%f %%)" % (upc_any_count, 100.0*upc_any_count/float(total_count)))
print("UPC[0-9]{6,9} count: %d (%f %%)" % (upc_count, 100.0*upc_count/float(total_count)))
print("UPC Free count: %d (%f %%)" % (upc_free_count, 100.0*upc_free_count/float(total_count)))
print("UPC weird count: %d (%f %% UPC)" % (upc_weird_count, 100.0*upc_weird_count/float(upc_any_count)))
print("UPC vulnerable: %d (%f %% UPC)" % (upc_vuln_count, 100.0*upc_vuln_count/float(upc_any_count)))
print("UPC vulnerable changed: %d (%f %% UPC)" % (upc_vuln_changed_count, 100.0*upc_vuln_changed_count/float(upc_any_count)))
print("UPC changed: %d (%f %% UPC)" % (upc_changed, 100.0*upc_changed/float(upc_any_count)))
print("UPC technicolor: %d (%f %% UPC)" % (upc_technicolor_count, 100.0*upc_technicolor_count/float(upc_any_count)))
print("UPC technicolor changed: %d (%f %% UPC %f %% Tech)" % (upc_technicolor_changed, 100.0*upc_technicolor_changed/float(upc_any_count), 100.0*upc_technicolor_changed/upc_technicolor_count))

print("Huawei count: %d (%f %%)" % (huawei_count, 100.0*huawei_count/float(total_count)))
print("UBEE count: ", ubee_count)
print("UBEE changed count: %d (%f %%)" % (ubee_changed_ssid, 100.0*ubee_changed_ssid/ubee_count))
print("UBEE matches: %d (%f %%), (%f %% UPC)" % (collisions_count, 100.0*collisions_count/(ubee_count-ubee_changed_ssid), 100.0*collisions_count/upc_any_count))
print("UBEE 2.4: ", ubee_24)
print("UBEE 5.0: ", ubee_5)
print("UBEE unknown: ", ubee_unknown)
print("UBEE no-match: ", ubee_no_match)
print("UBEE match: ", ubee_match)
print("UPC no-match: ", upc_no_match)
print("UPC 6: ", upc_ssid_chr_cnt[0])
print("UPC 7: ", upc_ssid_chr_cnt[1])
print("UPC 8: ", upc_ssid_chr_cnt[2])
print("UPC 9: ", upc_ssid_chr_cnt[3])
print("UPCubee 6: ", upc_ubee_ssid_chr_cnt[0])
print("UPCubee 7: ", upc_ubee_ssid_chr_cnt[1])
print("UPCubee 8: ", upc_ubee_ssid_chr_cnt[2])
print("UPCubee 9: ", upc_ubee_ssid_chr_cnt[3])
print("Wiggle added to kismet DB: %s" % wiggle_added)
print("Kismet placemarks added: %d" % kismet_placemarks_added)
print("KismetDB rec: %d, WigleDB rec: %d, total db size: %d " % (kismet_rec, wiggle_rec, len(database)))



