# UPC UBEE WPA2 generator proof-of-concept

Proof of concept code for generating default WPA2 passwords for 
UPC UBEE EBW3226 router with MAC prefix `64:7c:34` and for SSIDs of the form `UPC1234567` (7 digits).

- Proof of concept generator code is [ubee_keys.c](https://github.com/yolosec/upcgen/blob/master/ubee_keys.c) file in C.
- Python implementation for SSID and Password generator is in [pytools/ubee_wifileaks.py](https://github.com/yolosec/upcgen/blob/master/pytools/ubee_wifileaks.py).
Note profanity detection is not implemented in Python version.

For technical writeup see our [blog post](https://deadcode.me/blog/2016/07/01/UPC-UBEE-EVW3226-WPA2-Reversing.html)
