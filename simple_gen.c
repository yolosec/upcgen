#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <openssl/md5.h>

#define MD 10

/*
 * gcc -o2 -Wall -o simple_gen simple_gen.c -lcrypto
*/

void increase_mac_address(unsigned char* mac)
{
	// TODO inplement carry operation in case byte overflow
	mac[5] += 1;
}

uint32_t m(unsigned char c)
{
	uint32_t n = ((uint32_t) c) % MD;
	printf("--%.2X : %d\n",c,n);
	return n;
}


int generate_pass(unsigned const char * mac, unsigned char * hash_buff, unsigned char * passwd)
{
    MD5_CTX ctx;
    unsigned char buff1[100];
    unsigned char buff2[100];
    unsigned char buff3[100];
    unsigned char res[100];
    memset(buff1, 0, 100);
    memset(buff2, 0, 100);
    memset(buff3, 0, 100);
    memset(hash_buff, 0, 100);

    // 1.
    sprintf((char*)buff1, "%2X%2X%2X%2X%2X%2X555043444541554C5450415353504852415345", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // 2.
    MD5_Init(&ctx);
    MD5_Update(&ctx, buff1, strlen((char*)buff1)+1);
    MD5_Final(buff2, &ctx);

    // 3.
    sprintf((char*)buff3, "%.02X%.02X%.02X%.02X%.02X%.02X", buff2[0]&0xF, buff2[1]&0xF, buff2[2]&0xF, buff2[3]&0xF, buff2[4]&0xF, buff2[5]&0xF);

    // 4.
    MD5_Init(&ctx);
    MD5_Update(&ctx, buff3, strlen((char*)buff3)+1);
    MD5_Final(hash_buff, &ctx);

    sprintf((char*)passwd, "%c%c%c%c%c%c%c%c",
            0x41u + ((hash_buff[0]+hash_buff[8]) % 0x1Au),
            0x41u + ((hash_buff[1]+hash_buff[9]) % 0x1Au),
            0x41u + ((hash_buff[2]+hash_buff[10]) % 0x1Au),
            0x41u + ((hash_buff[3]+hash_buff[11]) % 0x1Au),
            0x41u + ((hash_buff[4]+hash_buff[12]) % 0x1Au),
            0x41u + ((hash_buff[5]+hash_buff[13]) % 0x1Au),
            0x41u + ((hash_buff[6]+hash_buff[14]) % 0x1Au),
            0x41u + ((hash_buff[7]+hash_buff[15]) % 0x1Au));

    return 0;
}


int main(int argc, char *argv[])
{
	MD5_CTX ctx;
  // PUT your mac here (this is read from /nvram/1/1, index 0x20 for 2GHz, 0x32 for 5GHz)
	unsigned char mac[6] = {0x64, 0x7c, 0x34, 0x59, 0x1f, 0xf8};

	unsigned char buff1[100];
	unsigned char buff2[100];
	unsigned char h1[100], h2[100];

	memset(buff1, 0, 100);
	memset(buff2, 0, 100);
	memset(h1, 0, 100);
	memset(h2, 0, 100);

	// Increase should be done only for 24Ghz
	increase_mac_address(mac);

	sprintf((char*)buff1, "%2X%2X%2X%2X%2X%2X555043444541554C5453534944", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	MD5_Init(&ctx);
	MD5_Update(&ctx, buff1, strlen((char*)buff1) + 1);
	MD5_Final(h1, &ctx);

	sprintf((char*)buff2, "%.02X%.02X%.02X%.02X%.02X%.02X", h1[0]&0xf, h1[1]&0xf, h1[2]&0xf, h1[3]&0xf, h1[4]&0xf, h1[5]&0xf);
	printf("%s\n", buff2);

	MD5_Init(&ctx);
	MD5_Update(&ctx, buff2, strlen((char*)buff2) + 1);
	MD5_Final(h2, &ctx);

	printf("SSID: UPC%d%d%d%d%d%d%d\n", m(h2[0]), m(h2[1]), m(h2[2]), m(h2[3]), m(h2[4]), m(h2[5]), m(h2[6]));

	generate_pass(mac, h2, buff1);
	printf("PASS:  %s\n", buff1);
	return 0;
}
