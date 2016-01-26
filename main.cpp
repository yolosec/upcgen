#include <iostream>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <sqlite3.h>

#define KEK_KEY_LEN  8
#define ITERATION    2000
#define INSERT_QUERY "INSERT INTO wifi(mac, pass) VALUES(?,?)"
using namespace std;

constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

int generate_pass(unsigned const char * mac, unsigned char * passwd);
void hex_str(unsigned char *data, char *dst, int len);

int main(int argc, char ** argv) {
    cout << "Generation started..." << endl;

    sqlite3 *db;
    int rc;
    unsigned char mac[] = {0x64, 0x7c, 0x34, 0x59, 0x1f, 0xf6};
    unsigned char macChr[100] = {0};
    unsigned char passwd[100] = {0};
    unsigned char pbkdfed[100] = {0};
    unsigned char pbkdfedChr[100] = {0};
    unsigned char salt[100] = {0};

    rc = sqlite3_open("/tmp/keys.db", &db);
    if(rc){
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      sqlite3_close(db);
      return(1);
    }

    rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS `wifi` (mac TEXT, ssid TEXT, pass TEXT);", NULL, 0, NULL);
    if( rc!=SQLITE_OK ){
        fprintf(stderr, "Could not create table %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }

    sqlite3_stmt *pStmt;
    rc = sqlite3_prepare(db, INSERT_QUERY, -1, &pStmt, NULL);
    if(rc!=SQLITE_OK){
        fprintf(stderr, "Could not create prepared statement %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }

    for(int i=0; i<1000; i++){ // sqlite3_exec(db, "BEGIN", NULL, 0, NULL);
        hex_str(mac, (char*)macChr, 3);
        generate_pass(mac, passwd);

        int res = PKCS5_PBKDF2_HMAC_SHA1((char*)passwd, 8, salt, 10, ITERATION, KEK_KEY_LEN, pbkdfed);
        hex_str(passwd, (char*)pbkdfedChr, KEK_KEY_LEN);

        // Store to database.
        sqlite3_bind_text(pStmt, 1, (char*)macChr, 3*2+1, SQLITE_STATIC);
        sqlite3_bind_text(pStmt, 2, (char*)pbkdfedChr, KEK_KEY_LEN*2+1, SQLITE_STATIC);
        if (sqlite3_step(pStmt) != SQLITE_DONE) {
            printf("\nCould not step %d (execute) stmt %s\n", i, sqlite3_errmsg(db));
            return 1;
        }
        sqlite3_reset(pStmt);
    }

    sqlite3_finalize(pStmt);
    sqlite3_close(db);
    cout << "generated" << endl;

    return 0;
}

inline void hex_str(unsigned char *data, char *dst, int len)
{
    for (int i = 0; i < len; ++i) {
        dst[2 * i]     = hexmap[(data[i] & 0xF0u) >> 4];
        dst[2 * i + 1] = hexmap[data[i] & 0x0Fu];
    }
}

inline int generate_pass(unsigned const char * mac, unsigned char * passwd)
{
    MD5_CTX ctx;
    unsigned char buff1[100];
    unsigned char buff2[100];
    unsigned char buff3[100];
    unsigned char buff4[100];
    unsigned char res[100];
    memset(buff1, 0, 100);
    memset(buff2, 0, 100);
    memset(buff3, 0, 100);
    memset(buff4, 0, 100);

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
    MD5_Final(buff4, &ctx);

    sprintf((char*)passwd, "%c%c%c%c%c%c%c%c",
            0x41u + ((buff4[0]+buff4[8]) % 0x1Au),
            0x41u + ((buff4[1]+buff4[9]) % 0x1Au),
            0x41u + ((buff4[2]+buff4[10]) % 0x1Au),
            0x41u + ((buff4[3]+buff4[11]) % 0x1Au),
            0x41u + ((buff4[4]+buff4[12]) % 0x1Au),
            0x41u + ((buff4[5]+buff4[13]) % 0x1Au),
            0x41u + ((buff4[6]+buff4[14]) % 0x1Au),
            0x41u + ((buff4[7]+buff4[15]) % 0x1Au));

    // TODO: profanity checking, if it contains a rude word, substitute.

    return 0;
}
