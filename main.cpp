#include <iostream>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <sqlite3.h>
#include <chrono>

#define KEK_KEY_LEN  8
#define ITERATION    2000
#define INSERT_QUERY "INSERT INTO wifi(id, mac, ssid, pass) VALUES(?,?,?,?);"
#define GET_LAST_QUERY "SELECT id FROM wifi WHERE 1 ORDER BY id DESC LIMIT 1;"
using namespace std;
using ns = chrono::nanoseconds;
using get_time = chrono::steady_clock ;

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

    // Create table
    rc = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS `wifi` (id INT primary key, mac TEXT, ssid TEXT, pass TEXT);", NULL, 0, NULL);
    if( rc!=SQLITE_OK ){
        fprintf(stderr, "Could not create table %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }

    // Prepare statements
    sqlite3_stmt *pStmt;
    sqlite3_stmt *pStmtLast;
    sqlite3_stmt *pStmtBegin;
    sqlite3_stmt *pStmtCommit;
    rc = sqlite3_prepare(db, INSERT_QUERY, -1, &pStmt, NULL);
    if(rc!=SQLITE_OK){
        fprintf(stderr, "Could not create prepared statement %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }
    rc = sqlite3_prepare(db, GET_LAST_QUERY, -1, &pStmtLast, NULL);
    if(rc!=SQLITE_OK){
        fprintf(stderr, "Could not create prepared statement %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }
    rc = sqlite3_prepare(db, "BEGIN;", -1, &pStmtBegin, NULL);
    if(rc!=SQLITE_OK){
        fprintf(stderr, "Could not create prepared statement %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }
    rc = sqlite3_prepare(db, "COMMIT;", -1, &pStmtCommit, NULL);
    if(rc!=SQLITE_OK){
        fprintf(stderr, "Could not create prepared statement %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }

    // Load last generated record
    long long lastIdx=-1;
    if (sqlite3_step(pStmtLast) == SQLITE_ROW){
        lastIdx = sqlite3_column_int64(pStmtLast, 0);
        cout << "Last generated idx: " << lastIdx << endl;
    }

    // Generate
    auto start = get_time::now();
    auto startTsx = get_time::now();

    int openTsx=0;
    unsigned long long i=0;
    unsigned long long c=0;
    for(int c3=0; c3<0x100; ++c3)
    for(int c4=0; c4<0x100; ++c4)
    for(int c5=0; c5<0x100; ++c5, ++i, ++c){
        if (lastIdx > 0 && i <= lastIdx){
            continue;
        }

        if ((c % 1000) == 0){
            if (openTsx != 0){
                if (sqlite3_step(pStmtCommit) != SQLITE_DONE){
                    printf("\nCould not commit tsx %s\n", sqlite3_errmsg(db));
                    return 1;
                }
            }

            if (sqlite3_step(pStmtBegin) != SQLITE_DONE){
                printf("\nCould not start tsx %s\n", sqlite3_errmsg(db));
                return 1;
            }

            startTsx = get_time::now();
            openTsx=1;
        }

        mac[3]=(unsigned char)c3;
        mac[4]=(unsigned char)c4;
        mac[5]=(unsigned char)c5;

        hex_str(mac+3, (char*)macChr, 3);
        generate_pass(mac, passwd);

        int res = PKCS5_PBKDF2_HMAC_SHA1((char*)passwd, 8, salt, 10, ITERATION, KEK_KEY_LEN, pbkdfed);
        hex_str(pbkdfed, (char*)pbkdfedChr, KEK_KEY_LEN);

        // Store to database.
        sqlite3_bind_int64(pStmt, 1, i);
        sqlite3_bind_text(pStmt, 2, (char*)macChr, 3*2, SQLITE_STATIC);
        sqlite3_bind_text(pStmt, 3, (char*)passwd, 8, SQLITE_STATIC);
        sqlite3_bind_text(pStmt, 4, (char*)pbkdfedChr, KEK_KEY_LEN*2, SQLITE_STATIC);
        if (sqlite3_step(pStmt) != SQLITE_DONE) {
            printf("\nCould not step %llu (execute) stmt %s\n", i, sqlite3_errmsg(db));
            return 1;
        }
        sqlite3_reset(pStmt);

        if ((i%1000) == 0){
            auto end = get_time::now();
            auto diff1 = end - startTsx;
            auto diff2 = end - start;
            printf("  %02X %02X %02X = %llu. Time round: %lld ms, time total: %lld ms\n", c3, c4, c5, i,
                   chrono::duration_cast<ns>(diff1).count(),
                   chrono::duration_cast<ns>(diff2).count());
        }
    }

    // Finalize.
    if (openTsx != 0){
        if (sqlite3_step(pStmtCommit) != SQLITE_DONE){
            printf("\nCould not commit tsx %s\n", sqlite3_errmsg(db));
            return 1;
        }
    }

    sqlite3_finalize(pStmt);
    sqlite3_finalize(pStmtLast);
    sqlite3_finalize(pStmtBegin);
    sqlite3_finalize(pStmtCommit);
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
