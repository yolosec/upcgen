//
// Util program for generating SQLite database with all passwords.
//
// Created by Dusan Klinec on 12.06.16.
//

#include <iostream>
#include <signal.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <sqlite3.h>
#include <chrono>
#include <cstring>
#include "main.h"
#include "ahocorasick/ahocorasick.h"
#include "ahocorasick/actypes.h"

#define KEK_KEY_LEN  8
#define ITERATION    1000

// SQL queries.
#define INSERT_QUERY "INSERT INTO wifi(id, mac, ssid, pass) VALUES(?,?,?,?);"
#define INSERT_PASS_QUERY "INSERT INTO wifi(id, mac, ssid, orig, pass, rudepass, profanity) VALUES(?,?,?,?,?,?,?);"
#define GET_LAST_QUERY "SELECT id FROM wifi WHERE 1 ORDER BY id DESC LIMIT 1;"

#define CREATE_TABLE "CREATE TABLE IF NOT EXISTS `wifi` (id INT primary key, mac TEXT, ssid TEXT, pass TEXT);"
#define CREATE_PASS_TABLE "CREATE TABLE IF NOT EXISTS `wifi` (id INT primary key, mac TEXT, ssid TEXT, orig TEXT, pass TEXT, rudepass TEXT, profanity TEXT);"

using namespace std;
using ns = chrono::nanoseconds;
using get_time = chrono::steady_clock ;

constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

char const * alternative_alphabet = UBEE_NONINSULTING_ALPHABET;

inline void generate_ssid(unsigned const char * mac, unsigned char * ssid);
inline int generate_pass(unsigned const char * mac, unsigned char * hash_buff, unsigned char * passwd);
inline int generate_profanity_free_pass(unsigned char * hash_buff, unsigned char const * new_pass);
void hex_str(unsigned char *data, char *dst, int len);
int prepare_db();
int deinit_db();
int init_trie();
int deinit_trie();
inline long contains_profanity(char const * pass, size_t len);
void intHandler(int dummy);

sqlite3 *db;
sqlite3_stmt *pStmt;
sqlite3_stmt *pStmtLast;
sqlite3_stmt *pStmtBegin;
sqlite3_stmt *pStmtCommit;

sqlite3 *dbPass;
sqlite3_stmt *pPassStmt;
sqlite3_stmt *pPassStmtBegin;
sqlite3_stmt *pPassStmtCommit;

AC_TRIE_t *trie;
static volatile int keepRunning = 1;

int main(int argc, char ** argv) {
    cout << "Generation started..." << endl;

    int rc;
    unsigned char mac[] = {0x64, 0x7c, 0x34, 0x59, 0x1f, 0xf6};
    unsigned char macChr[20] = {0};
    unsigned char macChr2[20] = {0};
    unsigned char passwd[100] = {0};
    unsigned char ssid[100] = {0};
    unsigned char passwd_proffree[100] = {0};
    unsigned char pbkdfed[100] = {0};
    unsigned char pbkdfedChr[100] = {0};
    unsigned char hash_buff[100];

    if (prepare_db() != 0){
        deinit_db();
        return -1;
    }

    init_trie();
    signal(SIGINT, intHandler);

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
    for(int c3=0; c3<0x100 && keepRunning; ++c3)
    for(int c4=0; c4<0x100 && keepRunning; ++c4)
    for(int c5=0; c5<0x100 && keepRunning; ++c5, ++i, ++c){
        if (lastIdx > 0 && i <= lastIdx){
            continue;
        }

        // Commit previous transaction / begin a new one.
        if ((c % 1000) == 0){
            if (openTsx != 0){
                if (sqlite3_step(pStmtCommit) != SQLITE_DONE){
                    printf("\nCould not commit tsx %s\n", sqlite3_errmsg(db));
                    return 1;
                }
                if (sqlite3_step(pPassStmtCommit) != SQLITE_DONE){
                    printf("\nCould not commit tsx %s\n", sqlite3_errmsg(dbPass));
                    return 1;
                }
            }

            if (sqlite3_step(pStmtBegin) != SQLITE_DONE){
                printf("\nCould not start tsx %s\n", sqlite3_errmsg(db));
                return 1;
            }
            if (sqlite3_step(pPassStmtBegin) != SQLITE_DONE){
                printf("\nCould not start tsx %s\n", sqlite3_errmsg(dbPass));
                return 1;
            }

            startTsx = get_time::now();
            openTsx=1;
        }

        mac[3]=(unsigned char)c3;
        mac[4]=(unsigned char)c4;
        mac[5]=(unsigned char)c5;
        unsigned char * passwd2compute = passwd;

        hex_str(mac+3, (char*)macChr, 3);
        hex_str(mac, (char*)macChr2, 6);
        generate_pass(mac, hash_buff, passwd);
        generate_ssid(mac, ssid);

        // Profanity check
        char const * profanity = NULL;
        long profanity_idx = contains_profanity((const char *)passwd, 8);
        if (profanity_idx >= 0){
            generate_profanity_free_pass(hash_buff, passwd_proffree);
            passwd2compute = passwd_proffree;
            profanity = profanities[(int)profanity_idx];
            printf("    profanity in: %02X %02X %02X = %10llu. SSID: %s Idx: %3ld, profanity: %12s, pass: %8s, newpass: %8s\n", c3, c4, c5, i,
                   ssid, profanity_idx, profanity, passwd, passwd_proffree);

#ifdef CHECK_PROFANITIES_IN_PASS2
            // Check profanity once again - not needed, there areno vowels in the alternative alphabet.
            long profanity_idx2 = contains_profanity((const char *)passwd_proffree, 8);
            if (profanity_idx2 >= 0){
                printf("    PROFANITY-AHA! IN: %02X %02X %02X = %10llu. Idx: %3ld, profanity: %12s, pass: %8s\n", c3, c4, c5, i,
                       profanity_idx2, profanities[(int)profanity_idx2], passwd_proffree);
            }
#endif
        }

        int res = PKCS5_PBKDF2_HMAC_SHA1((char*)passwd2compute, 8, macChr2, 12, ITERATION, KEK_KEY_LEN, pbkdfed);
        hex_str(pbkdfed, (char*)pbkdfedChr, KEK_KEY_LEN);

        // Store to database.
        sqlite3_bind_int64(pStmt, 1, i);
        sqlite3_bind_text(pStmt, 2, (char*)macChr, 3*2, SQLITE_STATIC);
        sqlite3_bind_text(pStmt, 3, (char*)ssid, 7, SQLITE_STATIC);
        sqlite3_bind_text(pStmt, 4, (char*)pbkdfedChr, KEK_KEY_LEN*2, SQLITE_STATIC);
        if (sqlite3_step(pStmt) != SQLITE_DONE) {
            printf("\nCould not step %llu (execute) stmt %s\n", i, sqlite3_errmsg(db));
            return 1;
        }
        sqlite3_reset(pStmt);

        // Store to pass db.
        sqlite3_bind_int64(pPassStmt, 1, i);
        sqlite3_bind_text(pPassStmt, 2, (char*)macChr, 3*2, SQLITE_STATIC);
        sqlite3_bind_text(pPassStmt, 3, (char*)ssid, 7, SQLITE_STATIC);
        sqlite3_bind_text(pPassStmt, 4, (char*)passwd2compute, 8, SQLITE_STATIC);
        sqlite3_bind_text(pPassStmt, 5, (char*)pbkdfedChr, KEK_KEY_LEN*2, SQLITE_STATIC);
        if (profanity_idx >= 0){
            sqlite3_bind_text(pPassStmt, 6, (char*)passwd, 8, SQLITE_STATIC);
            sqlite3_bind_text(pPassStmt, 7, (char*)profanity, (int)strlen(profanity), SQLITE_STATIC);
        } else {
            sqlite3_bind_null(pPassStmt, 6);
            sqlite3_bind_null(pPassStmt, 7);
        }

        if (sqlite3_step(pPassStmt) != SQLITE_DONE) {
            printf("\nCould not step %llu (execute) stmt %s\n", i, sqlite3_errmsg(dbPass));
            return 1;
        }
        sqlite3_reset(pPassStmt);

        // Progress monitoring.
        if ((i%1000) == 0){
            auto end = get_time::now();
            auto diff1 = end - startTsx;
            auto diff2 = end - start;
            printf("  %02X %02X %02X = %10llu. Time round: %10lld ms, time total: %15lld ms\n", c3, c4, c5, i,
                   chrono::duration_cast<ns>(diff1).count(),
                   chrono::duration_cast<ns>(diff2).count());
        }
    }

    // Commit last transaction.
    if (openTsx != 0){
        if (sqlite3_step(pStmtCommit) != SQLITE_DONE){
            printf("\nCould not commit tsx %s\n", sqlite3_errmsg(db));
            return 1;
        }
        if (sqlite3_step(pPassStmtCommit) != SQLITE_DONE){
            printf("\nCould not commit tsx %s\n", sqlite3_errmsg(dbPass));
            return 1;
        }
    }

    deinit_db();
    deinit_trie();
    cout << "Generation done. Kill triggered: " << (keepRunning==0?"YES":"NO") << "i: " << i << endl;

    return 0;
}

inline void generate_ssid(unsigned const char * mac, unsigned char * ssid)
{
    MD5_CTX ctx;
    unsigned char buff1[100];
	unsigned char buff2[100];
	unsigned char h1[100], h2[100];
	memset(buff1, 0, 100);
	memset(buff2, 0, 100);
	memset(h1, 0, 100);
	memset(h2, 0, 100);

	sprintf((char*)buff1, "%2X%2X%2X%2X%2X%2X555043444541554C5453534944", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	MD5_Init(&ctx);
	MD5_Update(&ctx, buff1, strlen((char*)buff1) + 1);
	MD5_Final(h1, &ctx);

	sprintf((char*)buff2, "%.02X%.02X%.02X%.02X%.02X%.02X", h1[0]&0xf, h1[1]&0xf, h1[2]&0xf, h1[3]&0xf, h1[4]&0xf, h1[5]&0xf);

	MD5_Init(&ctx);
	MD5_Update(&ctx, buff2, strlen((char*)buff2) + 1);
	MD5_Final(h2, &ctx);

  // SSID is in format UPC%d%d%d%d%d%d%d, return only traling numbers
    sprintf((char*)ssid, "%d%d%d%d%d%d%d", h2[0]%10, h2[1]%10, h2[2]%10, h2[3]%10, h2[4]%10, h2[5]%10, h2[6]%10);
}

inline int generate_pass(unsigned const char * mac, unsigned char * hash_buff, unsigned char * passwd)
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

inline int generate_profanity_free_pass(unsigned char * hash_buff, unsigned char const * new_pass)
{
    sprintf((char*)new_pass, "%c%c%c%c%c%c%c%c",
            alternative_alphabet[((hash_buff[0]+hash_buff[8]) % 0x1Au)],
            alternative_alphabet[((hash_buff[1]+hash_buff[9]) % 0x1Au)],
            alternative_alphabet[((hash_buff[2]+hash_buff[10]) % 0x1Au)],
            alternative_alphabet[((hash_buff[3]+hash_buff[11]) % 0x1Au)],
            alternative_alphabet[((hash_buff[4]+hash_buff[12]) % 0x1Au)],
            alternative_alphabet[((hash_buff[5]+hash_buff[13]) % 0x1Au)],
            alternative_alphabet[((hash_buff[6]+hash_buff[14]) % 0x1Au)],
            alternative_alphabet[((hash_buff[7]+hash_buff[15]) % 0x1Au)]);
    return 0;
}

int prepare_db()
{
    int rc = 0;
    rc = sqlite3_open("keys2.db", &db);
    if(rc){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }

    rc = sqlite3_open("keys_pass2.db", &dbPass);
    if(rc){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(dbPass);
        return(1);
    }

    // Create table
    rc = sqlite3_exec(db, CREATE_TABLE, NULL, 0, NULL);
    if( rc!=SQLITE_OK ){
        fprintf(stderr, "Could not create table %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }

    // Create table
    rc = sqlite3_exec(dbPass, CREATE_PASS_TABLE, NULL, 0, NULL);
    if( rc!=SQLITE_OK ){
        fprintf(stderr, "Could not create table %s\n", sqlite3_errmsg(dbPass));
        sqlite3_close(dbPass);
        return(1);
    }

    // Prepare statements
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

    // Prepare statements for passwd db.
    rc = sqlite3_prepare(dbPass, INSERT_PASS_QUERY, -1, &pPassStmt, NULL);
    if(rc!=SQLITE_OK){
        fprintf(stderr, "Could not create prepared statement %s\n", sqlite3_errmsg(dbPass));
        sqlite3_close(db);
        return(1);
    }
    rc = sqlite3_prepare(dbPass, "BEGIN;", -1, &pPassStmtBegin, NULL);
    if(rc!=SQLITE_OK){
        fprintf(stderr, "Could not create prepared statement %s\n", sqlite3_errmsg(dbPass));
        sqlite3_close(db);
        return(1);
    }
    rc = sqlite3_prepare(dbPass, "COMMIT;", -1, &pPassStmtCommit, NULL);
    if(rc!=SQLITE_OK){
        fprintf(stderr, "Could not create prepared statement %s\n", sqlite3_errmsg(dbPass));
        sqlite3_close(db);
        return(1);
    }

    return(0);
}

int deinit_db()
{
    sqlite3_finalize(pStmt);
    sqlite3_finalize(pStmtLast);
    sqlite3_finalize(pStmtBegin);
    sqlite3_finalize(pStmtCommit);
    sqlite3_close(db);

    sqlite3_finalize(pPassStmt);
    sqlite3_finalize(pPassStmtBegin);
    sqlite3_finalize(pPassStmtCommit);
    sqlite3_close(dbPass);

    return 0;
}

inline void hex_str(unsigned char *data, char *dst, int len)
{
    for (int i = 0; i < len; ++i) {
        dst[2 * i]     = hexmap[(data[i] & 0xF0u) >> 4];
        dst[2 * i + 1] = hexmap[data[i] & 0x0Fu];
    }
}

int init_trie()
{
    AC_PATTERN_t patt;

    /* Get a new trie */
    trie = ac_trie_create();

    for (int i = 0; i < PROFANITY_COUNT; i++) {
        /* Fill the pattern data */
        patt.ptext.astring = profanities[i];
        patt.ptext.length = strlen(profanities[i]);

        /* The replacement pattern is not applicable in this program, so better
         * to initialize it with 0 */
        patt.rtext.astring = NULL;
        patt.rtext.length = 0;

        /* Pattern identifier is optional */
        patt.id.u.number = i;
        patt.id.type = AC_PATTID_TYPE_NUMBER;

        /* Add pattern to automata */
        ac_trie_add (trie, &patt, 1);
    }

    /* Now the preprocessing stage ends. You must finalize the trie. Remember
     * that you can not add patterns anymore. */
    ac_trie_finalize (trie);
    return 0;
}

int deinit_trie()
{
    ac_trie_release (trie);
    return 0;
}

inline long contains_profanity(char const * pass, size_t len)
{
    long first_match = -1;
    AC_TEXT_t chunk;
    AC_MATCH_t match;
    chunk.astring = pass;
    chunk.length = len;

    /* Set the input text */
    ac_trie_settext (trie, &chunk, 0);

    /* Find matches */
    match = ac_trie_findnext(trie);
    if (!match.size){
        return first_match;
    }

    return match.patterns[0].id.u.number;
}

void intHandler(int dummy)
{
    keepRunning = 0;
}
