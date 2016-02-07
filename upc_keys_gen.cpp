//
// Created by Dusan Klinec on 06.02.16.
//

#include <iostream>
#include <signal.h>
#include <openssl/md5.h>
#include <sqlite3.h>
#include <chrono>
#include <cstring>
#include "main.h"
#include "ahocorasick/ahocorasick.h"
#include "ahocorasick/actypes.h"
#include "upc_keys_gen.h"

#define MAGIC_24GHZ 0xff8d8f20
#define MAGIC_5GHZ 0xffd9da60
#define MAGIC0 0xb21642c9ll
#define MAGIC1 0x68de3afll
#define MAGIC2 0x6b5fca6bll
#define MAX0 9
#define MAX1 99
#define MAX2 9
#define MAX3 9999

#define DB_NAME "upc.db"
#define INSERT_PASS_QUERY "INSERT INTO wifi(id, serial, mode, ssid, pass, profanity) VALUES(?,?,?,?,?,?);"
#define GET_LAST_QUERY "SELECT id FROM wifi WHERE 1 ORDER BY id DESC LIMIT 1;"

#define CREATE_PASS_TABLE "CREATE TABLE IF NOT EXISTS `wifi` (" \
                            "id INT primary key, " \
                            "serial TEXT, " \
                            "mode INT, " \
                            "ssid INT, " \
                            "pass TEXT, " \
                            "profanity TEXT);"

using namespace std;
using ns = chrono::nanoseconds;
using get_time = chrono::steady_clock ;

constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

void hex_str(unsigned char *data, char *dst, int len);
int prepare_db();
int deinit_db();
int init_trie();
int deinit_trie();
inline long contains_profanity(char const * pass, size_t len);
void compute_wpa2(int mode, char * serial, char * pass);
uint32_t upc_generate_ssid(uint32_t* data, uint32_t magic);
void intHandler(int dummy);

sqlite3 *db;
sqlite3_stmt *pStmt;
sqlite3_stmt *pStmtLast;
sqlite3_stmt *pStmtBegin;
sqlite3_stmt *pStmtCommit;

AC_TRIE_t *trie;
static volatile int keepRunning = 1;

int main(int argc, char ** argv) {
    cout << "Generation started..." << endl;

    int rc;
    char passwd[100] = {0};

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

    uint32_t buf[4];
    char serial[64];
    uint32_t ssid;

    for (buf[0] = 0; buf[0] <= MAX0 && keepRunning; buf[0]++)
        for (buf[1] = 0; buf[1] <= MAX1 && keepRunning; buf[1]++)
            for (buf[2] = 0; buf[2] <= MAX2 && keepRunning; buf[2]++)
                for (buf[3] = 0; buf[3] <= MAX3 && keepRunning; buf[3]++)
                    for(int mode=0; mode<2; mode++, ++i, ++c){
                    if (lastIdx > 0 && i <= lastIdx){
                        continue;
                    }

                    // Commit previous transaction / begin a new one.
                    if ((c % 10000) == 0){
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

                    sprintf(serial, "SAAP%d%02d%d%04d", buf[0], buf[1], buf[2], buf[3]);

                    ssid = upc_generate_ssid(buf, mode == 0 ? MAGIC_24GHZ : MAGIC_5GHZ);
                    compute_wpa2(mode, serial, passwd);

                    // Profanity check
                    char const * profanity = NULL;
                    long profanity_idx = contains_profanity((const char *)passwd, 8);
                    if (profanity_idx >= 0) {
                        profanity = profanities[(int) profanity_idx];
//                        printf("    profanity in: %s = %10llu. SSID: %u Idx: %3ld, profanity: %12s, pass: %8s\n", serial, i,
//                               ssid, profanity_idx, profanity, passwd);


                        // Store to pass db. id, serial, mode, ssid, pass, profanity
                        sqlite3_bind_int64(pStmt, 1, i);
                        sqlite3_bind_text(pStmt, 2, serial, strlen(serial), SQLITE_STATIC);
                        sqlite3_bind_int(pStmt, 3, mode);
                        sqlite3_bind_int64(pStmt, 4, ssid);
                        sqlite3_bind_text(pStmt, 5, passwd, 8, SQLITE_STATIC);
                        if (profanity_idx >= 0) {
                            sqlite3_bind_text(pStmt, 6, (char *) profanity, (int) strlen(profanity), SQLITE_STATIC);
                        } else {
                            sqlite3_bind_null(pStmt, 6);
                        }

                        if (sqlite3_step(pStmt) != SQLITE_DONE) {
                            printf("\nCould not step %llu (execute) stmt %s\n", i, sqlite3_errmsg(db));
                            return 1;
                        }
                        sqlite3_reset(pStmt);
                    }

                    // Progress monitoring.
                    if ((i%10000) == 0){
                        auto end = get_time::now();
                        auto diff1 = end - startTsx;
                        auto diff2 = end - start;
                        printf("  %s = %10llu. %.03f%% Time round: %10lld ms, time total: %15lld ms\n", serial, i, (i*100/200000000.0),
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
    }

    deinit_db();
    deinit_trie();
    cout << "Generation done. Kill triggered: " << (keepRunning==0?"YES":"NO") << "i: " << i << endl;

    return 0;
}

int prepare_db()
{
    int rc = 0;
    rc = sqlite3_open(DB_NAME, &db);
    if(rc){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }

    // Create table
    rc = sqlite3_exec(db, CREATE_PASS_TABLE, NULL, 0, NULL);
    if( rc!=SQLITE_OK ){
        fprintf(stderr, "Could not create table %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }

    // Prepare statements
    rc = sqlite3_prepare(db, INSERT_PASS_QUERY, -1, &pStmt, NULL);
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

    return(0);
}

int deinit_db()
{
    sqlite3_finalize(pStmt);
    sqlite3_finalize(pStmtLast);
    sqlite3_finalize(pStmtBegin);
    sqlite3_finalize(pStmtCommit);
    sqlite3_close(db);

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

void hash2pass(uint8_t *in_hash, char *out_pass)
{
    uint32_t i, a;

    for (i = 0; i < 8; i++) {
        a = in_hash[i] & 0x1f;
        a -= ((a * MAGIC0) >> 36) * 23;

        a = (a & 0xff) + 0x41;

        if (a >= 'I') a++;
        if (a >= 'L') a++;
        if (a >= 'O') a++;

        out_pass[i] = a;
    }
    out_pass[8] = 0;
}

uint32_t mangle(uint32_t *pp)
{
    uint32_t a, b;

    a = ((pp[3] * MAGIC1) >> 40) - (pp[3] >> 31);
    b = (pp[3] - a * 9999 + 1) * 11ll;

    return b * (pp[1] * 100 + pp[2] * 10 + pp[0]);
}

uint32_t upc_generate_ssid(uint32_t* data, uint32_t magic)
{
    uint32_t a, b;

    a = data[1] * 10 + data[2];
    b = data[0] * 2500000 + a * 6800 + data[3] + magic;

    return b - (((b * MAGIC2) >> 54) - (b >> 31)) * 10000000;
}

void compute_wpa2(int mode, char * serial, char * pass){
    MD5_CTX ctx;
    uint8_t message_digest[20];
    char serial_input[64];
    char tmpstr[17];
    size_t ln;
    uint8_t h1[16], h2[16];
    uint32_t hv[4], w1, w2, i;

    ln = strlen(serial);
    memset(serial_input, 0, 64);
    if (mode == 2) {
        for(i=0; i<ln; i++) {
            serial_input[ln-1-i] = serial[i];
        }
    } else {
        memcpy(serial_input, serial, ln);
    }

    MD5_Init(&ctx);
    MD5_Update(&ctx, serial_input, strlen(serial_input));
    MD5_Final(h1, &ctx);

    for (i = 0; i < 4; i++) {
        hv[i] = *(uint16_t *)(h1 + i*2);
    }

    w1 = mangle(hv);

    for (i = 0; i < 4; i++) {
        hv[i] = *(uint16_t *)(h1 + 8 + i*2);
    }

    w2 = mangle(hv);

    sprintf(tmpstr, "%08X%08X", w1, w2);

    MD5_Init(&ctx);
    MD5_Update(&ctx, tmpstr, strlen(tmpstr));
    MD5_Final(h2, &ctx);

    hash2pass(h2, pass);
}
