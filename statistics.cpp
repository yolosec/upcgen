//
// Util program for statistics computation for the blog post.
//
// Created by Dusan Klinec on 12.06.16.
//

#include <iostream>
#include <signal.h>
#include <openssl/md5.h>
#include <chrono>
#include <cstring>
#include <cmath>
#include "main.h"
#include "ahocorasick/ahocorasick.h"
#include "ahocorasick/actypes.h"

#define KEK_KEY_LEN  8
#define ITERATION    1000

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
int init_trie();
int deinit_trie();
inline long contains_profanity(char const * pass, size_t len, int * numberOfProfs);
void intHandler(int dummy);
inline double zscore(double observed, double expected, double samples);

AC_TRIE_t *trie;
static volatile int keepRunning = 1;

int main(int argc, char ** argv) {
    cout << "Generation started..." << endl;
    unsigned char mac[] = {0x64, 0x7c, 0x34, 0x59, 0x1f, 0xf6};
    unsigned char macChr[20] = {0};
    unsigned char macChr2[20] = {0};
    unsigned char passwd[100] = {0};
    unsigned char ssid[100] = {0};
    unsigned char passwd_proffree[100] = {0};
    unsigned char hash_buff[100];
    unsigned long profanity_counter[1024];
    unsigned int profanity_sizes[1024];
    unsigned long profanity_sizes_cnt[10];
    memset(profanity_counter, 0, sizeof(unsigned long)*1024);
    memset(profanity_sizes, 0, sizeof(unsigned int)*1024);
    memset(profanity_sizes_cnt, 0, sizeof(unsigned long)*10);
    double alphabetDistribution[26];

    init_trie();
    signal(SIGINT, intHandler);

    // Generate
    auto start = get_time::now();
    auto startTsx = get_time::now();

    unsigned long long i=0;
    unsigned long long c=0;
    unsigned long long j=0;
    unsigned long matrix[26][9];
    unsigned long matrixP[26][9];
    memset(matrix, 0, sizeof(unsigned long)*26*9);
    memset(matrixP, 0, sizeof(unsigned long)*26*9);

    // Number of all words in 8 char word language than contain x-character length profanity.
    const double profanityNum3chars = 71288256.0; // 6 * 26^5
    const double profanityNum4chars = 2284880.0; // 5 * 26^4
    const double profanityNum5chars = 70304.0; // 4 * 26^3
    const double languageNumWords   = 208827064576.0; // 26^8
    // Probability of a word with x character profanity in it in 8 char word.
    const double profanityProb3chars = profanityNum3chars / languageNumWords;
    const double profanityProb4chars = profanityNum4chars / languageNumWords;
    const double profanityProb5chars = profanityNum5chars / languageNumWords;

    //Strlen of profanities
    for(i=0; i<PROFANITY_REDUCED_COUNT; i++){
        profanity_sizes[i] = (unsigned int)strlen(profanitiesReduced[i]);
        int numProfs = 0;
        long profanity_idx = contains_profanity((const char *)profanitiesReduced[i], profanity_sizes[i], &numProfs);
        if (numProfs > 1){
            printf("Profanity %s contains %d another ones, e.g., %s\n", profanitiesReduced[i], numProfs-1, profanitiesReduced[profanity_idx]);
        }
    }

    // Alphabet distribution probability.
    // (1B + 1B) % 26 distribution
    int a,b;
    long mx[1024];
    long mxa[26];
    memset(mx, 0, sizeof(long)*1024);
    memset(mxa, 0, sizeof(long)*26);
    for(a=0; a<256;a++){
        for(b=0;b<256;b++){
            mx[a + b] += 1;
            mxa[(a + b) % 26] += 1;
        }
    }
    for(a=0; a<26; a++){
        alphabetDistribution[a] = mxa[a] / (65536.0);
    }

    // Iterate for all 2^24 MAC addresses.
    for(int c3=0; c3<0x100 && keepRunning; ++c3)
        for(int c4=0; c4<0x100 && keepRunning; ++c4)
            for(int c5=0; c5<0x100 && keepRunning; ++c5, ++i, ++c){

                mac[3]=(unsigned char)c3;
                mac[4]=(unsigned char)c4;
                mac[5]=(unsigned char)c5;

                hex_str(mac+3, (char*)macChr, 3);
                hex_str(mac, (char*)macChr2, 6);
                generate_pass(mac, hash_buff, passwd);
                generate_ssid(mac, ssid);

                // Profanity check
                int profCount = 0;
                char const * profanity = NULL;
                long profanity_idx = contains_profanity((const char *)passwd, 8, &profCount);
                if (profanity_idx >= 0){
                    if (profCount > 1){
                        printf(" #profs: %d, %s\n", profCount, passwd);
                    }

                    profanity_counter[profanity_idx] += 1;
                    profanity_sizes_cnt[profanity_sizes[profanity_idx]] += 1;

                    generate_profanity_free_pass(hash_buff, passwd_proffree);
                    profanity = profanitiesReduced[(int)profanity_idx];
//                    printf("    profanity in: %02X %02X %02X = %10llu. SSID: %s Idx: %3ld, profanity: %12s, pass: %8s, newpass: %8s\n", c3, c4, c5, i,
//                           ssid, profanity_idx, profanity, passwd, passwd_proffree);
                }

                for(j=0; j<8; j++){
                    matrix[passwd[j]-'A'][j]+=1;
                    matrix[passwd[j]-'A'][8]+=1;

                    matrixP[passwd_proffree[j]-'A'][j]+=1;
                    matrixP[passwd_proffree[j]-'A'][8]+=1;
                }

                // Progress monitoring.
                if ((i&0x7FFFFull) == 0){
                    auto end = get_time::now();
                    auto diff1 = end - startTsx;
                    auto diff2 = end - start;
                    printf("  %02X %02X %02X = %10llu. xTime round: %10lld ms, time total: %15lld\n", c3, c4, c5, i,
                           chrono::duration_cast<ns>(diff1).count(),
                           chrono::duration_cast<ns>(diff2).count());
                }
            }

    cout << "Generation done. Kill triggered: " << (keepRunning==0?"YES":"NO") << "i: " << i << endl;
    cout << "Matrix on distribution: " << endl;
    for(i=0; i<26; i++){
        printf("%c|%06ld|%06ld|%06ld|%06ld|%06ld|%06ld|%06ld|%06ld|%06ld\n",
               'A'+(char)i,
               matrix[i][0],
               matrix[i][1],
               matrix[i][2],
               matrix[i][3],
               matrix[i][4],
               matrix[i][5],
               matrix[i][6],
               matrix[i][7],
               matrix[i][8]
        );
    }

    printf("\n\n%%diff from the mean:\n");
    for(i=0; i<26; i++){
        printf("%c|%+1.6f|%+1.6f|%+1.6f|%+1.6f|%+1.6f|%+1.6f|%+1.6f|%+1.6f|%+1.6f\n",
               'A'+(char)i,
               matrix[i][0]/645277.538461538,
               matrix[i][1]/645277.538461538,
               matrix[i][2]/645277.538461538,
               matrix[i][3]/645277.538461538,
               matrix[i][4]/645277.538461538,
               matrix[i][5]/645277.538461538,
               matrix[i][6]/645277.538461538,
               matrix[i][7]/645277.538461538,
               matrix[i][8]/5162220.30769231
        );
    }

    printf("\n\nz-score:\n");
#define POW224 16777216.0
    for(i=0; i<26; i++){
        printf("%c|%+1.6f|%+1.6f|%+1.6f|%+1.6f|%+1.6f|%+1.6f|%+1.6f|%+1.6f|%+1.6f\n",
               'A'+(char)i,
               zscore(matrix[i][0]/POW224, 1/26.0, POW224),
               zscore(matrix[i][1]/POW224, 1/26.0, POW224),
               zscore(matrix[i][2]/POW224, 1/26.0, POW224),
               zscore(matrix[i][3]/POW224, 1/26.0, POW224),
               zscore(matrix[i][4]/POW224, 1/26.0, POW224),
               zscore(matrix[i][5]/POW224, 1/26.0, POW224),
               zscore(matrix[i][6]/POW224, 1/26.0, POW224),
               zscore(matrix[i][7]/POW224, 1/26.0, POW224),
               zscore(matrix[i][8]/(POW224*8), 1/26.0, POW224*8)
        );
    }

    printf("\n\nz-score distribution:\n");
    for(i=0; i<26; i++){
        printf("%c|%+1.6f|%+1.6f|%+1.6f|%+1.6f|%+1.6f|%+1.6f|%+1.6f|%+1.6f|%+1.6f\n",
               'A'+(char)i,
               zscore(matrix[i][0]/POW224, alphabetDistribution[i], POW224),
               zscore(matrix[i][1]/POW224, alphabetDistribution[i], POW224),
               zscore(matrix[i][2]/POW224, alphabetDistribution[i], POW224),
               zscore(matrix[i][3]/POW224, alphabetDistribution[i], POW224),
               zscore(matrix[i][4]/POW224, alphabetDistribution[i], POW224),
               zscore(matrix[i][5]/POW224, alphabetDistribution[i], POW224),
               zscore(matrix[i][6]/POW224, alphabetDistribution[i], POW224),
               zscore(matrix[i][7]/POW224, alphabetDistribution[i], POW224),
               zscore(matrix[i][8]/(POW224*8), alphabetDistribution[i], POW224*8)
        );
    }

    printf("\n\nz-score 95%%:\n");
    for(i=0; i<26; i++){
        printf("%c|%c|%c|%c|%c|%c|%c|%c|%c|%c\n",
               'A'+(char)i,
               abs(zscore(matrix[i][0] / POW224, 1 / 26.0, POW224))>2.0 ? 'x' : '-',
               abs(zscore(matrix[i][1] / POW224, 1 / 26.0, POW224))>2.0 ? 'x' : '-',
               abs(zscore(matrix[i][2] / POW224, 1 / 26.0, POW224))>2.0 ? 'x' : '-',
               abs(zscore(matrix[i][3] / POW224, 1 / 26.0, POW224))>2.0 ? 'x' : '-',
               abs(zscore(matrix[i][4] / POW224, 1 / 26.0, POW224))>2.0 ? 'x' : '-',
               abs(zscore(matrix[i][5] / POW224, 1 / 26.0, POW224))>2.0 ? 'x' : '-',
               abs(zscore(matrix[i][6] / POW224, 1 / 26.0, POW224))>2.0 ? 'x' : '-',
               abs(zscore(matrix[i][7] / POW224, 1 / 26.0, POW224))>2.0 ? 'x' : '-',
               abs(zscore(matrix[i][8] / (POW224 * 8), 1 / 26.0, POW224 * 8))>2.0 ? 'x' : '-'
        );
    }

    printf("\n\nz-score 99%%:\n");
    for(i=0; i<26; i++){
        printf("%c|%c|%c|%c|%c|%c|%c|%c|%c|%c\n",
               'A'+(char)i,
               abs(zscore(matrix[i][0] / POW224, 1 / 26.0, POW224))>2.58 ? 'x' : '-',
               abs(zscore(matrix[i][1] / POW224, 1 / 26.0, POW224))>2.58 ? 'x' : '-',
               abs(zscore(matrix[i][2] / POW224, 1 / 26.0, POW224))>2.58 ? 'x' : '-',
               abs(zscore(matrix[i][3] / POW224, 1 / 26.0, POW224))>2.58 ? 'x' : '-',
               abs(zscore(matrix[i][4] / POW224, 1 / 26.0, POW224))>2.58 ? 'x' : '-',
               abs(zscore(matrix[i][5] / POW224, 1 / 26.0, POW224))>2.58 ? 'x' : '-',
               abs(zscore(matrix[i][6] / POW224, 1 / 26.0, POW224))>2.58 ? 'x' : '-',
               abs(zscore(matrix[i][7] / POW224, 1 / 26.0, POW224))>2.58 ? 'x' : '-',
               abs(zscore(matrix[i][8] / (POW224 * 8), 1 / 26.0, POW224 * 8))>2.58 ? 'x' : '-'
        );
    }

    printf("\n\nz-score 95%% on distribution:\n");
    for(i=0; i<26; i++){
        printf("%c|%c|%c|%c|%c|%c|%c|%c|%c|%c\n",
               'A'+(char)i,
               abs(zscore(matrix[i][0] / POW224, alphabetDistribution[i], POW224))>2.0 ? 'x' : '-',
               abs(zscore(matrix[i][1] / POW224, alphabetDistribution[i], POW224))>2.0 ? 'x' : '-',
               abs(zscore(matrix[i][2] / POW224, alphabetDistribution[i], POW224))>2.0 ? 'x' : '-',
               abs(zscore(matrix[i][3] / POW224, alphabetDistribution[i], POW224))>2.0 ? 'x' : '-',
               abs(zscore(matrix[i][4] / POW224, alphabetDistribution[i], POW224))>2.0 ? 'x' : '-',
               abs(zscore(matrix[i][5] / POW224, alphabetDistribution[i], POW224))>2.0 ? 'x' : '-',
               abs(zscore(matrix[i][6] / POW224, alphabetDistribution[i], POW224))>2.0 ? 'x' : '-',
               abs(zscore(matrix[i][7] / POW224, alphabetDistribution[i], POW224))>2.0 ? 'x' : '-',
               abs(zscore(matrix[i][8] / (POW224 * 8), alphabetDistribution[i], POW224 * 8))>2.0 ? 'x' : '-'
        );
    }

    printf("\n\nz-score 99%% on distribution:\n");
    for(i=0; i<26; i++){
        printf("%c|%c|%c|%c|%c|%c|%c|%c|%c|%c\n",
               'A'+(char)i,
               abs(zscore(matrix[i][0] / POW224, alphabetDistribution[i], POW224))>2.58 ? 'x' : '-',
               abs(zscore(matrix[i][1] / POW224, alphabetDistribution[i], POW224))>2.58 ? 'x' : '-',
               abs(zscore(matrix[i][2] / POW224, alphabetDistribution[i], POW224))>2.58 ? 'x' : '-',
               abs(zscore(matrix[i][3] / POW224, alphabetDistribution[i], POW224))>2.58 ? 'x' : '-',
               abs(zscore(matrix[i][4] / POW224, alphabetDistribution[i], POW224))>2.58 ? 'x' : '-',
               abs(zscore(matrix[i][5] / POW224, alphabetDistribution[i], POW224))>2.58 ? 'x' : '-',
               abs(zscore(matrix[i][6] / POW224, alphabetDistribution[i], POW224))>2.58 ? 'x' : '-',
               abs(zscore(matrix[i][7] / POW224, alphabetDistribution[i], POW224))>2.58 ? 'x' : '-',
               abs(zscore(matrix[i][8] / (POW224 * 8), alphabetDistribution[i], POW224 * 8))>2.58 ? 'x' : '-'
        );
    }

    printf("\n\nProfanity counts:\n");
    for(i=3; i<6; i++){
        printf(" Prof %d chars: %ld", (int)i, profanity_sizes_cnt[i]);
    }

    printf("\n\nDistribution 1B+1B:\n");
    for(i=0; i<1024;i++){
        printf("%ld;",mx[i]);
    }

    printf("\n\n1B+1B `mod` 26:\n");
    for(i=0; i<1024;i++){
        printf("%ld;",mx[i] % 26);
    }

    printf("\n\nDistribution for 1B+1B mod 26:\n");
    for(i=0; i<26;i++){
        printf("%ld;",mxa[i]);
    }

    // Now with XOR
    memset(mx, 0, sizeof(long)*511);
    memset(mxa, 0, sizeof(long)*26);
    for(a=0; a<256;a++){
        for(b=0;b<256;b++){
            mx[a^b]+=1;
            mxa[(a^b)%26]+=1;
        }
    }
    printf("\n\nDistribution 1Bx1B:\n");
    for(i=0; i<256;i++){
        printf("%ld;",mx[i]);
    }

    printf("\n\nDistribution for 1Bx1B mod 26:\n");
    for(i=0; i<26;i++){
        printf("%ld;",mxa[i]);
    }

    return 0;
}

inline double zscore(double observed, double expected, double samples){
    return (observed-expected) / sqrt((expected*(1-expected))/samples);
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

    // MAC+hex(UPCDEAULTSSID)
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

    // 1. MAC + hex(UPCDEAULTPASSPHRASE)
    sprintf((char*)buff1, "%2X%2X%2X%2X%2X%2X555043444541554C5450415353504852415345", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // 2.
    MD5_Init(&ctx);
    MD5_Update(&ctx, buff1, strlen((char*)buff1)+1);
    MD5_Final(buff2, &ctx);

    // 3.
    sprintf((char*)buff3, "%.02X%.02X%.02X%.02X%.02X%.02X", buff2[0]&0xF, buff2[1]&0xF, buff2[2]&0xF, buff2[3]&0xF, buff2[4]&0xF, buff2[5]&0xF);
    //sprintf((char*)buff3, "%.02X%.02X%.02X%.02X%.02X%.02X", buff2[0], buff2[1], buff2[2], buff2[3], buff2[4], buff2[5]);

    // 4.
    MD5_Init(&ctx);
    MD5_Update(&ctx, buff3, strlen((char*)buff3)+1);
    MD5_Final(hash_buff, &ctx);

    // 5.
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

    for (int i = 0; i < PROFANITY_REDUCED_COUNT; i++) {
        /* Fill the pattern data */
        patt.ptext.astring = profanitiesReduced[i];
        patt.ptext.length = strlen(profanitiesReduced[i]);

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

inline long contains_profanity(char const * pass, size_t len, int * numberOfProfs)
{
    long first_match = -1, i=0;
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

    for(i=0; i<match.size && match.size>1; i++){
        printf("  - %s\n", profanitiesReduced[match.patterns[i].id.u.number]);
    }
    first_match = match.patterns[0].id.u.number;
    if (numberOfProfs == NULL){
        return first_match;
    }

    // Number of all profanities found in this word.
    *numberOfProfs += match.size;
    do {
        match = ac_trie_findnext(trie);
        *numberOfProfs += match.size;
        for(i=0; i<match.size; i++){
            printf("  + %s\n", profanitiesReduced[match.patterns[i].id.u.number]);
        }

    } while(match.size > 0);
    if (*numberOfProfs > 1){
        printf("  - %s\n", profanitiesReduced[first_match]);
    }

    return first_match;
}

void intHandler(int dummy)
{
    keepRunning = 0;
}
