#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../build/libahe.h"

int
main(void)
{
    // maabe
    char ** maabe = Ahe_maabe_NewMAABE();
    // authorities
    struct Ahe_maabe_NewMAABEAuth_return auth1, auth2, auth3;
    char * id1 = "auth1";
    char * id2 = "auth2";
    char * id3 = "auth3";
    char * attribs1[2] = {"auth1:at1", "auth1:at2"};
    char * attribs2[2] = {"auth2:at1", "auth2:at2"};
    char * attribs3[2] = {"auth3:at1", "auth3:at2"};
    auth1 = Ahe_maabe_NewMAABEAuth(maabe, id1, attribs1, 2);
    if (auth1.r0 == NULL) printf("sth went wrong with auth 1");
    auth2 = Ahe_maabe_NewMAABEAuth(maabe, id2, attribs2, 2);
    if (auth2.r0 == NULL) printf("sth went wrong with auth 2");
    auth3 = Ahe_maabe_NewMAABEAuth(maabe, id3, attribs3, 2);
    if (auth3.r0 == NULL) printf("sth went wrong with auth 2");
    // pubkeys
    struct Ahe_maabe_MaabeAuthPubKeys_return pks1, pks2, pks3;
    pks1 = Ahe_maabe_MaabeAuthPubKeys(auth1.r0, auth1.r1);
    if (pks1.r0 == NULL) printf("sth went wrong with pks 1");
    pks2 = Ahe_maabe_MaabeAuthPubKeys(auth2.r0, auth2.r1);
    if (pks2.r0 == NULL) printf("sth went wrong with pks 2");
    pks3 = Ahe_maabe_MaabeAuthPubKeys(auth3.r0, auth3.r1);
    if (pks3.r0 == NULL) printf("sth went wrong with pks 3");
    int pksLen = pks1.r1 + pks2.r1 + pks3.r1;
    char ** pks = (char **) malloc(sizeof(char *) * (pksLen + 1));
    if (pks == NULL) printf("error allocating memory for pks");
    for (int i = 0; i < pksLen; i++) {
        if (i < pks1.r1) {
            *(pks+i) = *(pks1.r0 + i);
        } else if (i < pks1.r1 + pks2.r1) {
            *(pks+i) = *(pks2.r0 + (i - pks1.r1));
        } else {
            *(pks+i) = *(pks3.r0 + (i - pks1.r1 - pks2.r1));
        }
    }
    *(pks + pksLen) = NULL;
    // encrypt
    struct Ahe_maabe_Encrypt_return enc;
    char * msg = "Attack at dawn!";
    char * bf = "((auth1:at1 AND auth2:at1) OR (auth1:at2 AND auth2:at2)) OR (auth3:at1 AND auth3:at2)";
    enc = Ahe_maabe_Encrypt(maabe, msg, bf, pks, pksLen);
    if (enc.r0 == NULL) printf("sth went wrong with enc");
    // get keys
    struct Ahe_maabe_GenerateAttribKeys_return keys1, keys2, keys3;
    char * gid = "gid1";
    keys1 = Ahe_maabe_GenerateAttribKeys(auth1.r0, auth1.r1, gid, attribs1, 2);
    if (keys1.r0 == NULL) printf("sth went wrong with keys1");
    keys2 = Ahe_maabe_GenerateAttribKeys(auth2.r0, auth2.r1, gid, attribs2, 2);
    if (keys2.r0 == NULL) printf("sth went wrong with keys2");
    keys3 = Ahe_maabe_GenerateAttribKeys(auth3.r0, auth3.r1, gid, attribs3, 2);
    if (keys3.r0 == NULL) printf("sth went wrong with keys3");
    /* char * ks1[] = {*(keys1.r0), *(keys1.r0+1), *(keys1.r0+2), */
                   /* *(keys2.r0), *(keys2.r0+1), *(keys2.r0+2), */
                   /* *(keys3.r0), *(keys3.r0+1), *(keys3.r0+2), */
                   /* NULL}; */
    /* char * ks2[] = {*(keys1.r0+3), *(keys1.r0+4), *(keys1.r0+5), */
                  /* *(keys2.r0+3), *(keys2.r0+4), *(keys2.r0+5), */
                  /* *(keys3.r0+3), *(keys3.r0+4), *(keys3.r0+5), */
                  /* NULL}; */
    /* char * ks3[] = {*(keys1.r0), *(keys1.r0+1), *(keys1.r0+2), */
                  /* *(keys2.r0+3), *(keys2.r0+4), *(keys2.r0+5), */
                  /* NULL}; */
    /* char * ks4[] = {*(keys1.r0+3), *(keys1.r0+4), *(keys1.r0+5), */
                  /* *(keys2.r0), *(keys2.r0+1), *(keys2.r0+2), */
                  /* NULL}; */
    /* char * ks5[] = {*(keys3.r0), *(keys3.r0+1), *(keys3.r0+2), */
                   /* *(keys3.r0+3), *(keys3.r0+4), *(keys3.r0+5), */
                   /* NULL}; */
    char ** ks1 = (char **) malloc(sizeof(char *) * 3*3+1);
    *(ks1+0) = *(keys1.r0+0);
    *(ks1+1) = *(keys1.r0+1);
    *(ks1+2) = *(keys1.r0+2);
    *(ks1+3) = *(keys2.r0+0);
    *(ks1+4) = *(keys2.r0+1);
    *(ks1+5) = *(keys2.r0+2);
    *(ks1+6) = *(keys3.r0+0);
    *(ks1+7) = *(keys3.r0+1);
    *(ks1+8) = *(keys3.r0+2);
    /* *(ks1+9) = NULL; */
    char ** ks2 = (char **) malloc(sizeof(char *) * 3*3+1);
    *(ks2+0) = *(keys1.r0+3);
    *(ks2+1) = *(keys1.r0+4);
    *(ks2+2) = *(keys1.r0+5);
    *(ks2+3) = *(keys2.r0+3);
    *(ks2+4) = *(keys2.r0+4);
    *(ks2+5) = *(keys2.r0+5);
    *(ks2+6) = *(keys3.r0+3);
    *(ks2+7) = *(keys3.r0+4);
    *(ks2+8) = *(keys3.r0+5);
    /* *(ks2+9) = NULL; */
    char ** ks3 = (char **) malloc(sizeof(char *) * 2*3+1);
    *(ks3+0) = *(keys1.r0+3);
    *(ks3+1) = *(keys1.r0+4);
    *(ks3+2) = *(keys1.r0+5);
    *(ks3+3) = *(keys2.r0+0);
    *(ks3+4) = *(keys2.r0+1);
    *(ks3+5) = *(keys2.r0+2);
    /* *(ks3+6) = NULL; */
    char ** ks4 = (char **) malloc(sizeof(char *) * 2*3+1);
    *(ks4+0) = *(keys1.r0+0);
    *(ks4+1) = *(keys1.r0+1);
    *(ks4+2) = *(keys1.r0+2);
    *(ks4+3) = *(keys2.r0+3);
    *(ks4+4) = *(keys2.r0+4);
    *(ks4+5) = *(keys2.r0+5);
    /* *(ks4+6) = NULL; */
    char ** ks5 = (char **) malloc(sizeof(char *) * 2*3+1);
    *(ks5+0) = *(keys3.r0+0);
    *(ks5+1) = *(keys3.r0+1);
    *(ks5+2) = *(keys3.r0+2);
    *(ks5+3) = *(keys3.r0+3);
    *(ks5+4) = *(keys3.r0+4);
    *(ks5+5) = *(keys3.r0+5);
    /* *(ks5+6) = NULL; */
    // decrypt
    char * pt1, * pt2, * pt3, * pt4, * pt5;
    pt1 = Ahe_maabe_Decrypt(maabe, enc.r0, enc.r1, ks1, 9);
    if (!pt1) return 1;
    if (strcmp(msg, pt1)) return 1;
    pt2 = Ahe_maabe_Decrypt(maabe, enc.r0, enc.r1, ks2, 9);
    if (!pt2) return 1;
    if (strcmp(msg, pt2)) return 1;
    pt3 = Ahe_maabe_Decrypt(maabe, enc.r0, enc.r1, ks3, 6);
    if (pt3) return 1;
    pt4 = Ahe_maabe_Decrypt(maabe, enc.r0, enc.r1, ks4, 6);
    if (pt4) return 1;
    pt5 = Ahe_maabe_Decrypt(maabe, enc.r0, enc.r1, ks5, 6);
    if (!pt5) return 1;
    if (strcmp(msg, pt5)) return 1;
    free(pks);
    free(ks1);
    free(ks2);
    free(ks3);
    free(ks4);
    free(ks5);
    return 0;
}
