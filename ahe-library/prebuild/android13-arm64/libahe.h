/* Code generated by cmd/cgo; DO NOT EDIT. */

/* package command-line-arguments */


#line 1 "cgo-builtin-export-prolog"

#include <stddef.h>

#ifndef GO_CGO_EXPORT_PROLOGUE_H
#define GO_CGO_EXPORT_PROLOGUE_H

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef struct { const char *p; ptrdiff_t n; } _GoString_;
#endif

#endif

/* Start of preamble from import "C" comments.  */


#line 3 "ahe.go"
#include <stdlib.h>

#line 1 "cgo-generated-wrapper"


/* End of preamble from import "C" comments.  */


/* Start of boilerplate cgo prologue.  */
#line 1 "cgo-gcc-export-header-prolog"

#ifndef GO_CGO_PROLOGUE_H
#define GO_CGO_PROLOGUE_H

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef size_t GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
#ifdef _MSC_VER
#include <complex.h>
typedef _Fcomplex GoComplex64;
typedef _Dcomplex GoComplex128;
#else
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;
#endif

/*
  static assertion to make sure the file is being used on architecture
  at least with matching size of GoInt.
*/
typedef char _check_for_64_bit_pointer_matching_GoInt[sizeof(void*)==64/8 ? 1:-1];

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef _GoString_ GoString;
#endif
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

#endif

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif

extern char** Ahe_maabe_NewMAABE();

/* Return type for Ahe_maabe_NewMAABEAuth */
struct Ahe_maabe_NewMAABEAuth_return {
	char** r0;
	int r1;
};
extern struct Ahe_maabe_NewMAABEAuth_return Ahe_maabe_NewMAABEAuth(char** maabeRawC, char* id, char** attribs, int attribsLen);

/* Return type for Ahe_maabe_MaabeAuthPubKeys */
struct Ahe_maabe_MaabeAuthPubKeys_return {
	char** r0;
	int r1;
};
extern struct Ahe_maabe_MaabeAuthPubKeys_return Ahe_maabe_MaabeAuthPubKeys(char** authC, int authCLen);

/* Return type for Ahe_maabe_AddAttribute */
struct Ahe_maabe_AddAttribute_return {
	char** r0;
	int r1;
};
extern struct Ahe_maabe_AddAttribute_return Ahe_maabe_AddAttribute(char** authC, int authCLen, char* attrib);

/* Return type for Ahe_maabe_Encrypt */
struct Ahe_maabe_Encrypt_return {
	char** r0;
	int r1;
};
extern struct Ahe_maabe_Encrypt_return Ahe_maabe_Encrypt(char** maabeRawC, char* msg, char* booleanFormula, char** pubkeys, int pubkeysLen);

/* Return type for Ahe_maabe_GenerateAttribKeys */
struct Ahe_maabe_GenerateAttribKeys_return {
	char** r0;
	int r1;
};
extern struct Ahe_maabe_GenerateAttribKeys_return Ahe_maabe_GenerateAttribKeys(char** authC, int authCLen, char* gid, char** attribs, int attribsLen);
extern char* Ahe_maabe_Decrypt(char** maabeRawC, char** ctRawC, int ctRawCLen, char** ksRawC, int ksRawCLen);
extern char* Ahe_maabe_PubKeyToJSON(char** pkC, int pkCLen);

/* Return type for Ahe_maabe_PubKeyFromJSON */
struct Ahe_maabe_PubKeyFromJSON_return {
	char** r0;
	int r1;
};
extern struct Ahe_maabe_PubKeyFromJSON_return Ahe_maabe_PubKeyFromJSON(char* data);
extern char* Ahe_maabe_AttribKeysToJSON(char** ks, int ksLen);

/* Return type for Ahe_maabe_AttribKeysFromJSON */
struct Ahe_maabe_AttribKeysFromJSON_return {
	char** r0;
	int r1;
};
extern struct Ahe_maabe_AttribKeysFromJSON_return Ahe_maabe_AttribKeysFromJSON(char* data);
extern char* Ahe_maabe_CipherToJSON(char** ct, int ctLen);

/* Return type for Ahe_maabe_CipherFromJSON */
struct Ahe_maabe_CipherFromJSON_return {
	char** r0;
	int r1;
};
extern struct Ahe_maabe_CipherFromJSON_return Ahe_maabe_CipherFromJSON(char* data);
extern char* Ahe_fame_NewFAME();

/* Return type for Ahe_fame_GenerateMasterKeys */
struct Ahe_fame_GenerateMasterKeys_return {
	char* r0;
	char* r1;
};
extern struct Ahe_fame_GenerateMasterKeys_return Ahe_fame_GenerateMasterKeys(char* fameRawC);

/* Return type for Ahe_fame_Encrypt */
struct Ahe_fame_Encrypt_return {
	char** r0;
	int r1;
};
extern struct Ahe_fame_Encrypt_return Ahe_fame_Encrypt(char* fameRawC, char* msg, char* booleanFormula, char* pubkey);

/* Return type for Ahe_fame_GenerateAttribKeys */
struct Ahe_fame_GenerateAttribKeys_return {
	char** r0;
	int r1;
};
extern struct Ahe_fame_GenerateAttribKeys_return Ahe_fame_GenerateAttribKeys(char* fameRawC, char** attribs, int attribsLen, char* skRawC);
extern char* Ahe_fame_Decrypt(char* fameRawC, char** ctRawC, int ctRawCLen, char** ksRawC, int ksRawCLen, char* pkRawC);

/* Return type for Ahe_GenerateSigKeys */
struct Ahe_GenerateSigKeys_return {
	char* r0;
	char* r1;
};
extern struct Ahe_GenerateSigKeys_return Ahe_GenerateSigKeys();
extern char* Ahe_SignCiphers(char* skRaw, char** ctsRaw, int ctsRawCLen);
extern int Ahe_VerifySig(char* ctsSignedRaw, char* vkRaw);

#ifdef __cplusplus
}
#endif