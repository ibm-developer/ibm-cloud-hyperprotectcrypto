/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "ep11.h"

void getMechanismInfo(int index);
CK_RV m_GenerateRandom(CK_BYTE_PTR rnd, CK_ULONG len, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}
/**/
/* note: external seeding not supported */
CK_RV m_SeedRandom(CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_DigestInit(unsigned char *state, size_t *len, const CK_MECHANISM_PTR pmech, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**/
CK_RV m_Digest(const unsigned char *state, size_t slen, CK_BYTE_PTR data, CK_ULONG len, CK_BYTE_PTR digest, CK_ULONG_PTR dglen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_DigestUpdate(unsigned char *state, size_t slen, CK_BYTE_PTR data, CK_ULONG dlen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_DigestKey(unsigned char *state, size_t slen, const unsigned char *key, size_t klen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_DigestFinal(const unsigned char *state, size_t slen, CK_BYTE_PTR digest, CK_ULONG_PTR dlen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_DigestSingle(CK_MECHANISM_PTR pmech, CK_BYTE_PTR data, CK_ULONG len, CK_BYTE_PTR digest, CK_ULONG_PTR dlen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_EncryptInit(unsigned char *state, size_t *slen, CK_MECHANISM_PTR pmech, const unsigned char *key, size_t klen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_DecryptInit(unsigned char *state, size_t *slen, CK_MECHANISM_PTR pmech, const unsigned char *key, size_t klen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**/
CK_RV m_EncryptUpdate(unsigned char *state, size_t slen, CK_BYTE_PTR plain, CK_ULONG plen, CK_BYTE_PTR cipher, CK_ULONG_PTR clen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_DecryptUpdate(unsigned char *state, size_t slen, CK_BYTE_PTR cipher, CK_ULONG clen, CK_BYTE_PTR plain, CK_ULONG_PTR plen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**/
/* one-pass en/decrypt with key blob */
CK_RV m_Encrypt(const unsigned char *state, size_t slen, CK_BYTE_PTR plain, CK_ULONG plen, CK_BYTE_PTR cipher, CK_ULONG_PTR clen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_Decrypt(const unsigned char *state, size_t slen, CK_BYTE_PTR cipher, CK_ULONG clen, CK_BYTE_PTR plain, CK_ULONG_PTR plen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**/
CK_RV m_EncryptFinal(const unsigned char *state, size_t slen, CK_BYTE_PTR output, CK_ULONG_PTR len, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_DecryptFinal(const unsigned char *state, size_t slen, CK_BYTE_PTR output, CK_ULONG_PTR len, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**/
/* en/decrypt directly with key blob */
CK_RV m_EncryptSingle(const unsigned char *key, size_t klen, CK_MECHANISM_PTR mech, CK_BYTE_PTR plain, CK_ULONG plen, CK_BYTE_PTR cipher, CK_ULONG_PTR clen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_DecryptSingle(const unsigned char *key, size_t klen, CK_MECHANISM_PTR mech, CK_BYTE_PTR cipher, CK_ULONG clen, CK_BYTE_PTR plain, CK_ULONG_PTR plen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**/
/* de+encrypt in one pass, without exposing cleartext */
CK_RV m_ReencryptSingle(const unsigned char *dkey, size_t dklen, const unsigned char *ekey, size_t eklen, CK_MECHANISM_PTR pdecrmech, CK_MECHANISM_PTR pencrmech, CK_BYTE_PTR in,
		CK_ULONG ilen, CK_BYTE_PTR out, CK_ULONG_PTR olen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_GenerateKey(CK_MECHANISM_PTR pmech, CK_ATTRIBUTE_PTR ptempl, CK_ULONG templcount, const unsigned char *pin, size_t pinlen, unsigned char *key, size_t *klen,
		unsigned char *csum, size_t *clen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**/
CK_RV m_GenerateKeyPair(CK_MECHANISM_PTR pmech, CK_ATTRIBUTE_PTR ppublic, CK_ULONG pubattrs, CK_ATTRIBUTE_PTR pprivate, CK_ULONG prvattrs, const unsigned char *pin, size_t pinlen,
		unsigned char *key, size_t *klen, unsigned char *pubkey, size_t *pklen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_SignInit(unsigned char *state, size_t *slen, CK_MECHANISM_PTR alg, const unsigned char *key, size_t klen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_VerifyInit(unsigned char *state, size_t *slen, CK_MECHANISM_PTR alg, const unsigned char *key, size_t klen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**/
CK_RV m_SignUpdate(unsigned char *state, size_t slen, CK_BYTE_PTR data, CK_ULONG dlen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_VerifyUpdate(unsigned char *state, size_t slen, CK_BYTE_PTR data, CK_ULONG dlen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**/
CK_RV m_SignFinal(const unsigned char *state, size_t stlen, CK_BYTE_PTR sig, CK_ULONG_PTR siglen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_VerifyFinal(const unsigned char *state, size_t stlen, CK_BYTE_PTR sig, CK_ULONG siglen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**/
CK_RV m_Sign(const unsigned char *state, size_t stlen, CK_BYTE_PTR data, CK_ULONG dlen, CK_BYTE_PTR sig, CK_ULONG_PTR siglen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_Verify(const unsigned char *state, size_t stlen, CK_BYTE_PTR data, CK_ULONG dlen, CK_BYTE_PTR sig, CK_ULONG siglen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**/
CK_RV m_SignSingle(const unsigned char *key, size_t klen, CK_MECHANISM_PTR pmech, CK_BYTE_PTR data, CK_ULONG dlen, CK_BYTE_PTR sig, CK_ULONG_PTR slen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_VerifySingle(const unsigned char *key, size_t klen, CK_MECHANISM_PTR pmech, CK_BYTE_PTR data, CK_ULONG dlen, CK_BYTE_PTR sig, CK_ULONG slen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* mackey is NULL for PKCS#11 formats, not for authenticated ones */
CK_RV m_WrapKey(const unsigned char *key, size_t keylen, const unsigned char *kek, size_t keklen, const unsigned char *mackey, size_t mklen, const CK_MECHANISM_PTR pmech,
		CK_BYTE_PTR wrapped, CK_ULONG_PTR wlen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**/
/* mackey is NULL for PKCS#11 formats, not for authenticated ones */
CK_RV m_UnwrapKey(const CK_BYTE_PTR wrapped, CK_ULONG wlen, const unsigned char *kek, size_t keklen, const unsigned char *mackey, size_t mklen, const unsigned char *pin,
		size_t pinlen, const CK_MECHANISM_PTR uwmech, const CK_ATTRIBUTE_PTR ptempl, CK_ULONG pcount, unsigned char *unwrapped, size_t *uwlen, CK_BYTE_PTR csum, CK_ULONG *cslen,
		uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_DeriveKey(CK_MECHANISM_PTR pderivemech, CK_ATTRIBUTE_PTR ptempl, CK_ULONG templcount, const unsigned char *basekey, size_t bklen, const unsigned char *data, size_t dlen,
		const unsigned char *pin, size_t pinlen, unsigned char *newkey, size_t *nklen, unsigned char *csum, size_t *cslen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**/
CK_RV m_GetMechanismList(CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR mechs, CK_ULONG_PTR count, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_GetMechanismInfo(CK_SLOT_ID slot, CK_MECHANISM_TYPE mech, CK_MECHANISM_INFO_PTR pmechinfo, uint64_t target) {
	printf("%s %d %s: mech %lx\n", __FILE__, __LINE__, __FUNCTION__, mech);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_GetAttributeValue(const unsigned char *obj, size_t olen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_SetAttributeValue(unsigned char *obj, size_t olen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_Login(CK_UTF8CHAR_PTR pin, CK_ULONG pinlen, const unsigned char *nonce, size_t nlen, unsigned char *pinblob, size_t *pinbloblen, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_Logout(const unsigned char *pin, size_t len, uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_admin(unsigned char *response1, size_t *r1len, unsigned char *response2, size_t *r2len, const unsigned char *cmd, size_t clen, const unsigned char *sigs, size_t slen,
		uint64_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_get_ep11_info() {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV m_get_xcp_info(CK_VOID_PTR pinfo, CK_ULONG_PTR infbytes,
                     unsigned int query,
                     unsigned int subquery,
                         target_t target) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/*--------------------------------------------------------------------------
 *  Module management.
 */
int m_add_backend(const char *name, unsigned int port) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

int m_init(void) {
	return CKR_OK;
}

int m_shutdown(void) {
	printf("%s %d %s FUNCTION_NOT_SUPPORTED\n", __FILE__, __LINE__, __FUNCTION__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

#ifdef __cplusplus
} //extern "C" }
#endif
