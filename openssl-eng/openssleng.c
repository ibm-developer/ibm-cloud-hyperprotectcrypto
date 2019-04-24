#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <evp/evp_locl.h>
#include <ec/ec_lcl.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/bn.h>
#include <ecdsa/ecs_locl.h>
#include <asn1/asn1_locl.h>
#include <pem/pem.h>

//ep11 API
int RemoteGenerateECDSAKeyPair(const unsigned char *curveOIDData, size_t curveOIDLength, unsigned char *privateKey, size_t *privateKeyLen, 
    unsigned char *pubKey, size_t *pubKeyLen);
int RemoteSignSingle(const unsigned char * privateKeyBlob, size_t keyBlobLen, const unsigned char * dgst, size_t dgstLen, unsigned char * signature, size_t *signatureLen);

const static int KEYBLOB_HEADER_LEN = sizeof(size_t);
//openssl functions, not in .h files
EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);

//openssl functions implementation, not exported
//set public key from oct string
EC_KEY *o2i_ECPublicKey(EC_KEY **a, const unsigned char **in, long len)
{
    EC_KEY *ret = NULL;

    if (a == NULL || (*a) == NULL || (*a)->group == NULL) {
        /*
         * sorry, but a EC_GROUP-structur is necessary to set the public key
         */
        ECerr(EC_F_O2I_ECPUBLICKEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    ret = *a;
    if (ret->pub_key == NULL &&
        (ret->pub_key = EC_POINT_new(ret->group)) == NULL) {
        ECerr(EC_F_O2I_ECPUBLICKEY, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!EC_POINT_oct2point(ret->group, ret->pub_key, *in, len, NULL)) {
        ECerr(EC_F_O2I_ECPUBLICKEY, ERR_R_EC_LIB);
        return 0;
    }
    /* save the point conversion form */
    ret->conv_form = (point_conversion_form_t) (*in[0] & ~0x01);
    *in += len;
    return ret;
}

//EC extra data functions
static void * (*ec_extra_data_dup_func) (void *) = NULL;
static void ec_extra_data_free_func (void * privateKeyBlobData) {
    OPENSSL_free(privateKeyBlobData);
    return;
}
static void ec_extra_data_clear_free_func (void * privateKeyBlobData) {
    OPENSSL_free(privateKeyBlobData);
    return;    
}

//======ECDSA methods
static ECDSA_SIG *my_ecdsa_do_sign(const unsigned char *dgst, int dgst_len,
                            const BIGNUM *inv, const BIGNUM *rp, EC_KEY *eckey)
{
    //reference code ecdsa_do_sign() in ecs_ossl.c
    int ok = 0, bits;
    size_t keyBlobLen = 0;
    BIGNUM *order = NULL;
    const EC_GROUP *group;
    ECDSA_SIG *ret;
    ECDSA_DATA *ecdsa;
    const BIGNUM *priv_key;
    unsigned char *ext_data = NULL, *keyBlobData = NULL;
    unsigned char sig[140]; // the biggest signature is (521+7)/8 * 2 = 132 bytes
    size_t siglen = 0;
    ecdsa = ecdsa_check(eckey);
    group = EC_KEY_get0_group(eckey);
    priv_key = EC_KEY_get0_private_key(eckey);

    if (group == NULL || priv_key == NULL || ecdsa == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ret = ECDSA_SIG_new();
    if (!ret) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if ((order = BN_new()) == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_GROUP_get_order(group, order, NULL)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_EC_LIB);
        goto err;
    }

    bits = BN_num_bits(order);
    /*
     * Need to truncate digest if it is too long: first truncate whole bytes. 
     * According to https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm, only 
     * L leftmost bits of HASH is used to generate signature, where L is the bit length of the group order
     */
    if (8 * dgst_len > bits)
        dgst_len = (bits + 7) / 8;
    /*For now this scenario will not happen: order bits cannot be divided by 8, and dgst bits is longer order bits.*/
    if (8 * dgst_len > bits) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_EC_LIB);
        goto err;
    }

    ext_data = EC_EX_DATA_get_data(eckey->method_data, ec_extra_data_dup_func, ec_extra_data_free_func, ec_extra_data_clear_free_func);
    if (ext_data == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_EC_LIB);
        printf("EC_EX_DATA_get_data failed\n");
        goto err;
    }
    memcpy(&keyBlobLen, ext_data, KEYBLOB_HEADER_LEN);
    keyBlobData = OPENSSL_malloc(keyBlobLen);
    if (keyBlobData == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_SYS_LIB);
        printf("my_ecdsa_do_sign OPENSSL_malloc %d bytes failed\n", (int)keyBlobLen);
        goto err;
    }
    memcpy(keyBlobData, ext_data + KEYBLOB_HEADER_LEN, keyBlobLen);
    
    siglen = sizeof(sig);
    int retRemote = RemoteSignSingle(keyBlobData, keyBlobLen, dgst, dgst_len, sig, &siglen);
    if (retRemote <= 0) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_CRYPTO_LIB);
        printf("RemoteSignSingle failed\n");
        goto err;
    }
    if (siglen % 2 != 0) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_CRYPTO_LIB);
        printf("Signature length is not even\n");
        goto err;
    }
    if (BN_bin2bn(sig, siglen/2, ret->r) == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
        printf("BN_bin2bn for r failed\n");
        goto err;       
    }
    if (BN_bin2bn(sig + siglen/2, siglen/2, ret->s) == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
        printf("BN_bin2bn for s failed\n");
        goto err;       
    }

    ok = 1;
 err:
    if (!ok) {
        ECDSA_SIG_free(ret);
        ret = NULL;
    }
    if (order)
        BN_free(order);
    if (keyBlobData)
        OPENSSL_free(keyBlobData);

    return ret;
}

static ECDSA_METHOD ecdsa_methds = {
    "my ecdsa methods",
    my_ecdsa_do_sign,
    NULL, // ecdsa_sign_setup. it is not needed since it is called within ecdsa_do_sign().
    NULL, // ecdsa_do_verify. it is needed when doing certificate/csr verify. it is setup in bind_helper.
    0,    // it is zero in builtin ECDSA_METHOD openssl_ecdsa_meth.
    NULL  // it is zero in builtin ECDSA_METHOD openssl_ecdsa_meth.
    };
//======ECDSA methods end

//======PKEY_METHODS for EC
static EVP_PKEY_METHOD pkey_method;

static int get_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid)
{
    static int pkey_nids[] = {
        EVP_PKEY_EC,
        0};

    if (!pmeth){ /* get the list of supported nids */
        *nids = pkey_nids;
        return sizeof(pkey_nids) / sizeof(int) - 1;
    }

    /* get the EVP_PKEY_METHOD */
    switch (nid)
    {
    case EVP_PKEY_EC:
        *pmeth = &pkey_method;
        return 1; /* success */
    }
    printf("Unexpeced nid %d\n", nid);
    *pmeth = NULL;
    return 0;
}

//reference pkey_ec_keygen() in ec_pmeth.c
static int init_eckey(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    //openssl struct EC_PKEY_CTX defined in ec_pmeth.c, not in .h file
    typedef struct {
        /* Key and paramgen group */
        EC_GROUP *gen_group;
        /* message digest */
        const EVP_MD *md;
        /* Duplicate key if custom cofactor needed */
        EC_KEY *co_key;
        /* Cofactor mode */
        signed char cofactor_mode;
        /* KDF (if any) to use for ECDH */
        char kdf_type;
        /* Message digest to use for key derivation */
        const EVP_MD *kdf_md;
        /* User key material */
        unsigned char *kdf_ukm;
        size_t kdf_ukmlen;
        /* KDF output length */
        size_t kdf_outlen;
    } EC_PKEY_CTX;
    
    EC_KEY *ec = NULL;
    EC_PKEY_CTX *dctx = ctx->data;
    if (ctx->pkey == NULL && dctx->gen_group == NULL) {
        ECerr(EC_F_PKEY_EC_KEYGEN, EC_R_NO_PARAMETERS_SET);
        return 0;
    }
    ec = EC_KEY_new();
    if (!ec)
        return 0;
    EVP_PKEY_assign_EC_KEY(pkey, ec);
    if (ctx->pkey) {
        /* Note: if error return, pkey is freed by parent routine */
        if (!EVP_PKEY_copy_parameters(pkey, ctx->pkey))
            return 0;
    } else {
        if (!EC_KEY_set_group(ec, dctx->gen_group))
            return 0;
    }
    //reference EC_KEY_generate_key() in ec_key.c
    ec->priv_key = BN_new();
    //BN_zero(ec->priv_key);
    ec->pub_key = EC_POINT_new(ec->group); 
    return 1;  
}
static int my_ec_pkeygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    int ok = 0;
    EC_KEY * ret_ec_key = NULL;
    EC_KEY * ec_key = NULL;
    unsigned char privateKey[640]; //keyblob is lower than 600 bytes
    unsigned char *pubKeyCoordinates = NULL;
    unsigned char * blobLenAndData = NULL;
    size_t privateKeyLen = 0;
    size_t pubKeyLen = 0;
    int success = 0, ret = 0;

    BIGNUM *order = NULL;
    const EC_GROUP *group = NULL;
    const ASN1_OBJECT * curve_OID = NULL;
    unsigned char full_OID[64] = {0};

    success = init_eckey(ctx, pkey);
    if (success == 0) {
        printf("init_eckey failed\n");
        return 0;       
    }
    ec_key = pkey->pkey.ec;

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    //get curve OID
    if (EC_GROUP_get_asn1_flag(group)) {
        int curve_name = EC_GROUP_get_curve_name(group);
        if (curve_name) {
            curve_OID = OBJ_nid2obj(curve_name);
            if (curve_OID == NULL) {
                ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BAD_GET_ASN1_OBJECT_CALL);
                goto err;
            }
            //OBJ_nid2obj() returns internal static data and no need to free.
            //curve_OID is raw bytes without asn1 type and length, now we add them
            if (curve_OID->length + 2 > sizeof(full_OID)) {
                ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BAD_GET_ASN1_OBJECT_CALL);
                goto err; 
            }
            memcpy(&full_OID[2], curve_OID->data, curve_OID->length);
            full_OID[0] = 0x06; //type is object identifier
            full_OID[1] = curve_OID->length;
        } 
        else {
            ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BAD_GET_ASN1_OBJECT_CALL);
            goto err;
        }
    } 
    else {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BAD_GET_ASN1_OBJECT_CALL);
        goto err;
    }
    
    //get order bit size    
    if ((order = BN_new()) == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_GROUP_get_order(group, order, NULL)) {
        ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_EC_LIB);
        goto err;
    }
    int bits = BN_num_bits(order);
    privateKeyLen = sizeof(privateKey);
    pubKeyLen = 2 * (bits+7)/8 + 1; //there is one header byte, "04" as uncompressed 
    pubKeyCoordinates = OPENSSL_malloc(pubKeyLen); 
    if (pubKeyCoordinates == NULL) {
        printf("my_ec_pkeygen OPENSSL_malloc %d failed\n", (int)pubKeyLen);
        goto err;       
    }
    success = RemoteGenerateECDSAKeyPair((const unsigned char *)full_OID, curve_OID->length + 2, privateKey, &privateKeyLen, pubKeyCoordinates, &pubKeyLen);
    if (success == 0) {
        printf("RemoteGenerateECDSAKeyPair failed\n");
        goto err;
    }

    //save privateKeyBlob.
    blobLenAndData = OPENSSL_malloc(privateKeyLen + KEYBLOB_HEADER_LEN);
    if (blobLenAndData == NULL) {
        printf("OPENSSL_malloc failed to allocate %d bytes\n", (int)(privateKeyLen + KEYBLOB_HEADER_LEN));
        goto err;
    }
    memcpy(blobLenAndData, &privateKeyLen, KEYBLOB_HEADER_LEN);
    memcpy(blobLenAndData + KEYBLOB_HEADER_LEN, privateKey, privateKeyLen);
    ret = EC_EX_DATA_set_data(&ec_key->method_data, (void *)blobLenAndData, ec_extra_data_dup_func,
        ec_extra_data_free_func, ec_extra_data_clear_free_func);
    if (ret == 0) {
        printf("EC_EX_DATA_set_data failed\n");
        goto err;
    }
    //save public key to EC_KEY public key structure
    ret_ec_key = o2i_ECPublicKey(&ec_key, (const unsigned char **)&pubKeyCoordinates, pubKeyLen);
    if (ret_ec_key != NULL) {
        pubKeyCoordinates -= pubKeyLen; //o2i_ECPublicKey change input pointer pubKeyCoordinates, need to change it back to free
        ok = 1;
    }
    else {
        EC_EX_DATA_free_data(&ec_key->method_data, ec_extra_data_dup_func, ec_extra_data_free_func, 
            ec_extra_data_clear_free_func);
        blobLenAndData = NULL; //it is freed inside EC_EX_DATA_free_data()
        printf("o2i_ECPublicKey return NULL\n");
    }
err:
    if (order) {
        BN_free(order);
    }
    if (pubKeyCoordinates) {
        OPENSSL_free(pubKeyCoordinates);
    }
    if (ok <= 0 && ec_key) {
        EVP_PKEY_assign_EC_KEY(pkey, NULL);
    }
    if (ok <= 0 && blobLenAndData) {
        OPENSSL_free(blobLenAndData);
    }   
    return ok;
}
//======PKEY_METHODS for EC ends

//======PKEY_ASN1_METHODS for EC
static EVP_PKEY_ASN1_METHOD pkey_asn1_method;

static int get_pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **pmeth, const int **nids, int nid)
{
    static int pkey_asn1_nids[] = {
        EVP_PKEY_EC,
        0};

    if (!pmeth){ /* get the list of supported nids */
        *nids = pkey_asn1_nids;
        return sizeof(pkey_asn1_nids) / sizeof(int) - 1;
    }
    switch (nid)
    {
    case EVP_PKEY_EC:
        *pmeth = &pkey_asn1_method;
        return 1; /* success */
    }
    printf("Unexpeced nid %d\n", nid);
    *pmeth = NULL;
    return 0;
}

static char* my_pem_str = "EC";

//reference ec_ameth.c, removed V_ASN1_SEQUENCE part
static EC_KEY *eckey_type2param(int ptype, void *pval)
{
    EC_KEY *eckey = NULL;
    EC_GROUP *group = NULL;

    if (ptype == V_ASN1_OBJECT) {
        const ASN1_OBJECT *poid = pval;

        /*
         * type == V_ASN1_OBJECT => the parameters are given by an asn1 OID
         */
        if ((eckey = EC_KEY_new()) == NULL) {
            ECerr(EC_F_ECKEY_TYPE2PARAM, ERR_R_MALLOC_FAILURE);
            goto ecerr;
        }
        group = EC_GROUP_new_by_curve_name(OBJ_obj2nid(poid));
        if (group == NULL)
            goto ecerr;
        EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
        if (EC_KEY_set_group(eckey, group) == 0)
            goto ecerr;
        EC_GROUP_free(group);
    } else {
        ECerr(EC_F_ECKEY_TYPE2PARAM, EC_R_DECODE_ERROR);
        goto ecerr;
    }

    return eckey;

 ecerr:
    EC_KEY_free(eckey);
    EC_GROUP_free(group);
    return NULL;
}

static int my_priv_decode (EVP_PKEY *pkey, PKCS8_PRIV_KEY_INFO *p8)
{
    X509_ALGOR *pkeyalg = p8->pkeyalg;
    ASN1_TYPE *blobData = p8->pkey;
    unsigned char * blobLenAndData = NULL;

    if (blobData == NULL) {
        printf("p8->pkey is NULL\n");
        return 0;
    } else if (blobData->value.octet_string == NULL) {
        printf("p8->pkey->value.octet_string is NULL\n");
        return 0;       
    }

    unsigned char *keyBlobRaw = blobData->value.octet_string->data;
    size_t keyBlobRawLen = blobData->value.octet_string->length;

    //reference eckey_priv_decode() in ec_ameth.c 
    void *pval = NULL;
    int ptype;
    EC_KEY *eckey = NULL;

    X509_ALGOR_get0(NULL, &ptype, &pval, pkeyalg);
    eckey = eckey_type2param(ptype, pval);
    if (!eckey){
        printf("eckey_type2param failed\n");
        goto ecliberr;
    }

    //setup EC Private key
    if (eckey->priv_key) {
        BN_free(eckey->priv_key);
    }
    eckey->priv_key = BN_new();
    //BN_zero(eckey->priv_key);

    //setup keyBlob
    blobLenAndData = OPENSSL_malloc(keyBlobRawLen + KEYBLOB_HEADER_LEN);
    if (blobLenAndData == NULL) {
        printf("my_priv_decode OPENSSL_malloc %d bytes failed\n", (int)(keyBlobRawLen + KEYBLOB_HEADER_LEN));
        goto ecliberr;
    }
    memcpy(blobLenAndData, &keyBlobRawLen, KEYBLOB_HEADER_LEN);
    memcpy(blobLenAndData + KEYBLOB_HEADER_LEN, keyBlobRaw, keyBlobRawLen);
    int ret = EC_EX_DATA_set_data(&eckey->method_data, (void *)blobLenAndData, ec_extra_data_dup_func,
        ec_extra_data_free_func, ec_extra_data_clear_free_func);
    if (ret <= 0) {
        printf("EC_EX_DATA_set_data in my_priv_decode failed\n");
        goto ecliberr;       
    }

    EVP_PKEY_assign_EC_KEY(pkey, eckey);
    pkey->type = EVP_PKEY_EC;
    return 1;

 ecliberr:
    ECerr(EC_F_ECKEY_PRIV_DECODE, ERR_R_EC_LIB);
    if (eckey)
        EC_KEY_free(eckey);
    if (blobLenAndData) {
        OPENSSL_free(blobLenAndData);
    }
    return 0;
}

static int my_priv_encode (PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pk)
{
    int ok = 0;
    EC_KEY *ec_key = pk->pkey.ec;
    unsigned char *ext_data, *keyBlobData = NULL;
    int ptype;
    size_t keyBlobLen = 0;

    //get group parameter first. get reference code from ec_asn1.c
    ASN1_OBJECT* pval = NULL;

    const EC_GROUP *group;
    int nid;

    if ((group = EC_KEY_get0_group(ec_key)) == NULL) {
        ECerr(EC_F_ECKEY_PARAM2TYPE, EC_R_MISSING_PARAMETERS);
        return 0;
    }
    if ((nid = EC_GROUP_get_curve_name(group)) != 0){
        pval = OBJ_nid2obj(nid);
        ptype = V_ASN1_OBJECT; //set ptype = V_ASN1_UNDEF; if want the PEM file not including algorithm information
    }
    else {
        printf("get group parameters failed: %d\n", nid);
        return 0;
    }

    unsigned int old_flags = EC_KEY_get_enc_flags(ec_key);
    EC_KEY_set_enc_flags(ec_key, old_flags | EC_PKEY_NO_PUBKEY);

    //copy keyblob data into memory
    ext_data = EC_EX_DATA_get_data(ec_key->method_data, ec_extra_data_dup_func, ec_extra_data_free_func, ec_extra_data_clear_free_func);
    if (ext_data == NULL) {
        printf("Get ec_key ext data failed\n");
        return 0;
    }
    memcpy(&keyBlobLen, ext_data, KEYBLOB_HEADER_LEN); //length of keyblob
    keyBlobData = OPENSSL_malloc(keyBlobLen);
    if (keyBlobData == NULL) {
        printf("OPENSSL_malloc failed to allocate %d bytes\n", (int)keyBlobLen);
        return 0;
    }
    memcpy(keyBlobData, ext_data + KEYBLOB_HEADER_LEN, keyBlobLen);
    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_X9_62_id_ecPublicKey), 0, ptype, pval, keyBlobData, (int)keyBlobLen)) {
        printf("PKCS8_pkey_set0 failed\n");
        goto encode_err;
    }
    if (ec_key->priv_key) {
        BN_zero(ec_key->priv_key);
    }
    ok = 1;

encode_err:
    if (ok <= 0 && keyBlobData) {
        OPENSSL_free(keyBlobData);
    }
    return ok;
}

/*this function is called when reading private key
 "openssl ec -engine xxx.so -in prikey-my.pem" -text -noout
 */
static int my_priv_print (BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)
{
    BIO_printf(out, "HSM EC key\n");
    return 1;
}

//function called in EVP_PKEY_cmp() when loading private key and certificate. Must return 1 for successful match
static int my_pub_cmp (const EVP_PKEY *a, const EVP_PKEY *b)
{
    return 1;
}
//function called in EVP_PKEY_cmp() when loading private key and certificate. Must return 1 for successful match
static int my_param_cmp (const EVP_PKEY *a, const EVP_PKEY *b)
{
    return 1;
}

//======PKEY_ASN1_METHODS for EC ends

//======Load private key
static EVP_PKEY *load_privkey(ENGINE *engine, const char *s_key_id,
		UI_METHOD *ui_method, void *callback_data)
{
    //reference openssl_load_privkey() in eng_openssl.c
    BIO *in;
    EVP_PKEY *key;
    in = BIO_new_file(s_key_id, "r");
    if (!in)
        return NULL;
    key = PEM_read_bio_PrivateKey(in, NULL, 0, NULL);
    BIO_free(in);
    return key;
}
//======Load private key ends

//=====Engine bind
static const char *engine_id = "grep11";
static const char *engine_name = "grep11 engine";
static int bind_helper(ENGINE *e, const char *id)
{
    int ret = 0;

    //setup pkey methods
    EVP_PKEY_METHOD *orig_meth = (EVP_PKEY_METHOD *)EVP_PKEY_meth_find(EVP_PKEY_EC);
    if (orig_meth != NULL){
        pkey_method.pkey_id = orig_meth->pkey_id;
        EVP_PKEY_meth_copy(&pkey_method, orig_meth);
        pkey_method.keygen = my_ec_pkeygen;
    }
    else{
        printf("Failed to get built-in EC pkey method\n");
    }

    //setup pkey asn1 methods
    const EVP_PKEY_ASN1_METHOD * orig_asn1_meth = EVP_PKEY_asn1_find(NULL, EVP_PKEY_EC);
    if (orig_asn1_meth != NULL) {
        pkey_asn1_method.pkey_id = orig_asn1_meth->pkey_id;
        pkey_asn1_method.pkey_base_id = orig_asn1_meth->pkey_base_id;
        pkey_asn1_method.pem_str = my_pem_str; //without this pem_str value, openssl will get crashed

        EVP_PKEY_asn1_copy(&pkey_asn1_method, orig_asn1_meth);

        pkey_asn1_method.priv_decode = my_priv_decode;
        pkey_asn1_method.priv_encode = my_priv_encode;
        pkey_asn1_method.priv_print = my_priv_print;
        pkey_asn1_method.pub_cmp = my_pub_cmp;
        pkey_asn1_method.param_cmp = my_param_cmp;
    }
    else {
        printf("Failed to get builtin EC pkey ASN1 method\n");
    }

    //setup ECDSA methods
    const ECDSA_METHOD * orig_ecdsa_methods = ECDSA_get_default_method();
    if (orig_ecdsa_methods == NULL) {
        printf("Failed to get builtin ECDSA_METHOD method\n");
    }
    ecdsa_methds.ecdsa_do_verify = orig_ecdsa_methods->ecdsa_do_verify;

    //setup engine
    if (!ENGINE_set_id(e, engine_id)){
        printf("ENGINE_set_id failed\n");
        goto end;
    }
    if (!ENGINE_set_name(e, engine_name)){
        printf("ENGINE_set_name failed\n");
        goto end;
    }
    if (!ENGINE_set_pkey_meths(e, get_pkey_meths) ||
        !ENGINE_set_pkey_asn1_meths(e, get_pkey_asn1_meths) ||
        !ENGINE_set_ECDSA(e, &ecdsa_methds) ||
        !ENGINE_set_load_privkey_function(e, load_privkey)
        ){
        printf("ENGINE_set failed\n");
        goto end;
    }
    ret = 1;
end:
    return ret;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
IMPLEMENT_DYNAMIC_CHECK_FN()
