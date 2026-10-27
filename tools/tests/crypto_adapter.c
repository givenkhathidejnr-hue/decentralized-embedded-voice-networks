/* Real AES-GCM / HMAC / HKDF via OpenSSL, behind the mbedTLS test ABI.
 * This tests production key schedules and protocol authentication, but is
 * not a substitute for testing ESP-IDF's hardware-accelerated mbedTLS. */
#include <assert.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"

const mbedtls_md_info_t *mbedtls_md_info_from_type(int t) { static int md=1; (void)t; return &md; }
int mbedtls_md_hmac(const mbedtls_md_info_t *m,const unsigned char *k,size_t kl,const unsigned char *p,size_t n,unsigned char *out) {
    (void)m; unsigned len=32; return HMAC(EVP_sha256(),k,(int)kl,p,n,out,&len)?0:-1;
}
static int hkdf(int mode,const unsigned char *salt,size_t sl,const unsigned char *key,size_t kl,const unsigned char *info,size_t il,unsigned char *out,size_t ol) {
    EVP_PKEY_CTX *c=EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF,NULL); if(!c) return -1;
    int ok=EVP_PKEY_derive_init(c)>0 && EVP_PKEY_CTX_hkdf_mode(c,mode)>0 &&
        EVP_PKEY_CTX_set_hkdf_md(c,EVP_sha256())>0 && EVP_PKEY_CTX_set1_hkdf_key(c,key,(int)kl)>0;
    if(salt && sl) ok=ok && EVP_PKEY_CTX_set1_hkdf_salt(c,salt,(int)sl)>0;
    if(info && il) ok=ok && EVP_PKEY_CTX_add1_hkdf_info(c,info,(int)il)>0;
    ok=ok && EVP_PKEY_derive(c,out,&ol)>0; EVP_PKEY_CTX_free(c); return ok?0:-1;
}
int mbedtls_hkdf(const mbedtls_md_info_t *m,const unsigned char *s,size_t sl,const unsigned char *k,size_t kl,const unsigned char *i,size_t il,unsigned char *o,size_t ol) {
    (void)m; return hkdf(EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND,s,sl,k,kl,i,il,o,ol);
}
int mbedtls_hkdf_expand(const mbedtls_md_info_t *m,const unsigned char *k,size_t kl,const unsigned char *i,size_t il,unsigned char *o,size_t ol) {
    (void)m; return hkdf(EVP_PKEY_HKDEF_MODE_EXPAND_ONLY,NULL,0,k,kl,i,il,o,ol);
}
void mbedtls_gcm_init(mbedtls_gcm_context *c) { memset(c,0,sizeof(*c)); }
void mbedtls_gcm_free(mbedtls_gcm_context *c) { memset(c,0,sizeof(*c)); }
int mbedtls_gcm_setkey(mbedtls_gcm_context *c,int id,const unsigned char *k,unsigned bits) { (void)id; if(bits!=128) return -1; memcpy(c->key,k,16); return 0; }
void test_nonce_used(const uint8_t key[16],const uint8_t nonce[12]);
int mbedtls_gcm_crypt_and_tag(mbedtls_gcm_context *a,int mode,size_t n,const unsigned char *iv,size_t il,const unsigned char *ad,size_t al,const unsigned char *p,unsigned char *out,size_t tl,unsigned char *tag) {
    (void)mode; assert(il==12); test_nonce_used(a->key,iv);
    EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new(); int l=0,x=0;
    int ok=EVP_EncryptInit_ex(c,EVP_aes_128_gcm(),NULL,a->key,iv)>0;
    ok=ok && EVP_EncryptUpdate(c,NULL,&l,ad,(int)al)>0;
    if(n) ok=ok && EVP_EncryptUpdate(c,out,&l,p,(int)n)>0;
    ok=ok && EVP_EncryptFinal_ex(c,out+n,&x)>0 && EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,(int)tl,tag)>0;
    EVP_CIPHER_CTX_free(c); return ok?0:-1;
}
int mbedtls_gcm_auth_decrypt(mbedtls_gcm_context *a,size_t n,const unsigned char *iv,size_t il,const unsigned char *ad,size_t al,const unsigned char *tag,size_t tl,const unsigned char *in,unsigned char *out) {
    assert(il==12); EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new(); int l=0,x=0;
    int ok=EVP_DecryptInit_ex(c,EVP_aes_128_gcm(),NULL,a->key,iv)>0;
    ok=ok && EVP_DecryptUpdate(c,NULL,&l,ad,(int)al)>0;
    if(n) ok=ok && EVP_DecryptUpdate(c,out,&l,in,(int)n)>0;
    ok=ok && EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,(int)tl,(void *)tag)>0 && EVP_DecryptFinal_ex(c,out+n,&x)>0;
    EVP_CIPHER_CTX_free(c); return ok?0:-1;
}

#include "mbedtls/ccm.h"
void mbedtls_ccm_init(mbedtls_ccm_context *c) { memset(c,0,sizeof(*c)); }
void mbedtls_ccm_free(mbedtls_ccm_context *c) { memset(c,0,sizeof(*c)); }
int mbedtls_ccm_setkey(mbedtls_ccm_context *c,int id,const unsigned char *k,unsigned bits) { (void)id;if(bits!=128)return -1;memcpy(c->key,k,16);return 0; }
int mbedtls_ccm_encrypt_and_tag(mbedtls_ccm_context *a,size_t n,const unsigned char *iv,size_t il,const unsigned char *ad,size_t al,const unsigned char *p,unsigned char *out,unsigned char *tag,size_t tl) {
    test_nonce_used(a->key,iv);EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new();int l=0;static const uint8_t empty=0;
    int ok=EVP_EncryptInit_ex(c,EVP_aes_128_ccm(),NULL,NULL,NULL)>0 &&
        EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_CCM_SET_IVLEN,(int)il,NULL)>0 &&
        EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_CCM_SET_TAG,(int)tl,NULL)>0 &&
        EVP_EncryptInit_ex(c,NULL,NULL,a->key,iv)>0 &&
        EVP_EncryptUpdate(c,NULL,&l,NULL,(int)n)>0 && EVP_EncryptUpdate(c,NULL,&l,ad,(int)al)>0 &&
        EVP_EncryptUpdate(c,out,&l,p?p:&empty,(int)n)>0 && EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_CCM_GET_TAG,(int)tl,tag)>0;
    EVP_CIPHER_CTX_free(c);return ok?0:-1;
}
int mbedtls_ccm_auth_decrypt(mbedtls_ccm_context *a,size_t n,const unsigned char *iv,size_t il,const unsigned char *ad,size_t al,const unsigned char *in,unsigned char *out,const unsigned char *tag,size_t tl) {
    EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new();int l=0;static const uint8_t empty=0;
    int ok=EVP_DecryptInit_ex(c,EVP_aes_128_ccm(),NULL,NULL,NULL)>0 &&
        EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_CCM_SET_IVLEN,(int)il,NULL)>0 &&
        EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_CCM_SET_TAG,(int)tl,(void *)tag)>0 &&
        EVP_DecryptInit_ex(c,NULL,NULL,a->key,iv)>0 &&
        EVP_DecryptUpdate(c,NULL,&l,NULL,(int)n)>0 && EVP_DecryptUpdate(c,NULL,&l,ad,(int)al)>0 &&
        EVP_DecryptUpdate(c,out,&l,in?in:&empty,(int)n)>0;
    EVP_CIPHER_CTX_free(c);return ok?0:-1;
}
