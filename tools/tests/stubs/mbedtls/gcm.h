#pragma once
#include <stddef.h>
#include <stdint.h>
#define MBEDTLS_CIPHER_ID_AES 1
#define MBEDTLS_GCM_ENCRYPT 1
/* OpenSSL-backed host adapter: no internal owning pointers, permitting the
 * simulator to save/restore complete node state between scheduled events. */
typedef struct { uint8_t key[16]; } mbedtls_gcm_context;
void mbedtls_gcm_init(mbedtls_gcm_context *);
void mbedtls_gcm_free(mbedtls_gcm_context *);
int mbedtls_gcm_setkey(mbedtls_gcm_context *,int,const unsigned char *,unsigned);
int mbedtls_gcm_crypt_and_tag(mbedtls_gcm_context *,int,size_t,const unsigned char *,size_t,const unsigned char *,size_t,const unsigned char *,unsigned char *,size_t,unsigned char *);
int mbedtls_gcm_auth_decrypt(mbedtls_gcm_context *,size_t,const unsigned char *,size_t,const unsigned char *,size_t,const unsigned char *,size_t,const unsigned char *,unsigned char *);
