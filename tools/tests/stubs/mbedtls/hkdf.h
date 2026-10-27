#pragma once
#include "md.h"
int mbedtls_hkdf(const mbedtls_md_info_t *,const unsigned char *,size_t,const unsigned char *,size_t,const unsigned char *,size_t,unsigned char *,size_t);
int mbedtls_hkdf_expand(const mbedtls_md_info_t *,const unsigned char *,size_t,const unsigned char *,size_t,unsigned char *,size_t);
