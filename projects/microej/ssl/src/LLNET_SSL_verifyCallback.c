/*
 * C
 *
 * Copyright 2017-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */
#include <LLNET_SSL_verifyCallback.h>
#include <openssl/ssl.h>
#include "stdio.h"

/**
 * @file
 * @brief LLNET_SSL_VERIFY implementation over OpenSSL.
 * @author MicroEJ Developer Team
 * @version 1.0.1
 * @date 27 November 2020
 */

#ifdef __cplusplus
	extern "C" {
#endif


int32_t LLNET_SSL_VERIFY_verifyCallback(int32_t ok, X509_STORE_CTX *ctx)
{
	X509 *cert;
	X509_NAME *cert_name;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	X509_OBJECT obj;
#else
	X509_OBJECT *obj = X509_OBJECT_new();
#endif
	int32_t nb_of_certs;
	int32_t index = 0;
	int32_t first_chain_cert_trusted_index = -1;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	int32_t error_depth =  ctx->error_depth;
#else
	int32_t error_depth = X509_STORE_CTX_get_error_depth(ctx);
#endif

	if(ok){
		//no error
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
		X509_OBJECT_free(obj);
#endif
		return ok;
	}
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	nb_of_certs = sk_X509_num(ctx->chain);
#else
	nb_of_certs = sk_X509_num(X509_STORE_CTX_get_chain(ctx));
#endif
	//loop through the certificates in the chain and get the index of the first trusted one
	//start peer's first to up
	while(index < nb_of_certs){
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
		cert=sk_X509_value(ctx->chain,index);
#else
		cert=sk_X509_value(X509_STORE_CTX_get_chain(ctx),index);
#endif
		cert_name=X509_get_subject_name(cert);
		//check if the current certificate in the chain is trusted
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
		if(X509_STORE_get_by_subject(ctx,X509_LU_X509,cert_name,&obj) == X509_LU_X509){
			//compare the two certificates (the chain certificate and the one got from the trust store)
			if(X509_cmp(cert, obj.data.x509) == 0){
				//the certificates are same => trusted certificate!
				first_chain_cert_trusted_index = index;
				break;
			}
		}
#else
		if(X509_STORE_get_by_subject(ctx,X509_LU_X509,cert_name,obj) == X509_LU_X509){
			//compare the two certificates (the chain certificate and the one got from the trust store)
			if(X509_cmp(cert, X509_OBJECT_get0_X509(obj)) == 0){
				//the certificates are same => trusted certificate!
				first_chain_cert_trusted_index = index;
				break;
			}
		}

#endif
		index++;
	}
	if(first_chain_cert_trusted_index == -1){
		//no trusted certificate found in the chain
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
		X509_OBJECT_free(obj);
#endif
		return 0; //error
	}else if(first_chain_cert_trusted_index > error_depth){
		//The certificate which causes the error is before the first one trusted in the chain.
		//All verification on a certificate which is before the first one trusted must be ok, otherwise we complain.
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
		X509_OBJECT_free(obj);
#endif
		return 0; //error

	}
	//else: the certificate which caused the error is (or is after) the first trusted one in the chain
	//skip the error.
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
		X509_OBJECT_free(obj);
#endif
	return 1;
}


#ifdef __cplusplus
	}
#endif
