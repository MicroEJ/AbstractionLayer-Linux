/*
 * C
 *
 * Copyright 2017-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */
#include <LLNET_SSL_verifyCallback.h>
#include <LLNET_SSL_util.h>
#include <openssl/ssl.h>
#include "stdio.h"

/**
 * @file
 * @brief LLNET_SSL_VERIFY implementation over OpenSSL.
 * @author MicroEJ Developer Team
 * @version 2.0.0
 * @date 25 July 2024
 */

#ifdef __cplusplus
	extern "C" {
#endif


int32_t LLNET_SSL_VERIFY_verifyCallback(int32_t ok, X509_STORE_CTX *ctx)
{
	LLNET_SSL_DEBUG_TRACE("ctx=0x%x\n", ctx);
	X509 *cert;
	X509_NAME *cert_name;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	X509_OBJECT obj;
#else
	X509_OBJECT *obj = X509_OBJECT_new();
#endif
	int32_t nb_of_certs;
	int32_t idx = 0;
	int32_t first_chain_cert_trusted_index = -1;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	int32_t error_depth =  ctx->error_depth;
#else
	int32_t error_depth = X509_STORE_CTX_get_error_depth(ctx);
#endif
	int32_t ret = ok;

	if (ret == 1) {
		//no error
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
		X509_OBJECT_free(obj);
#endif
		LLNET_SSL_DEBUG_TRACE("Preverify OK\n");
	} else {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
		nb_of_certs = sk_X509_num(ctx->chain);
#else
		nb_of_certs = sk_X509_num(X509_STORE_CTX_get_chain(ctx));
#endif
		//loop through the certificates in the chain and get the index of the first trusted one
		//start peer's first to up
		LLNET_SSL_DEBUG_TRACE("Chain contains %d certificate(s)\n", nb_of_certs);
		while(idx < nb_of_certs){
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
			cert=sk_X509_value(ctx->chain,index);
#else
			cert=sk_X509_value(X509_STORE_CTX_get_chain(ctx), idx);
#endif
			cert_name=X509_get_subject_name(cert);
			LLNET_SSL_DEBUG_TRACE("Certificate index %d subject: %s\n", idx, X509_NAME_oneline(cert_name, NULL, 0));
			//check if the current certificate in the chain is trusted
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
			if (X509_STORE_get_by_subject(ctx,X509_LU_X509,cert_name,&obj) == (int) X509_LU_X509) {
				//compare the two certificates (the chain certificate and the one got from the trust store)
				if (X509_cmp(cert, obj.data.x509) == 0) {
					//the certificates are same => trusted certificate!
					first_chain_cert_trusted_index = idx;
					break;
				}
			}
#else
			if (X509_STORE_get_by_subject(ctx,X509_LU_X509,cert_name,obj) == (int) X509_LU_X509) {
				//compare the two certificates (the chain certificate and the one got from the trust store)
				if (X509_cmp(cert, X509_OBJECT_get0_X509(obj)) == 0) {
					//the certificates are same => trusted certificate!
					first_chain_cert_trusted_index = idx;
					break;
				} else {
					LLNET_SSL_DEBUG_TRACE("Certificates do not match\n");
				}
			} else {
				LLNET_SSL_DEBUG_TRACE("Could not get certificate with subject\n");
			}
#endif
			idx++;
		}
		if (first_chain_cert_trusted_index == -1) {
			//no trusted certificate found in the chain
			LLNET_SSL_DEBUG_TRACE("No trusted certificate found in chain\n");
			ret = 0; //error
		} else if (first_chain_cert_trusted_index > error_depth) {
			//The certificate which causes the error is before the first one trusted in the chain.
			//All verification on a certificate which is before the first one trusted must be ok, otherwise we complain.
			LLNET_SSL_DEBUG_TRACE("Certificate not trusted in the chain\n");
			ret = 0; //error

		} else {
			//else: the certificate which caused the error is (or is after) the first trusted one in the chain
			//skip the error.
			ret = 1;
		}
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
		X509_OBJECT_free(obj);
#endif
	}
	return ret;
}


#ifdef __cplusplus
	}
#endif
