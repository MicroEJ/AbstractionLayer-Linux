/*
 * C
 *
 * Copyright 2015-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */
#include <LLNET_SSL_util.h>
#include <LLNET_SSL_CONSTANTS.h>
#include <LLNET_SSL_ERRORS.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#ifdef LLNET_SSL_DEBUG
#include <openssl/err.h>
#endif

/**
 * @file
 * @brief LLNET_SSL implementation over OpenSSL utility functions.
 * @author MicroEJ Developer Team
 * @version 1.0.1
 * @date 27 November 2020
 */

#ifdef __cplusplus
	extern "C" {
#endif

/**
 * Creates an X509 certificate from the given certificate data pointed by cert.
 * Stores in format the format of the certificate (CERT_PEM_FORMAT or CERT_DER_FORMAT).
 *
 * format may be null.
 *
 * Returns the created X509 or null on error.
 */
X509* LLNET_SSL_X509_CERT_create(uint8_t *cert, int32_t off, int32_t len, int32_t* format)
{
	BIO* mem;
	X509* x509;
	if(format != NULL)
	{
		*format = J_CERT_PARSE_ERROR; // Error by default
	}

	// Build an InputStream that reads data from the given buffer.
	mem = BIO_new_mem_buf((uint8_t*) (cert+off), len);

	//check the bio memory buffer
	if(mem == NULL){
		return NULL;
	}
	//try to parse as PEM certificate
	x509 = PEM_read_bio_X509(mem, NULL, NULL, NULL);
	if(x509 != NULL)
	{	//encoded PEM certificate
		if(format != NULL)
		{
			*format =  CERT_PEM_FORMAT;
		}
	}
	else
	{	//try to parse as DER certificate
		BIO_reset(mem);
		x509 = d2i_X509_bio(mem, NULL);
		if(x509 != NULL)
		{
			//encoded DER certificate
			if(format != NULL)
			{
				*format = CERT_DER_FORMAT;
			}
		}
	}

	BIO_vfree(mem);

	return x509;
}

#ifdef LLNET_SSL_DEBUG

void LLNET_SSL_print_errors() {
	char buf[80];
	int32_t err;

	// Print out the SSL error queue
	while (0 != (err = ERR_get_error())) {
		ERR_error_string_n(err, buf, sizeof(buf));
		printf("OpenSSL error reason = %s\n", buf);
	}
}

#endif

#ifdef __cplusplus
	}
#endif
