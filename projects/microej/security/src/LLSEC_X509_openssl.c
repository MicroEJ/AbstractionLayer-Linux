/*
* C
*
* Copyright 2017-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
*/

#include "LLSEC_openssl.h"
#include "LLSEC_X509_CERT_impl.h"
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <stdint.h>
#include <string.h>
#include <openssl/pem.h>

#ifdef __cplusplus
	extern "C" {
#endif

#define MICROEJ_LLSECU_X509_SUCCESS 1
#define MICROEJ_LLSECU_X509_ERROR   0


#define MICROEJ_LLSECU_X509_DER_FORMAT      (int)(1)
#define MICROEJ_LLSECU_X509_PEM_FORMAT      (int)(0)
#define MICROEJ_LLSECU_X509_UNKNOWN_FORMAT  (int)(-1)

// #define LLSEC_X509_DEBUG_TRACE

#ifdef LLSEC_X509_DEBUG_TRACE
#define LLSEC_X509_DEBUG_PRINTF(...) printf(__VA_ARGS__)
#else
#define LLSEC_X509_DEBUG_PRINTF(...) ((void)0)
#endif


static X509* get_x509_certificate(int8_t* cert_data, int32_t len, int* cert_format)
{
    LLSEC_X509_DEBUG_PRINTF("%s \n", __func__);
    X509 *x509;
    x509 = d2i_X509(NULL, (const unsigned char**)&cert_data, len);
    if (x509 != NULL)
    {
        if(cert_format != NULL)
            *cert_format = MICROEJ_LLSECU_X509_DER_FORMAT;
        return x509;
    }
    else
    {
        BIO *bp = BIO_new_mem_buf(cert_data, len);
        // Can we generate a x509 certificate with pem parsing
        x509 = PEM_read_bio_X509(bp, NULL, NULL, NULL);
        if(cert_format != NULL)
        {
            if(x509 != NULL)
            {
                *cert_format = MICROEJ_LLSECU_X509_PEM_FORMAT;
            }
            else
            {
                *cert_format = MICROEJ_LLSECU_X509_UNKNOWN_FORMAT;
            }
        }
        // x509 is NULL if PEM_read_bio failed
        BIO_free_all(bp);
        // Will return a NULL pointer if failed
        // Return a valid certificate on success
        return x509;
    }
}

/**
* Parses the given certificate to validate it and returns its encoded format type.
* @param cert the certificate buffer
* @param off the offset in the buffer at which the certificate content started
* @param len the certificate content length
* @return the certificate encoded format type (0 if PEM format or 1 if DER format); -1 if the certificate is not valid or an error occurs.
*
** Warning: cert must not be used outside of the VM task or saved
*/

int32_t LLSEC_X509_CERT_IMPL_parse(int8_t* cert, int32_t off, int32_t len)
{
    LLSEC_X509_DEBUG_PRINTF("%s \n", __func__);
    int cert_format = MICROEJ_LLSECU_X509_UNKNOWN_FORMAT;
    // cert_data format
    int8_t* cert_data = cert + off;
    X509* x509 = get_x509_certificate(cert_data, len, &cert_format);
    if(x509 != NULL)
    {
        X509_free(x509);
    }
    return cert_format;
}

/**
 *
 * @param cert
 * @param certLen
 * @param keyData
 * @param keyDataLength inparameter. Contains the length of keyData.
 * @return the number of bytes copied into keyData
 *
 ** Warning: cert_data must not be used outside of the VM task or saved

 ** Warning: key must not be used outside of the VM task or saved
 *
 * @throws NativeException on error.
 */

int32_t LLSEC_X509_CERT_IMPL_get_key(int8_t* cert_data, int32_t cert_data_length, uint8_t* key, int32_t key_length)
{
    LLSEC_X509_DEBUG_PRINTF("%s \n", __func__);
    LLSEC_pub_key* pub_key = (LLSEC_pub_key*)key;

    if (key_length < sizeof(*pub_key)) {
        SNI_throwNativeException(-1, "Invalid buffer length");
        return 0;
    }
    X509 *x509 = get_x509_certificate(cert_data, cert_data_length, NULL);
    if (x509 == NULL)
    {
        SNI_throwNativeException(-1, "Bad x509 certificate");
        return -1;
    }

    // Careful about memory leak here
    pub_key->key = X509_get_pubkey(x509);
    if (pub_key->key == NULL)
    {
        X509_free(x509);
        SNI_throwNativeException(-1, "Invalid public key from x509 certificate");
        return -1;
    }

    int32_t size = sizeof(*pub_key);
    X509_free(x509);
    LLSEC_X509_DEBUG_PRINTF("%s size=%i \n", __func__, size);
    return size;
}

int32_t LLSEC_X509_CERT_IMPL_verify(int8_t* cert_data, int32_t cert_data_length, uint8_t* key, int32_t key_length)
{
    LLSEC_X509_DEBUG_PRINTF("%s \n", __func__);
    LLSEC_pub_key* pub_key = (LLSEC_pub_key*)key;

    X509 *x509 = get_x509_certificate(cert_data, cert_data_length, NULL);
    if (x509 == NULL)
    {
        SNI_throwNativeException(-1, "Bad x509 certificate");
        return MICROEJ_LLSECU_X509_ERROR;
    }

    int rc = X509_verify(x509, pub_key->key);
    if (rc != MICROEJ_LLSECU_X509_SUCCESS)
    {
        // Error
        X509_free(x509);
        LLSEC_X509_DEBUG_PRINTF("LLSEC_X509 > verify error");
        SNI_throwNativeException(-1, "Error x509 verify failed");
        return MICROEJ_LLSECU_X509_ERROR;
    }

    X509_free(x509);
    return MICROEJ_LLSECU_X509_SUCCESS;
}

int32_t LLSEC_X509_CERT_IMPL_get_x500_principal_data(int8_t* cert_data, int32_t cert_data_length, uint8_t* principal_data, int32_t principal_data_length, uint8_t get_issuer)
{
    LLSEC_X509_DEBUG_PRINTF("%s \n", __func__);
    X509 *x509 = get_x509_certificate(cert_data, cert_data_length, NULL);
    if (x509 == NULL)
    {
        SNI_throwNativeException(-1, "Bad x509 certificate");
        return MICROEJ_LLSECU_X509_ERROR;
    }
    X509_NAME * name = NULL;
    if (get_issuer) {
    	name = X509_get_issuer_name(x509);
    } else {
    	name = X509_get_subject_name(x509);
    }

    if(name == NULL){
    	SNI_throwNativeException(-1, "Null name.");
		return MICROEJ_LLSECU_X509_ERROR;
    }
	char * data = NULL;
	size_t length = 0;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#ifndef OPENSSL_NO_BUFFER
    data = (char*)name->bytes->data;
    length = name->bytes->length;
#else
    data = name->bytes;
    length = strlen(data);
#endif //OPENSSL_NO_BUFFER
#else
	if(X509_NAME_get0_der(name, (const unsigned char**)&data, &length) != 1) {
		SNI_throwNativeException(-1, "Null or bad encoding name.");
		return MICROEJ_LLSECU_X509_ERROR;
	}
#endif //OPENSSL_VERSION_NUMBER < 0x10100000L

	if (length > principal_data_length){
    	SNI_throwNativeException(-1, "The principal data buffer is too small");
    	return MICROEJ_LLSECU_X509_ERROR;
    }

	memcpy(principal_data, data, length);
	return length;
}

/**
 * @brief Gets the size of the buffer that must be allocated to store the public key.
 * This buffer will be passed as <code>key</code> argument to
 * <code>LLSEC_X509_CERT_IMPL_get_key()</code>.
 *
 * @return The public key buffer size in bytes.
 */
int32_t LLSEC_X509_CERT_IMPL_get_key_size(void) {
	return sizeof(LLSEC_pub_key);
}

#ifdef __cplusplus
	}
#endif
