#include <openssl/pem.h>
#include <openssl/err.h>

#include "LogicateCryptography.h"
#include "NetworkCommon.h"

#include <openssl/pem.h>
#include <openssl/err.h>

/**
 * Generate a private and public RSA key using OpenSSL.
 * RSA key generation logic is not mine, though I have made modifications. 
 * 
 * \return An RSAKeys struct with all fields filled out.
 */
RSAKeys LGCrypto::GenerateRSAPair(int bits) {
    BIGNUM* bigNum = BN_new();
    BN_set_word(bigNum, RSA_F4);

    RSA* generatedKeys = RSA_new();
    RSA_generate_key_ex(generatedKeys, bits, bigNum, NULL);

    BIO* PEMBIOPublic  = BIO_new(BIO_s_mem()); 
    BIO* PEMBIOPrivate = BIO_new(BIO_s_mem());
    
    PEM_write_bio_RSAPublicKey(PEMBIOPublic, generatedKeys);
    PEM_write_bio_RSAPrivateKey(PEMBIOPrivate, generatedKeys, NULL, NULL, 0, NULL, NULL);

    int privateKeyLen   = BIO_pending(PEMBIOPrivate);
    int publicKeyLen    = BIO_pending(PEMBIOPublic);
    char* strPrivateKey = ( char* ) malloc(privateKeyLen + 1);
    char* strPublicKey  = ( char* ) malloc(publicKeyLen + 1);

    BIO_read(PEMBIOPrivate, strPrivateKey, privateKeyLen);
    BIO_read(PEMBIOPublic, strPublicKey, publicKeyLen);

    strPrivateKey[privateKeyLen] = '\0';
    strPublicKey[publicKeyLen] = '\0';

    BIO* bioPublicKey  = BIO_new_mem_buf(( void* ) strPublicKey, publicKeyLen);
    BIO* bioPrivateKey = BIO_new_mem_buf(( void* ) strPrivateKey, privateKeyLen);

    RSA* rsaPublicKey = NULL; 
    PEM_read_bio_RSAPublicKey(bioPublicKey, &rsaPublicKey, NULL, NULL);;
  
    RSA* rsaPrivateKey = NULL;
    PEM_read_bio_RSAPrivateKey(bioPrivateKey, &rsaPrivateKey, NULL, NULL);

    RSAKeys keys;
    keys.bioPublicKey = bioPublicKey;
    keys.bioPrivateKey = bioPrivateKey;
    keys.strPublicKey = std::string(strPublicKey);
    keys.strPrivateKey = std::string(strPrivateKey);
    keys.rsaPrivateKey = rsaPrivateKey;
    keys.rsaPublicKey = rsaPublicKey;

    BN_free(bigNum);
    RSA_free(generatedKeys);

    return keys;
}

//BYTESTRING LGCrypto::RSAEncrypt(BYTESTRING data, BIO* bio, BOOL privateKey) {
//    BIO* copied = NetCommon::BIODeepCopy(bio);
//    EVP_PKEY* key = privateKey ? PEM_read_bio_PrivateKey(copied, nullptr, nullptr, nullptr) : PEM_read_bio_PUBKEY(copied, nullptr, nullptr, nullptr);
//    if ( !key ) {
//        CLIENT_DBG("Encryption key error.");
//        return {};
//    }
//
//    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
//    if ( !ctx ) {
//        EVP_PKEY_free(key);
//        CLIENT_DBG("Context error.");
//        return {};
//    }
//
//    if ( EVP_PKEY_encrypt_init(ctx) <= 0 ) {
//        EVP_PKEY_free(key);
//        EVP_PKEY_CTX_free(ctx);
//        CLIENT_DBG("Encrypt init/padding error.");
//        return {};
//    }
//
//    if ( EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ) {
//        EVP_PKEY_free(key);
//        EVP_PKEY_CTX_free(ctx);
//        CLIENT_DBG("Padding error.");
//        return {};
//    }
//
//    size_t outLen;
//    if ( EVP_PKEY_encrypt(ctx, nullptr, &outLen, data.data(), data.size()) <= 0 ) {
//        EVP_PKEY_free(key);
//        EVP_PKEY_CTX_free(ctx);
//        CLIENT_DBG("Encrypt length error.");
//        return {};
//    }
//
//    BYTESTRING out(outLen);
//    if ( EVP_PKEY_encrypt(ctx, out.data(), &outLen, data.data(), data.size()) <= 0 ) {
//        EVP_PKEY_free(key);
//        EVP_PKEY_CTX_free(ctx);
//        CLIENT_DBG("Encryption error.");
//        return {};
//    }
//
//    out.resize(outLen);
//    EVP_PKEY_free(key);
//    EVP_PKEY_CTX_free(ctx);
//
//    CLIENT_DBG("Encryption successful.");
//    return out;
//}

BYTESTRING LGCrypto::RSAEncrypt(BYTESTRING data, RSA* key, BOOL privateKey) {
    BYTESTRING out(RSA_size(key));

    int result = privateKey ?
        RSA_private_encrypt(data.size(), data.data(), out.data(), key, RSA_PKCS1_PADDING)
        : RSA_public_encrypt(data.size(), data.data(), out.data(), key, RSA_PKCS1_PADDING);

    out.resize(result);

    return out;
}

BYTESTRING LGCrypto::RSADecrypt(BYTESTRING data, RSA* key, BOOL privateKey) {
    BYTESTRING out(RSA_size(key));

    int result = privateKey ?
        RSA_private_decrypt(data.size(), data.data(), out.data(), key, RSA_PKCS1_PADDING)
        : RSA_public_decrypt(data.size(), data.data(), out.data(), key, RSA_PKCS1_PADDING);

    out.resize(result);

    return out;
}

//BYTESTRING LGCrypto::RSADecrypt(BYTESTRING data, BIO* bio, BOOL privateKey) {
//    BIO* copied = NetCommon::BIODeepCopy(bio);
//    EVP_PKEY* key = privateKey ? PEM_read_bio_PrivateKey(copied, nullptr, nullptr, nullptr) : PEM_read_bio_PUBKEY(copied, nullptr, nullptr, nullptr);
//    if ( !key ) {
//        CLIENT_DBG("Decryption key error.");
//        return {};
//    }
//
//    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
//    if ( !ctx ) {
//        EVP_PKEY_free(key);
//        CLIENT_DBG("Context error.");
//        return {};
//    }
//
//    if ( EVP_PKEY_decrypt_init(ctx) <= 0 ) {
//        EVP_PKEY_free(key);
//        EVP_PKEY_CTX_free(ctx);
//        CLIENT_DBG("Decrypt init/padding error.");
//        return {};
//    }
//
//    if ( EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ) {
//        EVP_PKEY_free(key);
//        EVP_PKEY_CTX_free(ctx);
//        CLIENT_DBG("Padding error.");
//        return {};
//    }
//
//    size_t outLen;
//    if ( EVP_PKEY_decrypt(ctx, nullptr, &outLen, data.data(), data.size()) <= 0 ) {
//        EVP_PKEY_free(key);
//        EVP_PKEY_CTX_free(ctx);
//        CLIENT_DBG("Decrypt length error.");
//        return {};
//    }
//
//    BYTESTRING out(outLen);
//    if ( EVP_PKEY_decrypt(ctx, out.data(), &outLen, data.data(), data.size()) <= 0 ) {
//        EVP_PKEY_free(key);
//        EVP_PKEY_CTX_free(ctx);
//        CLIENT_DBG("Decryption error.");
//        return {};
//    }
//
//    out.resize(outLen);
//    EVP_PKEY_free(key);
//    EVP_PKEY_CTX_free(ctx);
//
//    CLIENT_DBG("Decryption successful.");
//    return out;
//}
