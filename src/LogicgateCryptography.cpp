#include "LogicateCryptography.h"
#include "Serialization.h"

#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string>


/**
 * Convert an OpenSSL RSA* type to an std::string in PEM format.
 * 
 * \param key - the key to convert to a string in PEM format
 * \return 'key' as an std::string in PEM format.
 */
std::string LGCrypto::RSAKeyToString(RSA* key, BOOL isPrivateKey) {
    BIO* bio = BIO_new(BIO_s_mem());

    if ( isPrivateKey )
        PEM_write_bio_RSAPrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
    else
        PEM_write_bio_RSAPublicKey(bio, key);

    BUF_MEM* buffer = NULL;
    BIO_get_mem_ptr(bio, &buffer);

    std::string pem(buffer->data, buffer->length);

    BIO_free(bio);
    return pem;
}

/**
 * Convert a rsa key as a string to an OpenSSL RSA* object.
 * 
 * \param s - an rsa key as a string to convert to a RSA* object.
 * \return s as a RSA* object
 */
RSA* LGCrypto::RSAKeyFromString(std::string& s) {
    BOOL isPublicKey = ( s.find("-----BEGIN RSA PUBLIC KEY-----") != std::string::npos );

    BIO* buffer = BIO_new_mem_buf(( void* ) s.data(), s.length());
    RSA* key = NULL;

    if ( isPublicKey )
        PEM_read_bio_RSAPublicKey(buffer, &key, NULL, NULL);
    else
        PEM_read_bio_RSAPrivateKey(buffer, &key, NULL, NULL);

    BIO_free(buffer);

    return key;
}

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
    keys.priv = rsaPrivateKey;
    keys.pub = rsaPublicKey;

    BN_free(bigNum);
    RSA_free(generatedKeys);

    return keys;
}

/**
 * Encrypt a bytestring using an RSA key.
 * 
 * \param data - serialized data to encrypt
 * \param key - RSA to encrypt data with
 * \param privateKey - whether or not 'key' is an rsa private
 * \return RSA encrypted 'data' on success or empty vector BYTESTRING on error
 */
BYTESTRING LGCrypto::RSAEncrypt(BYTESTRING data, RSA* key, BOOL privateKey) {
    BYTESTRING out(RSA_size(key));

    int result = privateKey ?
        RSA_private_encrypt(data.size(), data.data(), out.data(), key, RSA_PKCS1_PADDING)
        : RSA_public_encrypt(data.size(), data.data(), out.data(), key, RSA_PKCS1_PADDING);

    ( result == -1 ) ? out.resize(0) : out.resize(result);

    return out;
}

/**
 * Decrypt a bytestring using an RSA key.
 *
 * \param data - encrypted data to decrypt
 * \param key - RSA to decrypt data with
 * \param privateKey - whether or not 'key' is an rsa private
 * \return RSA decrypted 'data' on success or empty vector BYTESTRING on error
 */
BYTESTRING LGCrypto::RSADecrypt(BYTESTRING data, RSA* key, BOOL privateKey) {
    BYTESTRING out(RSA_size(key));

    int result = privateKey ?
        RSA_private_decrypt(data.size(), data.data(), out.data(), key, RSA_PKCS1_PADDING)
        : RSA_public_decrypt(data.size(), data.data(), out.data(), key, RSA_PKCS1_PADDING);

    ( result == -1 ) ? out.resize(0) : out.resize(result);

    out.resize(result);

    return out;
}

BYTESTRING LGCrypto::GenerateAESIV() {
    BYTESTRING iv(AES_BLOCK_SIZE);
    if ( !RAND_bytes(iv.data(), iv.size()) )
        iv = {};

    return iv;
}

BYTESTRING LGCrypto::Generate256AESKey() {
    BYTESTRING key(32); // aes 256
    if ( !RAND_bytes(key.data(), key.size()) )
        key = {};

    return key;
}

BYTESTRING LGCrypto::AESEncrypt(BYTESTRING data, BYTESTRING key, BYTESTRING iv) {
    size_t padded_len = ( ( data.size() + AES_BLOCK_SIZE - 1 ) / AES_BLOCK_SIZE ) * AES_BLOCK_SIZE;
    data.resize(padded_len, 0);

    BYTESTRING encrypted(padded_len);

    AES_KEY aes;
    AES_set_encrypt_key(key.data(), key.size() * 8, &aes);
    AES_cbc_encrypt(data.data(), encrypted.data(), data.size(), &aes, iv.data(), AES_ENCRYPT);

    return encrypted;
}

BYTESTRING LGCrypto::AESDecrypt(BYTESTRING data, BYTESTRING key, BYTESTRING iv) {
    BYTESTRING out(data.size());

    AES_KEY aes;
    AES_set_decrypt_key(key.data(), key.size() * 8, &aes);
    AES_cbc_encrypt(data.data(), out.data(), data.size(), &aes, const_cast< unsigned char* >( iv.data() ), AES_DECRYPT);

    unsigned char padding_size = out.back();
    out.resize(out.size() - padding_size);

    return out;
}
