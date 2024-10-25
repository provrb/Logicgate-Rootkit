#include <openssl/pem.h>

#include "LogicateCryptography.h"
#include "NetworkCommon.h"

BYTESTRING LGCrypto::RSADecrypt(BYTESTRING data, BIO* bio, BOOL privateKey) {
    BIO* copied = NetCommon::BIODeepCopy(bio);

    EVP_PKEY* priv = privateKey ? PEM_read_bio_PrivateKey(copied, nullptr, nullptr, nullptr) : PEM_read_bio_PUBKEY(copied, nullptr, nullptr, nullptr);
    if ( !priv ) {
        return {};
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
    if ( !ctx ) {
        EVP_PKEY_free(priv);
        return {};
    }

    if ( EVP_PKEY_decrypt_init(ctx) <= 0 ) {
        EVP_PKEY_free(priv);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    size_t     outLen;

    if ( EVP_PKEY_decrypt(ctx, NULL, &outLen, data.data(), data.size()) <= 0 ) {
        EVP_PKEY_free(priv);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    BYTESTRING out(outLen);

    if ( EVP_PKEY_decrypt(ctx, out.data(), &outLen, data.data(), data.size()) <= 0 ) {
        EVP_PKEY_free(priv);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    EVP_PKEY_free(priv);
    EVP_PKEY_CTX_free(ctx);

    out.resize(outLen);

    return out;
}

BYTESTRING LGCrypto::RSAEncrypt(BYTESTRING data, BIO* bio, BOOL privateKey) {
    BIO* copied = NetCommon::BIODeepCopy(bio);
    EVP_PKEY* pub = privateKey ? PEM_read_bio_PrivateKey(copied, nullptr, nullptr, nullptr) : PEM_read_bio_PUBKEY(copied, nullptr, nullptr, nullptr);
    if ( !pub )
        return {};

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub, nullptr);
    if ( !ctx ) {
        EVP_PKEY_free(pub);
        return {};
    }

    if ( EVP_PKEY_encrypt_init(ctx) <= 0 ) {
        EVP_PKEY_free(pub);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    size_t     outLen;
    if ( EVP_PKEY_encrypt(ctx, NULL, &outLen, data.data(), data.size()) <= 0 ) {
        EVP_PKEY_free(pub);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    BYTESTRING out(outLen);

    if ( EVP_PKEY_encrypt(ctx, out.data(), &outLen, data.data(), data.size()) <= 0 ) {
        EVP_PKEY_free(pub);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    out.resize(outLen);

    EVP_PKEY_free(pub);
    EVP_PKEY_CTX_free(ctx);

    return out;
}

BYTESTRING LGCrypto::RSADecrypt(BYTESTRING data, BOOL isPrivateKey) {
    BIO* key = isPrivateKey ? Serialization::GetBIOFromString(this->m_CryptoSecrets.strPrivateKey) : Serialization::GetBIOFromString(this->m_CryptoSecrets.strPublicKey);
    return this->RSADecrypt(data, key, isPrivateKey);
}

BYTESTRING LGCrypto::RSAEncrypt(BYTESTRING data, BOOL isPrivateKey) {
    BIO* key = isPrivateKey ? Serialization::GetBIOFromString(this->m_CryptoSecrets.strPrivateKey) : Serialization::GetBIOFromString(this->m_CryptoSecrets.strPublicKey);
    return this->RSAEncrypt(data, key, isPrivateKey);
}
