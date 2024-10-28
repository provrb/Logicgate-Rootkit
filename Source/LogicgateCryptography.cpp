#include <openssl/pem.h>
#include <openssl/err.h>

#include "LogicateCryptography.h"
#include "NetworkCommon.h"

BYTESTRING LGCrypto::RSADecrypt(BYTESTRING data, BIO* bio, BOOL privateKey) {
    BIO* copied = NetCommon::BIODeepCopy(bio);

    EVP_PKEY* priv = privateKey ? PEM_read_bio_PrivateKey(copied, nullptr, nullptr, nullptr) : PEM_read_bio_PUBKEY(copied, nullptr, nullptr, nullptr);
    if ( !priv ) {
        std::cout << "Bad decryption key\n";
        CLIENT_DBG("bad key!!!");
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
        CLIENT_DBG("bad decrypt init");
        return {};
    }

    size_t     outLen;

    if ( EVP_PKEY_decrypt(ctx, NULL, &outLen, data.data(), data.size()) <= 0 ) {
        EVP_PKEY_free(priv);
        EVP_PKEY_CTX_free(ctx);
        CLIENT_DBG("bad decrypt");
        return {};
    }

    BYTESTRING out(outLen);

    std::string d = "outlen : " + std::to_string(outLen) + "\n";
    CLIENT_DBG(d.c_str());

    if ( EVP_PKEY_decrypt(ctx, out.data(), &outLen, data.data(), data.size()) <= 0 ) {
        EVP_PKEY_free(priv);
        EVP_PKEY_CTX_free(ctx);
        CLIENT_DBG("bad decrypt 2");
        unsigned long err = ERR_get_error();
        char errBuf[120];
        ERR_error_string_n(err, errBuf, sizeof(errBuf));

        std::string errorMessage = "Decryption failed: ";
        errorMessage += errBuf;
        errorMessage += "\n";
        OutputDebugStringA(errorMessage.c_str());
        return {};
    }

    EVP_PKEY_free(priv);
    EVP_PKEY_CTX_free(ctx);

    out.resize(outLen);
    CLIENT_DBG("good decrypt!");

    return out;
}

BYTESTRING LGCrypto::RSAEncrypt(BYTESTRING data, BIO* bio, BOOL privateKey) {
    BIO* copied = NetCommon::BIODeepCopy(bio);
    EVP_PKEY* pub = privateKey ? PEM_read_bio_PrivateKey(copied, nullptr, nullptr, nullptr) : PEM_read_bio_PUBKEY(copied, nullptr, nullptr, nullptr);
    if ( !pub ) {
        std::cout << "bad encryption key\n";
        CLIENT_DBG("- bad key...");
        return {};
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub, nullptr);
    if ( !ctx ) {
        EVP_PKEY_free(pub);
        std::cout << "bad ctx\n";
        CLIENT_DBG("- bad ctx")
        return {};
    }

    if ( EVP_PKEY_base_id(pub) != EVP_PKEY_RSA ) {
        std::cout << "not a key\n";
        EVP_PKEY_free(pub);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    if ( EVP_PKEY_encrypt_init(ctx) <= 0 ) {
        EVP_PKEY_free(pub);
        EVP_PKEY_CTX_free(ctx);
        std::cout << "bad encrypt init\n";
        return {};
    }

    size_t     outLen;
    if ( EVP_PKEY_encrypt(ctx, NULL, &outLen, data.data(), data.size()) <= 0 ) {
        EVP_PKEY_free(pub);
        EVP_PKEY_CTX_free(ctx);
        std::cout << "bad encrypt\n";
        return {};
    }

    std::cout << "len: " << outLen << std::endl;

    BYTESTRING out(outLen);

    if ( EVP_PKEY_encrypt(ctx, out.data(), &outLen, data.data(), data.size()) <= 0 ) {
        EVP_PKEY_free(pub);
        EVP_PKEY_CTX_free(ctx);
        std::cout << "bad encrypt 2\n";
        return {};
    }

    out.resize(outLen);

    EVP_PKEY_free(pub);
    EVP_PKEY_CTX_free(ctx);

    std::cout << "good!\n";
    CLIENT_DBG("- good encryption. done");

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
