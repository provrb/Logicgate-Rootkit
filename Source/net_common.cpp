#include "../Headers/net_common.h"

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <vector>

std::vector<unsigned char> NetCommon::ExtractIV(std::string key) {
    std::vector<unsigned char> iv(16);
    for ( int i = 0; i < 15; i++ )
        iv.at(i) = key.at(i);

    return iv;
}

std::vector<unsigned char> NetCommon::AESEncryptBlob(NET_BLOB data) {
    if ( !data.cr.valid && !data.sr.valid )
        return {}; // not encrypting anything, bad blob

    if ( data.aesKey.empty() )
        return {};

    std::vector<unsigned char> req;
    if ( data.cr.valid ) {
        req.resize(sizeof(ClientRequest));
        memcpy(req.data(), &data.cr, sizeof(ClientRequest));
    }
    else if ( data.sr.valid ) {
        req.resize(sizeof(ServerRequest));
        memcpy(req.data(), &data.sr, sizeof(ServerRequest));
    }
    else
        return {};

    std::vector<unsigned char> iv = NetCommon::ExtractIV(data.aesKey);

    std::vector<unsigned char> buff(req.size());
    memcpy(buff.data(), req.data(), req.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if ( !ctx )
        return {};

    BOOL init = EVP_EncryptInit(ctx, EVP_aes_256_cbc(), reinterpret_cast< const unsigned char* >( data.aesKey.c_str() ), iv.data());
    if ( init != TRUE )
        return {};

    std::vector<unsigned char> cipherBuff(req.size() + AES_BLOCK_SIZE); // Allocate additional space for padding
    int len;

    BOOL update = EVP_EncryptUpdate(ctx, cipherBuff.data(), &len, buff.data(), static_cast< int >( buff.size() ));
    if ( update != TRUE )
        return {};

    int finalLen;
    BOOL evpFinal = EVP_EncryptFinal(ctx, cipherBuff.data() + len, &finalLen);
    if ( evpFinal != TRUE )
        return {};

    cipherBuff.resize(len + finalLen); // Adjust size to include padding

    EVP_CIPHER_CTX_free(ctx);

    return cipherBuff;
};
