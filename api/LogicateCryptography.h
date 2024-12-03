#pragma once

#include "NetworkTypes.h"
#include "Serialization.h"

constexpr int IV_SIZE = 16;
constexpr int KEY_SIZE = 32;

class LGCrypto {
public:
    LGCrypto() = delete;

    template <typename _Struct>
    static BYTESTRING EncryptStruct(_Struct data, BYTESTRING aes, BYTESTRING iv) {
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
    static BYTESTRING EncryptStruct(_Struct data, RSA* key, BOOL isPrivateKey) {
        BYTESTRING serialized;

        if constexpr ( !std::is_same<BYTESTRING, _Struct>::value )
            // not the same so convert data to BYTESTRING
            serialized = Serialization::SerializeStruct(data);

        return RSAEncrypt(serialized, key, isPrivateKey);
    }

    template <typename _Struct>
    static _Struct DecryptToStruct(BYTESTRING input, BYTESTRING aes) {
        BYTESTRING extractedIV(input.end() - IV_SIZE, input.end());
        BYTESTRING extractedEncrypted(input.begin(), input.end() - IV_SIZE); // received without iv
        BYTESTRING decrypted = LGCrypto::AESDecrypt(extractedEncrypted, aes, extractedIV);

        if ( !LGCrypto::GoodDecrypt(decrypted) )
            return {};
        
        return Serialization::DeserializeToStruct<_Struct>(decrypted);
    }

    // AES
    static BYTESTRING    GenerateAESIV();
    static BYTESTRING    Generate256AESKey();
    static BYTESTRING    AESEncrypt(BYTESTRING data, BYTESTRING key, BYTESTRING iv);
    static BYTESTRING    AESDecrypt(BYTESTRING data, BYTESTRING key, BYTESTRING iv);

    // RSA
    static RSAKeys       GenerateRSAPair(int bits);
    static BYTESTRING    RSADecrypt(BYTESTRING data, RSA* key, BOOL isPrivateKey);
    static BYTESTRING    RSAEncrypt(BYTESTRING data, RSA* key, BOOL isPrivateKey);
    static RSA*          RSAKeyFromString(std::string& s);
    static std::string   RSAKeyToString(RSA* key, BOOL isPrivateKey);
    
    static inline BOOL   GoodDecrypt(BYTESTRING d) { return ( d.size() != 0 ); }
};
