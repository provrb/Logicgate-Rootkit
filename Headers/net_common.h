#ifndef _NET_COMMON_
#define _NET_COMMON_

#include "framework.h"
#include "net_types.h"
#include "aes.hpp"

#include <string>

#pragma pack(2)
typedef struct {
    ClientRequest cr;
    ServerRequest sr;
    UDPResponse   udp;
    std::string   aesKey;
} NET_BLOB;

typedef std::vector<unsigned char> BYTESTRING;

namespace NetCommon
{

    inline BYTESTRING SerializeString(std::string s) {
        BYTESTRING bs;
        for ( BYTE c : s )
            bs.push_back(c);
        return bs;
    }

    BYTESTRING ExtractIV(std::string key);

    BYTESTRING AESEncryptBlob(NET_BLOB data);

    inline void DecryptByteString(BYTESTRING& string, std::string key) {
        BYTESTRING byteKey = NetCommon::SerializeString(key);
        Cipher::Aes<256> aes(byteKey.data());
        aes.decrypt_block(string.data());
    }

    inline BOOL IsBlobValid(NET_BLOB b) {
        return !b.aesKey.empty() && b.cr.valid || b.sr.valid || b.udp.isValid;
    }

    inline NET_BLOB RequestToBlob(ServerRequest request, std::string aesKey) {
        return NET_BLOB{ {0}, request, {0}, aesKey };
    }

    inline NET_BLOB RequestToBlob(ClientRequest request, std::string aesKey) {
        return NET_BLOB{ request, {0}, {0}, aesKey };
    }

}

#endif 