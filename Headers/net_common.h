#ifndef _NET_COMMON_
#define _NET_COMMON_

#include "framework.h"
#include "net_types.h"

#include <string>

typedef struct {
    ClientRequest cr;
    ServerRequest sr;
    std::string   aesKey;
} NET_BLOB;

namespace NetCommon
{

    std::vector<unsigned char> ExtractIV(std::string key);

    // Works to decrypt blobs
    // Meant to be used on both client and server
    std::vector<unsigned char> AESEncryptBlob(NET_BLOB data);
}

#endif 