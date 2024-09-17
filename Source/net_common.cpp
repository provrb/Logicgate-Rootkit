#include "../Headers/net_common.h"
#include "../Headers/aes.hpp"

#include <vector>

BYTESTRING NetCommon::ExtractIV(std::string key) {
    BYTESTRING iv(16);
    for ( int i = 0; i < 15; i++ )
        iv.at(i) = key.at(i);

    return iv;
}

BYTESTRING NetCommon::AESEncryptBlob(NET_BLOB data) {
    if ( IsBlobValid(data) == FALSE )
        return {};

    BYTESTRING req;

    if ( data.cr.valid ) {
        req.resize(sizeof(ClientRequest));
        char* bytes = reinterpret_cast< char* >( &data.cr );
        std::copy(bytes, bytes + sizeof(ClientRequest), req.begin());
    }
    else if ( data.sr.valid ) {
        req.resize(sizeof(ServerRequest));
        char* bytes = reinterpret_cast< char* >( &data.sr );
        std::copy(bytes, bytes + sizeof(ServerRequest), req.begin());
    }
    else if ( data.udp.isValid ) {
        req.resize(sizeof(UDPResponse));
        char* bytes = reinterpret_cast< char* >( &data.udp );
        std::copy(bytes, bytes + sizeof(UDPResponse), req.begin());
    }

    BYTESTRING key = NetCommon::SerializeString(data.aesKey);

    Cipher::Aes<256> aes(key.data());
    aes.encrypt_block(req.data());

    return req;
}
