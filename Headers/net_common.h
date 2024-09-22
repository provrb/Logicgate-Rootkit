#ifndef _NET_COMMON_
#define _NET_COMMON_

#include "framework.h"
#include "net_types.h"
#include "aes.hpp"

#include <string>

#define winsock32 std::string(HIDE("Ws2_32.dll"))

#pragma pack(2)
typedef struct {
    ClientRequest cr;
    ServerRequest sr;
    UDPResponse   udp;
    std::string   aesKey;
} NET_BLOB;

typedef std::vector<unsigned char> BYTESTRING;

// Function pointers
typedef SOCKET ( WINAPI* _socket)       ( int af, int type, int protocol );
typedef int    ( WINAPI* _WSAStartup )  ( WORD wVersionRequired, LPWSADATA lpWSAData );
typedef int    ( WINAPI* _closesocket ) ( SOCKET s );
typedef int    ( WINAPI* _WSACleanup )  ( void );
typedef int    ( WINAPI* _bind )        ( SOCKET s, const sockaddr* addr, int namelen );
typedef int    ( WINAPI* _sendto )      ( SOCKET s, const char* buf, int len, int flags, const sockaddr* addr, int tolen );
typedef int    ( WINAPI* _send )        ( SOCKET s, const char* buff, int len, int flags );
typedef int    ( WINAPI* _recv )        ( SOCKET s, char* buf, int len, int flags );
typedef int    ( WINAPI* _recvfrom )    ( SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen );
typedef int    ( WINAPI* _connect )     ( SOCKET s, const sockaddr* addr, int namelen );

// Dynamically loaded functions from the winsock library
inline _socket       CreateSocket = nullptr;
inline _WSAStartup   StartWSA = nullptr;
inline _WSACleanup   CleanWSA = nullptr;
inline _closesocket  CloseSocket = nullptr;
inline _bind         BindSocket = nullptr;
inline _sendto       SendTo = nullptr;
inline _send         Send = nullptr;
inline _recv         Receive = nullptr;
inline _recvfrom     ReceiveFrom = nullptr;
inline _connect      ConnectSocket = nullptr;

namespace NetCommon
{
    inline BOOL WSAInitialized = FALSE;

    /*
        Load all dynamically loaded wsa functions
    */
    void LoadWSAFunctions();

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