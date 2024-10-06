#ifndef _NET_COMMON_
#define _NET_COMMON_

#include "framework.h"
#include "net_types.h"
#include "aes.hpp"

#include <string>

#define winsock32 std::string(HIDE("Ws2_32.dll"))

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
typedef int    ( WINAPI* _listen )      ( SOCKET s, int backlog );
typedef int    ( WINAPI* _shutdown )    ( SOCKET s, int how );
typedef SOCKET ( WINAPI* _accept )      ( SOCKET s, sockaddr* addr, int* addrlen );
typedef unsigned short ( WINAPI* _htons )( unsigned short s );
typedef unsigned long ( WINAPI* _inet_addr )( const char* ip );
typedef hostent* ( WINAPI* _gethostbyname )( const char* name );

// Dynamically loaded functions from the winsock library
inline _socket        CreateSocket       = nullptr;
inline _WSAStartup    StartWSA           = nullptr;
inline _WSACleanup    CleanWSA           = nullptr;
inline _closesocket   CloseSocket        = nullptr;
inline _bind          BindSocket         = nullptr;
inline _sendto        SendTo             = nullptr;
inline _send          Send               = nullptr;
inline _recv          Receive            = nullptr;
inline _recvfrom      ReceiveFrom        = nullptr;
inline _connect       ConnectSocket      = nullptr;
inline _listen        SocketListen       = nullptr;
inline _shutdown      ShutdownSocket     = nullptr;
inline _accept        AcceptOnSocket     = nullptr;
inline _htons         HostToNetworkShort = nullptr;
inline _inet_addr     InternetAddress    = nullptr;
inline _gethostbyname GetHostByName      = nullptr;

namespace NetCommon
{
    inline BOOL WSAInitialized = FALSE; // Has the windows sockets api been initialized for this process

    /*
        Load all dynamically loaded wsa functions
    */
    void LoadWSAFunctions();

    /*
        Convert an std::string to a BYTESTRING
        (std::vector<unsigned char>)
    */
    inline BYTESTRING SerializeString(std::string s) {
        BYTESTRING bs;
        for ( BYTE c : s )
            bs.push_back(c);
        return bs;
    }

    template <typename _Struct>
    inline _Struct DeserializeToStruct(BYTESTRING b) {
        return *reinterpret_cast< _Struct* >( b.data() );
    }

    template <typename _Struct>
    inline BYTESTRING SerializeStruct(_Struct data) {
        BYTESTRING serialized(sizeof(_Struct));
        std::memcpy(serialized.data(), &data, sizeof(_Struct));

        return serialized;
    }

    /*
        Encrypt a NET_BLOB structure with an AES key defined
        in the NET_BLOB's AESKEY field. Return an
        encrypted BYTESTRING of the data.
    */
    BYTESTRING AESEncryptBlob(NET_BLOB data);

    
    // Encrypt a BYTESTRING using an aes key
    BYTESTRING AESEncryptStruct(BYTESTRING data, std::string aesKey);

    /*
        Decrypt a byte string using AES with the AES
        symmetrical key 'key'. 
        Returns decrypted bytestring back into string
    */
    inline void DecryptByteString(BYTESTRING& string, std::string key) {
        BYTESTRING byteKey = NetCommon::SerializeString(key);
        Cipher::Aes<256> aes(byteKey.data());
        aes.decrypt_block(string.data());
    }

    /*
        Decrypt a byte string received from a socket
        and cast it to whatever type Data is.

        Note: please be careful using this and make sure
        the data sent is supposed to be casted to the type 'Data'
        or else your values will be garbage
    */
    template <typename Data>
    inline Data DecryptInternetData(BYTESTRING string, std::string aesKey) {
        DecryptByteString(string, aesKey);
        return *reinterpret_cast< Data* >( string.data() );
    }

    /*
        Verify if a NET_BLOB is valid by checking the requests
        fields 'valid' field and checking if the AES key is empty.
    */
    inline BOOL IsBlobValid(NET_BLOB b) {
        return !b.aesKey.empty() && b.cr.valid || b.sr.valid || b.udp.isValid;
    }

    /*
        Convert server and client requests to a
        NET_BLOB structure, filling in all necessary info
        with the arguments passed, and filling all unnecessary info
        with 0 structures.
    */

    inline NET_BLOB RequestToBlob(ServerRequest request, std::string aesKey) {
        return NET_BLOB{ {0}, request, {}, aesKey };
    }

    inline NET_BLOB RequestToBlob(ClientRequest request, std::string aesKey) {
        return NET_BLOB{ request, {0}, {}, aesKey };
    }

}

#endif 