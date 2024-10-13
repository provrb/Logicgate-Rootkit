#pragma once

#include "framework.h"
#include "net_types.h"
#include "serialization.h"

#include <string>
#include <openssl/pem.h>
#include <iostream>

#define winsock32 std::string(HIDE("Ws2_32.dll"))

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

#ifdef CLIENT_RELEASE 
    #define CLIENT_DBG(string) OutputDebugStringA(string);
#else
    #define CLIENT_DBG(string)
#endif

/*
    Functions that will be used by both server and
    client, usually relevant to sending and receiving
    data over sockets.
*/
namespace NetCommon
{
    static BOOL        WSAInitialized = FALSE; // Has the windows sockets api been initialized for this process
    static sockaddr_in _default = {}; // default sockaddr_in parameter

    void         LoadWSAFunctions(); // Dynamically load wsa functions
    BYTESTRING   RSADecryptStruct(BYTESTRING data, BIO* bio, BOOL privateKey);
    BYTESTRING   RSAEncryptStruct(BYTESTRING data, BIO* bio, BOOL privateKey);
    inline BIO*  GetBIOFromString(std::string s) { return BIO_new_mem_buf(s.c_str(), s.size()); }

    template <typename _Struct>
    inline BOOL ReceiveData(
        _Struct& data,
        SOCKET s,
        SocketTypes type,
        sockaddr_in& receivedAddr = _default,
        BOOL encrypted = FALSE,
        BIO* rsaKey = {},
        BOOL privateKey = FALSE // is 'rsaKey' the public or private key 
    )
    {
        BYTESTRING responseBuffer;

        if constexpr ( std::is_same<_Struct, BYTESTRING>::value ) // use data as output buffer
            responseBuffer = data;

        int received = -1;

        // receive data size first
        uint32_t dataSize = 0;

        if ( type == SocketTypes::TCP ) {

            received = Receive(
                s,
                reinterpret_cast< char* >( &dataSize ),
                sizeof(dataSize),
                0
            );

            std::cout << "receiving " << dataSize << " bytes\n";
            if ( received == 0 ) {
                std::cout << "tcp connection closed\n";
                return FALSE;
            }
            else if ( received < 0 ) {
                std::cout << "error\n";
                return FALSE;
            }

            responseBuffer.resize(dataSize);

            received = Receive(
                s,
                reinterpret_cast< char* >( responseBuffer.data() ),
                responseBuffer.size(),
                0
            );
            responseBuffer.resize(received);
        }
        else if ( type == SocketTypes::UDP ) {
            int addrSize = sizeof(receivedAddr);

            received = ReceiveFrom(
                s,
                reinterpret_cast< char* >( &dataSize ),
                sizeof(dataSize),
                0,
                reinterpret_cast< sockaddr* >( &receivedAddr ),
                &addrSize
            );

            responseBuffer.resize(dataSize);

            received = ReceiveFrom(
                s,
                reinterpret_cast< char* >( responseBuffer.data() ),
                responseBuffer.size(),
                0,
                reinterpret_cast< sockaddr* >( &receivedAddr ),
                &addrSize
            );
        }

        // when this is true, you are responsible for decrypting after this function call if it is encrypted
        if constexpr ( std::is_same<BYTESTRING, _Struct>::value )
            data = responseBuffer;
        else {
            if ( encrypted ) {
                BYTESTRING cipher = NetCommon::RSADecryptStruct(responseBuffer, rsaKey, privateKey);
                std::cout << "decrypted\n";
                responseBuffer = cipher;
                std::cout << "test" << std::endl;
            }
            data = Serialization::DeserializeToStruct<_Struct>(responseBuffer);
        }

        return ( received != SOCKET_ERROR );
    }

    template <typename _Struct>
    inline BOOL TransmitData(
        _Struct message,
        SOCKET s,
        SocketTypes type,
        sockaddr_in udpAddr = _default,
        BOOL encryption = FALSE,
        BIO* rsaKey = {},
        BOOL privateKey = FALSE
    )
    {
        BYTESTRING serialized = Serialization::SerializeStruct(message);

        // message is already serialized/a bytestirng
        if constexpr ( std::is_same<BYTESTRING, _Struct>::value )
            serialized = message;

        int        sent = -1;

        if ( encryption ) {
            BYTESTRING encrypted = NetCommon::RSAEncryptStruct(serialized, rsaKey, privateKey);
            serialized = encrypted;
        }

        uint32_t size = serialized.size();

        if ( type == SocketTypes::TCP ) {
            // send data size
            sent = Send(
                s,
                reinterpret_cast< char* >( &size ),
                sizeof(size),
                0
            );

            // send data
            sent = Send(
                s,
                reinterpret_cast< char* >( serialized.data() ),
                serialized.size(),
                0
            );
        }
        else if ( type == SocketTypes::UDP ) {
            sent = SendTo(
                s,
                reinterpret_cast< char* >( &size ),
                sizeof(size),
                0,
                reinterpret_cast< sockaddr* >( &udpAddr ),
                sizeof(udpAddr)
            );

            sent = SendTo(
                s,
                reinterpret_cast< char* >( serialized.data() ),
                serialized.size(),
                0,
                reinterpret_cast< sockaddr* >( &udpAddr ),
                sizeof(udpAddr)
            );
        }

        return ( sent != SOCKET_ERROR );
    }
}