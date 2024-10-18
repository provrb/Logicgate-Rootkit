#pragma once

#include "framework.h"
#include "net_types.h"
#include "serialization.h"

#include <string>
#include <openssl/pem.h>
#include <iostream>

typedef std::vector<unsigned char> BYTESTRING;

// Dynamically loaded functions from the winsock library
static _socket        CreateSocket       = nullptr;
static _WSAStartup    StartWSA           = nullptr;
static _WSACleanup    CleanWSA           = nullptr;
static _closesocket   CloseSocket        = nullptr;
static _bind          BindSocket         = nullptr;
static _sendto        SendTo             = nullptr;
static _send          Send               = nullptr;
static _recv          Receive            = nullptr;
static _recvfrom      ReceiveFrom        = nullptr;
static _connect       ConnectSocket      = nullptr;
static _listen        SocketListen       = nullptr;
static _shutdown      ShutdownSocket     = nullptr;
static _accept        AcceptOnSocket     = nullptr;
static _htons         HostToNetworkShort = nullptr;
static _inet_addr     InternetAddress    = nullptr;
static _gethostbyname GetHostByName      = nullptr;
static _htonl         HostToNetworkLong  = nullptr;
static _ntohl         NetworkToHostLong  = nullptr;

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
    BIO*         BIODeepCopy(BIO* in);

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
        if ( !WSAInitialized ) return FALSE;

        BYTESTRING responseBuffer;
        int received = -1; // recv return value
        uint32_t dataSize = 0; // size of the data to be received

        if constexpr ( std::is_same<_Struct, BYTESTRING>::value ) // use data as output buffer
            responseBuffer = data;

        if ( type == SocketTypes::TCP ) {

            received = Receive(
                s,
                reinterpret_cast< char* >( &dataSize ),
                sizeof(dataSize),
                0
            );

            dataSize = NetworkToHostLong(dataSize);

            std::cout << "receiving " << dataSize << " bytes\n";
            if ( received == 0 ) {
                return FALSE;
            }
            else if ( received < 0 ) {
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
                std::cout << "encrypted...\n";
                BYTESTRING cipher = NetCommon::RSADecryptStruct(responseBuffer, rsaKey, privateKey);
                responseBuffer = cipher;
                std::cout << "decrypted!\n";
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
        if ( !WSAInitialized ) return FALSE;

        BYTESTRING serialized = Serialization::SerializeStruct(message);
        int        sent = -1;

        // message is already serialized/a bytestirng
        if constexpr ( std::is_same<BYTESTRING, _Struct>::value )
            serialized = message;

        if ( encryption ) {
            BYTESTRING encrypted = NetCommon::RSAEncryptStruct(serialized, rsaKey, privateKey);
            serialized = encrypted;
        }

        uint32_t size = HostToNetworkLong(serialized.size());

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