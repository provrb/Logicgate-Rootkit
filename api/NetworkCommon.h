#pragma once

#include "Framework.h"
#include "NetworkTypes.h"
#include "Serialization.h"
#include "ProcessManager.h"
#include "LogicateCryptography.h"

#include <string>
#include <openssl/pem.h>
#include <iostream>


// Dynamically loaded functions from the winsock library
inline ::_socket        CreateSocket       = nullptr;
inline ::_WSAStartup    StartWSA           = nullptr;
inline ::_WSACleanup    CleanWSA           = nullptr;
inline ::_closesocket   CloseSocket        = nullptr;
inline ::_bind          BindSocket         = nullptr;
inline ::_sendto        SendTo             = nullptr;
inline ::_send          Send               = nullptr;
inline ::_recv          Receive            = nullptr;
inline ::_recvfrom      ReceiveFrom        = nullptr;
inline ::_connect       ConnectSocket      = nullptr;
inline ::_listen        SocketListen       = nullptr;
inline ::_shutdown      ShutdownSocket     = nullptr;
inline ::_accept        AcceptOnSocket     = nullptr;
inline ::_htons         HostToNetworkShort = nullptr;
inline ::_inet_addr     InternetAddress    = nullptr;
inline ::_gethostbyname GetHostByName      = nullptr;
inline ::_htonl         HostToNetworkLong  = nullptr;
inline ::_ntohl         NetworkToHostLong  = nullptr;
inline ::_setsocketopt  SetSocketOptions = nullptr;

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
    inline BOOL        WSAInitialized = FALSE; // Has the windows sockets api been initialized for this process
    static sockaddr_in _default = {}; // default sockaddr_in parameter

    void         LoadWSAFunctions(); // Dynamically load wsa functions
    BIO*         BIODeepCopy(BIO* in);
    BOOL         ResetSocketTimeout(SOCKET sfd, int type);
    BOOL         SetSocketTimeout(SOCKET sfd, int timeoutMS, int type);

    template <typename _Struct>
    inline BOOL ReceiveData(
        _Struct& data,
        SOCKET s,
        SocketTypes type,
        sockaddr_in& receivedAddr = _default,
        BOOL encrypted = FALSE,
        RSA* rsaKey = {},
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

            if ( received <= 0 )
                return FALSE;

            responseBuffer.resize(dataSize);
            received = Receive(
                s,
                reinterpret_cast< char* >( responseBuffer.data() ),
                responseBuffer.size(),
                0
            );

            if ( received <= 0 )
                return FALSE;
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

            CLIENT_DBG("received data");
        }

        // when this is true, you are responsible for decrypting after this function call if it is encrypted
        if constexpr ( std::is_same<BYTESTRING, _Struct>::value )
            data = responseBuffer;
        else {
            if ( encrypted ) {
                BYTESTRING cipher = LGCrypto::RSADecrypt(responseBuffer, rsaKey, privateKey);
                responseBuffer = cipher;
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
        RSA* rsaKey = {},
        BOOL privateKey = FALSE
    )
    {
        if ( !WSAInitialized ) {
            CLIENT_DBG("wsa not initialiized");
            return FALSE;
        }

        BYTESTRING serialized = Serialization::SerializeStruct(message);
        int        sent = -1;

        // message is already serialized/a bytestirng
        if constexpr ( std::is_same<BYTESTRING, _Struct>::value )
            serialized = message;

        if ( encryption ) {
            BYTESTRING encrypted = LGCrypto::RSAEncrypt(serialized, rsaKey, privateKey);
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
            std::cout << "sent " << sent << " bytes fully\n";
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

        CLIENT_DBG("sent message");

        return ( sent != SOCKET_ERROR );
    }
}


// class NetworkManager...