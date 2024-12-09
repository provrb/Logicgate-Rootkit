#pragma once

#include "NetworkTypes.h"
#include "Serialization.h"
#include "LogicateCryptography.h"
#include "FileManager.h"

#ifdef CLIENT_RELEASE 
#define CLIENT_DBG(string) OutputDebugStringA(string);
#else
#define CLIENT_DBG(string)
#endif

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
inline ::_setsocketopt  SetSocketOptions   = nullptr;
inline ::_getsocketopt  GetSocketOptions   = nullptr;

// use when a sockaddr_in is not required for a function call
inline sockaddr_in NULL_ADDR = {}; 

class NetworkManager {
public:
    NetworkManager();

    /*
        TCP only operations. 
        If the socket provided is of UDP, the function will return false.
        This is to prevent data loss and fragmentation; UDP is unreliable.
    */
    bool IsTCPSocket(SOCKET s);                                 // Check if 's' is a TCP or UDP socket
    bool TransmitRSAKey(SOCKET s, RSA* key, bool isPrivateKey); // Convert an RSA* key to DER format. Send the length and then the key data
    bool SendTCPLargeData(const BYTESTRING& message, SOCKET s); // send a serialized message that is larger than TCP MTU (1494 bytes)
    bool ReceiveTCPLargeData(BYTESTRING& data, SOCKET s);       // receive a packet that is larger than TCP MTU (1492 bytes)
    bool SendFile(File& file, SOCKET s, BYTESTRING& aesKey);                        // Send a File over TCP. Turn contents into packets and send large data

    /*
        TCP and UDP functions.
        Any data sent or received that is over the MTU should be sent over TCP
        using SendTCPLargeData or ReceiveTCPLargeData.
        Beware of fragmentation when sending data over UDP.
    */
    void SetSocketTimeout(SOCKET s, int timeoutMS, int type);
    void ResetSocketTimeout(SOCKET s, int type);
    template <typename _Struct>
    bool TransmitData(
        _Struct message,
        SOCKET s,
        SocketTypes type,
        sockaddr_in& addr = NULL_ADDR,
        bool encrypted = false,
        RSA* rsaKey = nullptr,
        bool privateKey = false
    )
    {
        BYTESTRING serialized = Serialization::SerializeStruct(message);
        int        sent = SOCKET_ERROR;

        // message is already serialized/a bytestirng
        if constexpr ( std::is_same<BYTESTRING, _Struct>::value )
            serialized = message;

        if ( encrypted ) {
            BYTESTRING encrypted = LGCrypto::RSAEncrypt(serialized, rsaKey, privateKey);
            serialized = encrypted;
        }

        uint32_t size = serialized.size();

        if ( type == SocketTypes::TCP ) {
            // send data size
            sent = Send(s, reinterpret_cast< char* >( &size ), sizeof(size), 0);
            if ( sent == SOCKET_ERROR )
                return false;

            // send data
            sent = Send(s, reinterpret_cast< char* >( serialized.data() ), serialized.size(), 0);
        }
        else if ( type == SocketTypes::UDP ) {
            // send size of data
            sent = SendTo(s, reinterpret_cast< char* >( &size ), sizeof(size), 0, reinterpret_cast< sockaddr* >( &addr ), sizeof(addr));
            if ( sent == SOCKET_ERROR )
                return false;

            // send data
            sent = SendTo(s, reinterpret_cast< char* >( serialized.data() ), serialized.size(), 0, reinterpret_cast< sockaddr* >( &addr ), sizeof(addr));
        }

        return ( sent != SOCKET_ERROR );
    }

    template <typename _Struct>
    bool ReceiveData(
        _Struct& data,
        SOCKET s,
        SocketTypes type,
        sockaddr_in& addr = NULL_ADDR
    )
    {
        if ( !this->m_WSAInitialized ) return false;

        BYTESTRING responseBuffer;
        int        received = SOCKET_ERROR; // recv return value
        uint32_t   dataSize = 0; // size of the data to be received

        if constexpr ( std::is_same<_Struct, BYTESTRING>::value ) // use data as output buffer
            responseBuffer = data;

        if ( type == SocketTypes::TCP ) {
            // receive size of incoming data first
            received = Receive(s, reinterpret_cast< char* >( &dataSize ), sizeof(dataSize), 0);
            if ( received <= 0 ) return false;

            responseBuffer.resize(dataSize);

            // receive data
            received = Receive(s, reinterpret_cast< char* >( responseBuffer.data() ), responseBuffer.size(), 0);
        }
        else if ( type == SocketTypes::UDP ) {

            int addrSize = sizeof(addr);

            // receive size of incoming data first
            received = ReceiveFrom(s, reinterpret_cast< char* >( &dataSize ), sizeof(dataSize),
                0, reinterpret_cast< sockaddr* >( &addr ), &addrSize);

            if ( received <= 0 ) return false;

            responseBuffer.resize(dataSize);

            // receive data
            received = ReceiveFrom(s, reinterpret_cast< char* >( responseBuffer.data() ), responseBuffer.size(),
                0, reinterpret_cast< sockaddr* >( &addr ), &addrSize);
        }

        data = Serialization::DeserializeToStruct<_Struct>(responseBuffer);

        return ( received > 0 );
    }
private:
    static inline bool m_WSAInitialized = false;
};

