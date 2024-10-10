#ifndef _NET_COMMON_
#define _NET_COMMON_

#include "framework.h"
#include "net_types.h"

#include <string>
#include <openssl/pem.h>
#include <iostream>

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

#ifdef CLIENT_RELEASE 
    #define CLIENT_DBG(string) OutputDebugStringA(string);
#else
    #define CLIENT_DBG(string)
#endif


namespace NetCommon
{
    static BOOL        WSAInitialized = FALSE; // Has the windows sockets api been initialized for this process
    static sockaddr_in _default = {}; // default sockaddr_in parameter

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
        if constexpr ( std::is_same<BYTESTRING, _Struct>::value )
            return b;
        CLIENT_DBG("DeserializeToStruct");
        return *reinterpret_cast< _Struct* >( b.data() );
    }

    template <typename _Struct>
    inline BYTESTRING SerializeStruct(_Struct data) {
        BYTESTRING serialized(sizeof(_Struct));
        std::memcpy(serialized.data(), &data, sizeof(_Struct));

        return serialized;
    }
    
    BYTESTRING RSADecryptStruct(BYTESTRING data, BIO* bio);

    BYTESTRING RSAEncryptStruct(BYTESTRING data, BIO* bio);

    /*
        Decrypt a byte string received from a socket
        and cast it to whatever type Data is.

        Note: please be careful using this and make sure
        the data sent is supposed to be casted to the type 'Data'
        or else your values will be garbage
    */
    template <typename Data>
    inline Data DecryptInternetData(BYTESTRING string, BIO* rsaPrivKey) {
        string = NetCommon::RSADecryptStruct(string, rsaPrivKey);
        return *reinterpret_cast< Data* >( string.data() );
    }


    inline BIO* GetBIOFromString(char* s, int len) {
        return BIO_new_mem_buf(s, len);
    }

    inline std::string ConvertBIOToString(BIO* bio) {
        char* charString;
        long bytes = BIO_get_mem_data(bio, &charString);
        return std::string(charString, bytes);
    }

    template <typename _Struct>
    inline BOOL ReceiveData(
        _Struct& data,
        SOCKET s,
        SocketTypes type,
        sockaddr_in& receivedAddr = _default,
        BOOL encrypted = FALSE,
        BIO* rsaPubKey = {}
    ) 
    {
        BYTESTRING responseBuffer; 
        std::cout << "buffer\n";

        if constexpr ( std::is_same<_Struct, BYTESTRING>::value ) // use data as output buffer
            responseBuffer = data;
        
        std::cout << "setup buffer\n";
        CLIENT_DBG("buffer set up");

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

            responseBuffer.resize(dataSize);

            received = Receive(
                s,
                reinterpret_cast< char* >( responseBuffer.data() ),
                responseBuffer.size(),
                0
            );
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

        if constexpr ( std::is_same<BYTESTRING, _Struct>::value )
            data = responseBuffer;
        else {
            std::cout << "not the same\n";
            CLIENT_DBG("deserializing");
            responseBuffer.resize(received);
            if ( encrypted ) {
                std::cout << "we are receiving an encrypted struct\n";
                CLIENT_DBG("message is encrypted");
                BYTESTRING cipher = NetCommon::RSADecryptStruct(responseBuffer, rsaPubKey);
                responseBuffer = cipher;
            }
            CLIENT_DBG("deserialized?");
            data = NetCommon::DeserializeToStruct<_Struct>(responseBuffer);
        }
        
        std::cout << "deserialized...\n";
        return ( received != SOCKET_ERROR );
    }

    template <typename _Struct>
    BOOL TransmitData(
        _Struct message, 
        SOCKET s,
        SocketTypes type,
        sockaddr_in udpAddr = _default,
        BOOL encryption = FALSE,
        BIO* rsaKey = {}
    ) 
    {

        BYTESTRING serialized = NetCommon::SerializeStruct(message);
        BYTESTRING encrypted;
        int        sent = -1;
        
        if ( encryption ) {
            encrypted = NetCommon::RSAEncryptStruct(serialized, rsaKey);
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

    /*
        Functions that can be used to send and receive
        server and client-sided.
    */

    template <typename _Struct>
    BOOL TCPSendEncryptedMessage(_Struct message, SOCKET socket, BIO* rsaKey) {
        return TransmitData(message, socket, TCP, _default, TRUE, rsaKey);
    }

    template <typename _Struct>
    BOOL TCPSendMessage(_Struct message, SOCKET socket) {
        return TransmitData(message, socket, TCP);
    }
    
    template <typename _Struct>
    BOOL TCPRecvEncryptedMessage(SOCKET socket, _Struct& data, BIO* rsaPrivKey) {
        // need this to compile cause the default argument
        sockaddr_in recv; // if it works it works

        return ReceiveData(data, socket, TCP, recv);
    }

    template <typename _Struct>
    BOOL TCPRecvMessage(SOCKET socket, _Struct& data) {
        // need this to compile cause the default argument
        sockaddr_in recv; // if it works it works
        
        return ReceiveData(data, socket, TCP, recv);
    }

    template <typename _Struct>
    BOOL UDPSendMessage(_Struct message, SOCKET socket, sockaddr_in addr) {
        return TransmitData(message, socket, UDP, addr);
    }

    template <typename _Struct>
    sockaddr_in UDPRecvMessage(SOCKET socket, _Struct& data) {
        sockaddr_in receivedAddr;
        ReceiveData(data, socket, UDP, receivedAddr);
        return receivedAddr;
    }
}

#endif 