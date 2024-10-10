#ifndef _NET_COMMON_
#define _NET_COMMON_

#include "framework.h"
#include "net_types.h"
#include "aes.hpp"

#include <string>
#include <openssl/pem.h>

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

        return *reinterpret_cast< _Struct* >( b.data() );
    }

    template <typename _Struct>
    inline BYTESTRING SerializeStruct(_Struct data) {
        BYTESTRING serialized(sizeof(_Struct));
        std::memcpy(serialized.data(), &data, sizeof(_Struct));

        return serialized;
    }
    
    // Encrypt a BYTESTRING using an aes key
    BYTESTRING AESEncryptStruct(BYTESTRING data, std::string aesKey);

    BYTESTRING RSADecryptStruct(BYTESTRING data, BIO* bio);
    BYTESTRING RSAEncryptStruct(BYTESTRING data, BIO* bio);

    /*
        Decrypt a byte string using RSA with the RSA
        private key 'key'. 
        Returns decrypted bytestring back into string
    */
    inline void DecryptByteString(BYTESTRING& string, std::string key) {
        
        //BYTESTRING byteKey = NetCommon::SerializeString(key);
        //Cipher::Aes<256> aes(byteKey.data());
        //aes.decrypt_block(string.data());
    }

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

    template <typename _Struct>
    inline BOOL ReceiveData(_Struct& data, SOCKET s, SocketTypes type, sockaddr_in& receivedAddr = _default) {
        BYTESTRING responseBuffer; 
        std::cout << "buffer\n";

        if constexpr ( std::is_same<_Struct, BYTESTRING>::value ) // use data as output buffer
            responseBuffer = data;
        else // data isn't being used as output buffer, reset
            responseBuffer.resize(sizeof(_Struct));
        
        std::cout << "setup buffer\n";

        int received = -1;

        if ( type == SocketTypes::TCP ) {
            std::cout << " - tcp receive!\n";
            received = Receive(
                s,
                reinterpret_cast< char* >( responseBuffer.data() ),
                responseBuffer.size(),
                0
            );
            std::cout << "received..\n";
        }
        else if ( type == SocketTypes::UDP ) {
            int size = sizeof(receivedAddr);

            received = ReceiveFrom(
                s,
                reinterpret_cast< char* >( responseBuffer.data() ),
                responseBuffer.size(),
                0,
                reinterpret_cast< sockaddr* >( &receivedAddr ),
                &size
            );
        }

        if constexpr ( std::is_same<BYTESTRING, _Struct>::value )
            data = responseBuffer;
        else {
            responseBuffer.resize(received);
            data = NetCommon::DeserializeToStruct<_Struct>(responseBuffer);
        }
        
        std::cout << "deserialized...\n";
        return ( received != SOCKET_ERROR );
    }

    template <typename _Struct>
    BOOL TransmitData(_Struct message, SOCKET s, SocketTypes type, sockaddr_in udpAddr = _default) {
        BYTESTRING serialized = NetCommon::SerializeStruct(message);
        int        sent = -1;

        if ( type == SocketTypes::TCP )
            sent = Send(
                s,
                reinterpret_cast< char* >( serialized.data() ),
                serialized.size(),
                0
            );
        else if ( type == SocketTypes::UDP )
            sent = SendTo(
                s,
                reinterpret_cast< char* >( serialized.data() ),
                serialized.size(),
                0,
                reinterpret_cast< sockaddr* >( &udpAddr ),
                sizeof(udpAddr)
            );

        return ( sent != SOCKET_ERROR );
    }

    /*
        Functions that can be used to send and receive
        server and client-sided.
    */

    template <typename _Struct>
    BOOL TCPSendMessage(_Struct message, SOCKET socket) {
        return TransmitData(message, socket, TCP);
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