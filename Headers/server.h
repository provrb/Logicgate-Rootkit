#ifndef _SERVER_INTERFACE_H_
#define _SERVER_INTERFACE_H_

#include "net_common.h"
#include "client.h"

#include <thread>
#include <mutex>

#define MAX_CON 300 // max clients on a server

// first = public rsa key, second = private rsa key
using RSAKeys = std::pair<std::string, std::string>;
using ClientData = std::pair<Client, RSAKeys>;

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

	/*
		Shut down the current Server in this class
		'TCPServerDetails' and set it to a blank server struct
	*/
	inline void ShutdownServer(BOOL confirm) {
		if ( !confirm ) return;

		MarkServerAsDead(this->TCPServerDetails); // set alive field to false
		ShutdownSocket(this->TCPServerDetails.sfd, 2); // shutdown server socket for both read and write
		CloseSocket(this->TCPServerDetails.sfd);
		this->TCPServerDetails = {}; // set server details to new blank server structure
	}

	/*
		Binds, listens. accepts clients if tcp using
		the 'Server' instances. Sets 
	*/
	BOOL		   StartServer(Server& server);

	Server         NewServerInstance(SocketTypes serverType, int port);

	BOOL           TCPSendMessageToClient(long cuid, ServerCommand& req);

	BOOL           TCPSendMessageToClients(ServerCommand& req);
	
	/*
		A thread that receives clientRequests from each client that connects.

		If the ExpectingResponse boolean is set to true, this means a
		server function is waiting for a response from this client.
		Cast to ClientResponse instead of a ClientRequest, otherwise
		all received data is automatically interpreted as a ClientRequest.
	*/
	void           TCPReceiveMessagesFromClient(long cuid);

	ClientRequest  DecryptClientRequest(long cuid, BYTESTRING req);

	BYTESTRING     EncryptServerRequest(ServerRequest& req);

	/*
		Thread to accept clients to the tcp server.
		Will accept clients for the WHOLE LIFETIME of the
		tcp server in serverDetails
	*/
	void		   AcceptTCPConnections();

	/*
		Wait for a single client response from a client

		Set the ExpectingResponse flag in the Client struct to true
		telling TCPReceiveMessagesFromClient we want to cast the next
		received response to a ClientResponse. Then revert ExpectingResponse
	*/
	ClientResponse WaitForClientResponse(long cuid);

	/* 
		Use this when you know the informatin you're going to receive
		will be a client response not a cLient request. usually when a simple
		query like a ping request is sent to client from server.
	*/
	ClientResponse DecryptClientResponse(long cuid, BYTESTRING req); 

	/*
		Send a message to a client usually
		after receiving a message from a client over udp.
		UDPMessage contains this class for the TCPServer
		to update the clients connection client-side.
	*/
	BOOL           UDPSendMessageToClient(long cuid, UDPMessage& message);
	
	BOOL           UDPSendMessageToClient(Client& client, UDPMessage& message);


	/*
		A thread to recv udp messages from
		clients wanting to connect.
	*/
	void           ListenForUDPMessages();

	/*
		Insert Client into clientList, genearting a unique
		CUID, and then adding to clientList
	*/
	BOOL           AddToClientList(Client client);

	/*
		Used to see if a client is still alive.
		Will return ClientRepsonseCode C_OK if ping is sent
		and received. Otherwise, will be C_ERROR
	*/
	ClientResponse PingClient(long cuid);

	/*
		Check if cuid is in ClientList. If not
		return FALSE and catch std::out_of_range error.
	*/
	BOOL           ClientIsInClientList(long cuid);
	
	/*
		Ping the client. Wait for a response code of C_OK.
		Otherwise, client is dead.
	*/
	BOOL           IsClientAlive(long cuid);

	/*
		Get the client data from a client
		in the client list using CUID.
	*/
	inline const ClientData GetClientData(long cuid) {
		if ( !ClientIsInClientList(cuid) )
			return std::pair<Client, RSAKeys>({}, { "", "" }); // empty tuple

		return GetClientList().at(cuid);
	}

	inline std::unordered_map<long, ClientData>& GetClientList() {
		std::lock_guard<std::mutex> lock(ClientListMutex);
		return this->ClientList;
	}

	inline BOOL IsServerRunning(const Server& s) const {
		return s.alive;
	}

	inline const Server GetTCPServerDetails() const {
		return this->TCPServerDetails;
	}

protected:

	inline BOOL RemoveClientFromClientList(long cuid) {
		return GetClientList().erase(cuid) == 1; // true if 1 element was erased
	}

	inline BOOL MarkServerAsDead(Server& server) const {
		return ( server.alive = FALSE ) == FALSE;
	}

	inline BOOL MarkServerAsAlive(Server& server) const {
		return ( server.alive = TRUE ) == FALSE;
	}

	/*
		Generate an RSA public and private key
		and format it as an std::pair
	*/
	RSAKeys		   GenerateRSAPair();

	/*
		Perform a received and encrypted udp request
		from a client.
	*/
	BOOL           PerformUDPRequest(BYTESTRING req);

	template <typename Data>
	Data           DecryptClientData(BYTESTRING cipher, long cuid);

	/*
		A dictionary with the clientId that contains
		Information about the connected client alongside its private and public
		uniquely generated rsa key for all connected clients
	*/
	std::unordered_map<long, ClientData> ClientList;
	std::mutex ClientListMutex; // concurrency
	Server TCPServerDetails;
	Server UDPServerDetails;
};

#endif // _SERVER_H_