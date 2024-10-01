#ifndef _SERVER_INTERFACE_H_
#define _SERVER_INTERFACE_H_

#include "net_common.h"
#include "client.h"

#include <thread>
#include <mutex>

#define MAX_CON 300 // max clients on a server

// Constants to get data from ClientData tuple when using std::get
constexpr int CLIENT_CLASS    = 0;
constexpr int PUBLIC_RSA_KEY  = 1;
constexpr int PRIVATE_RSA_KEY = 2;
constexpr int AES_KEY         = 1; // AES Key is also public rsa key

// Client class, Public RSA Key, Private RSA Key
using ClientData = std::tuple<Client, std::string, std::string>;

class ServerInterface
{
public:
	ServerInterface() = default;

	ServerInterface(SocketTypes serverType, int serverPort, BOOL start)  {
		Server s = NewServerInstance(serverType, serverPort);
		
		if ( start )
			StartServer(s);
	}

	~ServerInterface() {
		if ( IsServerRunning(this->ServerDetails) )
			ShutdownServer();

		CleanWSA();
	}

	/*
		Binds, listens. accepts clients if tcp using
		the 'Server' instances. Sets 
	*/
	BOOL		   StartServer(const Server& server);

	/*
		Shut down the current Server in this class
		'ServerDetails' and set it to a blank server struct
	*/
	inline void    ShutdownServer() {
		MakeServerAsDead(this->ServerDetails); // set alive field to false
		ShutdownSocket(this->ServerDetails.sfd, 2); // shutdown server socket for both read and write
		CloseSocket(this->ServerDetails.sfd); 
		this->ServerDetails = {}; // set server details to new blank server structure
	}

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
		Insert Client into clientList, genearting a unique
		CUID, and then adding to clientList
	*/
	BOOL           AddToClientList(Client& client);

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
		Check if the client is alive by pinging the client.
		If the client is dead and the client is in ClientList,
		remove them. Return false if client is dead, 
	*/
	BOOL		   IsCUIDInUse(long cuid);
	
	/*
		Ping the client. Wait for a response code of C_OK.
		Otherwise, client is dead.
	*/
	BOOL           IsClientAlive(long cuid);

	inline BOOL RemoveClientFromClientList(long cuid) {
		return GetClientList().erase(cuid) == 1; // true if 1 element was erased
	}

	/*
		Get the client data from a client
		in the client list using CUID.
	*/
	inline const ClientData GetClientData(long cuid) {
		if ( !ClientIsInClientList(cuid) )
			return std::tuple<Client, std::string, std::string>({}, "", ""); // empty tuple

		return GetClientList().at(cuid);
	}

	inline std::unordered_map<long, ClientData>& GetClientList() {
		std::lock_guard<std::mutex> lock(ClientListMutex);
		return this->ClientList;
	}

	inline BOOL IsServerRunning(const Server& s) const {
		return s.alive;
	}

	inline const Server GetServerDetails() const {
		return this->ServerDetails;
	}

protected:


	inline BOOL MakeServerAsDead(Server& server) const {
		return ( server.alive = FALSE ) == FALSE;
	}

	/*
		A thread to recv udp messages from
		clients wanting to connect.
	*/
	void           ListenForUDPMessages();

	/*
		Perform a received and encrypted udp request
		from a client.
	*/
	BOOL           PerformUDPRequest(BYTESTRING req);

	template <typename Data>
	Data           DecryptClientData(BYTESTRING cipher, long cuid);

	/*
		Generate an RSA public and private key 
		and format it as an std::pair
	*/
	std::pair<std::string, std::string>  GenerateRSAPair();

	/*
		A dictionary with the clientId that contains
		Information about the connected client alongside its private and public
		uniquely generated rsa key for all connected clients
	*/
	std::unordered_map<long, ClientData> ClientList;
	std::mutex							 ClientListMutex; // concurrency
	Server								 ServerDetails; // TCP Server
};

#endif // _SERVER_H_