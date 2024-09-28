#ifndef _SERVER_INTERFACE_H_
#define _SERVER_INTERFACE_H_

#include "net_common.h"
#include "client.h"

#include <thread>
#include <mutex>

// Constants to get data from ClientData tuple when using std::get
constexpr int CLIENT_CLASS    = 0;
constexpr int PUBLIC_RSA_KEY  = 1;
constexpr int AES_KEY         = 1; // AES Key is also public rsa key
constexpr int PRIVATE_RSA_KEY = 2;

// Client class, Public RSA Key, Private RSA Key
using ClientData = std::tuple<Client, std::string, std::string>;

class ServerInterface
{
public:
	void           Start(); // Start a TCP server and start listening for UDP Requests

	BOOL           TCPSendMessageToClient(long cuid, ServerCommand req);
	BOOL           TCPSendMessageToClients(ServerCommand req);
	
	/*
		A thread that receives clientRequests from each client that connects.

		If the ExpectingResponse boolean is set to true, this means a
		server function is waiting for a response from this client.
		Cast to ClientResponse instead of a ClientRequest, otherwise
		all received data is automatically interpreted as a ClientRequest.
	*/
	void           TCPReceiveMessagesFromClient(long cuid);

	ClientRequest  DecryptClientRequest(long cuid, BYTESTRING req);
	BYTESTRING     EncryptServerRequest(ServerRequest req);

	/*
		Wait for a single client response from a client

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
	BOOL           UDPSendMessageToClient(long cuid, UDPMessage message);

	/*
		Insert Client into clientList, genearting a unique
		CUID, and then adding to clientList
	*/
	BOOL           AddToClientList(Client client);
	
	/*
		Accept a client connection to the tcp server.

		Use client class instead of client id because that is
		what is sent with the initial udp request and the client
		hasnt been added to the client list and cuid has not been
		generated for the client.
	*/
	BOOL           AcceptTCPConnection(Client clientToAccept);

	/*
		Used to see if a client is still alive.
		Will return ClientRepsonseCode C_OK if ping is sent
		and received. Otherwise, will be C_ERROR
	*/
	ClientResponse PingClient(long cuid);

	BOOL           ClientIsInClientList(long cuid);

	BOOL		   IsCUIDInUse(long cuid);
	
	BOOL           IsClientAlive(long cuid);

	inline BOOL    RemoveClientFromClientList(long cuid) {
		return GetClientList().erase(cuid);
	}

	inline ClientData GetClientData(long cuid) {
		try {
			return GetClientList().at(cuid);
		}
		catch ( const std::out_of_range& ) {}

		ClientData empty = { {}, "Client Doesn't Exist", "Client Doesn't Exist" };

		return empty;
	}

	inline std::unordered_map<long, ClientData> GetClientList() {
		return this->ClientList;
	}

protected:

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
	std::pair<std::string, std::string> GenerateRSAPair();

	/*
		A dictionary with the clientId that contains
		Information about the connected client alongside its private and public
		uniquely generated rsa key for all connected clients
	*/
	std::unordered_map<long, ClientData> ClientList;
	std::mutex							 ClientListMutex; // concurrency

private:
	int sfd = -1; // server socket file descriptor
};

#endif // _SERVER_H_